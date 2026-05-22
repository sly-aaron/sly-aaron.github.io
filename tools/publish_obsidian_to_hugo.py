#!/usr/bin/env python3
"""
Publish explicitly marked Obsidian notes into a Hugo site.

Default mode is dry-run. Use --apply to write files.
Only notes with YAML front matter public: true, publish: true, or blog_publish: true
are exported.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import shutil
import sys
import time
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any


if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

DEFAULT_VAULT = r"D:\ProgramData\Obsidian"
DEFAULT_HUGO = r"D:\ProgramData\blog\sly-aaron.github.io"
MANAGED_MARKER = "<!-- generated-by: obsidian_git_blog_pipeline -->"
SKIP_DIRS = {".git", ".obsidian", ".trash", ".sync", ".stfolder"}
SECTION_MAP_FILENAMES = ("blog_section_map.txt", "blog_section_map.map")
SECTION_MAP_SKIP_VALUES = {"", "-", "ignore", "none", "skip", "off"}
PUBLISH_META_KEYS = {
    "public",
    "publish",
    "blog_publish",
    "blog_section",
    "blog_slug",
    "blog_title",
    "private",
}


@dataclass
class SectionRule:
    source_prefix: str
    section: str | None
    skip: bool = False


@dataclass
class PublishedNote:
    path: Path
    rel_path: Path
    meta: dict[str, Any]
    body: str
    title: str
    section_parts: list[str]
    section_source: str
    slug: str
    target_dir: Path
    url_path: str


class Report:
    def __init__(self) -> None:
        self.notes_written: list[Path] = []
        self.notes_skipped: list[str] = []
        self.notes_blocked: list[str] = []
        self.assets_copied: list[tuple[Path, Path]] = []
        self.assets_missing: list[str] = []
        self.assets_ambiguous: list[str] = []


def normalize_section_path(text: str) -> str:
    cleaned = text.strip().replace("\\", "/")
    while cleaned.startswith("./"):
        cleaned = cleaned[2:]
    return cleaned.strip("/").lower()


def section_path_matches(path_text: str, prefix_text: str) -> bool:
    path_text = normalize_section_path(path_text)
    prefix_text = normalize_section_path(prefix_text)
    if not prefix_text:
        return False
    return path_text == prefix_text or path_text.startswith(prefix_text + "/")


def load_section_rules(path: Path) -> list[SectionRule]:
    rules: list[SectionRule] = []
    text = read_text(path)

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        if "#" in line:
            line = line.split("#", 1)[0].strip()
        if not line:
            continue

        separator = None
        for candidate in ("=>", "->", "="):
            if candidate in line:
                separator = candidate
                break
        if not separator:
            raise ValueError(f"Invalid section map line: {raw_line!r}")

        source, target = line.split(separator, 1)
        source = source.strip()
        target = target.strip()
        if not source:
            continue

        lowered = target.lower()
        if not target or lowered in SECTION_MAP_SKIP_VALUES:
            rules.append(SectionRule(source_prefix=source, section=None, skip=True))
        else:
            rules.append(SectionRule(source_prefix=source, section=target, skip=False))

    rules.sort(key=lambda rule: len(normalize_section_path(rule.source_prefix)), reverse=True)
    return rules


def discover_section_map_path(vault: Path, hugo: Path, override: str | None) -> Path | None:
    candidates: list[Path] = []

    if override:
        candidates.append(Path(override))
    else:
        candidates.extend(vault / name for name in SECTION_MAP_FILENAMES)
        candidates.extend(hugo / name for name in SECTION_MAP_FILENAMES)
        candidates.extend(hugo / "data" / name for name in SECTION_MAP_FILENAMES)
        candidates.extend(Path(__file__).with_name(name) for name in SECTION_MAP_FILENAMES)

    for candidate in candidates:
        if candidate.exists():
            return candidate.resolve()
    return None


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8-sig")
    except UnicodeDecodeError:
        return path.read_text(encoding="utf-8", errors="replace")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def split_frontmatter(text: str) -> tuple[dict[str, Any], str, str]:
    lines = text.splitlines(keepends=True)
    if not lines or lines[0].strip() != "---":
        return {}, "", text

    for index in range(1, len(lines)):
        if lines[index].strip() == "---":
            frontmatter = "".join(lines[1:index])
            body = "".join(lines[index + 1 :])
            return parse_frontmatter(frontmatter), frontmatter, body
    return {}, "", text


def parse_value(value: str) -> Any:
    value = value.strip()
    if value == "":
        return ""
    lower = value.lower()
    if lower in {"true", "yes", "on"}:
        return True
    if lower in {"false", "no", "off"}:
        return False
    if lower in {"null", "none", "~"}:
        return None
    if (value.startswith('"') and value.endswith('"')) or (
        value.startswith("'") and value.endswith("'")
    ):
        return value[1:-1]
    if value.startswith("[") and value.endswith("]"):
        inner = value[1:-1].strip()
        if not inner:
            return []
        return [parse_value(part.strip()) for part in inner.split(",")]
    return value


def parse_frontmatter(frontmatter: str) -> dict[str, Any]:
    meta: dict[str, Any] = {}
    current_key: str | None = None

    for raw_line in frontmatter.splitlines():
        line = raw_line.rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue

        list_match = re.match(r"^\s*-\s+(.*)$", line)
        if list_match and current_key:
            if not isinstance(meta.get(current_key), list):
                meta[current_key] = []
            meta[current_key].append(parse_value(list_match.group(1)))
            continue

        key_match = re.match(r"^([A-Za-z0-9_-]+)\s*:\s*(.*)$", line)
        if key_match:
            key = key_match.group(1)
            value = key_match.group(2).strip()
            if value == "":
                meta[key] = []
                current_key = key
            else:
                meta[key] = parse_value(value)
                current_key = None

    return meta


def is_truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in {"true", "yes", "on", "1"}


def is_publish_enabled(meta: dict[str, Any]) -> bool:
    return any(
        is_truthy(meta.get(key))
        for key in ("public", "publish", "blog_publish")
    )


def yaml_quote(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "null"
    text = str(value)
    if re.match(r"^[A-Za-z0-9_./:-]+$", text):
        return text
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def format_frontmatter(meta: dict[str, Any]) -> str:
    preferred = [
        "title",
        "date",
        "lastmod",
        "draft",
        "tags",
        "categories",
        "weight",
        "geekdocHidden",
        "geekdocCollapseSection",
    ]
    keys = [key for key in preferred if key in meta]
    keys.extend(sorted(key for key in meta if key not in keys))

    lines = ["---"]
    for key in keys:
        value = meta[key]
        if isinstance(value, list):
            lines.append(f"{key}:")
            for item in value:
                lines.append(f"  - {yaml_quote(item)}")
        else:
            lines.append(f"{key}: {yaml_quote(value)}")
    lines.append("---")
    return "\n".join(lines) + "\n"


def should_skip(path: Path, root: Path) -> bool:
    try:
        rel_parts = path.relative_to(root).parts
    except ValueError:
        rel_parts = path.parts
    return any(part in SKIP_DIRS or part.startswith(".git") for part in rel_parts)


def infer_title(body: str, path: Path) -> str:
    in_fence = False
    for line in body.splitlines():
        if re.match(r"^\s*(```|~~~)", line):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        match = re.match(r"^\s*#\s+(.+?)\s*$", line)
        if match:
            return match.group(1).strip()
    return path.stem


def slugify(text: str, fallback_seed: str) -> str:
    text = text.strip().lower()
    result = []
    for char in text:
        if char.isalnum() or char in {"-", "_"}:
            result.append(char)
        elif char in {" ", ".", "/", "\\", ":", "|"}:
            result.append("-")
    slug = re.sub(r"-+", "-", "".join(result)).strip("-_")
    if slug:
        return slug[:120]
    digest = hashlib.sha1(fallback_seed.encode("utf-8", errors="ignore")).hexdigest()[:10]
    return f"note-{digest}"


def safe_section_parts(section: Any) -> list[str]:
    section_text = str(section or "notes").strip().replace("\\", "/")
    section_text = section_text.strip("/")
    parts = [part for part in section_text.split("/") if part and part != "."]
    if not parts:
        return ["notes"]
    for part in parts:
        if part == ".." or ":" in part or part.startswith("~"):
            raise ValueError(f"Unsafe blog_section value: {section_text!r}")
    return [slugify(part, part) for part in parts]


def resolve_section_parts(
    rel_path: Path,
    meta_section: Any,
    section_rules: list[SectionRule],
) -> tuple[list[str] | None, str]:
    explicit_section = str(meta_section or "").strip()
    if explicit_section:
        return (
            safe_section_parts(explicit_section),
            f"front matter blog_section={explicit_section}",
        )

    rel_key = rel_path.with_suffix("").as_posix()
    for rule in section_rules:
        if section_path_matches(rel_key, rule.source_prefix):
            if rule.skip or not rule.section:
                return None, f"map {rule.source_prefix} => skip"
            return (
                safe_section_parts(rule.section),
                f"map {rule.source_prefix} => {rule.section}",
            )

    fallback_section = rel_path.parts[0] if len(rel_path.parts) > 1 else "notes"
    return (
        safe_section_parts(fallback_section),
        f"fallback top folder => {fallback_section}",
    )


def url_for_parts(parts: list[str]) -> str:
    return "/" + "/".join(urllib.parse.quote(part) for part in parts) + "/"


def note_key(path_text: str) -> str:
    cleaned = path_text.strip().replace("\\", "/")
    cleaned = cleaned.split("#", 1)[0]
    if cleaned.endswith(".md"):
        cleaned = cleaned[:-3]
    return cleaned.strip("/").lower()


def collect_published_notes(
    vault: Path,
    hugo: Path,
    allow_private: bool,
    section_rules: list[SectionRule],
    report: Report,
) -> tuple[list[PublishedNote], dict[str, PublishedNote]]:
    content_root = hugo / "content"
    notes: list[PublishedNote] = []
    seen_targets: dict[Path, Path] = {}

    for path in sorted(vault.rglob("*.md")):
        if should_skip(path, vault):
            continue
        text = read_text(path)
        meta, _, body = split_frontmatter(text)
        if not is_publish_enabled(meta):
            continue
        if is_truthy(meta.get("private")) and not allow_private:
            report.notes_skipped.append(f"{path}: private: true, skipped")
            continue

        rel_path = path.relative_to(vault)
        title = str(meta.get("blog_title") or meta.get("title") or infer_title(body, path))
        section_parts, section_source = resolve_section_parts(
            rel_path,
            meta.get("blog_section"),
            section_rules,
        )
        if section_parts is None:
            report.notes_skipped.append(f"{path}: {section_source}")
            continue
        slug = slugify(str(meta.get("blog_slug") or path.stem), str(rel_path))
        target_dir = content_root.joinpath(*section_parts, slug)

        previous = seen_targets.get(target_dir)
        if previous:
            report.notes_blocked.append(
                f"{path}: target collides with {previous}: {target_dir}"
            )
            continue
        seen_targets[target_dir] = path

        url_path = url_for_parts(section_parts + [slug])
        notes.append(
            PublishedNote(
                path=path,
                rel_path=rel_path,
                meta=meta,
                body=body,
                title=title,
                section_parts=section_parts,
                section_source=section_source,
                slug=slug,
                target_dir=target_dir,
                url_path=url_path,
            )
        )

    note_map: dict[str, PublishedNote] = {}
    for note in notes:
        rel_no_suffix = note.rel_path.with_suffix("").as_posix()
        note_map[note_key(note.rel_path.as_posix())] = note
        note_map[note_key(rel_no_suffix)] = note
        note_map[note_key(note.path.stem)] = note

    return notes, note_map


def build_asset_index(vault: Path) -> dict[str, list[Path]]:
    index: dict[str, list[Path]] = {}
    for path in vault.rglob("*"):
        if not path.is_file() or should_skip(path, vault) or path.suffix.lower() == ".md":
            continue
        index.setdefault(path.name.lower(), []).append(path)
    return index


def clean_obsidian_target(target: str) -> str:
    target = target.strip()
    target = target.split("|", 1)[0].strip()
    target = target.split("#", 1)[0].strip()
    if target.startswith("<") and target.endswith(">"):
        target = target[1:-1].strip()
    return urllib.parse.unquote(target)


def is_remote_or_site_path(target: str) -> bool:
    stripped = target.strip().lower()
    if stripped.startswith(("#", "/")):
        return True
    return bool(re.match(r"^[a-z][a-z0-9+.-]*:", stripped))


def resolve_attachment(
    raw_target: str,
    note_path: Path,
    vault: Path,
    asset_index: dict[str, list[Path]],
    report: Report,
) -> Path | None:
    target = clean_obsidian_target(raw_target)
    if not target or is_remote_or_site_path(target):
        return None

    target_path = Path(target)
    candidates: list[Path] = []
    if target_path.is_absolute():
        candidates.append(target_path)
    else:
        candidates.append(note_path.parent / target_path)
        candidates.append(vault / target_path)

    for candidate in candidates:
        if candidate.exists() and candidate.is_file():
            return candidate.resolve()

    matches = asset_index.get(Path(target).name.lower(), [])
    if not matches:
        report.assets_missing.append(f"{note_path}: missing asset {raw_target!r}")
        return None

    near_matches = [path for path in matches if path.parent == note_path.parent]
    chosen = sorted(near_matches or matches, key=lambda item: str(item).lower())[0]
    if len(matches) > 1:
        report.assets_ambiguous.append(
            f"{note_path}: {raw_target!r} matched multiple files, using {chosen}"
        )
    return chosen.resolve()


def unique_asset_name(source: Path, used_names: set[str]) -> str:
    safe_stem = slugify(source.stem, source.name)
    suffix = source.suffix.lower()
    candidate = f"{safe_stem}{suffix}"
    if candidate not in used_names:
        used_names.add(candidate)
        return candidate

    digest = hashlib.sha1(str(source).encode("utf-8", errors="ignore")).hexdigest()[:8]
    candidate = f"{safe_stem}-{digest}{suffix}"
    counter = 2
    while candidate in used_names:
        candidate = f"{safe_stem}-{digest}-{counter}{suffix}"
        counter += 1
    used_names.add(candidate)
    return candidate


def copy_asset(
    source: Path,
    note: PublishedNote,
    used_names: set[str],
    apply: bool,
    report: Report,
) -> str:
    asset_name = unique_asset_name(source, used_names)
    relative_link = f"assets/{urllib.parse.quote(asset_name)}"
    destination = note.target_dir / "assets" / asset_name
    if apply:
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
    report.assets_copied.append((source, destination))
    return relative_link


def split_markdown_target(raw: str) -> tuple[str, str]:
    text = raw.strip()
    if text.startswith("<") and ">" in text:
        end = text.index(">")
        return text[1:end], text[end + 1 :]
    for marker in [' "', " '"]:
        if marker in text:
            index = text.index(marker)
            return text[:index], text[index:]
    return text, ""


def rewrite_body(
    note: PublishedNote,
    vault: Path,
    note_map: dict[str, PublishedNote],
    asset_index: dict[str, list[Path]],
    apply: bool,
    report: Report,
) -> str:
    used_asset_names: set[str] = set()

    def replace_obsidian_image(match: re.Match[str]) -> str:
        raw_inner = match.group(1)
        parts = raw_inner.split("|")
        raw_target = parts[0].strip()
        alt = parts[1].strip() if len(parts) > 1 else Path(raw_target).stem
        source = resolve_attachment(raw_target, note.path, vault, asset_index, report)
        if not source:
            return match.group(0)
        link = copy_asset(source, note, used_asset_names, apply, report)
        return f"![{alt}]({link})"

    def replace_markdown_image(match: re.Match[str]) -> str:
        alt = match.group(1)
        raw_target = match.group(2)
        target, title_suffix = split_markdown_target(raw_target)
        if is_remote_or_site_path(target):
            return match.group(0)
        source = resolve_attachment(target, note.path, vault, asset_index, report)
        if not source:
            return match.group(0)
        link = copy_asset(source, note, used_asset_names, apply, report)
        return f"![{alt}]({link}{title_suffix})"

    def replace_wikilink(match: re.Match[str]) -> str:
        raw_inner = match.group(1)
        parts = raw_inner.split("|")
        raw_target = parts[0].strip()
        label = parts[1].strip() if len(parts) > 1 else raw_target.split("#", 1)[0]
        target_note = note_map.get(note_key(raw_target))
        if target_note:
            return f"[{label}]({target_note.url_path})"
        return label

    output_lines: list[str] = []
    in_fence = False
    for line in note.body.splitlines(keepends=True):
        if re.match(r"^\s*(```|~~~)", line):
            in_fence = not in_fence
            output_lines.append(line)
            continue
        if in_fence:
            output_lines.append(line)
            continue

        rewritten = re.sub(r"!\[\[([^\]]+)\]\]", replace_obsidian_image, line)
        rewritten = re.sub(r"!\[([^\]]*)\]\(([^)]+)\)", replace_markdown_image, rewritten)
        rewritten = re.sub(r"(?<!!)\[\[([^\]]+)\]\]", replace_wikilink, rewritten)
        output_lines.append(rewritten)

    return "".join(output_lines).lstrip()


def hugo_meta_for_note(note: PublishedNote) -> dict[str, Any]:
    meta = {key: value for key, value in note.meta.items() if key not in PUBLISH_META_KEYS}
    meta["title"] = str(note.meta.get("blog_title") or note.meta.get("title") or note.title)
    if "date" not in meta:
        meta["date"] = time.strftime("%Y-%m-%d", time.localtime(note.path.stat().st_mtime))
    if "lastmod" not in meta:
        meta["lastmod"] = time.strftime(
            "%Y-%m-%dT%H:%M:%S%z", time.localtime(note.path.stat().st_mtime)
        )
    return meta


def render_note(
    note: PublishedNote,
    vault: Path,
    note_map: dict[str, PublishedNote],
    asset_index: dict[str, list[Path]],
    apply: bool,
    report: Report,
) -> str:
    body = rewrite_body(note, vault, note_map, asset_index, apply, report)
    return format_frontmatter(hugo_meta_for_note(note)) + MANAGED_MARKER + "\n\n" + body


def publish_notes(args: argparse.Namespace) -> int:
    vault = Path(args.vault).resolve()
    hugo = Path(args.hugo).resolve()
    report = Report()

    if not vault.exists():
        print(f"Vault path not found: {vault}", file=sys.stderr)
        return 2
    if not (hugo / "hugo.toml").exists():
        print(f"Hugo site not found or hugo.toml missing: {hugo}", file=sys.stderr)
        return 2

    section_map_path = discover_section_map_path(vault, hugo, args.section_map)
    if args.section_map and not section_map_path:
        print(f"Section map file not found: {args.section_map}", file=sys.stderr)
        return 2

    section_rules: list[SectionRule] = []
    if section_map_path:
        section_rules = load_section_rules(section_map_path)

    notes, note_map = collect_published_notes(
        vault,
        hugo,
        args.allow_private,
        section_rules,
        report,
    )
    asset_index = build_asset_index(vault)
    apply = bool(args.apply)

    print("Mode:", "APPLY" if apply else "DRY-RUN")
    print(f"Vault: {vault}")
    print(f"Hugo:  {hugo}")
    if section_map_path:
        print(f"Section map: {section_map_path} ({len(section_rules)} rules)")
    else:
        print("Section map: none")
    print(f"Published notes found: {len(notes)}")

    for note in notes:
        target_index = note.target_dir / "index.md"
        if target_index.exists():
            existing = read_text(target_index)
            if MANAGED_MARKER not in existing and not args.force:
                report.notes_blocked.append(
                    f"{note.path}: target exists and is not managed: {target_index}"
                )
                continue

        rendered = render_note(note, vault, note_map, asset_index, apply, report)
        if apply:
            write_text(target_index, rendered)
        report.notes_written.append(target_index)
        action = "write" if apply else "would write"
        target_display = target_index.relative_to(hugo)
        print(
            f"{action}: {note.rel_path} -> {target_display} "
            f"({note.section_source})"
        )

    print()
    print(f"Notes {'written' if apply else 'planned'}: {len(report.notes_written)}")
    print(f"Assets {'copied' if apply else 'planned'}: {len(report.assets_copied)}")
    print(f"Skipped notes: {len(report.notes_skipped)}")
    print(f"Blocked notes: {len(report.notes_blocked)}")
    print(f"Missing assets: {len(report.assets_missing)}")
    print(f"Ambiguous assets: {len(report.assets_ambiguous)}")

    for line in report.notes_skipped + report.notes_blocked:
        print(f"WARN: {line}", file=sys.stderr)
    for line in report.assets_missing:
        print(f"WARN: {line}", file=sys.stderr)
    for line in report.assets_ambiguous:
        print(f"WARN: {line}", file=sys.stderr)

    if report.notes_blocked:
        return 1
    if args.fail_on_missing_assets and report.assets_missing:
        return 1
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Publish Obsidian notes with public: true, publish: true, "
            "or blog_publish: true into a Hugo site."
        )
    )
    parser.add_argument("--vault", default=DEFAULT_VAULT, help="Obsidian vault path")
    parser.add_argument("--hugo", default=DEFAULT_HUGO, help="Hugo site root path")
    parser.add_argument("--apply", action="store_true", help="Write files. Default is dry-run.")
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing target index.md even if it is not managed by this tool.",
    )
    parser.add_argument(
        "--allow-private",
        action="store_true",
        help="Allow publishing notes that also contain private: true.",
    )
    parser.add_argument(
        "--section-map",
        default="",
        help=(
            "Optional mapping file that translates vault path prefixes to public "
            "blog sections. Defaults to blog_section_map.txt in the vault, Hugo data, "
            "or this script's directory."
        ),
    )
    parser.add_argument(
        "--fail-on-missing-assets",
        action="store_true",
        help="Return non-zero if any local image or attachment cannot be copied.",
    )
    return parser


def main() -> int:
    return publish_notes(build_parser().parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
