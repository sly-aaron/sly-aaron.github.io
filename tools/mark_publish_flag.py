#!/usr/bin/env python3
from __future__ import annotations

import argparse
import codecs
import re
import sys
from dataclasses import dataclass
from pathlib import Path


if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

PUBLIC_LINE = "public: true"
BLOG_SECTION_RE = re.compile(r"^\s*blog_section\s*:", re.IGNORECASE)
PUBLIC_RE = re.compile(r"^\s*(public|publish)\s*:", re.IGNORECASE)


@dataclass
class NoteChange:
    path: Path
    action: str


def read_text(path: Path) -> tuple[str, bool]:
    raw = path.read_bytes()
    has_bom = raw.startswith(codecs.BOM_UTF8)
    text = raw.decode("utf-8-sig" if has_bom else "utf-8", errors="replace")
    return text, has_bom


def write_text(path: Path, text: str, has_bom: bool) -> None:
    if has_bom:
        text = "\ufeff" + text
    with path.open("w", encoding="utf-8", newline="") as handle:
        handle.write(text)


def detect_newline(text: str) -> str:
    return "\r\n" if "\r\n" in text else "\n"


def split_front_matter(text: str) -> tuple[list[str] | None, str]:
    if not text.startswith("---"):
        return None, text

    lines = text.splitlines(keepends=True)
    if not lines or lines[0].strip() != "---":
        return None, text

    end_index: int | None = None
    for index in range(1, len(lines)):
        if lines[index].strip() in {"---", "..."}:
            end_index = index
            break

    if end_index is None:
        return None, text

    front_matter = [line.rstrip("\r\n") for line in lines[1:end_index]]
    body = "".join(lines[end_index + 1 :])
    return front_matter, body


def rebuild_front_matter(front_matter: list[str], section: str) -> tuple[list[str], bool]:
    updated: list[str] = []
    public_seen = False
    section_seen = False
    changed = False

    for line in front_matter:
        if PUBLIC_RE.match(line):
            if not public_seen:
                updated.append(PUBLIC_LINE)
                if line.strip() != PUBLIC_LINE:
                    changed = True
                public_seen = True
            else:
                changed = True
            continue

        if section and BLOG_SECTION_RE.match(line):
            updated.append(f"blog_section: {section}")
            section_seen = True
            if line.strip() != f"blog_section: {section}":
                changed = True
            continue

        updated.append(line)

    insert_at = 1
    if not public_seen:
        updated.insert(insert_at, PUBLIC_LINE)
        insert_at += 1
        changed = True

    if section and not section_seen:
        updated.insert(insert_at, f"blog_section: {section}")
        changed = True

    return updated, changed


def render_note(text: str, section: str) -> tuple[str, bool, str]:
    newline = detect_newline(text)
    front_matter, body = split_front_matter(text)

    if front_matter is None:
        lines = ["---", PUBLIC_LINE]
        if section:
            lines.append(f"blog_section: {section}")
        lines.append("---")
        rendered = newline.join(lines) + newline + newline + body.lstrip("\r\n")
        return rendered, True, "inserted front matter"

    updated_front_matter, changed = rebuild_front_matter(front_matter, section)
    if not changed:
        return text, False, "already had public flag"

    rendered = (
        "---"
        + newline
        + newline.join(updated_front_matter)
        + newline
        + "---"
        + newline
        + newline
        + body.lstrip("\r\n")
    )
    return rendered, True, "updated front matter"


def resolve_folder(vault: Path, folder: str) -> Path:
    target = Path(folder)
    if not target.is_absolute():
        target = vault / target
    return target.resolve()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Batch add public: true to Obsidian notes in a folder."
    )
    parser.add_argument("--vault", default=r"D:\ProgramData\Obsidian", help="Vault root path")
    parser.add_argument("--folder", required=True, help="Folder inside the vault to update")
    parser.add_argument(
        "--section",
        default="",
        help="Optional blog_section to stamp into the same notes.",
    )
    parser.add_argument("--apply", action="store_true", help="Write changes. Default is dry-run.")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    vault = Path(args.vault).resolve()
    target = resolve_folder(vault, args.folder)

    if not vault.exists():
        print(f"Vault not found: {vault}")
        return 2
    if not target.exists():
        print(f"Target folder not found: {target}")
        return 2
    if target != vault and vault not in target.parents:
        print(f"Target folder must live inside the vault: {target}")
        return 2

    markdown_files = sorted(target.rglob("*.md"))
    if not markdown_files:
        print(f"No markdown files found under: {target}")
        return 0

    mode = "APPLY" if args.apply else "DRY-RUN"
    print(f"Mode: {mode}")
    print(f"Vault: {vault}")
    print(f"Target: {target}")
    print(f"Markdown files found: {len(markdown_files)}")

    changed_notes: list[NoteChange] = []
    skipped_notes: list[Path] = []

    for path in markdown_files:
        text, has_bom = read_text(path)
        rendered, changed, action = render_note(text, args.section.strip())
        rel_path = path.relative_to(vault)

        if not changed:
            skipped_notes.append(rel_path)
            continue

        changed_notes.append(NoteChange(path=path, action=action))
        print(f"- {rel_path}: {action}")
        if args.apply:
            write_text(path, rendered, has_bom)

    print(f"Changed notes: {len(changed_notes)}")
    print(f"Unchanged notes: {len(skipped_notes)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
