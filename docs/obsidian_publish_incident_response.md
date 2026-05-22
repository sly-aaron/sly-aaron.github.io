# Obsidian 笔记同步到公开博客

这条链路只做一件事：从私有 Obsidian vault 里挑出你明确允许公开的笔记，复制到公开 Hugo 博客仓库的 `content/` 里。

## 1. 三个目录

- 私有 vault：`D:\ProgramData\Obsidian`
- 公开博客仓库：`D:\ProgramData\blog\sly-aaron.github.io`
- 同步工具：`D:\ProgramData\blog\sly-aaron.github.io\tools`

## 2. 一篇笔记怎么声明“可以公开”

在 Obsidian 笔记最顶部写 front matter：

```markdown
---
title: 应急响应复盘
public: true
---
```

`public: true` 只表示这篇允许公开，不决定它放到博客哪个栏目。旧的 `publish: true`、`blog_publish: true` 仍然兼容，但以后建议统一写 `public: true`。

如果笔记里写了 `private: true`，同步脚本默认会跳过；除非你运行脚本时显式加 `--allow-private`。

## 3. 它到底会进 `content/` 的哪个目录

同步脚本按这个顺序决定落点：

1. 如果笔记里写了 `blog_section`，这一篇优先按它走。
2. 否则看博客仓库根目录的 `blog_section_map.txt`。
3. 如果没有命中映射，就用私有 vault 顶层文件夹名兜底。

最推荐的日常方式是：每篇只写 `public: true`，栏目统一交给 `blog_section_map.txt`。

当前映射表在这里：

```text
D:\ProgramData\blog\sly-aaron.github.io\blog_section_map.txt
```

当前规则类似这样：

```text
# 私有 vault 路径前缀 => 公开博客分类
ctf => ctf
电子取证 => digital-forensics
应急响应 => incident-response
草稿区 => skip
```

例子：

- `D:\ProgramData\Obsidian\应急响应\某篇.md`
- 笔记里只有 `public: true`
- 映射表命中 `应急响应 => incident-response`
- 最终写到 `content/incident-response/<slug>/index.md`

`slug` 默认来自文件名；如果你想指定 URL 末尾，可以在笔记里写：

```markdown
---
public: true
blog_slug: ir-retrospective
---
```

这样会写到：

```text
content/incident-response/ir-retrospective/index.md
```

只有个别文章要放到特殊栏目时，才需要在单篇里写：

```markdown
---
public: true
blog_section: ctf
---
```

## 4. 先预览落点

进入博客仓库：

```powershell
cd "D:\ProgramData\blog\sly-aaron.github.io"
$OutputEncoding = [System.Text.UTF8Encoding]::new()
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new()
```

先 dry-run，不会写文件：

```powershell
python .\tools\publish_obsidian_to_hugo.py --vault "D:\ProgramData\Obsidian" --hugo "."
```

输出会直接告诉你每篇会写到哪里，例如：

```text
would write: 应急响应\某篇.md -> content\incident-response\某篇\index.md (map 应急响应 => incident-response)
```

你只要看两件事：

- `-> content\...` 是最终会进入公开博客仓库的位置。
- 括号里的 `map ... => ...` 是它为什么会进这个栏目。

如果你看到 `fallback top folder`，说明没有命中映射表，建议先补 `blog_section_map.txt`，不要急着 `--apply`。

## 5. 正式写入公开博客仓库

确认预览没问题后再执行：

```powershell
python .\tools\publish_obsidian_to_hugo.py --vault "D:\ProgramData\Obsidian" --hugo "." --apply
```

这一步会把允许公开的笔记写入 `content/`，附件也会复制到对应文章目录下面。它不会把整个私有 vault 传到公开仓库，只复制带 `public: true` 的笔记。

## 6. 批量给某个文件夹加 `public: true`

比如整个 `应急响应` 文件夹都准备公开，先预览：

```powershell
python .\tools\mark_publish_flag.py --vault "D:\ProgramData\Obsidian" --folder "应急响应"
```

确认列表没问题后正式写回：

```powershell
python .\tools\mark_publish_flag.py --vault "D:\ProgramData\Obsidian" --folder "应急响应" --apply
```

这个脚本只改 Obsidian 笔记的 front matter，不会复制文章到博客。真正复制仍然要跑 `publish_obsidian_to_hugo.py --apply`。

## 7. 推送到公开博客

写入 `content/` 后，提交并推送公开博客仓库：

```powershell
git add content blog_section_map.txt docs tools
git commit -m "publish obsidian notes"
git push
```

这个站点已经接了 GitHub Actions，推送后会自动构建和部署，不需要手工维护 `public/`。

## 8. 一句话记忆

`public: true` 决定发不发，`blog_section_map.txt` 决定发到哪里，dry-run 输出决定你敢不敢正式发布。
