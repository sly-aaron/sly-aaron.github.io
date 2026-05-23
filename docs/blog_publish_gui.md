# 博客发布预览 GUI

这个工具是一个 Windows PowerShell/WinForms 图形界面，用来预览私有
Obsidian 仓库里哪些笔记会被发布到公开 Hugo 博客。

它不依赖 Python。

## 启动

双击：

```text
D:\ProgramData\blog\sly-aaron.github.io\tools\blog_publish_gui.cmd
```

或者手动运行：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "D:\ProgramData\blog\sly-aaron.github.io\tools\blog_publish_gui.ps1"
```

## 它会显示什么

表格会列出带有以下任意 front matter 标记的笔记：

```yaml
public: true
publish: true
blog_publish: true
```

每篇笔记会显示：

- `Source`: path inside the private vault
- `Target`: 预计会写入公开 Hugo 仓库的路径
- `URL`: 预计公开访问路径
- `Rule`: 为什么会进入这个目录，比如 `blog_section` 或 `blog_section_map.txt`
- `Status`: `new`, `update`, `protected`, or `collision`

`Status` 的含义：

- `new`: 公开博客里还没有这篇，正式发布时会新建
- `update`: 公开博客里已有这篇，并且是脚本管理的文件，正式发布时会更新
- `protected`: 目标位置已有手写文件，工具不会自动覆盖
- `collision`: 多篇私有笔记会写到同一个公开路径，需要先改文件名或 `blog_slug`

这个 GUI 目前只做预览，不会复制笔记到 `content/`，也不会 commit 或 push。

## 本地预览按钮

- `Start preview`: 用当前端口启动 `hugo server`
- `Stop preview`: 只停止这个 GUI 启动的 Hugo 进程
- `Open browser`: 打开 `http://127.0.0.1:<port>/`

预览日志会写到 `%TEMP%\sly-aaron-blog-gui-preview`，不会污染 Git 仓库。

## 映射规则

点击 `Open map` 会打开：

```text
D:\ProgramData\blog\sly-aaron.github.io\blog_section_map.txt
```

日常规则可以这样理解：

```text
public: true decides whether to publish
blog_section_map.txt decides where it goes
```

也就是：

- `public: true` 决定这篇发不发
- `blog_section_map.txt` 决定这篇发到博客哪个栏目

如果某篇笔记自己写了 `blog_section`，它会优先覆盖映射表。

## 正式发布

GUI 只是帮你看清楚“会发布什么、会发布到哪里”。确认没问题后，再在博客仓库运行：

```powershell
cd /d D:\ProgramData\blog\sly-aaron.github.io
python .\tools\publish_obsidian_to_hugo.py --vault "D:\ProgramData\Obsidian" --hugo "." --apply
git add content static blog_section_map.txt
git commit -m "publish obsidian notes"
git push origin main
```
