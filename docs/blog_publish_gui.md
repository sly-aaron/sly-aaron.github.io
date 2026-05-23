# 博客发布预览 GUI

这个工具是一个 Windows PowerShell/WinForms 图形界面，用来预览私有
Obsidian 仓库里哪些笔记会被发布到公开 Hugo 博客。

GUI 本身不依赖 Python。点击正式同步按钮时，它会复用仓库里已有的
`tools/publish_obsidian_to_hugo.py` 发布脚本，因为附件复制、wikilink
改写和 front matter 清理都已经在这个脚本里实现好了。

## 启动

双击：

```text
D:\ProgramData\blog\sly-aaron.github.io\tools\blog_publish_gui.cmd
```

或者手动运行：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "D:\ProgramData\blog\sly-aaron.github.io\tools\blog_publish_gui.ps1"
```

## 预览列表

表格会列出带有以下任意 front matter 标记的笔记：

```yaml
public: true
publish: true
blog_publish: true
```

每篇笔记会显示：

- `Source`: 私有 vault 里的原始路径
- `Target`: 预计写入公开 Hugo 仓库的路径
- `URL`: 预计公开访问路径
- `Rule`: 为什么会进入这个目录，比如 `blog_section` 或 `blog_section_map.txt`
- `Status`: `new`, `update`, `protected`, or `collision`

`Status` 的含义：

- `new`: 公开博客里还没有这篇，正式同步时会新建
- `update`: 公开博客里已有这篇，并且是脚本管理的文件，正式同步时会更新
- `protected`: 目标位置已有手写文件，工具不会自动覆盖
- `collision`: 多篇私有笔记会写到同一个公开路径，需要先改文件名或 `blog_slug`

如果列表里出现 `protected` 或 `collision`，`Sync to content` 会拒绝执行。

## 正式同步按钮

点击 `Sync to content` 后，GUI 会先重新扫描一次列表，然后弹窗确认。
确认后它会执行等价于下面的命令：

```powershell
python .\tools\publish_obsidian_to_hugo.py --vault "D:\ProgramData\Obsidian" --hugo "." --apply
```

如果勾选了 `Allow private:true`，会额外加上：

```powershell
--allow-private
```

这个按钮会把允许公开的笔记和附件写入 `content/`，但不会自动 commit，
也不会自动 push 到 GitHub。同步完成后，建议先检查改动：

```powershell
cd /d D:\ProgramData\blog\sly-aaron.github.io
git status --short content static
git diff -- content static
```

确认没问题后再手动提交推送：

```powershell
git add content static blog_section_map.txt
git commit -m "publish obsidian notes"
git push origin main
```

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
