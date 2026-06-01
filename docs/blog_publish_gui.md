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

确认没问题后，可以点击 `Commit & push`，或者手动提交推送：

```powershell
git add content static blog_section_map.txt
git commit -m "publish obsidian notes"
git push origin main
```

同步完成后，GUI 会自动在日志里显示 `content/`、`static/` 和
`blog_section_map.txt` 的 Git 状态。你也可以随时点 `Changed files`
重新查看这些待提交改动。

## 提交推送按钮

点击 `Commit & push` 后，GUI 会：

- 只检查 `content/`、`static/` 和 `blog_section_map.txt`
- 弹窗显示即将提交的发布文件
- 让你填写 commit message，默认是 `publish obsidian notes`
- 执行 `git add -- content static blog_section_map.txt`
- 执行 `git commit -m "<message>" -- content static blog_section_map.txt`
- 执行 `git push origin <当前分支>`

这个按钮不会 stage 或 commit `public/`，所以 Hugo 本地预览生成出来的
`public/` 改动不会被它一起推上去。

如果提交推送失败，弹窗和 GUI 日志会显示详细日志路径：

```text
%TEMP%\sly-aaron-blog-gui-git\commit-push.log
```

## 本地预览按钮

- `Start preview`: 用当前端口启动 `hugo server`
- `Stop preview`: 只停止这个 GUI 启动的 Hugo 进程
- `Open browser`: 打开 `http://127.0.0.1:<port>/`
- `Changed files`: 在日志里显示准备发布的 Git 改动，不包含 `public/`
- `Commit & push`: 提交并推送准备发布的 Git 改动，不包含 `public/`

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

## 在 GUI 里修改标题和发布位置

刷新列表后，点选表格里的一篇文章，下面的 `Selected note title and rule`
区域会自动显示当前文章。

单篇文章临时覆盖：

- `blog_title`: 写入私有 vault 这篇 Markdown 的 front matter，只影响博客显示标题
- `blog_section`: 写入私有 vault 这篇 Markdown 的 front matter，只影响这一篇发布到哪个栏目
- `Save note rule`: 保存上面两个字段，留空会移除对应覆盖项

路径映射批量规则：

- `map source`: 私有 vault 里的路径前缀，比如 `应急响应/比赛WP`
- `map section`: 公开博客里的栏目路径，比如 `incident-response/wp`
- `Save map rule`: 写入或更新公开博客仓库的 `blog_section_map.txt`

可以这样理解：

```text
blog_title / blog_section = 只改当前选中的这一篇
blog_section_map.txt = 改一整类路径的默认发布位置
```

例如你希望 `应急响应/比赛WP` 下面的所有公开笔记都进入
`content/incident-response/wp/`，就在 GUI 里选中其中任意一篇，把
`map source` 改成 `应急响应/比赛WP`，把 `map section` 改成
`incident-response/wp`，然后点 `Save map rule`。之后这类笔记只要写了
`public: true`，同步时就会自动进入这个栏目。
