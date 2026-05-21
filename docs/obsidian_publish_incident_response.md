# 应急响应文件夹如何同步到公开博客

这份文档记录的是我这次把私有 Obsidian 里的 `应急响应` 目录同步到公开 Hugo 博客的完整链路。
核心思路很简单：

`私有 vault 里先标记要公开的笔记 -> 导出到公开博客仓库的 content/ -> Hugo 构建 -> GitHub Pages 发布`

## 1. 你需要知道的三个目录

- `D:\ProgramData\Obsidian`：私有 Obsidian vault，本地目录，不是公开仓库
- `D:\ProgramData\blog\sly-aaron.github.io`：公开 Hugo 博客仓库
- `E:\codex cli工作目录\obsidian_git_blog_pipeline`：我用来做同步的脚本目录

## 2. `publish: true` 写在哪里

`publish: true` 写在 Obsidian 笔记的 front matter 里，不是写在博客仓库里。

示例：

```markdown
---
title: 应急响应复盘
publish: true
---
```

如果一篇笔记没有 `publish: true`，脚本默认不会导出它。

## 3. 如果要批量给整个目录加发布标记

比如把私有 vault 里的整个 `应急响应` 文件夹都准备好公开，可以先预览：

```powershell
python .\mark_publish_flag.py --vault "D:\ProgramData\Obsidian" --folder "应急响应"
```

确认没问题后，再真正写回 front matter：

```powershell
python .\mark_publish_flag.py --vault "D:\ProgramData\Obsidian" --folder "应急响应" --apply
```

这个脚本只改 Markdown front matter，不会复制到公开博客。

## 4. `blog_section_map.txt` 是干什么的

它负责把私有目录前缀映射到公开分类。

我这次用的是这种映射：

```text
CTF => ctf
取证 => digital-forensics
应急响应 => incident-response
蓝队/应急演练 => incident-response
草稿区 => skip
```

意思是：

- 私有 vault 里 `应急响应` 下的内容，默认导出到公开博客的 `content/incident-response/`
- `skip` 表示跳过不发

如果你以后想改分类，就改这个文件，不用改脚本。

## 5. 先预览，再正式写入

先看脚本会导出什么：

```powershell
python .\publish_obsidian_to_hugo.py --vault "D:\ProgramData\Obsidian" --hugo "D:\ProgramData\blog\sly-aaron.github.io"
```

确认输出没问题后，正式写入公开博客仓库：

```powershell
python .\publish_obsidian_to_hugo.py --vault "D:\ProgramData\Obsidian" --hugo "D:\ProgramData\blog\sly-aaron.github.io" --apply
```

这一步会把选中的笔记写成 Hugo 文章，位置通常是：

```text
content/incident-response/<slug>/index.md
```

附件也会一起复制到对应目录下面。

## 6. 这次 `应急响应` 目录到底做了什么

这次我做的流程大致是：

1. 在私有 vault 里把 `应急响应` 目录下需要公开的笔记加上 `publish: true`
2. 确认 `blog_section_map.txt` 里有 `应急响应 => incident-response`
3. 跑 `publish_obsidian_to_hugo.py --apply`
4. 把导出的 `content/` 和相关模板改动推到公开博客仓库
5. 交给 GitHub Actions 构建并部署

## 7. 为什么公开仓库里还会有 `content/` 和 `data/`

- `content/` 是 Hugo 的源码内容，不是多余目录
- `data/` 放菜单、索引分组之类的配置
- `public/` 是 Hugo 的构建结果，通常是生成物，不是你手工编辑的主战场

这次站点已经接了 GitHub Actions，所以一般只需要推源码，构建交给 CI。

## 8. 现在“比赛 WP / 其他内容”的分组在哪里改

如果你想改应急响应首页或索引里的分组规则，改这里：

```text
data/indexes/incident-response.yaml
```

当前规则是按关键词把 `比赛 WP` 和 `其他内容` 分开。
你以后要拆成更细的组，只要改这个 YAML 就行。

## 9. 私有仓库访问要不要私钥

如果你说的是现在这个工作区里的私有 vault，它就是本地目录，**不需要私钥**。
如果你把私有 vault 放到远程 Git 仓库，才需要 Git 认证方式，比如：

- HTTPS + credential manager
- SSH key

## 10. 最后给你一套可直接照抄的命令

```powershell
python .\mark_publish_flag.py --vault "D:\ProgramData\Obsidian" --folder "应急响应" --apply
python .\publish_obsidian_to_hugo.py --vault "D:\ProgramData\Obsidian" --hugo "D:\ProgramData\blog\sly-aaron.github.io" --apply
git -C "D:\ProgramData\blog\sly-aaron.github.io" add content data layouts static hugo.toml blog_section_map.txt docs/obsidian_publish_incident_response.md
git -C "D:\ProgramData\blog\sly-aaron.github.io" commit -m "publish incident response notes"
git -C "D:\ProgramData\blog\sly-aaron.github.io" push
```

如果站点已经接了 GitHub Actions，推送后等它构建完成就行，不需要你手工把 `public/` 逐个维护进去。
