param(
    [switch]$SelfTest
)

$ErrorActionPreference = "Stop"

$DefaultVault = "D:\ProgramData\Obsidian"
$DefaultHugo = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$ManagedMarker = "<!-- generated-by: obsidian_git_blog_pipeline -->"
$SkipDirs = @(".git", ".obsidian", ".trash", ".sync", ".stfolder")
$SkipMapValues = @("", "-", "ignore", "none", "skip", "off")

$script:HugoProcess = $null

function Read-Utf8Text {
    param([string]$Path)

    $encoding = New-Object System.Text.UTF8Encoding($false, $false)
    $text = [System.IO.File]::ReadAllText($Path, $encoding)
    if ($text.Length -gt 0 -and $text[0] -eq [char]0xFEFF) {
        return $text.Substring(1)
    }
    return $text
}

function Convert-SimpleValue {
    param([string]$Value)

    $text = $Value.Trim()
    if ($text.Length -eq 0) { return "" }

    $lower = $text.ToLowerInvariant()
    if ($lower -in @("true", "yes", "on", "1")) { return $true }
    if ($lower -in @("false", "no", "off", "0")) { return $false }
    if ($lower -in @("null", "none", "~")) { return $null }

    if (($text.StartsWith('"') -and $text.EndsWith('"')) -or ($text.StartsWith("'") -and $text.EndsWith("'"))) {
        return $text.Substring(1, $text.Length - 2)
    }

    if ($text.StartsWith("[") -and $text.EndsWith("]")) {
        $inner = $text.Substring(1, $text.Length - 2).Trim()
        if ($inner.Length -eq 0) { return @() }
        return @($inner.Split(",") | ForEach-Object { Convert-SimpleValue $_ })
    }

    return $text
}

function Split-FrontMatter {
    param([string]$Text)

    $match = [regex]::Match($Text, "(?s)\A---\r?\n(.*?)\r?\n(?:---|\.\.\.)\r?\n?(.*)\z")
    if (-not $match.Success) {
        return [pscustomobject]@{
            Meta = @{}
            Body = $Text
            HasFrontMatter = $false
        }
    }

    $meta = @{}
    $currentKey = $null
    foreach ($raw in ($match.Groups[1].Value -split "\r?\n")) {
        $line = $raw.TrimEnd()
        if ([string]::IsNullOrWhiteSpace($line) -or $line.TrimStart().StartsWith("#")) {
            continue
        }

        $listMatch = [regex]::Match($line, "^\s*-\s+(.*)$")
        if ($listMatch.Success -and $currentKey) {
            if (-not ($meta[$currentKey] -is [System.Collections.IList])) {
                $meta[$currentKey] = @()
            }
            $meta[$currentKey] = @($meta[$currentKey]) + (Convert-SimpleValue $listMatch.Groups[1].Value)
            continue
        }

        $keyMatch = [regex]::Match($line, "^([A-Za-z0-9_-]+)\s*:\s*(.*)$")
        if ($keyMatch.Success) {
            $key = $keyMatch.Groups[1].Value
            $value = $keyMatch.Groups[2].Value.Trim()
            if ($value.Length -eq 0) {
                $meta[$key] = @()
                $currentKey = $key
            } else {
                $meta[$key] = Convert-SimpleValue $value
                $currentKey = $null
            }
        }
    }

    return [pscustomobject]@{
        Meta = $meta
        Body = $match.Groups[2].Value
        HasFrontMatter = $true
    }
}

function Test-Truthy {
    param($Value)

    if ($Value -is [bool]) { return $Value }
    if ($null -eq $Value) { return $false }
    return ($Value.ToString().Trim().ToLowerInvariant() -in @("true", "yes", "on", "1"))
}

function Test-PublishEnabled {
    param([hashtable]$Meta)

    return ((Test-Truthy $Meta["public"]) -or (Test-Truthy $Meta["publish"]) -or (Test-Truthy $Meta["blog_publish"]))
}

function Get-RelativePathText {
    param(
        [string]$BasePath,
        [string]$Path
    )

    $base = [System.IO.Path]::GetFullPath($BasePath)
    if (-not $base.EndsWith([System.IO.Path]::DirectorySeparatorChar)) {
        $base += [System.IO.Path]::DirectorySeparatorChar
    }

    $baseUri = New-Object System.Uri($base)
    $pathUri = New-Object System.Uri([System.IO.Path]::GetFullPath($Path))
    return [System.Uri]::UnescapeDataString($baseUri.MakeRelativeUri($pathUri).ToString()).Replace("/", "\")
}

function Test-SkippedPath {
    param(
        [string]$Root,
        [string]$Path
    )

    $rel = Get-RelativePathText $Root $Path
    foreach ($part in ($rel -split "[\\/]+")) {
        if ($part -in $SkipDirs -or $part.StartsWith(".git")) {
            return $true
        }
    }
    return $false
}

function Get-Sha1Short {
    param([string]$Text)

    $sha1 = [System.Security.Cryptography.SHA1]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
        $hash = $sha1.ComputeHash($bytes)
        return (($hash | ForEach-Object { $_.ToString("x2") }) -join "").Substring(0, 10)
    } finally {
        $sha1.Dispose()
    }
}

function Convert-ToSlug {
    param(
        [string]$Text,
        [string]$FallbackSeed
    )

    $source = ($Text + "").Trim().ToLowerInvariant()
    $builder = New-Object System.Text.StringBuilder
    $separators = " ./\:|"

    foreach ($ch in $source.ToCharArray()) {
        if ([char]::IsLetterOrDigit($ch) -or $ch -eq "-" -or $ch -eq "_") {
            [void]$builder.Append($ch)
        } elseif ($separators.IndexOf($ch) -ge 0) {
            [void]$builder.Append("-")
        }
    }

    $slug = [regex]::Replace($builder.ToString(), "-+", "-").Trim("-_")
    if ($slug.Length -gt 120) {
        $slug = $slug.Substring(0, 120)
    }
    if ($slug.Length -eq 0) {
        $slug = "note-" + (Get-Sha1Short $FallbackSeed)
    }
    return $slug
}

function Convert-ToSectionParts {
    param([string]$Section)

    $sectionText = ($Section + "").Trim().Replace("\", "/").Trim("/")
    if ($sectionText.Length -eq 0) { $sectionText = "notes" }

    $parts = @()
    foreach ($part in ($sectionText -split "/")) {
        if ([string]::IsNullOrWhiteSpace($part) -or $part -eq ".") {
            continue
        }
        if ($part -eq ".." -or $part.Contains(":") -or $part.StartsWith("~")) {
            throw "Unsafe blog_section: $Section"
        }
        $parts += (Convert-ToSlug $part $part)
    }

    if ($parts.Count -eq 0) { return @("notes") }
    return $parts
}

function Normalize-SectionPath {
    param([string]$Text)

    $cleaned = ($Text + "").Trim().Replace("\", "/")
    while ($cleaned.StartsWith("./")) {
        $cleaned = $cleaned.Substring(2)
    }
    return $cleaned.Trim("/").ToLowerInvariant()
}

function Test-SectionMatch {
    param(
        [string]$PathText,
        [string]$PrefixText
    )

    $pathValue = Normalize-SectionPath $PathText
    $prefixValue = Normalize-SectionPath $PrefixText
    if ($prefixValue.Length -eq 0) { return $false }
    return ($pathValue -eq $prefixValue -or $pathValue.StartsWith($prefixValue + "/"))
}

function Find-SectionMapPath {
    param(
        [string]$Vault,
        [string]$Hugo
    )

    $names = @("blog_section_map.txt", "blog_section_map.map")
    $candidates = @()
    foreach ($name in $names) { $candidates += (Join-Path $Vault $name) }
    foreach ($name in $names) { $candidates += (Join-Path $Hugo $name) }
    foreach ($name in $names) { $candidates += (Join-Path (Join-Path $Hugo "data") $name) }
    foreach ($name in $names) { $candidates += (Join-Path $PSScriptRoot $name) }

    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }
    return ""
}

function Get-SectionRules {
    param([string]$MapPath)

    $rules = @()
    if (-not $MapPath) { return $rules }

    foreach ($rawLine in ((Read-Utf8Text $MapPath) -split "\r?\n")) {
        $line = $rawLine.Trim()
        if ($line.Length -eq 0 -or $line.StartsWith("#")) { continue }
        if ($line.Contains("#")) {
            $line = $line.Split("#", 2)[0].Trim()
        }
        if ($line.Length -eq 0) { continue }

        $separator = $null
        foreach ($candidate in @("=>", "->", "=")) {
            if ($line.Contains($candidate)) {
                $separator = $candidate
                break
            }
        }
        if (-not $separator) { continue }

        $parts = $line.Split(@($separator), 2, [System.StringSplitOptions]::None)
        $source = $parts[0].Trim()
        $target = $parts[1].Trim()
        if ($source.Length -eq 0) { continue }

        $skip = ($target.ToLowerInvariant() -in $SkipMapValues)
        $rules += [pscustomobject]@{
            SourcePrefix = $source
            Section = $(if ($skip) { "" } else { $target })
            Skip = $skip
        }
    }

    return @($rules | Sort-Object @{ Expression = { (Normalize-SectionPath $_.SourcePrefix).Length }; Descending = $true })
}

function Resolve-Section {
    param(
        [string]$RelPath,
        [hashtable]$Meta,
        [object[]]$Rules
    )

    $explicit = ($Meta["blog_section"] + "").Trim()
    if ($explicit.Length -gt 0) {
        return [pscustomobject]@{
            Parts = @(Convert-ToSectionParts $explicit)
            Source = "front matter blog_section=$explicit"
            Skipped = $false
        }
    }

    $relNoSuffix = [System.IO.Path]::ChangeExtension($RelPath, $null).Replace("\", "/")
    foreach ($rule in $Rules) {
        if (Test-SectionMatch $relNoSuffix $rule.SourcePrefix) {
            if ($rule.Skip) {
                return [pscustomobject]@{
                    Parts = @()
                    Source = "map $($rule.SourcePrefix) => skip"
                    Skipped = $true
                }
            }
            return [pscustomobject]@{
                Parts = @(Convert-ToSectionParts $rule.Section)
                Source = "map $($rule.SourcePrefix) => $($rule.Section)"
                Skipped = $false
            }
        }
    }

    $relParts = @($RelPath -split "[\\/]+")
    $top = $(if ($relParts.Count -gt 1) { $relParts[0] } else { "notes" })
    return [pscustomobject]@{
        Parts = @(Convert-ToSectionParts $top)
        Source = "fallback top folder => $top"
        Skipped = $false
    }
}

function Get-TitleFromBody {
    param(
        [string]$Body,
        [string]$Fallback
    )

    $inFence = $false
    foreach ($line in ($Body -split "\r?\n")) {
        if ($line -match "^\s*(```|~~~)") {
            $inFence = -not $inFence
            continue
        }
        if ($inFence) { continue }
        $match = [regex]::Match($line, "^\s*#\s+(.+?)\s*$")
        if ($match.Success) {
            return $match.Groups[1].Value.Trim()
        }
    }
    return $Fallback
}

function Join-PathParts {
    param([string[]]$Parts)

    if ($Parts.Count -eq 0) { return "" }
    $current = $Parts[0]
    for ($i = 1; $i -lt $Parts.Count; $i++) {
        $current = Join-Path $current $Parts[$i]
    }
    return $current
}

function Get-UrlPath {
    param([string[]]$Parts)

    $encoded = @()
    foreach ($part in $Parts) {
        $encoded += [System.Uri]::EscapeDataString($part)
    }
    return "/" + ($encoded -join "/") + "/"
}

function Get-PublishPlan {
    param(
        [string]$Vault,
        [string]$Hugo,
        [bool]$AllowPrivate
    )

    $notes = @()
    $skipped = @()
    $blocked = @()

    if (-not (Test-Path -LiteralPath $Vault)) {
        throw "Vault path not found: $Vault"
    }
    if (-not (Test-Path -LiteralPath (Join-Path $Hugo "hugo.toml"))) {
        throw "Hugo site not found or hugo.toml missing: $Hugo"
    }

    $mapPath = Find-SectionMapPath $Vault $Hugo
    $rules = @(Get-SectionRules $mapPath)
    $seenTargets = @{}
    $contentRoot = Join-Path $Hugo "content"

    $files = @(Get-ChildItem -LiteralPath $Vault -Recurse -Filter "*.md" -File -ErrorAction SilentlyContinue)
    foreach ($file in ($files | Sort-Object FullName)) {
        if (Test-SkippedPath $Vault $file.FullName) { continue }

        $text = Read-Utf8Text $file.FullName
        $split = Split-FrontMatter $text
        $meta = $split.Meta
        if (-not (Test-PublishEnabled $meta)) { continue }

        $relPath = Get-RelativePathText $Vault $file.FullName
        if ((Test-Truthy $meta["private"]) -and -not $AllowPrivate) {
            $skipped += "${relPath}: private: true"
            continue
        }

        $section = Resolve-Section $relPath $meta $rules
        if ($section.Skipped) {
            $skipped += "${relPath}: $($section.Source)"
            continue
        }

        $title = ($meta["blog_title"] + "").Trim()
        if ($title.Length -eq 0) { $title = ($meta["title"] + "").Trim() }
        if ($title.Length -eq 0) { $title = Get-TitleFromBody $split.Body $file.BaseName }

        $slugSource = ($meta["blog_slug"] + "").Trim()
        if ($slugSource.Length -eq 0) { $slugSource = $file.BaseName }
        $slug = Convert-ToSlug $slugSource $relPath

        $targetParts = @($section.Parts) + @($slug)
        $targetDir = Join-PathParts (@($contentRoot) + $targetParts)
        $targetIndex = Join-Path $targetDir "index.md"
        $targetRel = Get-RelativePathText $Hugo $targetIndex
        $targetKey = $targetIndex.ToLowerInvariant()
        $status = "ready"

        if ($seenTargets.ContainsKey($targetKey)) {
            $status = "collision"
            $blocked += "${relPath}: target collides with $($seenTargets[$targetKey])"
        } else {
            $seenTargets[$targetKey] = $relPath
            if (Test-Path -LiteralPath $targetIndex) {
                $existing = Read-Utf8Text $targetIndex
                if ($existing.Contains($ManagedMarker)) {
                    $status = "update"
                } else {
                    $status = "protected"
                    $blocked += "${relPath}: target exists and is not managed: $targetRel"
                }
            } else {
                $status = "new"
            }
        }

        $notes += [pscustomobject]@{
            Status = $status
            Title = $title
            Source = $relPath
            Target = $targetRel
            Url = Get-UrlPath $targetParts
            Rule = $section.Source
            Modified = $file.LastWriteTime.ToString("yyyy-MM-dd HH:mm")
        }
    }

    return [pscustomobject]@{
        Notes = $notes
        Skipped = $skipped
        Blocked = $blocked
        MapPath = $mapPath
        RuleCount = $rules.Count
        Vault = $Vault
        Hugo = $Hugo
    }
}

function Test-LocalPort {
    param([int]$Port)

    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $async = $client.BeginConnect("127.0.0.1", $Port, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne(250, $false)) {
            return $false
        }
        $client.EndConnect($async)
        return $true
    } catch {
        return $false
    } finally {
        $client.Close()
    }
}

function Quote-ProcessArgument {
    param([string]$Value)

    $text = $Value + ""
    if ($text.Length -eq 0) { return '""' }
    if ($text -notmatch '[\s"]') { return $text }

    $text = $text -replace '(\\+)$', '$1$1'
    $text = $text.Replace('"', '\"')
    return '"' + $text + '"'
}

function Join-ProcessArguments {
    param([string[]]$Arguments)

    return (($Arguments | ForEach-Object { Quote-ProcessArgument $_ }) -join " ")
}

function Get-PythonLauncher {
    $python = Get-Command "python.exe" -ErrorAction SilentlyContinue
    if ($python) {
        return [pscustomobject]@{
            FilePath = $python.Source
            PrefixArgs = @()
            Display = "python"
        }
    }

    $py = Get-Command "py.exe" -ErrorAction SilentlyContinue
    if ($py) {
        return [pscustomobject]@{
            FilePath = $py.Source
            PrefixArgs = @("-3")
            Display = "py -3"
        }
    }

    throw "Python was not found. Install Python or make sure python.exe / py.exe is in PATH."
}

function Write-GitPublishStatus {
    param([string]$Hugo)

    try {
        if (-not (Test-Path -LiteralPath (Join-Path $Hugo ".git"))) {
            Add-Log "Git status skipped: Hugo path is not a Git repository"
            return
        }

        Add-Log "Changed publish files:"
        $output = & git -C $Hugo status --short -- content static blog_section_map.txt 2>&1
        $exitCode = $LASTEXITCODE
        if ($output) {
            foreach ($line in $output) {
                if (($line + "").Trim().Length -gt 0) {
                    Add-Log ($line + "")
                }
            }
        } else {
            Add-Log "No pending changes under content, static, or blog_section_map.txt"
        }

        if ($exitCode -ne 0) {
            Add-Log "Git status failed with exit code $exitCode"
        }
    } catch {
        Add-Log "Git status failed: $($_.Exception.Message)"
    }
}

if ($SelfTest) {
    $plan = Get-PublishPlan -Vault $DefaultVault -Hugo $DefaultHugo -AllowPrivate:$false
    "Published candidates: $($plan.Notes.Count)"
    "Skipped: $($plan.Skipped.Count)"
    "Blocked: $($plan.Blocked.Count)"
    "Section map: $($plan.MapPath)"
    exit 0
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

function Add-Log {
    param([string]$Message)

    $time = Get-Date -Format "HH:mm:ss"
    $script:LogBox.AppendText("[$time] $Message`r`n")
}

function New-Label {
    param([string]$Text)

    $label = New-Object System.Windows.Forms.Label
    $label.Text = $Text
    $label.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft
    $label.Dock = "Fill"
    return $label
}

function Select-FolderInto {
    param([System.Windows.Forms.TextBox]$TextBox)

    $dialog = New-Object System.Windows.Forms.FolderBrowserDialog
    $dialog.SelectedPath = $TextBox.Text
    if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $TextBox.Text = $dialog.SelectedPath
    }
}

$form = New-Object System.Windows.Forms.Form
$form.Text = "Obsidian -> Public Blog Preview"
$form.StartPosition = "CenterScreen"
$form.Size = New-Object System.Drawing.Size(1220, 780)
$form.MinimumSize = New-Object System.Drawing.Size(980, 620)

$root = New-Object System.Windows.Forms.TableLayoutPanel
$root.Dock = "Fill"
$root.ColumnCount = 1
$root.RowCount = 6
$root.Padding = New-Object System.Windows.Forms.Padding(10)
$root.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 34))) | Out-Null
$root.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 34))) | Out-Null
$root.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 44))) | Out-Null
$root.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 26))) | Out-Null
$root.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100))) | Out-Null
$root.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 118))) | Out-Null
$form.Controls.Add($root)

$vaultRow = New-Object System.Windows.Forms.TableLayoutPanel
$vaultRow.Dock = "Fill"
$vaultRow.ColumnCount = 3
$vaultRow.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 86))) | Out-Null
$vaultRow.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100))) | Out-Null
$vaultRow.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 86))) | Out-Null
$root.Controls.Add($vaultRow, 0, 0)

$vaultBox = New-Object System.Windows.Forms.TextBox
$vaultBox.Dock = "Fill"
$vaultBox.Text = $DefaultVault
$vaultButton = New-Object System.Windows.Forms.Button
$vaultButton.Text = "Browse..."
$vaultButton.Dock = "Fill"
$vaultButton.Add_Click({ Select-FolderInto $vaultBox })
$vaultRow.Controls.Add((New-Label "Vault"), 0, 0)
$vaultRow.Controls.Add($vaultBox, 1, 0)
$vaultRow.Controls.Add($vaultButton, 2, 0)

$hugoRow = New-Object System.Windows.Forms.TableLayoutPanel
$hugoRow.Dock = "Fill"
$hugoRow.ColumnCount = 3
$hugoRow.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 86))) | Out-Null
$hugoRow.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100))) | Out-Null
$hugoRow.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 86))) | Out-Null
$root.Controls.Add($hugoRow, 0, 1)

$hugoBox = New-Object System.Windows.Forms.TextBox
$hugoBox.Dock = "Fill"
$hugoBox.Text = $DefaultHugo
$hugoButton = New-Object System.Windows.Forms.Button
$hugoButton.Text = "Browse..."
$hugoButton.Dock = "Fill"
$hugoButton.Add_Click({ Select-FolderInto $hugoBox })
$hugoRow.Controls.Add((New-Label "Hugo"), 0, 0)
$hugoRow.Controls.Add($hugoBox, 1, 0)
$hugoRow.Controls.Add($hugoButton, 2, 0)

$buttonRow = New-Object System.Windows.Forms.FlowLayoutPanel
$buttonRow.Dock = "Fill"
$buttonRow.FlowDirection = "LeftToRight"
$buttonRow.WrapContents = $false
$root.Controls.Add($buttonRow, 0, 2)

$refreshButton = New-Object System.Windows.Forms.Button
$refreshButton.Text = "Refresh list"
$refreshButton.Width = 120
$buttonRow.Controls.Add($refreshButton)

$syncButton = New-Object System.Windows.Forms.Button
$syncButton.Text = "Sync to content"
$syncButton.Width = 118
$buttonRow.Controls.Add($syncButton)

$allowPrivateCheck = New-Object System.Windows.Forms.CheckBox
$allowPrivateCheck.Text = "Allow private:true"
$allowPrivateCheck.Width = 125
$allowPrivateCheck.Checked = $false
$buttonRow.Controls.Add($allowPrivateCheck)

$portLabel = New-Object System.Windows.Forms.Label
$portLabel.Text = "Port"
$portLabel.Width = 36
$portLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleRight
$buttonRow.Controls.Add($portLabel)

$portBox = New-Object System.Windows.Forms.TextBox
$portBox.Text = "1313"
$portBox.Width = 58
$buttonRow.Controls.Add($portBox)

$startButton = New-Object System.Windows.Forms.Button
$startButton.Text = "Start preview"
$startButton.Width = 116
$buttonRow.Controls.Add($startButton)

$stopButton = New-Object System.Windows.Forms.Button
$stopButton.Text = "Stop preview"
$stopButton.Width = 88
$stopButton.Enabled = $false
$buttonRow.Controls.Add($stopButton)

$openButton = New-Object System.Windows.Forms.Button
$openButton.Text = "Open browser"
$openButton.Width = 96
$buttonRow.Controls.Add($openButton)

$mapButton = New-Object System.Windows.Forms.Button
$mapButton.Text = "Open map"
$mapButton.Width = 96
$buttonRow.Controls.Add($mapButton)

$changedButton = New-Object System.Windows.Forms.Button
$changedButton.Text = "Changed files"
$changedButton.Width = 104
$buttonRow.Controls.Add($changedButton)

$serverStatus = New-Object System.Windows.Forms.Label
$serverStatus.Text = "Preview stopped"
$serverStatus.AutoSize = $true
$serverStatus.Padding = New-Object System.Windows.Forms.Padding(12, 8, 0, 0)
$buttonRow.Controls.Add($serverStatus)

$summary = New-Object System.Windows.Forms.Label
$summary.Dock = "Fill"
$summary.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft
$summary.Text = "Click Refresh list to preview notes with public:true / publish:true / blog_publish:true"
$root.Controls.Add($summary, 0, 3)

$grid = New-Object System.Windows.Forms.DataGridView
$grid.Dock = "Fill"
$grid.ReadOnly = $true
$grid.AllowUserToAddRows = $false
$grid.AllowUserToDeleteRows = $false
$grid.SelectionMode = "FullRowSelect"
$grid.MultiSelect = $false
$grid.AutoSizeColumnsMode = "Fill"
$grid.RowHeadersVisible = $false
$root.Controls.Add($grid, 0, 4)

$script:LogBox = New-Object System.Windows.Forms.TextBox
$script:LogBox.Dock = "Fill"
$script:LogBox.Multiline = $true
$script:LogBox.ScrollBars = "Vertical"
$script:LogBox.ReadOnly = $true
$script:LogBox.Font = New-Object System.Drawing.Font("Consolas", 9)
$root.Controls.Add($script:LogBox, 0, 5)

function Set-GridRows {
    param([object[]]$Rows)

    $table = New-Object System.Data.DataTable
    foreach ($column in @("Status", "Title", "Source", "Target", "URL", "Rule", "Modified")) {
        [void]$table.Columns.Add($column)
    }

    foreach ($row in $Rows) {
        [void]$table.Rows.Add(
            $row.Status,
            $row.Title,
            $row.Source,
            $row.Target,
            $row.Url,
            $row.Rule,
            $row.Modified
        )
    }

    $grid.DataSource = $table
    if ($grid.Columns.Count -ge 7) {
        $grid.Columns[0].FillWeight = 52
        $grid.Columns[1].FillWeight = 135
        $grid.Columns[2].FillWeight = 190
        $grid.Columns[3].FillWeight = 210
        $grid.Columns[4].FillWeight = 120
        $grid.Columns[5].FillWeight = 160
        $grid.Columns[6].FillWeight = 78
    }

    foreach ($gridRow in $grid.Rows) {
        $status = $gridRow.Cells[0].Value + ""
        if ($status -in @("collision", "protected")) {
            $gridRow.DefaultCellStyle.BackColor = [System.Drawing.Color]::MistyRose
        } elseif ($status -eq "update") {
            $gridRow.DefaultCellStyle.BackColor = [System.Drawing.Color]::Honeydew
        }
    }
}

function Refresh-PublishList {
    try {
        Add-Log "Scanning publishable notes"
        $plan = Get-PublishPlan -Vault $vaultBox.Text.Trim() -Hugo $hugoBox.Text.Trim() -AllowPrivate:$allowPrivateCheck.Checked
        Set-GridRows $plan.Notes
        $blockedCount = $plan.Blocked.Count
        $summary.Text = "Candidates: $($plan.Notes.Count); skipped: $($plan.Skipped.Count); blocked: $blockedCount; map: $($plan.MapPath)"
        Add-Log "Scan done: candidates=$($plan.Notes.Count), skipped=$($plan.Skipped.Count), blocked=$blockedCount"
        if ($blockedCount -gt 0) {
            foreach ($line in $plan.Blocked) { Add-Log "BLOCKED: $line" }
        }
    } catch {
        [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, "Scan failed", "OK", "Error") | Out-Null
        Add-Log "Scan failed: $($_.Exception.Message)"
    }
}

function Invoke-SyncToContent {
    $syncButton.Enabled = $false
    $refreshButton.Enabled = $false
    $form.UseWaitCursor = $true

    try {
        $vault = $vaultBox.Text.Trim()
        $hugo = $hugoBox.Text.Trim()
        Add-Log "Preparing content sync"

        $plan = Get-PublishPlan -Vault $vault -Hugo $hugo -AllowPrivate:$allowPrivateCheck.Checked
        Set-GridRows $plan.Notes
        $blockedCount = $plan.Blocked.Count
        $summary.Text = "Candidates: $($plan.Notes.Count); skipped: $($plan.Skipped.Count); blocked: $blockedCount; map: $($plan.MapPath)"

        if ($plan.Notes.Count -eq 0) {
            [System.Windows.Forms.MessageBox]::Show("No publishable notes were found.", "Nothing to sync", "OK", "Information") | Out-Null
            Add-Log "Sync skipped: no publishable notes"
            return
        }

        if ($blockedCount -gt 0) {
            foreach ($line in $plan.Blocked) { Add-Log "BLOCKED: $line" }
            [System.Windows.Forms.MessageBox]::Show(
                "Sync is blocked by protected files or target collisions. Check the log, fix them, then try again.",
                "Sync blocked",
                "OK",
                "Warning"
            ) | Out-Null
            return
        }

        $privateText = $(if ($allowPrivateCheck.Checked) { "`r`n`r`nWarning: Allow private:true is enabled." } else { "" })
        $message = "This will write $($plan.Notes.Count) note(s) into the public Hugo content directory.`r`n`r`nIt will not commit or push to GitHub.$privateText`r`n`r`nContinue?"
        $confirm = [System.Windows.Forms.MessageBox]::Show(
            $message,
            "Sync to content",
            [System.Windows.Forms.MessageBoxButtons]::YesNo,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        )
        if ($confirm -ne [System.Windows.Forms.DialogResult]::Yes) {
            Add-Log "Sync cancelled by user"
            return
        }

        $publishScript = Join-Path $PSScriptRoot "publish_obsidian_to_hugo.py"
        if (-not (Test-Path -LiteralPath $publishScript)) {
            throw "Publish script not found: $publishScript"
        }

        $launcher = Get-PythonLauncher
        $syncDir = Join-Path $env:TEMP "sly-aaron-blog-gui-sync"
        if (-not (Test-Path -LiteralPath $syncDir)) {
            New-Item -ItemType Directory -Path $syncDir | Out-Null
        }
        $stdout = Join-Path $syncDir "publish.stdout.log"
        $stderr = Join-Path $syncDir "publish.stderr.log"
        Set-Content -LiteralPath $stdout -Value "" -Encoding UTF8
        Set-Content -LiteralPath $stderr -Value "" -Encoding UTF8

        $args = @()
        $args += @($launcher.PrefixArgs)
        $args += @($publishScript, "--vault", $vault, "--hugo", $hugo, "--apply")
        if ($allowPrivateCheck.Checked) {
            $args += "--allow-private"
        }

        $argumentLine = Join-ProcessArguments $args
        Add-Log "Running publish script with --apply"
        $process = Start-Process -FilePath $launcher.FilePath -ArgumentList $argumentLine -WorkingDirectory $hugo -WindowStyle Hidden -PassThru -Wait -RedirectStandardOutput $stdout -RedirectStandardError $stderr

        foreach ($line in ((Read-Utf8Text $stdout) -split "\r?\n")) {
            if ($line.Trim().Length -gt 0) { Add-Log $line }
        }
        foreach ($line in ((Read-Utf8Text $stderr) -split "\r?\n")) {
            if ($line.Trim().Length -gt 0) { Add-Log "WARN: $line" }
        }

        if ($process.ExitCode -ne 0) {
            throw "Publish script failed with exit code $($process.ExitCode). Check the log above."
        }

        Add-Log "Content sync finished"
        Write-GitPublishStatus $hugo
        [System.Windows.Forms.MessageBox]::Show(
            "Content sync finished. Review git diff, then commit and push when you are ready.",
            "Sync finished",
            "OK",
            "Information"
        ) | Out-Null
        Refresh-PublishList
    } catch {
        [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, "Sync failed", "OK", "Error") | Out-Null
        Add-Log "Sync failed: $($_.Exception.Message)"
    } finally {
        $form.UseWaitCursor = $false
        $refreshButton.Enabled = $true
        $syncButton.Enabled = $true
    }
}

function Get-PortValue {
    $port = 0
    if (-not [int]::TryParse($portBox.Text.Trim(), [ref]$port) -or $port -lt 1 -or $port -gt 65535) {
        throw "Port must be an integer from 1 to 65535"
    }
    return $port
}

function Start-HugoPreview {
    try {
        if ($script:HugoProcess -and -not $script:HugoProcess.HasExited) {
            Add-Log "Preview is already running"
            return
        }

        $hugoRoot = $hugoBox.Text.Trim()
        if (-not (Test-Path -LiteralPath (Join-Path $hugoRoot "hugo.toml"))) {
            throw "Hugo site not found or hugo.toml missing: $hugoRoot"
        }

        $port = Get-PortValue
        if (Test-LocalPort $port) {
            throw "127.0.0.1:$port is already in use. Unknown processes will not be stopped automatically."
        }

        $previewDir = Join-Path $env:TEMP "sly-aaron-blog-gui-preview"
        if (-not (Test-Path -LiteralPath $previewDir)) {
            New-Item -ItemType Directory -Path $previewDir | Out-Null
        }
        $stdout = Join-Path $previewDir "hugo.stdout.log"
        $stderr = Join-Path $previewDir "hugo.stderr.log"
        Set-Content -LiteralPath $stdout -Value "" -Encoding UTF8
        Set-Content -LiteralPath $stderr -Value "" -Encoding UTF8

        $args = @(
            "server",
            "--bind", "127.0.0.1",
            "--port", "$port",
            "--baseURL", "http://127.0.0.1:$port/",
            "--disableFastRender"
        )

        $script:HugoProcess = Start-Process -FilePath "hugo" -ArgumentList $args -WorkingDirectory $hugoRoot -WindowStyle Hidden -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr
        Add-Log "Started Hugo preview, PID=$($script:HugoProcess.Id), URL=http://127.0.0.1:$port/"
    } catch {
        [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, "Start failed", "OK", "Error") | Out-Null
        Add-Log "Start failed: $($_.Exception.Message)"
    }
}

function Stop-HugoPreview {
    try {
        if ($script:HugoProcess -and -not $script:HugoProcess.HasExited) {
            Stop-Process -Id $script:HugoProcess.Id -Force
            Add-Log "Stopped Hugo preview, PID=$($script:HugoProcess.Id)"
        } else {
            Add-Log "Preview is not running"
        }
    } catch {
        Add-Log "Stop failed: $($_.Exception.Message)"
    }
}

function Update-ServerStatus {
    try {
        $port = Get-PortValue
    } catch {
        $serverStatus.Text = "Invalid port"
        return
    }

    $running = ($script:HugoProcess -and -not $script:HugoProcess.HasExited)
    $portOpen = Test-LocalPort $port

    if ($running) {
        $serverStatus.Text = "Preview running; port " + $(if ($portOpen) { "open" } else { "starting" })
    } elseif ($portOpen) {
        $serverStatus.Text = "Port is used by another process"
    } else {
        $serverStatus.Text = "Preview stopped"
    }

    $startButton.Enabled = -not $running
    $stopButton.Enabled = $running
}

$refreshButton.Add_Click({ Refresh-PublishList })
$syncButton.Add_Click({ Invoke-SyncToContent })
$changedButton.Add_Click({ Write-GitPublishStatus $hugoBox.Text.Trim() })
$startButton.Add_Click({ Start-HugoPreview })
$stopButton.Add_Click({ Stop-HugoPreview })
$openButton.Add_Click({
    try {
        $port = Get-PortValue
        Start-Process "http://127.0.0.1:$port/"
    } catch {
        [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, "Open failed", "OK", "Error") | Out-Null
    }
})
$mapButton.Add_Click({
    try {
        $map = Find-SectionMapPath $vaultBox.Text.Trim() $hugoBox.Text.Trim()
        if (-not $map) { throw "blog_section_map.txt was not found" }
        Start-Process "notepad.exe" $map
    } catch {
        [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, "Open map failed", "OK", "Error") | Out-Null
    }
})

$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 1200
$timer.Add_Tick({ Update-ServerStatus })
$timer.Start()

$form.Add_Shown({ Refresh-PublishList })
$form.Add_FormClosing({
    if ($script:HugoProcess -and -not $script:HugoProcess.HasExited) {
        Stop-HugoPreview
    }
})

[System.Windows.Forms.Application]::Run($form)
