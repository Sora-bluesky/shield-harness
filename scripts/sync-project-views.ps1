<#
.SYNOPSIS
    Generates 4 markdown project view files from backlog.yaml.

.DESCRIPTION
    Reads tasks/backlog.yaml (Clawless SoT) and generates:
      - docs/project/ROADMAP.md    (Phase overview + Mermaid timeline)
      - docs/project/WBS.md        (Work Breakdown Structure tree)
      - docs/project/GANTT.md      (Mermaid gantt diagram)
      - docs/project/MILESTONES.md (Milestone progress table)

    Part of ADR-033 (Project Management SoT).

.PARAMETER BacklogPath
    Path to backlog.yaml. Defaults to "tasks/backlog.yaml".

.PARAMETER OutputDir
    Output directory for generated markdown files. Defaults to "docs/project".

.EXAMPLE
    pwsh scripts/sync-project-views.ps1
    pwsh scripts/sync-project-views.ps1 -BacklogPath "tasks/backlog.yaml" -OutputDir "docs/project"
#>

param(
    [string]$BacklogPath = "tasks/backlog.yaml",
    [string]$OutputDir = "docs/project"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ============================================================
# Constants
# ============================================================
$HEADER_LINE = "<!-- auto-generated from backlog.yaml. DO NOT EDIT -->"

# Status emoji lookup (using surrogate pair workaround for multi-byte emoji)
$STATUS_EMOJI = @{
    "done"        = "`u{2705}"   # check mark
    "in_progress" = "`u{1F504}"  # counterclockwise arrows
    "backlog"     = "`u{23F3}"   # hourglass
    "blocked"     = "`u{1F6AB}"  # no entry
    "not_started" = "`u{23F3}"   # hourglass
}

# ============================================================
# Helper: Get status emoji for a given status string
# ============================================================
function Get-StatusEmoji {
    param([string]$Status)
    if ($STATUS_EMOJI.ContainsKey($Status)) {
        return $STATUS_EMOJI[$Status]
    }
    return $Status
}

# ============================================================
# Helper: Build the auto-generated header block
# ============================================================
function Get-AutoHeader {
    param([string]$Timestamp)
    return @(
        $HEADER_LINE
        "<!-- generated_at: $Timestamp -->"
    ) -join "`n"
}

# ============================================================
# Test-Prerequisites
# ============================================================
function Test-Prerequisites {
    <#
    .SYNOPSIS
        Verify that powershell-yaml module is available.
    #>
    if (-not (Get-Module -ListAvailable -Name "powershell-yaml")) {
        Write-Error "FAIL-CLOSE: powershell-yaml module not found. Install: Install-Module powershell-yaml -Scope CurrentUser"
        exit 1
    }
}

# ============================================================
# Read-Backlog
# ============================================================
function Read-Backlog {
    <#
    .SYNOPSIS
        Parse and validate backlog.yaml.
    .PARAMETER Path
        Path to backlog.yaml file.
    .OUTPUTS
        Parsed backlog data as hashtable.
    #>
    param([string]$Path)

    Import-Module powershell-yaml -ErrorAction Stop

    if (-not (Test-Path $Path)) {
        Write-Error "FAIL-CLOSE: Backlog file not found: $Path"
        exit 1
    }

    $rawContent = Get-Content -Path $Path -Raw -Encoding utf8
    $data = ConvertFrom-Yaml -Yaml $rawContent

    # Validate version
    if ([string]$data.version -ne "2.0") {
        Write-Error "FAIL-CLOSE: backlog.yaml version must be '2.0', got '$($data.version)'"
        exit 1
    }

    # Validate required top-level keys
    foreach ($key in @("metadata", "phases", "milestones", "tasks")) {
        if (-not $data.ContainsKey($key)) {
            Write-Error "FAIL-CLOSE: backlog.yaml missing required key: $key"
            exit 1
        }
    }

    # Validate each task has required fields
    foreach ($task in $data.tasks) {
        foreach ($field in @("id", "intent", "status")) {
            if (-not $task.ContainsKey($field) -or $null -eq $task[$field]) {
                Write-Error "FAIL-CLOSE: Task missing required field '$field': $($task | ConvertTo-Json -Compress)"
                exit 1
            }
        }
    }

    return $data
}

# ============================================================
# Export-Roadmap
# ============================================================
function Export-Roadmap {
    <#
    .SYNOPSIS
        Generate docs/project/ROADMAP.md with phase overview,
        Mermaid timeline, and task status table.
    #>
    param(
        [object]$Data,
        [string]$OutputDir,
        [string]$Timestamp
    )

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine((Get-AutoHeader -Timestamp $Timestamp))
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("# Clawless ロードマップ")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("> 自動生成: ${Timestamp}（backlog.yaml から生成。直接編集禁止）")

    foreach ($phase in $Data.phases) {
        $phaseId = [string]$phase.id
        $phaseName = [string]$phase.name
        $phaseStart = if ($null -ne $phase.start_date) { [string]$phase.start_date } else { "TBD" }
        $phaseTarget = if ($null -ne $phase.target_date) { [string]$phase.target_date } else { "TBD" }

        # Count tasks in this phase
        $phaseTasks = @($Data.tasks | Where-Object { [string]$_.phase -eq $phaseId })
        $doneTasks = @($phaseTasks | Where-Object { [string]$_.status -eq "done" })
        $totalCount = $phaseTasks.Count
        $doneCount = $doneTasks.Count
        $progress = if ($totalCount -gt 0) { [math]::Round(($doneCount / $totalCount) * 100) } else { 0 }

        [void]$sb.AppendLine("")
        [void]$sb.AppendLine("## $phaseName")
        [void]$sb.AppendLine("")
        [void]$sb.AppendLine("期間: ${phaseStart} ～ ${phaseTarget} | 進捗: ${progress}%（${doneCount}/${totalCount} タスク完了）")

        # Mermaid timeline diagram — group tasks by milestone
        $phaseMilestones = @($Data.milestones | Where-Object { [string]$_.phase -eq $phaseId })

        [void]$sb.AppendLine("")
        [void]$sb.AppendLine('```mermaid')
        [void]$sb.AppendLine("timeline")
        [void]$sb.AppendLine("    title Clawless $phaseName")

        foreach ($ms in $phaseMilestones) {
            $msId = [string]$ms.id
            $msName = [string]$ms.name

            [void]$sb.AppendLine("    section $msName")

            $msTasks = @($phaseTasks | Where-Object { [string]$_.milestone -eq $msId })
            foreach ($task in $msTasks) {
                $taskIntent = [string]$task.intent
                # Plain text only — NO :done: or :active: modifiers (non-standard for timeline)
                [void]$sb.AppendLine("        $taskIntent")
            }
        }

        [void]$sb.AppendLine('```')

        # Task status table
        [void]$sb.AppendLine("")
        [void]$sb.AppendLine("| ID | タスク | ステータス | 担当 | 期限 |")
        [void]$sb.AppendLine("|---|---|---|---|---|")

        foreach ($task in $phaseTasks) {
            $taskId = [string]$task.id
            $taskIntent = [string]$task.intent
            $taskStatus = [string]$task.status
            $statusEmoji = Get-StatusEmoji -Status $taskStatus
            $assignee = if ($null -ne $task.assignee) { [string]$task.assignee } else { "-" }
            $dueDate = if ($null -ne $task.due_date) { [string]$task.due_date } else { "-" }
            [void]$sb.AppendLine("| $taskId | $taskIntent | $statusEmoji $taskStatus | $assignee | $dueDate |")
        }
    }

    $outPath = Join-Path $OutputDir "ROADMAP.md"
    $sb.ToString() | Set-Content -Path $outPath -Encoding utf8 -NoNewline
    Write-Host "  [OK] $outPath"
}

# ============================================================
# Export-WBS
# ============================================================
function Export-WBS {
    <#
    .SYNOPSIS
        Generate docs/project/WBS.md with Phase -> Milestone -> Task
        hierarchy using indented tree with status icons.
    #>
    param(
        [object]$Data,
        [string]$OutputDir,
        [string]$Timestamp
    )

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine((Get-AutoHeader -Timestamp $Timestamp))
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("# Clawless WBS（作業分解構成）")
    [void]$sb.AppendLine("")

    foreach ($phase in $Data.phases) {
        $phaseId = [string]$phase.id
        $phaseName = [string]$phase.name

        [void]$sb.AppendLine("## $phaseName")
        [void]$sb.AppendLine("")

        $phaseMilestones = @($Data.milestones | Where-Object { [string]$_.phase -eq $phaseId })

        foreach ($ms in $phaseMilestones) {
            $msId = [string]$ms.id
            $msName = [string]$ms.name
            $msStatus = [string]$ms.status
            $msEmoji = Get-StatusEmoji -Status $msStatus

            [void]$sb.AppendLine("### $msEmoji $msName")
            [void]$sb.AppendLine("")

            $msTasks = @($Data.tasks | Where-Object {
                [string]$_.phase -eq $phaseId -and [string]$_.milestone -eq $msId
            })

            foreach ($task in $msTasks) {
                $taskId = [string]$task.id
                $taskIntent = [string]$task.intent
                $taskStatus = [string]$task.status

                # Checkbox style: [x] done, [!] blocked, [ ] others
                $checkbox = switch ($taskStatus) {
                    "done"    { "[x]" }
                    "blocked" { "[!]" }
                    default   { "[ ]" }
                }

                [void]$sb.AppendLine("- $checkbox ${taskId}: $taskIntent")
            }

            [void]$sb.AppendLine("")
        }
    }

    $outPath = Join-Path $OutputDir "WBS.md"
    $sb.ToString() | Set-Content -Path $outPath -Encoding utf8 -NoNewline
    Write-Host "  [OK] $outPath"
}

# ============================================================
# Export-Gantt
# ============================================================
function Export-Gantt {
    <#
    .SYNOPSIS
        Generate docs/project/GANTT.md with Mermaid gantt diagram.
        Tasks without start_date or due_date are skipped.
    #>
    param(
        [object]$Data,
        [string]$OutputDir,
        [string]$Timestamp
    )

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine((Get-AutoHeader -Timestamp $Timestamp))
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("# Clawless ガントチャート")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("> 自動生成: $Timestamp")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine('```mermaid')
    [void]$sb.AppendLine("gantt")
    [void]$sb.AppendLine("    title Clawless 開発スケジュール")
    [void]$sb.AppendLine("    dateFormat YYYY-MM-DD")
    [void]$sb.AppendLine("    axisFormat %m/%d")

    foreach ($phase in $Data.phases) {
        $phaseId = [string]$phase.id
        $phaseName = [string]$phase.name

        # Collect renderable tasks (those with both dates) first
        $phaseTasks = @($Data.tasks | Where-Object { [string]$_.phase -eq $phaseId })
        $renderableTasks = @($phaseTasks | Where-Object {
            $null -ne $_.start_date -and $null -ne $_.due_date
        })

        # Skip section if no renderable tasks
        if ($renderableTasks.Count -eq 0) { continue }

        [void]$sb.AppendLine("")
        [void]$sb.AppendLine("    section $phaseName")

        foreach ($task in $renderableTasks) {
            $taskId = [string]$task.id
            $taskIntent = [string]$task.intent
            $taskStatus = [string]$task.status
            $startDate = [string]$task.start_date
            $dueDate = [string]$task.due_date

            # Mermaid gantt status modifiers
            $statusModifier = switch ($taskStatus) {
                "done"        { "done, " }
                "in_progress" { "active, " }
                "blocked"     { "crit, " }
                default       { "" }
            }

            # Sanitize task ID for Mermaid identifier
            $mermaidId = $taskId.ToLower().Replace("-", "_")

            # Check depends_on for 'after' syntax
            $dependsOn = $task.depends_on
            $hasValidDep = $false
            $afterClause = ""

            if ($null -ne $dependsOn -and $dependsOn.Count -gt 0) {
                $depIdRaw = [string]$dependsOn[0]
                $depMermaidId = $depIdRaw.ToLower().Replace("-", "_")
                # Only use 'after' if the dependency itself has dates (i.e. is in the gantt)
                $depTask = $Data.tasks | Where-Object { [string]$_.id -eq $depIdRaw } | Select-Object -First 1
                if ($null -ne $depTask -and $null -ne $depTask.start_date -and $null -ne $depTask.due_date) {
                    $hasValidDep = $true
                    $afterClause = "after $depMermaidId"
                }
            }

            if ($hasValidDep) {
                # Duration-based syntax with 'after' dependency
                $startDt = [datetime]::Parse($startDate)
                $endDt = [datetime]::Parse($dueDate)
                $days = [math]::Max(1, ($endDt - $startDt).Days)
                [void]$sb.AppendLine("    $taskIntent :${statusModifier}${mermaidId}, ${afterClause}, ${days}d")
            }
            else {
                # Explicit date range syntax
                [void]$sb.AppendLine("    $taskIntent :${statusModifier}${mermaidId}, ${startDate}, ${dueDate}")
            }
        }
    }

    [void]$sb.AppendLine('```')

    $outPath = Join-Path $OutputDir "GANTT.md"
    $sb.ToString() | Set-Content -Path $outPath -Encoding utf8 -NoNewline
    Write-Host "  [OK] $outPath"
}

# ============================================================
# Export-Milestones
# ============================================================
function Export-Milestones {
    <#
    .SYNOPSIS
        Generate docs/project/MILESTONES.md with milestone progress
        table including delay detection.
    #>
    param(
        [object]$Data,
        [string]$OutputDir,
        [string]$Timestamp
    )

    $today = [datetime]::UtcNow.Date

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine((Get-AutoHeader -Timestamp $Timestamp))
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("# Clawless マイルストーン")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("> 自動生成: $Timestamp")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("| ID | 名称 | 目標日 | Phase | ステータス | 進捗 | 遅延 |")
    [void]$sb.AppendLine("|---|---|---|---|---|---|---|")

    foreach ($ms in $Data.milestones) {
        $msId = [string]$ms.id
        $msName = [string]$ms.name
        $msTargetDate = if ($null -ne $ms.target_date) { [string]$ms.target_date } else { "-" }
        $msPhase = if ($null -ne $ms.phase) { [string]$ms.phase } else { "-" }
        $msStatus = [string]$ms.status
        $statusEmoji = Get-StatusEmoji -Status $msStatus

        # Count done / total tasks for this milestone
        $msTasks = @($Data.tasks | Where-Object { [string]$_.milestone -eq $msId })
        $doneCount = @($msTasks | Where-Object { [string]$_.status -eq "done" }).Count
        $totalCount = $msTasks.Count
        $progressStr = "${doneCount}/${totalCount}"

        # Delay calculation: if target_date < today AND not done
        $delayStr = "-"
        if ($msTargetDate -ne "-" -and $msStatus -ne "done") {
            try {
                $targetDt = [datetime]::Parse($msTargetDate)
                if ($today -gt $targetDt) {
                    $delayDays = ($today - $targetDt).Days
                    $delayStr = "`u{26A0}`u{FE0F} ${delayDays}日遅延"
                }
            }
            catch {
                # Date parse failure — skip delay calculation
                $delayStr = "-"
            }
        }

        [void]$sb.AppendLine("| $msId | $msName | $msTargetDate | $msPhase | $statusEmoji $msStatus | $progressStr | $delayStr |")
    }

    $outPath = Join-Path $OutputDir "MILESTONES.md"
    $sb.ToString() | Set-Content -Path $outPath -Encoding utf8 -NoNewline
    Write-Host "  [OK] $outPath"
}

# ============================================================
# Update-LastSync
# ============================================================
function Update-LastSync {
    <#
    .SYNOPSIS
        Update metadata.last_sync in backlog.yaml to current ISO 8601
        timestamp using targeted regex replacement (avoids YAML
        round-trip formatting issues).
    #>
    param(
        [string]$Path,
        [string]$Timestamp
    )

    $content = Get-Content -Path $Path -Raw -Encoding utf8

    # Match last_sync with quoted value (empty or existing timestamp)
    $pattern = '(last_sync:\s*)(".*?"|''''|"")'
    $replacement = "`${1}`"$Timestamp`""
    $newContent = $content -replace $pattern, $replacement

    if ($newContent -eq $content) {
        # Fallback: last_sync with no value at all
        $pattern2 = '(last_sync:\s*)([\r\n])'
        $replacement2 = "`${1}`"$Timestamp`"`${2}"
        $newContent = $content -replace $pattern2, $replacement2
    }

    Set-Content -Path $Path -Value $newContent -Encoding utf8 -NoNewline
    Write-Host "  [OK] Updated last_sync in $Path"
}

# ============================================================
# Main orchestration
# ============================================================
function Main {
    $startTime = Get-Date
    $timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

    Write-Host "=== sync-project-views ==="
    Write-Host "  Backlog: $BacklogPath"
    Write-Host "  Output:  $OutputDir"
    Write-Host ""

    # 1. Check prerequisites
    Write-Host "[1/8] Checking prerequisites..."
    Test-Prerequisites

    # 2. Read and validate backlog
    Write-Host "[2/8] Reading backlog..."
    $data = Read-Backlog -Path $BacklogPath

    # 3. Create output directory if needed
    Write-Host "[3/8] Ensuring output directory..."
    if (-not (Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
        Write-Host "  Created: $OutputDir"
    }

    # 4. Export Roadmap
    Write-Host "[4/8] Generating ROADMAP.md..."
    Export-Roadmap -Data $data -OutputDir $OutputDir -Timestamp $timestamp

    # 5. Export WBS
    Write-Host "[5/8] Generating WBS.md..."
    Export-WBS -Data $data -OutputDir $OutputDir -Timestamp $timestamp

    # 6. Export Gantt
    Write-Host "[6/8] Generating GANTT.md..."
    Export-Gantt -Data $data -OutputDir $OutputDir -Timestamp $timestamp

    # 7. Export Milestones
    Write-Host "[7/8] Generating MILESTONES.md..."
    Export-Milestones -Data $data -OutputDir $OutputDir -Timestamp $timestamp

    # 8. Update last_sync
    Write-Host "[8/8] Updating last_sync..."
    Update-LastSync -Path $BacklogPath -Timestamp $timestamp

    # Summary
    $elapsed = (Get-Date) - $startTime
    Write-Host ""
    Write-Host "=== Complete ==="
    Write-Host "  Generated 4 files in $($elapsed.TotalSeconds.ToString('F1'))s:"
    Write-Host "    - $(Join-Path $OutputDir 'ROADMAP.md')"
    Write-Host "    - $(Join-Path $OutputDir 'WBS.md')"
    Write-Host "    - $(Join-Path $OutputDir 'GANTT.md')"
    Write-Host "    - $(Join-Path $OutputDir 'MILESTONES.md')"
    Write-Host "  last_sync: $timestamp"
}

# ============================================================
# Entry point with fail-close error handling
# ============================================================
try {
    Main
}
catch {
    Write-Error "FAIL-CLOSE: $($_.Exception.Message)"
    exit 1
}
