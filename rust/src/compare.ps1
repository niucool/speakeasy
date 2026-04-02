$py_dir = "c:\Projects\github\speakeasy\speakeasy"
$rs_dir = "c:\Projects\github\speakeasy\rust\src"

$py_files = Get-ChildItem -Path $py_dir -Recurse -Filter "*.py" | Where-Object { $_.Name -ne "__init__.py" -and $_.Name -ne "__main__.py" }

$not_ported = @()
$not_fully_implemented = @()

foreach ($py_file in $py_files) {
    if ($py_file.FullName -match "\\tests\\" -or $py_file.FullName -match "tests\.py") { continue }
    $rel_path = $py_file.FullName.Substring($py_dir.Length + 1)
    
    $rs_rel_path = $rel_path -replace '\.py$', '.rs'
    $rs_path = Join-Path $rs_dir $rs_rel_path
    
    if (-not (Test-Path $rs_path)) {
        # Check if mod.rs
        $mod_rel = $rs_rel_path -replace '\.rs$', '\mod.rs'
        $rs_dir_mod = Join-Path $rs_dir $mod_rel
        if (Test-Path $rs_dir_mod) {
            $rs_path = $rs_dir_mod
        } else {
            # Check edge cases
            if ($rel_path -match "api") {
                # Could be under winenv
                $winenv_rel = ($rel_path -replace "^windows\\api", "winenv\api\usermode") -replace '\.py$', '.rs'
                $rs_path_winenv = Join-Path $rs_dir $winenv_rel
                if (Test-Path $rs_path_winenv) {
                    $rs_path = $rs_path_winenv
                } else {
                    $winenv_rel_k = ($rel_path -replace "^windows\\api", "winenv\api\kernelmode") -replace '\.py$', '.rs'
                    $rs_path_winenv_k = Join-Path $rs_dir $winenv_rel_k
                    if (Test-Path $rs_path_winenv_k) {
                        $rs_path = $rs_path_winenv_k
                    } else {
                        $not_ported += $rel_path
                        continue
                    }
                }
            } else {
                $not_ported += $rel_path
                continue
            }
        }
    }
    
    $py_lines = (Get-Content $py_file.FullName | Measure-Object).Count
    $rs_content = Get-Content $rs_path -Raw
    $rs_lines = (Get-Content $rs_path | Measure-Object).Count
    
    $is_stub = $false
    $reason = ""
    
    if ($rs_content -match "unimplemented!\(\)") {
        $is_stub = $true
        $reason = "contains unimplemented!()"
    } elseif ($rs_content -match "fn call" -and $rs_content -match "\{\s*0\s*\}") {
        $is_stub = $true
        $reason = "stub API handler returning 0"
    } elseif ($rs_lines -le 35 -and $py_lines -gt 150) {
        $is_stub = $true
        $reason = "significantly smaller size"
    }
    
    if ($is_stub) {
        $not_fully_implemented += "- $rel_path (Python: $py_lines lines, Rust: $rs_lines lines) - $reason"
    }
}

Write-Host "================ NOT PORTED ================"
$not_ported | Sort-Object | ForEach-Object { Write-Host "- $_" }

Write-Host "`n================ PORTED BUT NOT FULLY IMPLEMENTED ================"
$not_fully_implemented | Sort-Object | ForEach-Object { Write-Host "$_" }
