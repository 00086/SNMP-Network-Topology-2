# 自動切換至腳本所在目錄
Set-Location $PSScriptRoot

.\influxd.exe 2>&1 | ForEach-Object {
    if ($_ -match '(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z)') {
        $utcTime = [datetime]::Parse($Matches[1])
        $localTime = $utcTime.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss.ffffff")
        $_ -replace $Matches[1], $localTime
    } else { $_ }
}