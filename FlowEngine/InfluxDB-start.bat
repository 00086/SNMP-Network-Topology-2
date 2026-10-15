@echo off
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -Command ".\influxd.exe 2>&1 | ForEach-Object { if ($_ -match '(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z)') { $utcTime = [datetime]::Parse($Matches[1]); $localTime = $utcTime.ToLocalTime().ToString('yyyy-MM-dd HH:mm:ss.ffffff'); $_ -replace $Matches[1], $localTime } else { $_ } }"