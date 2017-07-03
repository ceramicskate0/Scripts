param ( 
[string]$path = "C:\temp\",
[Int32]$days = 0 
)

$limit = (Get-Date).AddDays(-$days)

Get-ChildItem -Path $path -Recurse -Force | Where-Object { !$_.PSIsContainer -and $_.CreationTime -lt $limit } | Remove-Item -Force
