param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]] $TrainingArgs
)

$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$Drive = $Root.Substring(0, 1).ToLowerInvariant()
$Rest = $Root.Substring(2).Replace("\", "/")
$WslRoot = "/mnt/$Drive$Rest"
& wsl.exe bash "$WslRoot/scripts/run_federated_training.sh" @TrainingArgs
exit $LASTEXITCODE
