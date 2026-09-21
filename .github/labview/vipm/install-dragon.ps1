$ErrorActionPreference = 'Stop'

$dragonFiles = @(Get-ChildItem -Path 'C:\vipm' -Filter '*.dragon' -Recurse -File)
if ($dragonFiles.Count -eq 0) {
    throw 'No Dragon dependency files were staged in C:\vipm.'
}

foreach ($dragonFile in $dragonFiles) {
    & dragon apply $dragonFile.FullName
    if ($LASTEXITCODE -ne 0) {
        throw "Dragon failed to apply '$($dragonFile.Name)' with exit code $LASTEXITCODE."
    }
}

$pluginSdk = 'C:\Program Files\National Instruments\LabVIEW 2026\vi.lib\FlexLogger\SDK\PluginSDK.lvlibp'
if (-not (Test-Path -LiteralPath $pluginSdk -PathType Container)) {
    throw "FlexLogger Plugin Development Kit was not installed: '$pluginSdk' is missing."
}
