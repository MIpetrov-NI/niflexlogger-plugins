$ErrorActionPreference = 'Stop'

$nipkg = Get-Command nipkg -ErrorAction Stop
$feedName = 'ni-flexlogger-pdk-2026-q3'
$feedUrl = 'https://download.ni.com/support/nipkg/products/ni-f/ni-flexlogger-plugin-development-kit/26.5/released'
$package = 'ni-flexlogger-plugin-development-kit=26.5.0.49720-0+f568'

& $nipkg.Source feed-add --name=$feedName $feedUrl
if ($LASTEXITCODE -ne 0) {
    throw "NIPM failed to add the '$feedName' feed with exit code $LASTEXITCODE."
}

& $nipkg.Source update $feedName
if ($LASTEXITCODE -ne 0) {
    throw "NIPM failed to update the '$feedName' feed with exit code $LASTEXITCODE."
}

& $nipkg.Source install --accept-eulas --assume-yes $package
if ($LASTEXITCODE -ne 0) {
    throw "NIPM failed to install '$package' with exit code $LASTEXITCODE."
}

$pluginSdk = 'C:\Program Files\National Instruments\LabVIEW 2026\vi.lib\FlexLogger\SDK\PluginSDK.lvlibp'
if (-not (Test-Path -LiteralPath $pluginSdk -PathType Container)) {
    throw "FlexLogger Plugin Development Kit was not installed: '$pluginSdk' is missing."
}
