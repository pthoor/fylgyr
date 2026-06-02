[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ResourceGroupName,

    [Parameter(Mandatory = $false)]
    [Alias('DeploymentName')]
    [string]$InfrastructureDeploymentName = '',

    [Parameter(Mandatory = $false)]
    [string]$FunctionAppName = '',

    [Parameter(Mandatory = $false)]
    [string]$FunctionStorageAccountName = '',

    [Parameter(Mandatory = $false)]
    [string]$PublishDeploymentName = 'fylgyr-function-package',

    [Parameter(Mandatory = $false)]
    [string]$TemplateFile = 'docs/sentinel/deploy/fylgyr-sentinel.bicep',

    [Parameter(Mandatory = $false)]
    [string]$ParameterFile = 'docs/sentinel/deploy/fylgyr-sentinel.local.bicepparam',

    [Parameter(Mandatory = $false)]
    [string]$ContainerName = 'function-packages',

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 30)]
    [int]$SasExpiryDays = 7
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Resolve-RepoPath {
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$RepoRoot,

        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if ([System.IO.Path]::IsPathRooted($Path)) {
        return (Resolve-Path -Path $Path).Path
    }

    return (Resolve-Path -Path (Join-Path -Path $RepoRoot -ChildPath $Path)).Path
}

function Invoke-AzCli {
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    $output = & az @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Azure CLI command failed: az $($Arguments -join ' ')"
    }

    return ($output -join "`n")
}

function Get-LatestSuccessfulDeploymentName {
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ResourceGroup
    )

    $deploymentsJson = Invoke-AzCli -Arguments @(
        'deployment', 'group', 'list',
        '--resource-group', $ResourceGroup,
        '-o', 'json'
    )

    $deployments = $deploymentsJson | ConvertFrom-Json
    $latest = $deployments |
        Where-Object { $_.properties.provisioningState -eq 'Succeeded' } |
        Sort-Object { [datetime]$_.properties.timestamp } -Descending |
        Select-Object -First 1

    if ($null -eq $latest -or [string]::IsNullOrWhiteSpace($latest.name)) {
        throw 'No successful deployment found in the target resource group.'
    }

    return [string]$latest.name
}

function Get-FunctionAppNameFromResourceGroup {
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ResourceGroup
    )

    $appsJson = Invoke-AzCli -Arguments @(
        'functionapp', 'list',
        '--resource-group', $ResourceGroup,
        '-o', 'json'
    )

    $apps = $appsJson | ConvertFrom-Json
    if ($null -eq $apps -or $apps.Count -eq 0) {
        throw 'No Function App found in the target resource group. Pass -FunctionAppName explicitly.'
    }

    if ($apps.Count -eq 1) {
        return [string]$apps[0].name
    }

    $fylgyrApps = $apps | Where-Object {
        $null -ne $_.tags -and
        $null -ne $_.tags.solution -and
        $_.tags.solution -eq 'fylgyr'
    }

    if ($fylgyrApps.Count -eq 1) {
        return [string]$fylgyrApps[0].name
    }

    throw 'Multiple Function Apps found in the resource group. Pass -FunctionAppName explicitly.'
}

function Get-StorageAccountNameFromFunctionAppSetting {
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ResourceGroup,

        [Parameter(Mandatory = $true)]
        [string]$FunctionApp
    )

    $settingsJson = Invoke-AzCli -Arguments @(
        'functionapp', 'config', 'appsettings', 'list',
        '--name', $FunctionApp,
        '--resource-group', $ResourceGroup,
        '-o', 'json'
    )

    $settings = $settingsJson | ConvertFrom-Json
    $storageSetting = ($settings | Where-Object { $_.name -eq 'AzureWebJobsStorage' } | Select-Object -First 1)
    if ($null -eq $storageSetting -or [string]::IsNullOrWhiteSpace($storageSetting.value)) {
        return ''
    }

    if ($storageSetting.value -match 'AccountName=([^;]+)') {
        return [string]$Matches[1]
    }

    return ''
}

function Get-ModulePackageRoot {
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ModuleName
    )

    $module = Get-Module -ListAvailable -Name $ModuleName |
        Sort-Object -Property Version -Descending |
        Select-Object -First 1

    if ($null -eq $module) {
        Install-Module -Name $ModuleName -Repository PSGallery -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
        $module = Get-Module -ListAvailable -Name $ModuleName |
            Sort-Object -Property Version -Descending |
            Select-Object -First 1
    }

    if ($null -eq $module -or [string]::IsNullOrWhiteSpace($module.Path)) {
        throw "Failed to resolve module '$ModuleName' for packaging."
    }

    $moduleDir = [System.IO.DirectoryInfo](Split-Path -Path $module.Path -Parent)
    if ($moduleDir.Name -match '^[0-9]') {
        return $moduleDir.Parent.FullName
    }

    return $moduleDir.FullName
}

try {
    if ($null -eq (Get-Command -Name 'az' -ErrorAction SilentlyContinue)) {
        throw 'Azure CLI is required but was not found on PATH.'
    }

    $repoRoot = (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..')).Path
    $templatePath = Resolve-RepoPath -RepoRoot $repoRoot -Path $TemplateFile
    $parameterPath = Resolve-RepoPath -RepoRoot $repoRoot -Path $ParameterFile

    $usedInfrastructureDeploymentName = ''
    $functionAppName = $FunctionAppName
    $storageAccountName = $FunctionStorageAccountName

    if ([string]::IsNullOrWhiteSpace($functionAppName)) {
        $functionAppName = Get-FunctionAppNameFromResourceGroup -ResourceGroup $ResourceGroupName
    }

    if ([string]::IsNullOrWhiteSpace($storageAccountName)) {
        $storageAccountName = Get-StorageAccountNameFromFunctionAppSetting -ResourceGroup $ResourceGroupName -FunctionApp $functionAppName
    }

    if ([string]::IsNullOrWhiteSpace($storageAccountName)) {
        if ([string]::IsNullOrWhiteSpace($InfrastructureDeploymentName)) {
            $InfrastructureDeploymentName = Get-LatestSuccessfulDeploymentName -ResourceGroup $ResourceGroupName
        }

        $usedInfrastructureDeploymentName = $InfrastructureDeploymentName
        $outputsJson = Invoke-AzCli -Arguments @(
            'deployment', 'group', 'show',
            '--name', $InfrastructureDeploymentName,
            '--resource-group', $ResourceGroupName,
            '--query', 'properties.outputs',
            '-o', 'json'
        )

        $outputs = $outputsJson | ConvertFrom-Json
        if ([string]::IsNullOrWhiteSpace($functionAppName) -and $null -ne $outputs.functionAppResourceId -and -not [string]::IsNullOrWhiteSpace($outputs.functionAppResourceId.value)) {
            $functionAppName = ($outputs.functionAppResourceId.value -split '/')[-1]
        }

        if ($null -ne $outputs.functionStorageAccountNameOut -and -not [string]::IsNullOrWhiteSpace($outputs.functionStorageAccountNameOut.value)) {
            $storageAccountName = $outputs.functionStorageAccountNameOut.value
        }
    }

    if ([string]::IsNullOrWhiteSpace($functionAppName)) {
        throw 'Could not determine Function App name. Pass -FunctionAppName explicitly.'
    }

    if ([string]::IsNullOrWhiteSpace($storageAccountName)) {
        throw 'Could not determine Function storage account. Pass -FunctionStorageAccountName explicitly.'
    }

    $stageRoot = Join-Path -Path $repoRoot -ChildPath '.tmp/fylgyr-function-package'
    $functionRoot = Join-Path -Path $stageRoot -ChildPath 'FylgyrTimer'
    $modulesRoot = Join-Path -Path $stageRoot -ChildPath 'Modules'
    $artifactRoot = Join-Path -Path $repoRoot -ChildPath 'artifacts'
    $artifactPath = Join-Path -Path $artifactRoot -ChildPath 'fylgyr-function.zip'

    Remove-Item -Path $stageRoot -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $artifactPath -Force -ErrorAction SilentlyContinue

    New-Item -Path $functionRoot -ItemType Directory -Force | Out-Null
    New-Item -Path $modulesRoot -ItemType Directory -Force | Out-Null
    New-Item -Path $artifactRoot -ItemType Directory -Force | Out-Null

    @'
{
  "version": "2.0"
}
'@ | Set-Content -Path (Join-Path -Path $stageRoot -ChildPath 'host.json') -Encoding utf8

    Copy-Item -Path (Join-Path -Path $repoRoot -ChildPath 'docs/sentinel/azure-function/run.ps1') -Destination (Join-Path -Path $functionRoot -ChildPath 'run.ps1') -Force
    Copy-Item -Path (Join-Path -Path $repoRoot -ChildPath 'docs/sentinel/azure-function/function.json') -Destination (Join-Path -Path $functionRoot -ChildPath 'function.json') -Force
    Copy-Item -Path (Join-Path -Path $repoRoot -ChildPath 'src/Fylgyr') -Destination (Join-Path -Path $modulesRoot -ChildPath 'Fylgyr') -Recurse -Force

    $bundledDependencyModules = @('powershell-yaml')
    foreach ($moduleName in $bundledDependencyModules) {
        $moduleRoot = Get-ModulePackageRoot -ModuleName $moduleName
        Copy-Item -Path $moduleRoot -Destination (Join-Path -Path $modulesRoot -ChildPath $moduleName) -Recurse -Force
    }

    Compress-Archive -Path (Join-Path -Path $stageRoot -ChildPath '*') -DestinationPath $artifactPath -Force

    $storageKey = Invoke-AzCli -Arguments @(
        'storage', 'account', 'keys', 'list',
        '--resource-group', $ResourceGroupName,
        '--account-name', $storageAccountName,
        '--query', '[0].value',
        '-o', 'tsv'
    )

    if ([string]::IsNullOrWhiteSpace($storageKey)) {
        throw 'Failed to retrieve storage account key for function package upload.'
    }

    Invoke-AzCli -Arguments @(
        'storage', 'container', 'create',
        '--name', $ContainerName,
        '--account-name', $storageAccountName,
        '--account-key', $storageKey,
        '--public-access', 'off'
    ) | Out-Null

    $blobName = 'fylgyr-function-{0}.zip' -f (Get-Date -Format 'yyyyMMddHHmmss')

    Invoke-AzCli -Arguments @(
        'storage', 'blob', 'upload',
        '--container-name', $ContainerName,
        '--name', $blobName,
        '--file', $artifactPath,
        '--account-name', $storageAccountName,
        '--account-key', $storageKey,
        '--overwrite', 'true'
    ) | Out-Null

    $expiry = (Get-Date).ToUniversalTime().AddDays($SasExpiryDays).ToString('yyyy-MM-ddTHH:mmZ')
    $sas = Invoke-AzCli -Arguments @(
        'storage', 'blob', 'generate-sas',
        '--container-name', $ContainerName,
        '--name', $blobName,
        '--permissions', 'r',
        '--expiry', $expiry,
        '--https-only',
        '--account-name', $storageAccountName,
        '--account-key', $storageKey,
        '-o', 'tsv'
    )

    if ([string]::IsNullOrWhiteSpace($sas)) {
        throw 'Failed to generate SAS token for uploaded function package.'
    }

    if ([string]::IsNullOrWhiteSpace($PublishDeploymentName)) {
        $PublishDeploymentName = 'fylgyr-function-package'
    }

    $functionPackageUri = "https://$storageAccountName.blob.core.windows.net/$ContainerName/$blobName`?$sas"

    Invoke-AzCli -Arguments @(
        'deployment', 'group', 'create',
        '--name', $PublishDeploymentName,
        '--resource-group', $ResourceGroupName,
        '--template-file', $templatePath,
        '--parameters', $parameterPath,
        '--parameters', "functionPackageUri=$functionPackageUri"
    ) | Out-Null

    Write-Host "Function package deployed to app: $functionAppName"
    if (-not [string]::IsNullOrWhiteSpace($usedInfrastructureDeploymentName)) {
        Write-Host "Infrastructure deployment used: $usedInfrastructureDeploymentName"
    }
    Write-Host "Storage account used: $storageAccountName"
    Write-Host "Deployment update: $PublishDeploymentName"
}
catch {
    throw "Failed to publish Fylgyr function package: $($_.Exception.Message)"
}
