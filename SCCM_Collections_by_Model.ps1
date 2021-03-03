$PSD = "Site Code" # Site code 
$ProviderMachineName = "Server FQDN" # SMS Provider machine name

$initParams = @{}

if((Get-Module ConfigurationManager) -eq $null) {
    Import-Module "$($ENV:SMS_ADMIN_UI_PATH)\..\ConfigurationManager.psd1" @initParams 
}

if((Get-PSDrive -Name $PSD -PSProvider CMSite -ErrorAction SilentlyContinue) -eq $null) {
    New-PSDrive -Name $PSD -PSProvider CMSite -Root $ProviderMachineName @initParams
}

Set-Location "$($PSD):\" @initParams


$BasePath = $PSD + ":\DeviceCollection\$($PSD)-Windows Clients\Test"

# Проверка корневого каталога для каталогов производителей
If (!(Test-Path $BasePath)){
    New-Item -Path $BasePath
}

function New-SCCMCollection {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = "Limiting", HelpMessage = "Creats Limiting collection")]
        [switch]$Limiting,

        [Parameter(Mandatory = $true, ParameterSetName = "Device", HelpMessage = "Creats Device Collection")]
        [switch]$Device,

        [Parameter(Mandatory = $true, ParameterSetName = "Limiting", HelpMessage = "Collection Name")]
        [Parameter(Mandatory = $true, ParameterSetName = "Device")]
        [string]$CollectionName,

        [Parameter(Mandatory = $true, ParameterSetName = "Limiting", HelpMessage = "Limiting Collection Name")]
        [Parameter(Mandatory = $true, ParameterSetName = "Device")]
        [string]$LimitingCollection,

        [Parameter(Mandatory = $true, ParameterSetName = "Limiting", HelpMessage = "Collection Folder")]
        [Parameter(Mandatory = $true, ParameterSetName = "Device")]
        [string]$CollectionFolder,

        [Parameter(Mandatory = $true, ParameterSetName = "Limiting", HelpMessage = "Manufacturer")]
        [Parameter(Mandatory = $true, ParameterSetName = "Device")]
        [string]$Manufacturer,

        [Parameter(Mandatory = $true, ParameterSetName = "Device", HelpMessage = "Model")]
        [string]$Model
    )
    $BasicQuery = "select distinct 
    SMS_R_SYSTEM.ResourceID
    ,SMS_R_SYSTEM.ResourceType
    ,SMS_R_SYSTEM.Name
    ,SMS_R_SYSTEM.SMSUniqueIdentifier
    ,SMS_R_SYSTEM.ResourceDomainORWorkgroup
    ,SMS_R_SYSTEM.Client 
    from SMS_R_System 
    inner join SMS_G_System_COMPUTER_SYSTEM on SMS_G_System_COMPUTER_SYSTEM.ResourceId = SMS_R_System.ResourceId 
    inner join SMS_G_System_OPERATING_SYSTEM on SMS_G_System_OPERATING_SYSTEM.ResourceID = SMS_R_System.ResourceId 
    WHERE SMS_G_System_OPERATING_SYSTEM.ProductType = `"1`""

    Switch ($PSCmdlet.ParameterSetName){
        "Limiting" {
            Switch ($Manufacturer){
                HP {
                    $Query = "$($BasicQuery) and SMS_G_System_COMPUTER_SYSTEM.Manufacturer = `"HP`" or 
                    SMS_G_System_COMPUTER_SYSTEM.Manufacturer Like `"Hewlett%`""
                    $RuleName = "$($PSD)-$($Manufacturer)-All"
                    $Comment = "All $($Manufacturer) devices"
                }
                default {
                    $Query = "$($BasicQuery) and SMS_G_System_COMPUTER_SYSTEM.Manufacturer like `"$($Manufacturer)%`""
                    $RuleName = "$($PSD)-$($Manufacturer)-All"
                    $Comment = "All $($Manufacturer) devices"
                }
            }            
        }
        "Device" {
            $Query = "$($BasicQuery) and SMS_G_System_COMPUTER_SYSTEM.Model like `"$($Model)%`""
            $RuleName = "$($PSD)-$($Manufacturer)-$($Model)"
            $Comment = "All $($Model) Devices"
        }
    }
   

    New-CMDeviceCollection -Name $CollectionName -LimitingCollectionName $LimitingCollection -RefreshType Periodic `
    -RefreshSchedule $Schedule -Comment $Comment | Out-Null
    Add-CMDeviceCollectionQueryMembershipRule -RuleName $RuleName -CollectionName $CollectionName -QueryExpression $Query
    Move-CMObject -FolderPath $CollectionFolder -InputObject (Get-CMDeviceCollection -Name $CollectionName)
}

$BasePath = $PSD + ":\DeviceCollection\P07-Windows Clients\Test"

# Проверка корневого каталога для каталогов производителей
If (!(Test-Path $BasePath)){
    New-Item -Path $BasePath
}

# Выборка всех проинвентаризированных моделей производителей (только клиентские операционные системы)
$AllManufacturers = Invoke-CMWmiQuery -Query "select distinct 
SMS_G_System_COMPUTER_SYSTEM.Manufacturer
, SMS_G_System_COMPUTER_SYSTEM.Model
from SMS_R_System 
inner join SMS_G_System_COMPUTER_SYSTEM on SMS_G_System_COMPUTER_SYSTEM.ResourceId = SMS_R_System.ResourceId 
inner join SMS_G_System_OPERATING_SYSTEM on SMS_G_System_OPERATING_SYSTEM.ResourceID = SMS_R_System.ResourceId
WHERE SMS_G_System_OPERATING_SYSTEM.ProductType = `"1`"" `
| Select-Object manufacturer, model

$ManufacturersHashTable = $AllManufacturers | Group-Object Manufacturer -AsHashTable

foreach ($manufacturer in $ManufacturersHashTable.GetEnumerator()){
    Switch ($manufacturer.Name){
        {($_ -eq 'HP') -or ($_ -like 'Hewlet*')}{
            $ManufacturerFolder = $BasePath + "\" + "HP"
            $ManufacturerName = "HP"    
        }
        {$_ -like 'ASUS*'} {
            $ManufacturerFolder = $BasePath + "\" + "ASUS"
            $ManufacturerName = "ASUS"
        }
        default {
            $ManufacturerFolder = $BasePath + "\" + $manufacturer.Name
            $ManufacturerName = $manufacturer.Name
        }
    }
    If (!(Test-Path $ManufacturerFolder)){
        Write-Host "Path $($ManufacturerFolder) not exists"
        New-Item -Path $ManufacturerFolder
    }
    If ($null -eq (Get-CMDeviceCollection -Name "$($PSD)-$($ManufacturerName)-All")){
        Write-Host "Creating collection $($PSD)-$($ManufacturerName)-All in $($ManufacturerFolder)"
        New-SCCMCollection -Limiting -CollectionName "$($PSD)-$($ManufacturerName)-All" -LimitingCollection "P07-Computers" -CollectionFolder $ManufacturerFolder -Manufacturer $ManufacturerName
    }

    foreach ($model in $manufacturer.Value){
        Switch ($Manufacturer.Name){
            Lenovo {
                $ModelName = $model.model.SubString(0,4)
            }
            default {
                $ModelName = $model.model
            }
        }
        If ($null -eq (Get-CMDeviceCollection -Name "$($PSD)-$($ManufacturerName)-$($ModelName)")){
            Write-Host "Creating collection $($PSD)-$($ManufacturerName)-$($ModelName) in $($ManufacturerFolder)"
            New-SCCMCollection -Device -CollectionName "$($PSD)-$($ManufacturerName)-$($ModelName)" -LimitingCollection "$($PSD)-$($ManufacturerName)-All" -CollectionFolder $ManufacturerFolder -Manufacturer $ManufacturerName -Model $ModelName
        } 
    }
}
