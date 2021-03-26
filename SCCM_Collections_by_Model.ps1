function Add-Collections {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = "Limiting", HelpMessage = "Creats Limiting collection")]
        [switch]$Limiting,

        [Parameter(Mandatory = $true, ParameterSetName = "Device", HelpMessage = "Creats Device Collection")]
        [switch]$Device,

        [Parameter(Mandatory = $true, ParameterSetName = "Limiting", HelpMessage = "Limiting Collection Name")]        
        [string]$LimitingCollection,

        [Parameter(Mandatory = $true, ParameterSetName = "Limiting", HelpMessage = "Collection Folder")]        
        [string]$CollectionFolder,
        
        [Parameter(Mandatory = $true, ParameterSetName = "Device", ValueFromPipeline)]        
        $InputValues,

        [Parameter(Mandatory = $true, ParameterSetName = "Limiting", HelpMessage = "Manufacturer Name")]
        [Parameter(Mandatory = $true, ParameterSetName = "Device", HelpMessage = "Manufacturer Name", ValueFromPipelineByPropertyName)]        
        [string]$Manufacturer,        
        
        [Parameter(Mandatory = $true, ParameterSetName = "Device", HelpMessage = "Computer Model Name", ValueFromPipelineByPropertyName)]
        [string]$Model
    )
    
    begin {
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
    }
    
    process {
        Switch ($PSCmdlet.ParameterSetName){
            "Limiting" {
                Switch ($Manufacturer){
                    HP {
                        $CollectionName = "$($PSD)-$($Manufacturer)-All"
                        $Query = "$($BasicQuery) and SMS_G_System_COMPUTER_SYSTEM.Manufacturer = `"HP`" or 
                        SMS_G_System_COMPUTER_SYSTEM.Manufacturer Like `"Hewlett%`""
                        $RuleName = "$($PSD)-$($Manufacturer)-All"
                        $Comment = "All $($Manufacturer) devices"
                    }
                    default {
                        $CollectionName = "$($PSD)-$($Manufacturer)-All"
                        $Query = "$($BasicQuery) and SMS_G_System_COMPUTER_SYSTEM.Manufacturer like `"$($Manufacturer)%`""
                        $RuleName = "$($PSD)-$($Manufacturer)-All"
                        $Comment = "All $($Manufacturer) devices"
                    }
                }            
            }
            "Device" {
                $CollectionName = "$($PSD)-$($Model)"
                $CollectionFolder = $InputValues.folder
                $LimitingCollection = "$($PSD)-$($Manufacturer)-All"
                $Query = "$($BasicQuery) and SMS_G_System_COMPUTER_SYSTEM.Model like `"$($InputValues.sku)%`""
                $RuleName = "$($PSD)-$($InputValues.sku)"                
                $Comment = "All $($Model) ($($InputValues.sku)) Devices"
            }
        }
        if ($manufacturer -ne 'Other'){
            # Uncomemnt the following lines for debug collection creation process
            <#Write-Host "Creating device collection:"
            Write-Host "Name: $($CollectionName)"
            Write-Host "Limiting Collection: $($LimitingCollection)"
            Write-Host "Collection Rule: $($RuleName)"
            Write-Host "Rule Query: $($Query)"
            Write-Host "Move $($CollectionName) to $CollectionFolder"
            Write-Host "------------------------------"#>

            if ($null -eq (Get-CMDeviceCollection -Name $CollectionName)){
                New-CMDeviceCollection -Name $CollectionName -LimitingCollectionName $LimitingCollection `
                -Comment $Comment | Out-Null
                Add-CMDeviceCollectionQueryMembershipRule -RuleName $RuleName -CollectionName $CollectionName -QueryExpression $Query
                Move-CMObject -FolderPath $CollectionFolder -InputObject (Get-CMDeviceCollection -Name $CollectionName)
            }
            elseif ($null -eq $RuleName) {
                Add-CMDeviceCollectionQueryMembershipRule -RuleName $RuleName -CollectionName $CollectionName -QueryExpression $Query
            }            
        }
        Switch ($PSCmdlet.ParameterSetName){
            "Limiting" {
                Get-CMCollection -Name "$($PSD)-Other" | Add-CMDeviceCollectionExcludeMembershipRule -ExcludeCollectionName $CollectionName                
            }
        }
    }
    
    end {
        
    }
}

# Site code
$PSD = "P01"  
# SMS Provider machine FQDN-name
$ProviderMachineName = "SERVER.domain.local" 

$initParams = @{}

if($null -eq (Get-Module ConfigurationManager)) {
    Import-Module "$($ENV:SMS_ADMIN_UI_PATH)\..\ConfigurationManager.psd1" @initParams 
}

if($null -eq (Get-PSDrive -Name $PSD -PSProvider CMSite -ErrorAction SilentlyContinue)) {
    New-PSDrive -Name $PSD -PSProvider CMSite -Root $ProviderMachineName @initParams
}

Set-Location "$($PSD):\" @initParams

# Setting Base folder for all collections
$BasePath = $PSD + ":\DeviceCollection\$($PSD)-Windows Clients\$($PSD)-Коллекции по производителям"
# Setting Base limiting collection
$BaseLimitingCollection = "$($PSD)-Computers"

# Setting up proxy settings
$proxy = "proxy_server_name:port"
$wc = New-Object System.Net.WebClient
$wc.Proxy = [System.Net.WebProxy]::new($Proxy)
$Wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials

# Getting Lenovo catalog from site
[xml]$COMPUTERXML = $wc.DownloadString('https://download.lenovo.com/cdrt/td/catalog.xml')

# Check if Base Folder exists
If (!(Test-Path $BasePath)){
    New-Item -Path $BasePath
}

# Create folder for all unknown device models collection
$OtherFolder = $BasePath+"\Other"
If (!(Test-Path $OtherFolder)){
    New-Item -Path $OtherFolder
}

# Create Collection for all unknown device models and move it to $OtherFolder
# This base collection includes all computers from limiting collection $BaseLimitingCollection
If ($null -eq (Get-CMDeviceCollection -Name "$($PSD)-Other")){
    New-CMDeviceCollection -Name "$($PSD)-Other" -LimitingCollectionName $BaseLimitingCollection
    Get-CMCollection -Name "$($PSD)-Other" | Add-CMDeviceCollectionIncludeMembershipRule -IncludeCollectionName $BaseLimitingCollection
    Move-CMObject -FolderPath $OtherFolder -InputObject (Get-CMDeviceCollection -Name "$($PSD)-Other")
}

# Selecting all invetoried manufactures on client devices
$AllManufacturers = Invoke-CMWmiQuery -Query "select distinct 
SMS_G_System_COMPUTER_SYSTEM.Manufacturer
, SMS_G_System_COMPUTER_SYSTEM.Model
from SMS_R_System 
inner join SMS_G_System_COMPUTER_SYSTEM on SMS_G_System_COMPUTER_SYSTEM.ResourceId = SMS_R_System.ResourceId 
inner join SMS_G_System_OPERATING_SYSTEM on SMS_G_System_OPERATING_SYSTEM.ResourceID = SMS_R_System.ResourceId
WHERE SMS_G_System_OPERATING_SYSTEM.ProductType = `"1`"" `
| Select-Object manufacturer, model, sku, folder

$NewValues = @()

# Data alignment
foreach ($manufacturer in $AllManufacturers){
    Switch ($manufacturer.manufacturer){
        {($_ -eq 'HP') -or ($_ -like 'Hewlet*')}{
            $manufacturer.manufacturer = "HP"
            $manufacturer.sku = $manufacturer.model
            $manufacturer.folder = $BasePath + "\$($manufacturer.manufacturer)"            
        }
        {$_ -like 'ASUS*'} {
            $manufacturer.manufacturer = "ASUS"
            $manufacturer.sku = $manufacturer.model
            $manufacturer.folder = $BasePath + "\$($manufacturer.manufacturer)" 
        }
        "Lenovo"{
            $manufacturer.manufacturer = "Lenovo"
            $manufacturer.sku = $manufacturer.model.SubString(0,4)
            # Setting readable model from downloaded file
            $manufacturer.model = ($COMPUTERXML.Products.Product.Queries | Where-Object {$_.Types.Type -eq $manufacturer.sku} | select-object version | Get-Unique).version
            $manufacturer.folder = $BasePath + "\$($manufacturer.manufacturer)" 
        }
        default {            
            $manufacturer.manufacturer = "Other"
            $manufacturer.folder = $BasePath + "\$($manufacturer.manufacturer)" 
        }
    }
    $NewValues+= $manufacturer
}

# Convert to hash-table
$ManufacturersHashTable = $NewValues | Select-Object manufacturer, model, sku, folder -Unique | Group-Object manufacturer -AsHashTable

foreach ($item in $ManufacturersHashTable.GetEnumerator()){
    $ManufacturerFolder = $BasePath+"\"+$item.key.ToString()
    If (!(Test-Path $ManufacturerFolder)){
        New-Item -Path $ManufacturerFolder
    }  
    # Create limiting collections  
    Add-Collections -Limiting -LimitingCollection $BaseLimitingCollection -Manufacturer $item.key.ToString() -CollectionFolder $ManufacturerFolder
    # Create device collection fot each model
    foreach ($currentitem in $ManufacturersHashTable[$item.key].model){        
        $values = $ManufacturersHashTable[$item.key] | Where-Object model -EQ $currentitem | Select-Object sku, folder
        $values | Add-Collections -Device -Model $currentitem -Manufacturer $item.key.ToString()        
    } 
}
