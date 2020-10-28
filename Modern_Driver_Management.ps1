<#
    .SYNOPSIS
    Resize-Image resizes an image file

    .DESCRIPTION
    This function uses the native .NET API to crop a square and resize an image file

    .PARAMETER Endpoint
    Specify the internal fully qualified domain name of the server hosting the AdminService, e.g. CM01.domain.local.

    .PARAMETER UserName
    UserName to access AdminService

    .PARAMETER UsrPwd
    User Password to access AdminService

    .PARAMETER BypassCertCheck
    Specify if bypass adminservice certificate check is required

    .EXAMPLE
    Resize the image to a specific size:
    .\Resize-Image.ps1 -InputFile "C:\userpic.jpg" -OutputFile "C:\userpic-400.jpg"-SquareHeight 400
#>

[CmdletBinding()]
param (
    [parameter(Mandatory=$true,HelpMessage = "Specify the internal fully qualified domain name of the server hosting the AdminService, e.g. CM01.domain.local.")]
	[ValidateNotNullOrEmpty()]
	[string]$Endpoint,

    [Parameter(Mandatory=$true,HelpMessage="Username to connect to AdminService")]
    [ValidateNotNullOrEmpty()]
    [string]$UserName,

    [Parameter(Mandatory=$true,HelpMessage="Password")]
    [ValidateNotNullOrEmpty()]
    [string]$UsrPwd,
    
    [Parameter(Mandatory=$true,HelpMessage="Specify if bypass self-signadminservice certificate is needed")]
    [ValidateNotNullOrEmpty()]
    [bool]$BypassCertCheck
)

begin{
    
}

Process{
function Get-ComputerSKU {
    $CurrentComputer = Get-WmiObject -class Win32_ComputerSystem | Select-Object Manufacturer, Model, SystemSKUNumber
    switch ($CurrentComputer.Manufacturer){
        'HP'{
            $ComputerSKU = $CurrentComputer.SystemSKUNumber.SubString(0,4)
        }
        'Lenovo'{
            $ComputerSKU = $CurrentComputer.Model.SubString(0,4)
        }
    }
    return $ComputerSKU
}

function Get-OSBuild {
    Switch ((Get-WmiObject -Class Win32_OperatingSystem).BuildNumber){
        '16299'{
            $OSBuild = '1709'
        }
        '17763'{
            $OSBuild = '1809'
        }
        '18363'{
            $OSBuild = '1909'
        }
    }
    return $OSBuild
}

function Invoke-DownloadDriverPackage {
    param (        
        [Parameter(HelpMessage="PackageID")]
        [string]$PackageID,
        [parameter(HelpMessage = "Path")]
		[string]$LocationPath
    )
    $TSEnvironment.Value("OSDDownloadDownloadPackages") = $PackageID
    $TSEnvironment.Value("OSDDownloadDestinationLocationType") = "Custom"
    $TSEnvironment.Value("OSDDownloadDestinationPath") = $LocationPath
    
    Start-Process -FilePath "OSDDownloadContent.exe" -NoNewWindow -PassThru -ErrorAction "Stop"    
}

function Invoke-CMResetDownloadContentVariables {
    #Write-CMLogEntry -Value " - Setting task sequence variable OSDDownloadDownloadPackages to a blank value" -Severity 1
    $TSEnvironment.Value("OSDDownloadDownloadPackages") = [System.String]::Empty
    
    #Write-CMLogEntry -Value " - Setting task sequence variable OSDDownloadDestinationLocationType to a blank value" -Severity 1
    $TSEnvironment.Value("OSDDownloadDestinationLocationType") = [System.String]::Empty
    
    #Write-CMLogEntry -Value " - Setting task sequence variable OSDDownloadDestinationVariable to a blank value" -Severity 1
    $TSEnvironment.Value("OSDDownloadDestinationVariable") = [System.String]::Empty
    
    #Write-CMLogEntry -Value " - Setting task sequence variable OSDDownloadDestinationPath to a blank value" -Severity 1
    $TSEnvironment.Value("OSDDownloadDestinationPath") = [System.String]::Empty
}

function Invoke-DriverInstallation {
    param (
        [parameter(HelpMessage = "123")]
        [string]$ContentLocation
    )
    $DriverPackageFile = Get-ChildItem -Path $ContentLocation
    try {
        $DriverMountFolder = Join-Path -Path $ContentLocation -ChildPath "Mount"
        IF (-not(Test-Path $DriverMountFolder)){
            New-Item -Path $DriverMountFolder -Force -ItemType Directory | Out-Null
        }
    }
    catch {
        
    }
    try {
        Mount-WindowsImage -Path $DriverMountFolder -ImagePath $DriverPackageFile.FullName -Index 1 -ErrorAction Stop
    }
    catch {
        
    }
    $ApplyDriverInvocation = Start-Process -FilePath "dism.exe" -ArgumentList "/Image:$($TSEnvironment.Value('OSDTargetSystemDrive'))\", "/Add-Driver /Driver:$($ContentLocation)", "/Recurse"
}
function Get-PackageBySKU {
    [CmdletBinding()]
    param (        
        [Parameter(ValueFromPipeline)]        
        $package,        
        [Parameter(ValueFromPipelineByPropertyName)]
        [String]
        $OSBuild, 
        [Parameter(ValueFromPipelineByPropertyName)]
        [String]
        $ComputerSKU
    )
    
    begin {
        
    }
    
    process {
        $temp = @{}
        $Temp = $package.Description | ConvertFrom-StringData
        if (($temp.$Build = $OSBuild) -and ($temp.SystemSKU = $ComputerSKU)){
            Write-Host "Found package matching condition: "$package.PackageID
            return $package
        }
    }
    
    end {
        
    }
}



$Uri = "https://"+$Endpoint+"/AdminService/wmi/SMS_Package"


$TSEnvironment = New-Object -ComObject "Microsoft.SMS.TSEnvironment" -ErrorAction Stop


if ($BypassCertCheck -eq $true){
    if (-not("dummy" -as [type])) {
        add-type -TypeDefinition @"
        using System;
        using System.Net;
        using System.Net.Security;
        using System.Security.Cryptography.X509Certificates;
        
        public static class Dummy {
            public static bool ReturnTrue(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors){
                return true;
            }
            public static RemoteCertificateValidationCallback GetDelegate() {
                return new RemoteCertificateValidationCallback(Dummy.ReturnTrue);
            }
        }
"@
}
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = [dummy]::GetDelegate()
}

$ComputerManufacturer = (Get-WmiObject -class Win32_ComputerSystem).Manufacturer

$OSBuild = Get-OSBuild

$ComputerSKU = Get-ComputerSKU


$Body = @{
    "`$filter" = "Manufacturer eq '"+$ComputerManufacturer+"'"
    "`$select" = "Name,Description,Manufacturer,Version,SourceDate,PackageID"
}

$Global:Credential = New-Object System.Management.Automation.PSCredential -ArgumentList $UserName, ($UsrPwd | ConvertTo-SecureString -Force -AsPlainText)
$Global:InvokeRestMethodCredentials = @{
    "Credential" = ($Global:Credential)
}


$Packages = Invoke-RestMethod -Method Get -Uri $Uri -UseDefaultCredentials -Body $Body @Global:InvokeRestMethodCredentials | Select-Object -ExpandProperty Value


$PackageToApply = $Packages | Get-PackageBySKU -OSBuild $OSBuild -ComputerSKU $ComputerSKU
$PackageToApply
Invoke-DownloadDriverPackage -PackageID $PackageToApply.PackageID -LocationPath "C:\Temp\"
Invoke-DriverInstallation -ContentLocation "C:\Temp"


}
end {
    Invoke-CMResetDownloadContentVariables
}