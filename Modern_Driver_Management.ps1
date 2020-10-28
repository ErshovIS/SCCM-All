<#
    .SYNOPSIS
    Script for modern driver management solution

    .NOTES
    Created on: 29.10.2020
    Created by: ershov.is@gmail.com

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
    
#>

[CmdletBinding()]
param (
    [parameter(Mandatory=$true,HelpMessage = "Specify the internal fully qualified domain name of the server hosting the AdminService, e.g. CM01.domain.local.")]
	[ValidateNotNullOrEmpty()]
	[string]$Endpoint,

    [Parameter(Mandatory=$true,HelpMessage = "AdminService UserName")]
    [ValidateNotNullOrEmpty()]
    [string]$UserName,

    [Parameter(Mandatory=$true,HelpMessage = "AdminService User Password")]
    [ValidateNotNullOrEmpty()]
    [string]$UsrPwd,
    
    [Parameter(Mandatory=$true,HelpMessage = "Specify if bypass self-sign AdminService certificate is needed")]
    [ValidateNotNullOrEmpty()]
    [bool]$BypassCertCheck
)

begin{
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
    $Global:Credential = New-Object System.Management.Automation.PSCredential -ArgumentList $UserName, ($UsrPwd | ConvertTo-SecureString -Force -AsPlainText)
    $Global:InvokeRestMethodCredentials = @{
        "Credential" = ($Global:Credential)
        }

    $LogDirectory = $Script:TSEnvironment.Value("_SMSTSLogPath")
    
}

Process{
    function Write-CMLog {
    Param (
		[Parameter(Mandatory = $true, HelpMessage = "Message to write in Log file")]
        [ValidateNotNullOrEmpty()]
		[string]$Message,
 
		[Parameter(Mandatory = $true, HelpMessage = "Entry severity. 1 - Info, 2 - Warning, 3 - Error")]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("1", "2", "3")]
		[string]$Severity,
 
		[Parameter(Mandatory = $false, HelpMessage = "Log file name (DriverManagement.log default")]
        [ValidateNotNullOrEmpty()]
		[string]$LogFileName = "DriverManagement.log"
    )
 
	$EntryTime = Get-Date -Format "HH:mm:ss.fff"
	$EntryDate = Get-Date -Format "dd-MM-yyyy"
    $Context = $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
 
    $LogFilePath = Join-Path $LogDirectory -ChildPath $LogFileName
     
	$LogMessage = "<![LOG[$($Message)]LOG]!><time=""$($Time)"" date=""$($Date)"" component=""DriverManagement"" context=""$($Context)"" type=""$($Severity)"" thread=""$($PID)"" file="""">"
	Out-File -InputObject $LogMessage -Append -NoClobber -Encoding UTF8 -FilePath $LogFilePath
}


    function Get-ComputerSKU {
        Write-CMLog -Message "Detecting Computer SKU" -Severity 1
        $CurrentComputer = Get-WmiObject -class Win32_ComputerSystem | Select-Object Manufacturer, Model, SystemSKUNumber
        switch ($CurrentComputer.Manufacturer){
            'HP'{
                $ComputerSKU = $CurrentComputer.SystemSKUNumber.SubString(0,4)
            }
            'Lenovo'{
                $ComputerSKU = $CurrentComputer.Model.SubString(0,4)
            }
        }
        Write-CMLog -Message "Detected computer SKU as: $($ComputerSKU)" -Severity 1
        return $ComputerSKU
    }

    function Get-OSBuild {
        Write-CMLog -Message "Detecting computer OS Build" -Severity 1
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
        Write-CMLog -Message "Detected OS Build AS: $($OSBuild)" -Severity 1
        return $OSBuild
    }

    function Invoke-DownloadDriverPackage {
        param (        
            [Parameter(Mandatory = $true, HelpMessage = "Specify PackageID to Download")]
            [string]$PackageID,
            [parameter(Mandatory = $true, HelpMessage = "Specify Path for Package")]
		    [string]$LocationPath
        )
        Write-CMLog -Message "PackageID $($PackageID) will be download in: $($LocationPath)" -Severity 1

        $TSEnvironment.Value("OSDDownloadDownloadPackages") = $PackageID
        $TSEnvironment.Value("OSDDownloadDestinationLocationType") = "Custom"
        $TSEnvironment.Value("OSDDownloadDestinationPath") = $LocationPath
    
        Start-Process -FilePath "OSDDownloadContent.exe" -NoNewWindow -PassThru -ErrorAction "Stop"
        Write-CMLog -Message "PackageID $($PackageID) was successful downloaded to: $($LocationPath)" -Severity 1
    }

    function Invoke-CMResetDownloadContentVariables {
        Write-CMLog -Message " - Setting task sequence variable OSDDownloadDownloadPackages to a blank value" -Severity 1
        $TSEnvironment.Value("OSDDownloadDownloadPackages") = [System.String]::Empty
    
        Write-CMLog -Message " - Setting task sequence variable OSDDownloadDestinationLocationType to a blank value" -Severity 1
        $TSEnvironment.Value("OSDDownloadDestinationLocationType") = [System.String]::Empty
    
        Write-CMLog -Message " - Setting task sequence variable OSDDownloadDestinationVariable to a blank value" -Severity 1
        $TSEnvironment.Value("OSDDownloadDestinationVariable") = [System.String]::Empty
    
        Write-CMLog -Message " - Setting task sequence variable OSDDownloadDestinationPath to a blank value" -Severity 1
        $TSEnvironment.Value("OSDDownloadDestinationPath") = [System.String]::Empty
    }

    function Invoke-DriverInstallation {
        param (
            [parameter(Mandatory = $true, HelpMessage = "Specify driver content location")]
            [string]$ContentLocation
        )
        $DriverPackageFile = Get-ChildItem -Path $ContentLocation
        try {
            $DriverMountFolder = Join-Path -Path $ContentLocation -ChildPath "Mount"
            Write-CMLog -Message "Driver installation folder is: $($DriverMountFolder)" -Severity 1
            IF (-not(Test-Path $DriverMountFolder)){
                New-Item -Path $DriverMountFolder -Force -ItemType Directory | Out-Null
            }
        }
        catch {
        
        }
        try {
            Write-CMLog -Message "Mounting driver package" -Severity 1
            Mount-WindowsImage -Path $DriverMountFolder -ImagePath $DriverPackageFile.FullName -Index 1 -ErrorAction Stop
        }
        catch {
        
        }
        Write-CMLog -Message "Applying drivers from $($ContentLocation) to $($TSEnvironment.Value('OSDTargetSystemDrive'))"
        $ApplyDriverInvocation = Start-Process -FilePath "dism.exe" -ArgumentList "/Image:$($TSEnvironment.Value('OSDTargetSystemDrive'))\", "/Add-Driver /Driver:$($ContentLocation)", "/Recurse"
    }

    function Get-PackageBySKU {
        [CmdletBinding()]
        param (        
            [Parameter(ValueFromPipeline, Mandatory = $true, HelpMessage = "")]        
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
                Write-CMLog -Message "Found package matching condition: $($package.PackageID)" -Severity 1
                return $package
            }
        }
    
        end {
        
        }
    }


    $ComputerManufacturer = (Get-WmiObject -class Win32_ComputerSystem).Manufacturer

    $OSBuild = Get-OSBuild

    $ComputerSKU = Get-ComputerSKU


    $Body = @{
        "`$filter" = "Manufacturer eq '"+$ComputerManufacturer+"'"
        "`$select" = "Name,Description,Manufacturer,Version,SourceDate,PackageID"
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
