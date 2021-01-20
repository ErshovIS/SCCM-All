<#
    .SYNOPSIS
        Script for modern driver management. Script detects, downloads and installs WIM-driver package during OSD
    
    .DESCRIPTION
        Script uses Task Sequence variables UserName and UserPassword to access AdminService Endpoint during OSD. While acting in Debug mode UserName and password must be privided as parameters.
                
    .PARAMETER DebugMode
        Sets script to run in Debug mode to verify
    .PARAMETER BareMetal
    
    .PARAMETER LogPath
    .PARAMETER Endpoint
        AdminService server FQDN, e.g. SRV.domain.local
    .PARAMETER UserName
        User account with at least read access to AdminService
    .PARAMETER UserPassword
        UserPassword to access AdminService endpoint
    .PARAMETER BypassCertCheck
        This parameter helps to bypass self-sign or not trusted certificate check while accessing AdminService
    .PARAMETER OSBuild
    .EXAMPLE
        Script detects driver package for operating system build 1809 and bypasses AdminService certificate check during OSD: 
        .\modern_driver_management_v2.ps1 -BareMetal -Endpoint "SRV.domain.local" -BypassCertCheck $true -OSBuild 1809
        Script searches AdminService for OS build 1709 driver package using specified UserName and Password and stores output log file in C:\Temp:
        .\modern_driver_management_v2.ps1 -Debug -Endpoint "SRV.domain.local" -UserName "user" -UserPassword "StrongUserPassword" -BypassCertCheck $true -LogPath "C:\Temp" -OSBuild 1709
    .NOTES
        Created by: @ErshovIS (https://github.com/ErshovIS)
        Created on: 2020-11-02
        
        1.0.0 - 2020-11-02: Script created
        1.0.1 - 2020-11-05: Debug mode behaviour changed. Script stores DriverManagement.log in $LogLocation path during Debug Mode. Network logging excluded for BareMetal mode during OSD.
                    If multiple packages matching condition found the most recent is selected.
        1.0.2 - 2020-11-10: Minor bug fixed. Incorrect condition while determining most matching package fixed.
        1.0.3 - 2021-01-20: Hewlett-Packard Mnaufacturer detection fixed. Changed default download location based on _OSDDetectedWinDrive variable
#>
[CmdletBinding()]
param (
    # Parameter help description
    [Parameter(Mandatory = $true, ParameterSetName = "Debug", HelpMessage = "Start script in Debug Mode")]
    [Switch]$DebugMode,

    # Parameter help description
    [Parameter(Mandatory = $true, ParameterSetName = "BareMetal", HelpMessage = "Start script in Normal Mode")]
    [switch]$BareMetal,
    
    # Parameter help description
    [Parameter(Mandatory = $true, ParameterSetName = "Debug", HelpMessage = "Enter Location to store log files after script compleats")]
    [ValidateNotNullOrEmpty()]
    [String]$LogPath,

    # Parameter help description
    [Parameter(Mandatory = $true, ParameterSetName = "Debug", HelpMessage = "Specify AdminService server FQDN, e.g. SRV.domain.local ")]
    [Parameter(Mandatory = $true, ParameterSetName = "BareMetal")]
    [ValidateNotNullOrEmpty()]
    [string]$Endpoint,

    # Parameter help description
    [Parameter(Mandatory = $true, ParameterSetName = "Debug", HelpMessage = "Specify UserName to access AdminService")]    
    [ValidateNotNullOrEmpty()]
    [string]$UserName,

    # Parameter help description
    [Parameter(Mandatory = $true, ParameterSetName = "Debug", HelpMessage = "Specify user password to access AdminService")]
    [ValidateNotNullOrEmpty()]
    [string]$UserPassword,

    # Parameter help description
    [Parameter(Mandatory = $true, ParameterSetName = "Debug", HelpMessage = "Specify if bypass self-sign AdminService certificate is needed")]
    [Parameter(Mandatory = $true, ParameterSetName = "BareMetal")]
    [ValidateNotNullOrEmpty()]
    [string]$BypassCertCheck,

    # Parameter help description
    [Parameter(Mandatory = $true, ParameterSetName = "BareMetal", HelpMessage = "Specify Target OS Build, e.g. 1909")]
    [Parameter(Mandatory = $true, ParameterSetName = "Debug")]
    [ValidateNotNullOrEmpty()]
    [string]$OSBuild
)
begin {

    # Variable initialization
    if ($PSCmdlet.ParameterSetName -eq "BareMetal"){
        $TSEnvironment = New-Object -ComObject "Microsoft.SMS.TSEnvironment" -ErrorAction Stop
        $LogDirectory = $Script:TSEnvironment.Value("_SMSTSLogPath")
    }
    else {
        $LogDirectory = $LogPath
    }    
    $ContentLocation = Join-Path $TSEnvironment.Value("_OSDDetectedWinDrive") -ChildPath "Temp"
    $URI = "https://$($Endpoint)/AdminService/wmi/SMS_Package"

    if ($BypassCertCheck-eq $true){
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

    if ($PSCmdlet.ParameterSetName -eq "Debug"){
        $Script:Credentials = New-Object System.Management.Automation.PSCredential -ArgumentList $UserName, ($UserPassword | ConvertTo-SecureString -Force -AsPlainText)        
    }
    else {
        $Script:Credentials = New-Object System.Management.Automation.PSCredential -ArgumentList $TSEnvironment.Value("UserName"), ($TSEnvironment.Value("UserPassword") | ConvertTo-SecureString -Force -AsPlainText)
    }
    
}
process {
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
        if (-not(Test-Path -Path 'variable:global:TimezoneBias')) {
			[string]$global:TimezoneBias = [System.TimeZoneInfo]::Local.GetUtcOffset((Get-Date)).TotalMinutes
			if ($TimezoneBias -match "^-") {
				$TimezoneBias = $TimezoneBias.Replace('-', '+')
			}
			else {
				$TimezoneBias = '-' + $TimezoneBias
			}
		}
		$EntryTime = -join @((Get-Date -Format "HH:mm:ss.fff"), $TimezoneBias)
        $EntryDate = Get-Date -Format "MM-dd-yyyy"
        $Context = $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
     
        $LogFilePath = Join-Path $LogDirectory -ChildPath $LogFileName
         
        $LogMessage = "<![LOG[$($Message)]LOG]!><time=""$($EntryTime)"" date=""$($EntryDate)"" component=""DriverManagement"" context=""$($Context)"" type=""$($Severity)"" thread=""$($PID)"" file="""">"        
        Out-File -InputObject $LogMessage -Append -NoClobber -Encoding UTF8 -FilePath $LogFilePath
    }

    function Get-ComputerManufacturer {
        Write-CMLog -Message "Detecting Computer Manufacturer" -Severity 1
        $Manufacturer = (Get-WmiObject -class Win32_ComputerSystem).Manufacturer
        Write-CMLog -Message "Manufacturer detected as $($Manufacturer)" -Severity 1
        return $Manufacturer
    }

    function Get-ComputerSKU {
        param (
            # Computer Manufacturer
            [Parameter(Mandatory = $true, HelpMessage = "Specufy Computer Manufacturer, e.g. Lenovo, HP")]
            [ValidateNotNullOrEmpty()]
            [string]$Manufacturer
        )
        Write-CMLog -Message "Detecting Computer SKU" -Severity 1
        switch ($Manufacturer) {
            {($_ -eq 'HP') -or ($_ -like 'Hewlett*')}{
                $ComputerSKU = (Get-WmiObject -class Win32_ComputerSystem | Select-Object Manufacturer, Model, SystemSKUNumber).SystemSKUNumber.SubString(0,4)
            }
            'Lenovo' {
                $ComputerSKU = (Get-WmiObject -class Win32_ComputerSystem | Select-Object Manufacturer, Model, SystemSKUNumber).Model.SubString(0,4)
            }
            {($_ -like 'VMWare*')} {
                $ComputerSKU = 'VMWR'
            }
        }
        Write-CMLog -Message "Detected computer SKU as: $($ComputerSKU)" -Severity 1
        return $ComputerSKU
    }    

    function Get-PackageIDToInstall {
        [CmdletBinding()]
        param (        
            [Parameter(Mandatory = $true, HelpMessage = "Specify Package", ValueFromPipeline)]       
            $package,       

            [Parameter(Mandatory = $true, HelpMessage = "Specify Operating System Build", ValueFromPipelineByPropertyName)]
            [String]$OSBuild, 

            [Parameter(Mandatory = $true, HelpMessage = "Specify Computer SKU", ValueFromPipelineByPropertyName)]
            [String]$ComputerSKU
        )
        begin{            
            $allMatchingPackages = @()
        }
        process {
            $temp = @{} 
            $Temp = $package.Description | ConvertFrom-StringData  
            if (($temp.Build -eq $OSBuild) -and ($temp.SystemSKU -eq $ComputerSKU)){
                Write-CMLog -Message "Found package matching condition: $($package.PackageID)" -Severity 1                
                $allMatchingPackages += $package
            }            
        }
        end {
            Write-CMLog -Message "Found total $(($allMatchingPackages | Measure-Object).Count) matching packages for OS $($OSBuild) and SKU $($ComputerSKU)" -Severity 1
            if (($allMatchingPackages | Measure-Object).Count -gt 1){
                Write-CMLog -Message "Detecting most recent driver package..." -Severity 1                
                $result = $allMatchingPackages | Sort-Object SourceDate | Select-Object PackageID -Last 1
            }
            else {
                $result = $allMatchingPackages[0]
            }
            Write-CMLog -Message "The most matching package is $($result.PackageID)" -Severity 1      
            return $result.PackageID
        }
    }
    function Get-PackageToApply {
        param (
            # Computer Manufacturer
            [Parameter(Mandatory = $true, HelpMessage = "Specify Computer Manufacturer, e.g. Lenovo, HP, VMWare, Inc.")]
            [ValidateNotNullOrEmpty()]
            [string]$Manufacturer,

            # OS Build to apply driver package
            [Parameter(Mandatory = $true, HelpMessage = "Specify Operating System Build")]
            [ValidateNotNullOrEmpty()]
            [string]$OSBuild,

            # Computer SKU for 
            [Parameter(Mandatory = $true, HelpMessage = "Specify SKU")]
            [ValidateNotNullOrEmpty()]
            [string]$ComputerSKU
        )

        Write-CMLog -Message "Performing PackageID detection" -Severity 1
        
        Write-CMLog -Message "Creating AdminService filter" -Severity 1
        $Body = @{
            "`$filter" = "Manufacturer eq '"+$Manufacturer+"'"
            "`$select" = "Name,Description,Manufacturer,Version,SourceDate,PackageID"
        }
        
        Write-CMLog -Message "Detecting Packages for $($Manufacturer)" -Severity 1
        $Packages = Invoke-RestMethod -Method Get -Uri $URI -Body $Body -Credential $Script:Credentials | Select-Object -ExpandProperty Value
        Write-CMLog -Message "Found total $(($Packages | Measure-Object).Count) package(s) for Manufacturer $($Manufacturer)" -Severity 1
        $PackageID = $Packages | Get-PackageIDToInstall -ComputerSKU $ComputerSKU -OSBuild $OSBuild

        return $PackageID
    }

    function Invoke-DriverInstallation {
        param (
            # Driver PackageID for download and install
            [Parameter(Mandatory = $true, HelpMessage = "Specify PackageID for installation")]
            [ValidateNotNullOrEmpty()]
            [string]$PackageID,

            # Local content folder
            [Parameter(Mandatory = $true, HelpMessage = "Specify Content Location")]
            [ValidateNotNullOrEmpty()]
            [string]$ContentLocation
        )
        Write-CMLog -Message "PackageID $($PackageID) will be download in: $($ContentLocation). It will take some time." -Severity 1
        
        $TSEnvironment.Value("OSDDownloadDownloadPackages") = $PackageID
        $TSEnvironment.Value("OSDDownloadDestinationLocationType") = "Custom"
        $TSEnvironment.Value("OSDDownloadDestinationPath") = $ContentLocation
        try {
            if (-not(Test-Path $ContentLocation)){
                New-Item -Path $ContentLocation -ItemType Directory -Force | Out-Null
            }
        }
        catch [System.Exception] {
            Write-CMLog -Message "Failed to create $($ContentLocation) with error $($_.Exception.Message)" -Severity 3
        }

        try{
            $DownloadProcess = Start-Process -FilePath "OSDDownloadContent.exe" -NoNewWindow -PassThru -ErrorAction "Stop"
            $DownloadProcess.WaitForExit()
            Write-CMLog -Message "PackageID $($PackageID) was successful downloaded to: $($ContentLocation)" -Severity 1
        }
        catch [System.Exception]{
            Write-CMLog -Message "Failed to download PackageID $($PackageID) with exception $($_.Exception.Message)" -Severity 3
        }   
        # Get driver compressed file
        $DriverPackageFile = Get-ChildItem -Path $ContentLocation -Filter "*.wim" -Recurse
        try {
            $DriverMountFolder = Join-Path -Path $ContentLocation -ChildPath "Mount"
            Write-CMLog -Message "Driver installation folder is: $($DriverMountFolder)" -Severity 1
            IF (-not(Test-Path $DriverMountFolder)){
                New-Item -Path $DriverMountFolder -Force -ItemType Directory | Out-Null
            }
        }
        catch [System.Exception]{
            Write-CMLog -Message "Failed to create mount folder in $($ContentLocation) with exception $($_.Exception.Message)" -Severity 3
        }
        try {
            Write-CMLog -Message "Mounting driver package $($DriverPackageFile.Name) to $($DriverMountFolder)" -Severity 1
            Mount-WindowsImage -Path $DriverMountFolder -ImagePath $DriverPackageFile.FullName -Index 1 -ErrorAction Stop
        }
        catch [System.Exception]{
            Write-CMLog -Message "Failed to Mount WIM-file with exception $($_.Exception.Message)" -Severity 3
        }

        try{
            Write-CMLog -Message "Applying drivers from $($DriverMountFolder) to $($TSEnvironment.Value('OSDTargetSystemDrive'))" -Severity 1
            Write-CMLog -Message "DISM parameters: /Image:$($TSEnvironment.Value('OSDTargetSystemDrive'))\ /Add-Driver /Driver:$($DriverMountFolder) /Recurse" -Severity 1
            $ApplyDrivers = Start-Process -FilePath "dism.exe" -ArgumentList "/Image:$($TSEnvironment.Value('OSDTargetSystemDrive'))\ /Add-Driver /Driver:$($DriverMountFolder) /Recurse" -NoNewWindow -PassThru -ErrorAction "Stop"
            $Handle = $ApplyDrivers.Handle
            $ApplyDrivers.WaitForExit()
        }
        catch [System.Exception]{
            Write-CMLog -Message "Failed to add drivers using DISM. Exception $($_.Exception.Message)" -Severity 3
        }
        # Performing cleanup
        # Dismounting WIM-file
        try {
            Write-CMLog -Message "Dismounting image from $($DriverMountFlder)" -Severity 1
            Dismount-WindowsImage -Path $DriverMountFolder -Discard -ErrorAction "Stop"
        }
        catch [System.Exception] {
            Write-CMLog -Message "Failed to dismount image from $($DriverMountFolder) with error $($_.Exception.Message)" -Severity 3
        }
        # Removing package download folder
        # Remove-Item -LiteralPath $ContentLocation -Force -Recurse
    }

    function Invoke-CMResetVariables {        
        Write-CMLog -Message "Reseting OSDDownloadDownloadPackages variable" -Severity 1
        $TSEnvironment.Value("OSDDownloadDownloadPackages") = [System.String]::Empty
    
        Write-CMLog -Message "Reseting OSDDownloadDestinationLocationType variable" -Severity 1
        $TSEnvironment.Value("OSDDownloadDestinationLocationType") = [System.String]::Empty
    
        Write-CMLog -Message "Reseting OSDDownloadDestinationPath variable" -Severity 1
        $TSEnvironment.Value("OSDDownloadDestinationPath") = [System.String]::Empty
    }
    
    $Manufacturer = Get-ComputerManufacturer
    $SKU = Get-ComputerSKU -Manufacturer $Manufacturer
    $PackageID = Get-PackageToApply -Manufacturer $Manufacturer -OSBuild $OSBuild -ComputerSKU $SKU
    IF ($PSCmdlet.ParameterSetName -eq "BareMetal"){
        Invoke-DriverInstallation -ContentLocation $ContentLocation -PackageID $PackageID
    }
}
end {    
    IF ($PSCmdLet.ParameterSetName -eq "BareMetal") {		
        Invoke-CMResetVariables
    }
}
