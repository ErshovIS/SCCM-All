function Invoke-CMPivotReportGeneration {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, HelpMessage = "SSRS FQDN")]
        [ValidateNotNullOrEmpty()]
        [string]$SSRSURL,
        [Parameter(Mandatory = $true, HelpMessage = "Path to the report")]
        [ValidateNotNullOrEmpty()]
        [string]$ReportPath,
        [Parameter(Mandatory = $true, HelpMessage = "CMPivot Operation ID")]
        [ValidateNotNullOrEmpty()]
        [string]$OperationID
    )
    
    begin {
        $baseFolder = "C:\TEMP\"
        $deviceInfo = "<DeviceInfo><NoHeader>True</NoHeader></DeviceInfo>"
        $extension = ""
        $mimeType = ""
        $encoding = ""
        $warnings = $null
        $streamIDs = $null
    }
    
    process {
        $reportServerURI = "http://$($SSRSURL)/ReportServer/ReportExecution2005.asmx?WSDL"
        $RS = New-WebServiceProxy -Class 'RS' -NameSpace 'RS' -Uri $reportServerURI -UseDefaultCredential
        $RS.Url = $reportServerURI
        $Report = $RS.GetType().GetMethod("LoadReport").Invoke($RS, @($ReportPath, $null))
        $parameters = @()
        $parameters += New-Object RS.ParameterValue
        $parameters[0].Name  = "OperationID"
        $parameters[0].Value = $OperationID
        $RS.SetExecutionParameters($parameters, "en-us") > $null

        # Render the report to a byte array.  The first argument is the report format.
        # The formats are: PDF, XML, CSV, WORD (.doc), EXCEL (.xls), IMAGE (.tif), MHTML (.mhtml).
        $RenderOutput = $RS.Render('EXCEL',
            $deviceInfo,
            [ref] $extension,
            [ref] $mimeType,
            [ref] $encoding,
            [ref] $warnings,
            [ref] $streamIDs
        )
    }
    
    end {
        # Convert array bytes to file and write
        $FileName = $baseFolder + "CMPivot_Example_01.xls"
        $Stream = New-Object System.IO.FileStream($FileName), Create, Write
        $Stream.Write($RenderOutput, 0, $RenderOutput.Length)
        $Stream.Close()
        explorer $baseFolder
    }
}
function Get-CMPivotInfo {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, HelpMessage = "Specify AdminService FQDN")]
        [ValidateNotNullOrEmpty()]
        [string]$SiteServer,
        [Parameter(Mandatory = $true, HelpMessage = "Provide collection ID", ValueFromPipeline)]
        [string]$Collection,
        [Parameter(Mandatory = $true, HelpMessage = "Specify SSRS FQDN")]
        [ValidateNotNullOrEmpty()]
        [string]$SSRSURL,
        [Parameter(Mandatory = $true, HelpMessage = "Specify path to SSRS report, e.g. /ConfigMgr_01/CMPivot/CMPivot_Example_01")]
        [ValidateNotNullOrEmpty()]
        [string]$ReportPath
    )
    
    begin {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        
    }
    
    process {
        $BaseUri = "https://$($SiteServer)/AdminService/v1.0/"
        $Query = "ComputerSystem | project  Name, Model, Device | order by Name | join (Bios | project SerialNumber)"
        $Params = @{
            Method = "Post"
            Uri = "$($BaseUri)/Collections('$Collection')/AdminService.RunCmpivot"
            Body = @{"InputQuery"="$($Query)"} | ConvertTo-Json
            ContentType = "application/json"
            UseDefaultCredentials = $true
        }
        $Results = Invoke-RestMethod @Params  
        $OperationID = $Results.OperationId  
        $uri = '{0}SMS_CMPivotStatus?$filter=ClientOperationId eq {1}' -f $BaseUri, $OperationID

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
        do {
            Start-Sleep -Seconds 15
            $Request = Invoke-RestMethod -Uri $uri -UseDefaultCredentials -Method Get | Select-Object -ExpandProperty Value
        } while ($Request.Count -eq '0')
    }
    
    end {
        Invoke-CMPivotReportGeneration -SSRSURL $SSRSURL -ReportPath $ReportPath -OperationID $Results.OperationId
    }
}

$SiteCode = "P01" # Site code 
$ProviderMachineName = "S001ITA-0030.msft.local"
$initParams = @{}
if((Get-Module ConfigurationManager) -eq $null) {
    Import-Module "$($ENV:SMS_ADMIN_UI_PATH)\..\ConfigurationManager.psd1" @initParams 
}
if((Get-PSDrive -Name $SiteCode -PSProvider CMSite -ErrorAction SilentlyContinue) -eq $null) {
    New-PSDrive -Name $SiteCode -PSProvider CMSite -Root $ProviderMachineName @initParams
}
Set-Location "$($SiteCode):\" @initParams


(Get-CMCollection -name "All Systems").collectionid | Get-CMPivotInfo -SiteServer $ProviderMachineName -SSRSURL "S001ITA-0060.msft.local" -ReportPath "/ConfigMgr_P01/CMPivot/CMPivot_Example_01"