function MonthlyUpdatesNotification {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline)]
        $SUG,
        [Parameter(ValueFromPipelineByPropertyName)]
        $chat_id
    )
    
    begin {
        # Site configuration
        $PSD = "P07" # Site code 
        $ProviderMachineName = "S701CM-P07.sibur.local" # SMS Provider machine name

        # Customizations
        $initParams = @{}
        #$initParams.Add("Verbose", $true) # Uncomment this line to enable verbose logging
        #$initParams.Add("ErrorAction", "Stop") # Uncomment this line to stop the script on any errors

        # Do not change anything below this line

        # Import the ConfigurationManager.psd1 module 
        if((Get-Module ConfigurationManager) -eq $null) {
            Import-Module "$($ENV:SMS_ADMIN_UI_PATH)\..\ConfigurationManager.psd1" @initParams 
        }

        # Connect to the site's drive if it is not already present
        if((Get-PSDrive -Name $PSD -PSProvider CMSite -ErrorAction SilentlyContinue) -eq $null) {
            New-PSDrive -Name $PSD -PSProvider CMSite -Root $ProviderMachineName @initParams
        }
        # Set the current location to be the site code.
        Set-Location "$($PSD):\" @initParams

        #Токен бота
        $bot_token = "742685649:AAGqUKWhitvt9hxnx5OH7VODYTLlISkpn9c"
        #ID чата для целей тестирования
        #$chat_id = "-368164031"
        $KeyFile = "\\s701fs-fs01\gpo$\UserAccounts\AES.key"
        $SCOMWebAccessUser = "Sibur\A701-SCOMWebUser"
        $EncryptedPasswordFile = "\\s701fs-fs01\gpo$\UserAccounts\Telegram.securestring"
        $key = Get-Content $KeyFile
        $SecureStringPassword = Get-Content -Path $EncryptedPasswordFile | ConvertTo-SecureString -Key $key
        $proxy = "http://s701ss-squid01.sibur.local:8080"
        $WebCredentials = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $SCOMWebAccessUser,$SecureStringPassword
    }
    
    process {
        $updateInfo = Get-CMSoftwareUpdateGroup -Name $SUG;
        $Updates = Get-CMSoftwareUpdate -UpdateGroupID $updateInfo.CI_ID -fast | where-object {$_.DateCreated -gt (Get-Date).AddMonths(-1)} | Sort-Object datecreated | Select-Object ArticleID , datecreated , LocalizedInformativeURL , LocalizedDisplayName
        $message = "*"+$($SUG -replace ".{9}$").Split(":")[1].Trim()+"*`n"
        $message = $message.Replace("-","\-") 
        ForEach ($update in $Updates){    
            $update.LocalizedDisplayName = $update.LocalizedDisplayName.Replace(".","\.")    
            $update.LocalizedDisplayName = $update.LocalizedDisplayName.Replace("-","\-")    
            $update.LocalizedDisplayName = $update.LocalizedDisplayName.Replace("(","\(")    
            $update.LocalizedDisplayName = $update.LocalizedDisplayName.Replace(")","\)")    
            $message += "*[KB"+$update.ArticleID+"]("+$update.LocalizedInformativeURL+")* "+$update.LocalizedDisplayName+"`n"
        }
    }
    
    end {
        $uri = "https://api.telegram.org/bot$bot_token/sendMessage"
        $InputObject = @{chat_id=$chat_id; text=$message; "parse_mode" = "markdownV2"; "disable_web_page_preview" = "True"}
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Method Post -Uri $uri -ContentType "application/json;charset=utf-8" -Body (ConvertTo-Json -Compress -InputObject $InputObject) -Proxy $proxy -ProxyCredential $WebCredentials
    }
}