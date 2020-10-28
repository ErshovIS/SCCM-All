function MonthlyUpdatesNotification {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline)]
        $SUGName,
        [Parameter(ValueFromPipelineByPropertyName)]
        $SUGCI_ID,
        [Parameter(ValueFromPipelineByPropertyName)]
        $chat_id
    )
    
    begin {        
        #Токен бота
        $bot_token = "742685649:AAGqUKWhitvt9hxnx5OH7VODYTLlISkpn9c"
        #ID чата для целей тестирования
        #$chat_id = "-368164031"
        $KeyFile = "D:\!Scripts\AES.key"
        $SCOMWebAccessUser = "Sibur\A701-SCOMWebUser"
        $EncryptedPasswordFile = "D:\!Scripts\Telegram.securestring"
        $key = Get-Content $KeyFile
        $SecureStringPassword = Get-Content -Path $EncryptedPasswordFile | ConvertTo-SecureString -Key $key
        $proxy = "http://s701ss-squid01.sibur.local:8080"
        $WebCredentials = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $SCOMWebAccessUser,$SecureStringPassword
    }
    
    process {
        $message = ""
        #$updateInfo = Get-CMSoftwareUpdateGroup -Name $SUG;
        $Updates = Get-CMSoftwareUpdate -UpdateGroupID $SUGCI_ID -fast | where-object {$_.DateCreated -gt (Get-Date).AddMonths(-1)} | Sort-Object datecreated | Select-Object ArticleID , LocalizedInformativeURL , LocalizedDisplayName
        $message = "*"+$($SUGName -replace ".{9}$").Split(":")[1].Trim()+"*`n"
        $message = $message.Replace("-","\-") 
        ForEach  ($update in $Updates){    
            $update.LocalizedDisplayName = $update.LocalizedDisplayName.Replace(".","\.")    
            $update.LocalizedDisplayName = $update.LocalizedDisplayName.Replace("-","\-")    
            $update.LocalizedDisplayName = $update.LocalizedDisplayName.Replace("(","\(")    
            $update.LocalizedDisplayName = $update.LocalizedDisplayName.Replace(")","\)")    
            $message += "*[KB"+$update.ArticleID+"]("+$update.LocalizedInformativeURL+")* "+$update.LocalizedDisplayName+"`n"
        }        
        $uri = "https://api.telegram.org/bot$bot_token/sendMessage"
        $InputObject = @{chat_id=$chat_id; text=$message; "parse_mode" = "markdownV2"; "disable_web_page_preview" = "True";}
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Method Post -Uri $uri -ContentType "application/json;charset=utf-8" -Body (ConvertTo-Json -Compress -InputObject $InputObject) -Proxy $proxy -ProxyCredential $WebCredentials
    }
    
    end {
        
    }
}