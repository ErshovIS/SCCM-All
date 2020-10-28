# Site configuration
Import-Module D:\!scripts\fMonthlyUpdatesNotification.psm1
$PSD = "P07" # Site code 
$ProviderMachineName = "S701CM-P07.sibur.local" # SMS Provider machine name

$initParams = @{}

if((Get-Module ConfigurationManager) -eq $null) {
    Import-Module "$($ENV:SMS_ADMIN_UI_PATH)\..\ConfigurationManager.psd1" @initParams 
}

if((Get-PSDrive -Name $PSD -PSProvider CMSite -ErrorAction SilentlyContinue) -eq $null) {
    New-PSDrive -Name $PSD -PSProvider CMSite -Root $ProviderMachineName @initParams
}

Set-Location "$($PSD):\" @initParams


#Returns a date object of the second tuesday of the month for given month and year
 function SecondTuesday ([int]$Month, [int]$Year) {
     [int]$Day = 1
     while((Get-Date -Day $Day -Hour 0 -Millisecond 0 -Minute 0 -Month $Month -Year $Year -Second 0).DayOfWeek -ne "Tuesday") {
         $day++
     }
     $day += 7
     return (Get-Date -Day $Day -Hour 0 -Millisecond 0 -Minute 0 -Month $Month -Year $Year -Second 0)
}

$Date = Get-Date -DisplayHint Date
$TodayMonth = $Date.Month
$TodayYear = $Date.Year
$SecTues = SecondTuesday $TodayMonth $TodayYear


# Поиск и замена окон обслуживания для компьютеров второй тестовой группы. Начало окна обслуживания - через 5 дней после Patch Tuesday

# Фильтр для поиска коллекций второй тестовой группы
$TestGroup2BaseCollection = 'P07000E5'
# $filter = $PSD + " - Updates:*TestGroup_2*"
# Сдвиг в днях относительно Patch Tuesday для начала окна обслуживания
$StartDate = $SecTues.AddDays(5)
# Время начала окна обслуживания
$StartTime = $StartDate.AddHours(1)
# Длительность окна обслуживания
$EndTime = $StartTime.AddHours(4)
# Создание расписания окна обслуживания по параметрам
$Schedule = NEW-CMSchedule -Start $StartTime -End $EndTime -NonRecurring

# Коллекции второй пользовательской тестовой группы
# Удаление существующих окон обслуживания
foreach ($mw in Get-CMMaintenanceWindow -CollectionId $TestGroup2BaseCollection){
    Remove-CMMaintenanceWindow -CollectionId $TestGroup2BaseCollection -MaintenanceWindowName $mw.Name -Force
}
# Формирование нового имени для окна обслуживания
$newMWName = $PSD + " - MW - TestGroup_2"

# Создание нового окна обслуживания
New-CMMaintenanceWindow -CollectionID $TestGroup2BaseCollection -ApplyToSoftwareUpdateOnly -Name $newMWName -Schedule $Schedule

# Поиск и замена окон обслуживания для компьютеров продуктовых коллекций. Начало окна обслуживания - через 19 дней после Patch Tuesday

# Фильтр для поиска коллекций второй тестовой группы
$ProductionBaseCollection = 'P07000E6'
#$filter = $PSD + " - Updates:*All"
# Сдвиг в днях относительно Patch Tuesday для начала окна обслуживания
$StartDate = $SecTues.AddDays(19)
# Время начала окна обслуживания
$StartTime = $StartDate.AddHours(1)
# Длительность окна обслуживания
$EndTime = $StartTime.AddHours(4)
# Создание расписания окна обслуживания по параметрам
$Schedule = NEW-CMSchedule -Start $StartTime -End $EndTime -NonRecurring

foreach ($mw in Get-CMMaintenanceWindow -CollectionId $ProductionBaseCollection){
    Remove-CMMaintenanceWindow -CollectionId $ProductionBaseCollection -MaintenanceWindowName $mw.Name -Force
}

# Формирование нового имени для окна обслуживания
$newMWName = $PSD + " - MW - Production"

# Создание нового окна обслуживания
New-CMMaintenanceWindow -CollectionID $ProductionBaseCollection -ApplyToSoftwareUpdateOnly -Name $newMWName -Schedule $Schedule

# Корректировка SUG с учётом предыдущих месяцев
$AllSUG=Get-CMSoftwareUpdateGroup | Select-Object SourceSite, LocalizedDisplayName, datecreated, CI_ID
$LocalSiteSUG = $AllSUG | Where-Object {$_.SourceSite -eq "$PSD"} | sort-object datecreated -Descending | Select-Object -last 6

# Корректировка SUG с учётом предыдущих месяцев
foreach ($SUG in $LocalSiteSUG){
    $latestSUG =  $LocalSiteSUG | Where-Object {($_.DateCreated -lt (Get-Date).AddMonths(-1) -and $_.dateCreated -gt (Get-Date).AddMonths(-2)) 
    -and $_.LocalizedDisplayName -match $SUG.LocalizedDisplayName
    } `
    | Select-Object localizeddisplayname, datecreated, ci_id
    if ($null -ne $latestSUG){        
        Remove-CMSoftwareUpdateGroup -Id $SUG.CI_ID -Force
        Set-CMSoftwareUpdateGroup -Id $latestSUG.ci_id -NewName $SUG.LocalizedDisplayName
    }
    $latestSUG
}

# Оповещение в телегу по апдейтам
$LatestSUG = $AllSUG | Where-Object {$_.SourceSite -eq "$PSD" -and $_.LocalizedDisplayName -like "*Server*"} | sort-object datecreated | Select-Object -last 2 
$LatestSUG.LocalizedDisplayName | MonthlyUpdatesNotification -chat_id "-368164031" -SUGCI_ID $LatestSUG.CI_ID
