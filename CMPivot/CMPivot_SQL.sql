select Coll.CollectionName
	,comp.ResourceID
	,task.LastUpdateTime
	,tbl.col.value('@Name', 'varchar(128)') AS Name
	,tbl.col.value('@Model', 'varchar(128)') As Model
	,tbl.col.value('@SerialNumber', 'varchar(128)') As SerialNumber
from [dbo].[vSMS_CMPivotTask] as Task
join [dbo].[Collections] as Coll on Coll.SiteID = Task.CollectionID
join [dbo].[vSMS_CMPivotResult] as result on result.TaskID=task.TaskID
CROSS APPLY (select cast(result.ScriptOutput as xml)) AS T(X)
CROSS APPLY T.X.nodes('//result/e') Tbl(Col)
JOIN v_GS_COMPUTER_SYSTEM AS comp ON comp.Name0 = tbl.col.value('@Name', 'varchar(128)')
where ClientOperationId=@OperationID