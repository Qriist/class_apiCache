#Include <SingleRecordSQL>
#Include <functions>
#Include <LibCrypt>
#Include <class_SQLiteDB>
#Include <WinHttpRequest>
#Include <string_things>
#Include <class_apiCache>
#SingleInstance, Force
SendMode Input
SetWorkingDir, %A_ScriptDir%
SetBatchLines, -1


apiCache := new class_apiCache
apiCache.init(A_ScriptDir "\cache",A_ScriptDir "\winApi.db")

;msgbox % apiCache.lastResponseHeaders
foundRecords := apiCache.findRecords(,"adhoc",,,1)
msgbox % foundRecords.Count() ;"`n`n" st_printarr(foundRecords)