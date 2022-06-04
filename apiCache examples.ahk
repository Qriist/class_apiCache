#Include <SingleRecordSQL>
#Include <functions>
#Include <LibCrypt>
#Include <class_SQLiteDB_modified>
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
foundRecords := apiCache.findFingerprints(,"disk",,,1)
msgbox % foundRecords.Count() ;"`n`n" st_printarr(foundRecords)

;msgbox % apiCache.fetchFingerprints(foundRecords).count()


testObj := []
for k,v in foundRecords{
    testobj.push(v)
    if (a_index = 1000)
        break
}

msgbox % apiCache.fetchFingerprints(testObj).count()
