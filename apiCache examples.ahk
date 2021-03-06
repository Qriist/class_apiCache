;NOTE: not really full of examples at the moment.
;   Pretty much just used this for scratch while writing the class.
;   Will update with with actual useful examples ~soon~.

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

start := A_TickCount
apiCache := new class_apiCache
apiCache.init(A_ScriptDir "\cache",A_ScriptDir "\empty.db")
loop,files, % A_ScriptDir "\temp\*.html" 
{
    SplitPath(A_LoopFileLongPath,FileName,FileDir,FileExt,FileBase)
    if !InStr(FileBase,"-h")
    apiCache.sideloadFingerprint(A_LoopFileLongPath,A_LoopFileLongPath,,,FileDir "\" FileBase "-h.html",1)
}
;apiCache.init(A_ScriptDir "\cache",A_ScriptDir "\winApi.db")
;apiCache.init(A_ScriptDir "\cache",A_ScriptDir "\uncompressed.db")
;apiCache.exportUncompressedDb(A_ScriptDir "\uncompressed.db",0)
;msgbox % apiCache.lastResponseHeaders
ExitApp
foundRecords := apiCache.findFingerprints("disk",,,,1)
stop1 := (A_TickCount - start) / 1000 

;msgbox % foundRecords.Count() ;"`n`n" st_printarr(foundRecords) 
;heldObj := apiCache.fetchFingerprints(foundRecords)
fingerprintObj := []
for k,v in foundRecords {
    fingerprintObj.push({"fingerprint":v,"outFile":a_scriptDir "\temp\" a_index ".html","outResponseHeaderFile":a_scriptDir "\temp\" a_index "-h.html"})
    ;apiCache.exportFingerprint(v,a_scriptDir "\temp\" a_index ".html",a_scriptDir "\temp\" a_index "-h.html")
}

apiCache.exportFingerprints(fingerprintObj)
stop2 := ((A_TickCount - start) / 1000) - stop1
msgbox % "search:" stop1 "`nfetch:" stop2 "`n" foundRecords.count() "`n" heldObj.count() "`n" testObj.count()
exitapp

testObj := []
for k,v in heldObj {
    testObj[v["fingerprint"]] := 1
}
stop2 := ((A_TickCount - start) / 1000) - stop1
msgbox % "search:" stop1 "`nfetch:" stop2 "`n" foundRecords.count() "`n" heldObj.count() "`n" testObj.count()