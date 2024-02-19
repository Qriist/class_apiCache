;#Include <SingleRecordSQL>
;#Include <LibCrypt>
#Include %A_MyDocuments%\Autohotkey\Lib\v2\class_SQLiteDB_modified.ahk
;#Include %A_MyDocuments%\Autohotkey\Lib\v2\Winhttp.ahk
#Include %A_MyDocuments%\Autohotkey\Lib\v2\WinhttpRequest.ahk
;#Include <string_things>
class class_ApiCache{ 
	acDB := ""	;api cache DB
	acDir := ""	;api cache dir, used only for bulk downloads
	uncDB := ""
	acExpiry := 518400	;api cache expiry
							;how many seconds to wait before burning api call for fresh file
							;default = 518400 (6 days)
	web := WinHttpRequest()
	outHeadersText := ""
	outHeadersMap := Map()
	preparedOutHeadersText := ""
	lastResponseHeaders := ""
	WinHttpRequest_encoding := "UTF-8"
	WinHttpRequest_windowsCache := "Cache-Control: no-cache"
	openTransaction := 0
	lastServedSource := "nothing"	;holds the string "server" if the class burned api, or "cache" otherwise.
	bulkRetObj := []
	preparedSQL := Map()
	compiledSQL := Map()
	init(pathToDir,pathToDB){
		this.initDir(pathToDir)
		this.initDB(pathToDB)
		this.initPreparedStatements()
	}
	initDir(pathToDir){	;don't need anymore?
		DirCreate(pathToDir)
		this.acDir := Trim(pathToDir,"\")
	}
	initDB(pathToDB,journal_mode := "wal",synchronous := 0){	
		If FileExist(pathToDB){
			this.acDB :=  SQLiteDB()
			if !this.acDB.openDB(pathToDB)
				msgbox("error opening database")
		}
		else{
			SplitPath(pathToDB,&FileName,&FileDir)
			DirCreate(FileDir)
			this.acDB :=  SQLiteDB()
			this.acDB.openDB(pathToDB)
			ddlObj := this.initSchema()
			
			for k,v in ddlObj {
				
				if !this.acDB.exec(v)
					msgbox("error creating table in new database")
			}
		}
		this.acDB.exec("PRAGMA journal_mode=" journal_mode ";")
		this.acDB.exec("PRAGMA synchronous=" synchronous ";")
		
		
		;this.acDB.getTable("PRAGMA synchronous;",table)
		;msgbox % st_printArr(table)
		;this.acDB.exec("VACUUM;")
	}
	initSchema(){
		retObj := []
		ret := "
		(
		CREATE TABLE simpleCacheTable (
			fingerprint       TEXT PRIMARY KEY UNIQUE,
			url               TEXT,
			headers           TEXT,
			responseHeaders   BLOB,
			responseHeadersSz INTEGER,
			timestamp         INTEGER,
			expiry            INTEGER,
			mode              INTEGER,
			data              BLOB,
			dataSz            INTEGER
		`);
		)"
		retObj.push(ret)
		
		ret := "
		(
		CREATE VIEW vRecords AS
			SELECT fingerprint,
				url,
				headers,
				sqlar_uncompress(responseHeaders, responseHeadersSz) AS responseHeaders,
				timestamp,
				expiry,
				sqlar_uncompress(data, dataSz) AS data
			FROM simpleCacheTable;
		)"
		retObj.push(ret)
		
		ret := "
		(
		CREATE VIEW vRecords_complete AS
			SELECT fingerprint,
				url,
				headers,
				sqlar_uncompress(responseHeaders, responseHeadersSz) AS responseHeaders,
				responseHeadersSz,
				mode,
				timestamp,
				expiry,
				sqlar_uncompress(data, dataSz) AS data,
				dataSz
			FROM simpleCacheTable;
		)"
		retObj.push(ret)
		
		return retObj		
	}
	initExpiry(expiry){
		this.acExpiry := expiry
	}
	initPreparedStatements(){
		this.preparedSQL["retrieve/server"] := "INSERT OR IGNORE INTO simpleCacheTable (data,dataSz,expiry,fingerprint,headers,mode,responseHeaders,responseHeadersSz,	timestamp,url) "
			.	"VALUES (sqlar_compress(CAST(? AS BLOB)),LENGTH(CAST(? AS BLOB)),?,?,?,?,sqlar_compress(CAST(? AS BLOB)),LENGTH(CAST(? AS BLOB)),?,?) "
			.	"ON CONFLICT ( fingerprint ) "
			.	"DO UPDATE SET "
			.	"data = excluded.data,"
			.	"dataSz = excluded.dataSz,"
			.	"expiry = excluded.expiry,"
			.	"headers = excluded.headers,"
			.	"mode = excluded.mode,"
			.	"responseHeaders = excluded.responseHeaders,"
			.	"responseHeadersSz = excluded.responseHeadersSz,"
			.	"timestamp = excluded.timestamp,"
			.	"url = excluded.url;"
		
		this.preparedSQL["retrieve/cache"] := "SELECT sqlar_uncompress(data,dataSz) AS data, sqlar_uncompress(responseHeaders,responseHeadersSz) AS responseHeaders "
			.	"FROM simpleCacheTable "
			.	"WHERE fingerprint = ? "
			.	"AND expiry > ?;"
		
		this.preparedSQL["invalidateRecord"] := "UPDATE simpleCacheTable SET expiry = 0 WHERE fingerprint = ?;"
		; msgbox "UPDATE simpleCacheTable SET expiry = 0 WHERE fingerprint = '?';"
		for k,v in this.preparedSQL {
			st := ""
			this.acDB.Prepare(v,&st)
			this.compiledSQL[k] := st
		}
	}
	setHeaders(headersMap := Map()){
		this.outHeadersMap := headersMap
		this.outHeadersText := ""
		for k,v in headersMap {
			this.outHeadersText .= k ": " v "`n"
		}
		this.preparedOutHeadersText := this.sqlQuote(this.outHeadersText)
	}
	retrieve(url, post?, outHeadersMap := Map(), &options := "", expiry?, forceBurn?){
		sql := ""
		table := ""
		chkCache := ""
		if !IsSet(expiry)
			expiry := this.acExpiry
		/*
			-check if url+header (fingerprint) exists in db
			-if url doesn't exist -> burn api
				
			-check expiry
			-if url too old -> burn api
				
			-if url (fingerprint) AND expiry is good AND fileblob exists -> return fileblob from db
				?-if file doesn't exist (which it should) -> burn api
		*/
		; msgbox  url
		
		fingerprint := this.generateFingerprint(url
			,	(this.outHeadersText=""?unset:this.outHeadersText)
			,	(!IsSet(post)?unset:post))
		;,responseHeaders := headers	;WinHttpRequest will overwrite the ByRef Headers var otherwise
			;,SHA512_url := LC_SHA512(url)
			;,SHA512_headers := LC_SHA512(headers)
			;,fingerprint := SHA512_url SHA512_headers

		timestamp := expiry_timestamp := A_NowUTC	;makes the timestamp consistent across the method
		expiry_timestamp := DateAdd(expiry_timestamp, expiry, "seconds")
		;msgbox timestamp "`n" expiry_timestamp

		If !IsSet(forceBurn){	;skips useless db call if set
			SQL := "SELECT sqlar_uncompress(data,dataSz) AS data, sqlar_uncompress(responseHeaders,responseHeadersSz) AS responseHeaders "
				.	"FROM simpleCacheTable "
				.	"WHERE fingerprint = '" fingerprint "' "
				.	"AND expiry > " Min(timestamp,expiry_timestamp) ";"	;uses lower number between current and user-set timestamp
			If !this.acDB.getTable(sql,&table)	;finds data only if it hasn't expired
				msgbox A_Clipboard := "--expiry check failed under optional burn`n" sql
			
			If (table.RowCount > 0) {	;RowCount will = 0 if nothing found
				table.NextNamed(&chkCache)
				this.lastResponseHeaders := chkCache["responseHeaders"]
				this.lastServedSource := "cache"
				return chkCache["data"]	;returns previously cached data
			}
		}
		;msgbox fingerprint
		
		; WinHttpRequest(url, post, responseHeaders, options this.WinHttpRequest_encoding "`n" WinHttpRequest_windowsCache)
		;outHeadersMap["Accept-Encoding"] := "br, gzip, deflate, compress"	;add compression headers to request
		
		;msgbox outHeadersMap["Accept-Encoding"]
		; req := this.acWeb.request(url,(!IsSet(post)?'GET':'POST'),post?,outHeadersMap)
		response := this.web.request(url)
		; req := this.web.openRequest("GET",url,this.WinHttpRequest_encoding)    ;uses nested Request class
		; for k,v in this.outHeadersMap {
		; 	req.setRequestHeader(k,v)
		; }
		; req.setRequestHeader("Accept-Encoding","gzip, deflate")
		; req.send()
		
		this.lastResponseHeaders := this.web.getAllResponseHeaders()
		; quotedResponseText := this.sqlQuote(web.responseText)
		; quotedResponseHeaders := this.sqlQuote(this.lastResponseHeaders)

		;Types := {Blob: 1, Double: 1, Int: 1, Int64: 1, Null: 1, Text: 1}
		insMap := Map(1,Map("Text",  response)	;data
				,	2,Map("Text", response)	;dataSz
			 	,	3,Map("Int64",expiry_timestamp)	;expiry
				,	4,Map("Text", fingerprint)	;fingerprint
				,	5,Map((this.preparedOutHeadersText=""?"NULL":"Text"),(this.preparedOutHeadersText=""?"NULL":this.preparedOutHeadersText))	;headers
				,	6,Map("Int","777")
				,	7,Map("Text", this.lastResponseHeaders)	;responseHeaders
				,	8,Map("Text", this.lastResponseHeaders)	;responseHeadersSz
				,	9,Map("Int64",timestamp)	;timestamp
				,	10,Map("Text",url))	;url
		this.compiledSQL["retrieve/server"].Bind(insMap)
		,this.compiledSQL["retrieve/server"].Step()
		,this.compiledSQL["retrieve/server"].Reset()
		this.lastServedSource := "server"

		return response


		;msgbox (StrLen(this.outHeadersText)=0?"Null":"Text")
		; insMap := Map(1,Map("Text",url)	;url
		;,	2,Map((StrLen(this.outHeadersText)=0?"Null":"Text"),(StrLen(this.outHeadersText)=0?:"":this.outHeadersText)	;headers
		; ,	3,Map("Blob","sqlar_compress(" this.lastResponseHeaders ")")	;responseHeaders
		; ,	4,Map("Int","length(" this.lastResponseHeaders ")")	;responseHeadersSz
		; ,	5,Map("Text",fingerprint)	;fingerprint
		; ,	6,Map("Int64",timestamp)	;timestamp
		; ,	7,Map("Int64",expiry_timestamp)	;expiry
		; ,	8,Map("Int64",mode)	;mode
		; ,	9,Map("Blob","sqlar_compress(" req.responseBody ")")	;data
		; ,	10,Map("Int64","length(" req.responseBody ")")))	;dataSz
/*
		quotedResponseText := this.sqlQuote(req.responseText)
		quotedResponseHeaders := this.sqlQuote(this.lastResponseHeaders)
		insMap := Map()
		insMap["url"] := "'" url "'"
		insMap["headers"] := this.outHeadersText
		insMap["responseHeaders"] := "sqlar_compress(CAST(" quotedResponseHeaders " AS BLOB))"	
		insMap["responseHeadersSz"] := "length(CAST(" quotedResponseHeaders " AS BLOB))"
			;,"responseHeadersSz":StrPut(responseHeaders, "UTF-8")
		insMap["fingerprint"] := "'" fingerprint "'"
		insMap["timestamp"] := timestamp
		insMap["expiry"] := expiry_timestamp
		insMap["mode"] := "777"
		insMap["dataSz"] := "length(CAST(" quotedResponseText " AS BLOB))"
			;,"dataSz":StrPut(post, "UTF-8")
		insMap["data"] := "sqlar_compress(CAST(" quotedResponseText " AS BLOB))"

		SQL := "INSERT OR IGNORE INTO simpleCacheTable (data,dataSz,expiry,fingerprint,headers,mode,responseHeaders,responseHeadersSz,timestamp,url) VALUES ("
			.	insMap["data"] ",`n"
			.	insMap["dataSz"] ",`n"
			.	insMap["expiry"] ",`n"
			.	insMap["fingerprint"] ",`n"
			.	(insMap["headers"]=""?"NULL":insMap["headers"]) ",`n"
			.	insMap["mode"] ",`n"
			.	insMap["responseHeaders"] ",`n"
			.	insMap["responseHeadersSz"] ",`n"
			.	insMap["timestamp"] ",`n"
			.	insMap["url"] 
			.	") ON CONFLICT ( fingerprint ) "
			.	"DO UPDATE SET "
			.	"data = excluded.data,"
			.	"dataSz = excluded.dataSz,"
			.	"expiry = excluded.expiry,"
			.	"headers = excluded.headers,"
			.	"mode = excluded.mode,"
			.	"responseHeaders = excluded.responseHeaders,"
			.	"responseHeadersSz = excluded.responseHeadersSz,"
			.	"timestamp = excluded.timestamp,"
			.	"url = excluded.url;"
		; msgbox a_clipboard := sql
		; return req.responseText


		if (this.openTransaction = 0)
			this.acDB.exec("BEGIN TRANSACTION;")
		;msgbox % clipboard := sql
		if !this.acDB.exec(sql)
			msgbox a_clipboard := "--insObj failure`n" sql
		if (this.openTransaction = 0)				
			If !this.acDB.exec("COMMIT;")
				msgbox "commit failure"
		this.lastServedSource := "server"

		;StrPut(gibberish, buf := Buffer(StrPut(aa)))
		;MsgBox(StrGet(req.responseBody, "CP0"))
		;msgbox req.responseBody
		return req.responseText
		

		; ;don't think I need this fetch after the insertion? keeping for now
		; SQL := "SELECT sqlar_uncompress(data,size) AS data FROM vRecords WHERE fingerprint = '" fingerprint "';"
		
		; this.acDB.getTable(sql,table)
		; table.NextNamed(chkCache)
		
		; return chkCache["data"]	;returns previously cached data
		*/
	}
	/*	bulk insert stuff
			
		
		buildBulkRetrieve(url,headers := "",expiry := "",forceBurn := 0){
		;queues one fingerprint for .bulkRetrieve()
			if (expiry = "")
				expiry := this.acExpiry
			
			fingerprintObj := {"url":url,"forceBurn":forceBurn,"expiry":expiry,"options":{"headers":headers,"gid":format("{1:016X}",this.bulkRetObj.count()+1),"dir":this.acDir,"out":this.generateFingerprint(url,headers)}}
			this.bulkRetObj.push(fingerprintObj)
		}
		bulkRetrieve(maxConcurrentDownloads := 5, urlObj := ""){
			if (urlObj = "")
				urlObj := this.bulkRetObj
		;msgbox % st_printArr(urlObj)
			cuidFingerprintMap := []
			mapIndex := 0
			retFingerprints := []
		;msgbox % this.acDir "\bulk.txt"
			bulk := FileOpen(this.acDir "\bulk.txt","w")
			for k,v in urlObj{
			;check if the fingerprint's cache is expired
			;fingerprint := this.generateFingerprint(v["url"],v["options","headers"])	
				fingerprint := v["options","out"]
				
				timestamp := expiry_timestamp := A_NowUTC	;makes the timestamp consistent across the method
				EnvAdd,expiry_timestamp, % v["expiry"], Seconds	
				
				If (v["forceBurn"] = 0){	;skips unneeded db call if !0
				;not pulling data at this stage so we don't need blobs
					SQL := "SELECT fingerprint FROM simpleCacheTable WHERE fingerprint = '" fingerprint "' AND expiry > " Min(timestamp,expiry_timestamp) ";"	;uses lower number between current and user-set timestamp
					If !this.acDB.getTable(sql,table)	;finds data only if it hasn't expired
						msgbox % clipboard := "--expiry check failed under optional burn`n" sql
				;msgbox % clipboard := sql
				;msgbox % st_printArr(table)
					If (table.RowCount > 0) {	;RowCount will = 0 if nothing found
					;add to the list of fingerprints
						retFingerprints[fingerprint] := {"url":v["url"],"headers":v["options","headers"],"source":"cache"}
						continue	;will use cached data so nothing to do
					}
				}
			;msgbox % "yo"
				bulk.write(this.formatAria2cUrl(v["url"],v["options"]) "`n")
				mapIndex += 1
				cuidFingerprintMap[mapIndex] := {"fingerprint":fingerprint,"url":v["url"],"headers":v["options","headers"]}	;assuming the .count() = aria2c's CUID
			}
			bulk.close()
		;msgbox % "test"
			if !(FileGetSize(this.acDir "\bulk.txt") > 20)	;file is definitely too small
				return retFingerprints	;all files were found in cache
			
		;actually download the bulk items
		;aria2c -i out.txt --http-accept-gzip true --max-concurrent-downloads=30 --console-log-level=notice  --log=log.txt
			FileDelete, % this.acDir "\bulk.log"
			runLine := chr(34) A_ScriptDir "\aria2c.exe"	chr(34) a_space
			.	"-i " chr(34) this.acDir "\bulk.txt" chr(34) a_space
			.	"--http-accept-gzip true" a_space
			.	"--http-no-cache" a_space
			.	"--max-concurrent-downloads=" maxConcurrentDownloads a_space
			.	"--allow-overwrite" a_space
			.	"--log-level=info" a_space
			.	"--disk-cache=250M" a_space
			.	"--deferred-input true" a_space
			.	"--log=" chr(34) this.acDir "\bulk.log" chr(34)
		;msgbox % clipboard := runLine
			RunWait, % runLine
			
		;parse the log for responseHeaders
			static needle := "mUs)\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+ \[INFO] \[HttpConnection.+] CUID#(\d+) - Response received:\r?\n(.+)\r?\n\r?\n"
			parseLog := RegExMatchGlobal(FileOpen(this.acDir "\bulk.log","r").read(),needle,0)
		;msgbox % st_printArr(parseLog)
			
			for k,v in parseLog {
				cuid := v[1] + 6
				fingerprint := cuidFingerprintMap[cuid,"fingerprint"]
				if (fingerprint = ""){
				;msgbox % st_printArr(v) st_printArr(cuidFingerprintMap)
					
				}
			;msgbox % 
				quotedResponseHeaders := sqlQuote(v[2])
				insObj := {"url":cuidFingerprintMap[cuid,"url"]
				,"headers":cuidFingerprintMap[cuid,"headers"]
				,"responseHeaders":"sqlar_compress(CAST(" quotedResponseHeaders " AS BLOB))"	
				,"responseHeadersSz":"length(CAST(" quotedResponseHeaders " AS BLOB))"
				;,"responseHeadersSz":StrPut(responseHeaders, "UTF-8")
				,"fingerprint":fingerprint
				,"timestamp":timestamp
				,"expiry":expiry_timestamp
				,"mode":"777"
				,"dataSz":FileGetSize(this.acDir "\" fingerprint)
				;,"dataSz":StrPut(post, "UTF-8")
				,"data":"sqlar_compress(READFILE(" sqlQuote(this.acDir "\" fingerprint) "))"}	 
				
			;SQL := SingleRecordSQL("simpleCacheTable",insObj,"fingerprint",,"responseHeaders,data")
				SQL := SingleRecordSQL("simpleCacheTable",insObj,"fingerprint",,"responseHeaders,responseHeadersSz,data,dataSz")
				
				
			;if (this.openTransaction = 0)
				;this.acDB.exec("BEGIN TRANSACTION;")
			;msgbox % clipboard := sql
				if !this.acDB.exec(sql)
					msgbox % clipboard := "--insObj failure`n" sql
				FileDelete, % this.acDir "\" fingerprint
			;if (this.openTransaction = 0)				
				;If !this.acDB.exec("COMMIT;")
					;msgbox % "commit failure"
				this.lastServedSource := "server"
			;msgbox % st_printArr(v)
			}
			
			
		;import into the db
		;return retFingerprints
		}
		formatAria2cUrl(url,options := ""){
			for k,v in options {
				switch k {
					case "headers" :{
						for k,v in StrSplit(options["headers"],"`n","`r"){
							if (v != "")
								opts .= "`n" a_tab "header=" v
						}
					}
					default : {
						if (v != "")
							opts .= "`n" a_tab k "=" v
					}
				}
			}
			return url opts
		}
	*/
	findRecords(urlToMatch := "",  dataToMatch := "", headersToMatch := "", responseHeadersToMatch := "",urlPartialMatch := 0){
		;looking for any records which match the parameters
		;blank parameters will not be considered
		;url is exact unless urlPartialMatch != 0, others will always look for partial matches
		;will return a Map object with [fingerprint,url,headers] fields to help prevent memory overflow

		SQL := "SELECT fingerprint,url,headers from vRecords WHERE "
		.	(urlToMatch!=""?(urlPartialMatch=0?"url = " this.sqlQuote(urlToMatch) :"INSTR(url," this.sqlQuote(urlToMatch) ")"):"url IS NOT NULL")	;more complicated logic at url to simplify the next three
		.	(dataToMatch!=""?" AND INSTR(data," this.sqlQuote(dataToMatch) ")":"")
		.	(headersToMatch=""?"":" AND INSTR(headers," this.sqlQuote(headersToMatch) ")")	;probably less likely to search headers so the null string is first match
		.	(responseHeadersToMatch=""?"":" AND INSTR(responseHeaders," this.sqlQuote(responseHeadersToMatch) ")")	;same as above
		.	";"
		; msgbox A_Clipboard := sql
		table := ""
		if !this.acDB.gettable(SQL,&table)
			msgbox a_clipboard "--Failure in findRecords`n" SQL
		retObj := Map()
		nextObj := Map()
		loop table.rowCount {
			table.nextNamed(&nextObj)
			retObj.push(nextObj)
		}
		return retObj
	}
	; fetchRecords(recordObj){
	; 	;accepts a linear array of fingerprints to return any number of rows
	; }
	; findAndFetchRecords(){	;find and fetch records in one step
	; 	;TODO
	; }
	generateFingerprint(url,headers?,post?){
		;returns a concatonated hash of the outgoing url+headers+post
		;fingerprint is 128/256/384 characters, depending on if headers and/or post is unset
		return this.hash(&url,"SHA512") 
			.	(!IsSetRef(&headers)?"":this.hash(&headers,"SHA512")) 
			.	(!IsSetRef(&post)?"":this.hash(&post,"SHA512")) 
	}
	sqlQuote(input){
		return "'" (!InStr(input,"'")?input:StrReplace(input,"'","''")) "'"
	}
	invalidateRecords(recordArr){
		;accepts a linear array of fingerprints to forcefully stale any number of records
		;this does NOT delete the records, it sets the expiry to 0
		;useful when there's a known list of updated fingerprints
		
		if (this.openTransaction = 0)	;makes sure the user hasn't manually opened a transaction
			this.begin()
		for k,v in recordArr
			this.invalidateRecord(v)
		if (this.openTransaction = 1)
			this.commit()
	}
	invalidateRecord(fingerprint){
		;this does NOT delete the records, it sets the expiry to 0
		finMap := Map(1,Map("Text",fingerprint))
		this.compiledSQL["invalidateRecord"].Bind(finMap)
		,this.compiledSQL["invalidateRecord"].Step()
		,this.compiledSQL["invalidateRecord"].Reset()
	}
	; purge(url,header := "", partialHeaderMatch := 1){	;accepts an array of urls + headers to remove from the db+disk
		
	; 	loop, % urlobj.count(){
	; 		this.acDB.getNamedTable("SELECT diskId from cacheTable where url = '" urlObj[a_index] "';",table)
	; 		Loop, % table["rows"].count(){
	; 			table.next(out)
	; 			FileDelete, % this.acDir "\" out["diskId"]
	; 		}
	; 		this.acDB.exec("DELETE FROM cacheTable WHERE url = '" urlObj[a_index] "';")
	; 	}
	; }
	; massPurge(urlObj){
	; 	;TODO
	; }
	nuke(reallyNuke := 0){	;you didn't really like this db, did you?
		if (reallyNuke != 1)
			return
		this.acDB.exec("DELETE FROM simpleCacheTable;")
	}
	CloseDB(){
		this.acDB.exec("PRAGMA optimize;")
		return this.acDb.CloseDB()
	}
	exportUncompressedDb(pathToUncompressedDB,overwrite := 0,journal_mode := "wal"){
		;create a db that can be used by any version of SQLite
		if FileExist(pathToUncompressedDB){
			if (overwrite!=1)
				return
			else
				FileDelete pathToUncompressedDB
		}
		this.uncDB := SQLiteDB()
		this.uncDB.openDB(pathToUncompressedDB)
		uncObj := []
		unc := "
		(
		CREATE TABLE simpleCacheTable (
			fingerprint       TEXT PRIMARY KEY UNIQUE,
			url               TEXT,
			headers           TEXT,
			responseHeaders   BLOB,
			responseHeadersSz INTEGER,
			timestamp         INTEGER,
			expiry            INTEGER,
			mode              INTEGER,
			data              BLOB,
			dataSz            INTEGER
		`);
		)"
		uncObj.push(unc)
		
		unc := "
		(
		CREATE VIEW vRecords AS
			SELECT fingerprint,
				url,
				headers,
				responseHeaders,
				timestamp,
				expiry,
				data
			FROM simpleCacheTable;
		)"
		uncObj.push(unc)
		
		unc := " 
		(
		CREATE VIEW vRecords_complete AS
			SELECT fingerprint,
				url,
				headers,
				responseHeaders,
				responseHeadersSz,
				mode,
				timestamp,
				expiry,
				data,
				dataSz
			FROM simpleCacheTable;
		)"
		uncObj.push(unc)
		if (overwrite!=0)
			for k,v in uncObj {
				tableDDL := v
				If !this.uncDB.exec(tableDDL)
					msgbox "--Error creating table in uncompressed DB`n" tableDDL
			}
		this.uncDB.exec("PRAGMA journal_mode=" journal_mode ";")			
		;this.uncDB.exec("VACUUM;")		
		this.uncDB.CloseDB()
		
		this.acDB.AttachDB(pathToUncompressedDB, "unc")
		SQL := "INSERT OR IGNORE INTO unc.simpleCacheTable SELECT * FROM main.vRecords_Complete;"
		this.acDB.exec(SQL)
		this.acDB.DetachDB("unc")
	}
	begin(){
		if (this.openTransaction = 1)	;can't open a new statement
			return
		;this.acDB.exec("PRAGMA locking_mode = EXCLUSIVE;")
		this.acDB.exec("BEGIN TRANSACTION;")
		this.openTransaction := 1
	}
	commit(){
		if (this.openTransaction = 0)	;nothing to commit
			return
		this.acDB.exec("COMMIT;")
		;this.acDB.exec("PRAGMA locking_mode = NORMAL;")
		this.openTransaction := 0
	}

	hash(&item:="", hashType:="", c_size:="", cb:="") { ; default hashType = SHA256 /// default enc = UTF-16
		Static _hLib:=DllCall("LoadLibrary","Str","bcrypt.dll","UPtr"), LType:="SHA256", LItem:="", LBuf:="", LSize:="", d_LSize:=1024000
		Static n:={hAlg:0,hHash:0,size:0,obj:""}
			 , o := {md2:n.Clone(),md4:n.Clone(),md5:n.Clone(),sha1:n.Clone(),sha256:n.Clone(),sha384:n.Clone(),sha512:n.Clone()}
		_file:="", LType:=(hashType?StrUpper(hashType):LType), LItem:=(item?item:LItem), ((!o.%LType%.hAlg)?make_obj():"")

		If (!item && !hashType) { ; Free buffers/memory and release objects.
			return !graceful_exit()
		} Else If (Type(LItem) = "String" && FileExist(LItem)) { ; Determine buffer type.
			_file := FileOpen(LItem,"r"), LBuf := true, LSize:=(c_size?c_size:d_LSize)
		} Else If (Type(item) = "String") {
			LBuf := Buffer(StrPut(item,"UTF-8")-1,0), LItem:="", LSize:=d_LSize
			temp_buf := Buffer(LBuf.size+1,0), StrPut(item, temp_buf, "UTF-8"), copy_str()
		} Else If (Type(item) = "Buffer")
			LBuf := item, LItem:="", LSize:=d_LSize
		
		If (LBuf && !(outVal:="")) {
			hDigest := Buffer(o.%LType%.size) ; Create new digest obj
			Loop t:=(!_file ? 1 : (_file.Length//LSize)+1)
				(_file?_file.RawRead(LBuf:=Buffer(((_len:=_file.Length-_file.Pos)<LSize)?_len:LSize,0)):"")
			  , r7 := DllCall("bcrypt\BCryptHashData","UPtr",o.%LType%.obj.ptr,"UPtr",LBuf.ptr,"UInt",LBuf.size,"UInt",0)
			  , ((Type(cb)="Func") ? cb(A_index/t) : "")
			r8 := DllCall("bcrypt\BCryptFinishHash","UPtr",o.%LType%.obj.ptr,"UPtr",hDigest.ptr,"UInt",hDigest.size,"UInt",0)
			Loop hDigest.size ; convert hDigest to hex string
				outVal .= Format("{:02X}",NumGet(hDigest,A_Index-1,"UChar"))
		}
		
		_file?(_file.Close(),LBuf:=""):""
		return outVal
		
		make_obj() { ; create hash object
			r1 := DllCall("bcrypt\BCryptOpenAlgorithmProvider","UPtr*",&hAlg:=0,"Str",LType,"UPtr",0,"UInt",0x20) ; BCRYPT_HASH_REUSABLE_FLAG = 0x20
			
			r3 := DllCall("bcrypt\BCryptGetProperty","UPtr",hAlg,"Str","ObjectLength"
							  ,"UInt*",&objSize:=0,"UInt",4,"UInt*",&_size:=0,"UInt",0) ; Just use UInt* for bSize, and ignore _size.
			
			r4 := DllCall("bcrypt\BCryptGetProperty","UPtr",hAlg,"Str","HashDigestLength"
							   ,"UInt*",&hashSize:=0,"UInt",4,"UInt*",&_size:=0,"UInt",0), obj:= Buffer(objSize)
			
			r5 := DllCall("bcrypt\BCryptCreateHash","UPtr",hAlg,"UPtr*",&hHash:=0       ; Setup fast reusage of hash obj...
						 ,"UPtr",obj.ptr,"UInt",obj.size,"UPtr",0,"UInt",0,"UInt",0x20) ; ... with 0x20 flag.
			
			o.%LType% := {obj:obj, hHash:hHash, hAlg:hAlg, size:hashSize}
		}
		
		graceful_exit(r1:=0, r2:=0) {
			For name, obj in o.OwnProps() {
				If o.%name%.hHash && (r1 := DllCall("bcrypt\BCryptDestroyHash","UPtr",o.%name%.hHash)
								  ||  r2 := DllCall("bcrypt\BCryptCloseAlgorithmProvider","UPtr",o.%name%.hAlg,"UInt",0))
					throw Error("Unable to destroy hash object.")
				o.%name%.hHash := o.%name%.hAlg := o.%name%.size := 0, o.%name%.obj := ""
			} LBuf := "", LItem := "", LSize := c_size
		}
		
		copy_str() => DllCall("NtDll\RtlCopyMemory","UPtr",LBuf.ptr,"UPtr",temp_buf.ptr,"UPtr",LBuf.size)
	}
}