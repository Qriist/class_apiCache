#requires Autohotkey v2.0
;#SingleInstance, Force
SetWorkingDir A_ScriptDir
#Include %A_MyDocuments%\Autohotkey\Lib\v2\class_SQLiteDB_modified.ahk
; #Include %A_MyDocuments%\Autohotkey\Lib\v2\Winhttp.ahk
#Include %A_MyDocuments%\Autohotkey\Lib\v2\WinhttpRequest.ahk
#include C:\Projects\class_apiCache\lib\class_apiCache.ahk
; test := Map("a","1","b","2","c","3")
; test := ["a","1","b","2","c","3"]
; test := {"a":"1","b":"2","c":"3"}

; for k,v in test.OwnProps()
;     msgbox v
; ExitApp




url := "https://db.ygoprodeck.com/api/v7/checkDBVer.php"    ;X-Content-Encoding-Over-Network: br    -works
url := "https://titsandasses.org/"  ;X-Content-Encoding-Over-Network: gzip  -works

; url := "https://docs.microsoft.com/en-us/windows/win32/api/toc.json"    ;Content-Encoding: gzip -broken
; url := "https://www.digg.com/"  ;Content-Encoding: br   -broken

apiCache := class_apiCache()
apiCache.init(A_ScriptDir,A_ScriptDir "\sqlar_test.db")
apiCache.retrieve(url)
;msgbox apiCache.generateFingerprint(url,"test")
msgbox apiCache.lastServedSource
; web := WinHttpRequest()
; req := web.request(url)
; msgbox web.getAllResponseHeaders()
; msgbox req


; fp := fingerprint()
; msgbox fp.retrieve(url)
; msgbox fp.generateFingerprint(url,"test")
fp := apiCache.generateFingerprint(url)
; apiCache.invalidateRecord(fp)

ExitApp
test := ""
; msgbox apiCache.retrieve(url,&test)

ExitApp
; web := Winhttp()
; req := web.openRequest("GET",url,"UTF-8")
; req.setRequestHeader("Accept-Encoding","gzip")
; req.send()
; msgbox req.getAllResponseHeaders()

; web := WinHttpRequest()
; req := web.request(url,,,test)
; msgbox req
; test["Accept-Encoding"] := "gzip"
;msgbox test["Accept-Encoding"]
; test := {"Accept-Encoding":"gzip"}
; test := {}
; msgbox Type(test)

ExitApp
; gzip := web.getAllResponseHeaders()
; gzipSize := StrLen(gzipText)

; textText := web.request(url)
; text := web.getAllResponseHeaders()
; textSize := StrLen(textText)
; msgbox sort(gzip)
; ExitApp
; headers := Map()
; headers["test"] := "junk"
; apiCache.setHeaders(headers)
; bindMap := Map(1,Map("a","b"))
; msgbox bindMap[1]["a"]
; apiCache.invalidateRecord(apiCache.generateFingerprint(url))

; out := apiCache.retrieve(url)
; out := apiCache.findRecords("")
; apiCache.begin()
; for k,v in out {

    ; apiCache.retrieve(url)
    ; tooltip a_index " / " out.length
    ; if (a_index=25)
    ;     break
; }
; apiCache.commit()
    ; apiCache.nuke(1)
; loop out.length
    ; msgbox(a_index ": " out[a_index]["url"])
; msgbox(apiCache.lastServedSource)
; apiCache.invalidateRecord(apiCache.generateFingerprint(url))

; purgeArr := []
; purgeArr.push(apiCache.generateFingerprint(url))
; apiCache.invalidateRecords(purgeArr)

; msgbox 

;apiCache.exportUncompressedDb(a_scriptdir "\v2test.db",1)
; apiCache.CloseDB()
ExitApp
;apiCache.init(A_ScriptDir "\cache",A_ScriptDir "\winApi.db")

;msgbox % apiCache.lastResponseHeaders
;foundRecords := apiCache.findRecords(,"adhoc",,,1)
;msgbox % foundRecords.Count() ;"`n`n" st_printarr(foundRecords)



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

/**
 * Prints the formatted value of a variable (number, string, object).
 * Leaving all parameters empty will return the current function and newline in an Array: [func, newline]
 * @param value Optional: the variable to print. 
 *     If omitted then new settings (output function and newline) will be set.
 *     If value is an object/class that has a ToString() method, then the result of that will be printed.
 * @param func Optional: the print function to use. Default is OutputDebug.
 *     Not providing a function will cause the Print output to simply be returned as a string.
 * @param newline Optional: the newline character to use (applied to the end of the value). 
 *     Default is newline (`n).
 */
 Print(value?, func?, newline?) {
	static p := OutputDebug, nl := "`n"
	if IsSet(func)
		p := func
	if IsSet(newline)
		nl := newline
	if IsSet(value) {
		val := IsObject(value) ? ToString(value) nl : value nl
		return HasMethod(p) ? p(val) : val
	}
	return [p, nl]
}

/**
 * Converts a value (number, array, object) to a string.
 * Leaving all parameters empty will return the current function and newline in an Array: [func, newline]
 * @param value Optional: the value to convert. 
 * @returns {String}
 */
 ToString(val?) {
    if !IsSet(val)
        return "unset"
    valType := Type(val)
    switch valType, 0 {
        case "String":
            return "'" val "'"
        case "Integer", "Float":
            return val
        default:
            self := "", iter := "", out := ""
            try self := ToString(val.ToString()) ; if the object has ToString available, print it
            if valType != "Array" { ; enumerate object with key and value pair, except for array
                try {
                    enum := val.__Enum(2) 
                    while (enum.Call(&val1, &val2))
                        iter .= ToString(val1) ":" ToString(val2?) ", "
                }
            }
            if !IsSet(enum) { ; if enumerating with key and value failed, try again with only value
                try {
                    enum := val.__Enum(1)
                    while (enum.Call(&enumVal))
                        iter .= ToString(enumVal?) ", "
                }
            }
            if !IsSet(enum) && (valType = "Object") && !self { ; if everything failed, enumerate Object props
                for k, v in val.OwnProps()
                    iter .= SubStr(ToString(k), 2, -1) ":" ToString(v?) ", "
            }
            iter := SubStr(iter, 1, StrLen(iter)-2)
            if !self && !iter && !((valType = "Array" && val.Length = 0) || (valType = "Map" && val.Count = 0) || (valType = "Object" && ObjOwnPropCount(val) = 0))
                return valType ; if no additional info is available, only print out the type
            else if self && iter
                out .= "value:" self ", iter:[" iter "]"
            else
                out .= self iter
            return (valType = "Object") ? "{" out "}" : (valType = "Array") ? "[" out "]" : valType "(" out ")"
    }
}


/************************************************************************
 * @description Read and write gzip data using libarchive
 * @file gzip.ahk
 * @author thqby
 * @date 2023/10/01
 * @version 1.0.0
 ***********************************************************************/

 class gzip {
	/**
	 * Decompress the gzip data
	 * @param {Buffer|Integer} data Data to be decompressed
	 * @param {Integer} size Data size
	 * @returns {Buffer}
	 */
	static decode(data, size?) {
		gz := this.reader()
		r := gz.read_support_filter_gzip() || gz.read_support_format_raw() ||
			gz.read_open_memory(data, size ?? data.size) || gz.read_next_header(0)
		if r < 0
			throw Error(gz.error_string())
		buf := Buffer()
		while !r := gz.read_data_block(&data := 0, &size := 0, &offset := 0)
			buf.Size += size, DllCall('RtlMoveMemory', 'ptr', buf.Ptr + offset, 'ptr', data, 'uptr', size)
		if r > 0
			return buf
		throw Error(gz.error_string())
	}
	/**
	 * Compress data into gzip
	 * @param {Buffer|Integer} data Data that needs to be compressed
	 * @param {Integer} size Data size
	 * @param {Integer} compression_level 0~9 compression levels, up to 9, with the highest compression rate but the slowest compression speed
	 * @returns {Buffer}
	 */
	static encode(data, size?, compression_level?) {
		size := size ?? data.size, gz := gzip.writer(), buf := Buffer((bufsize := size + 56) + 8)	; Reserved 56 + 8 bytes
		pused := buf.Ptr + bufsize, entry := gzip.entry(), entry.entry_set_filetype(32768)	; IFREG
		r := gz.write_add_filter_gzip() || gz.write_set_format_raw() ||
			IsSet(compression_level) && gz.write_set_options('compression-level=' compression_level) ||
			gz.write_open_memory(buf, bufsize, pused := buf.Ptr + bufsize) ||
			gz.write_header(entry) || (gz.write_data(data, size), gz.write_close())
		if r < 0
			throw Error(gz.error_string())
		if !(buf.Size := NumGet(pused, 'uptr'))
			throw Error('Failed')
		return buf
	}
	static __New() {
		#DllLoad archiveint.dll
		mod := DllCall('GetModuleHandle', 'str', 'archiveint', 'ptr'), is_32bit := A_PtrSize = 4
		get_proc_addr := !is_32bit ? (name, *) => DllCall('GetProcAddress', 'ptr', mod, 'astr', 'archive_' name, 'ptr')
			: (name, argsize) => DllCall('GetProcAddress', 'ptr', mod, 'astr', '_archive_' name '@' argsize, 'ptr')
		base_reader := this.DeleteProp('Prototype'), base_writer := base_reader.Clone(), base_entry := base_reader.Clone()
		read_new := write_new := entry_new := 0
		for k, v in Map('reader', 'read', 'writer', 'write', 'entry', 'entry') {
			(base := base_%k%).__Class := 'gzip.' k, %v%_new := DllCall.Bind(get_proc_addr(v '_new', 0))
			base.DefineProp('__Delete', { call: DllCall.Bind(get_proc_addr(v '_free', 4), 'ptr') })
			this.DefineProp(k, { call: ((base, new, *) => { base: base, ptr: new() }).Bind(base, %v%_new) })
		}

		; load archive_read_xx
		base := base_reader
		load('error_string', 'ptr', , 'astr')
		load('read_data_block', 'ptr', , 'ptr*', , 'uptr*', , 'int64*', unset)
		load('read_next_header', 'ptr', , 'ptr*', unset)
		load('read_open_memory', 'ptr', , 'ptr', , 'uptr', unset)
		load('read_support_filter_gzip', 'ptr', unset)
		load('read_support_format_raw', 'ptr', unset)

		; load archive_write_xx
		base := base_writer
		base.DefineProp('error_string', { call: base_reader.error_string })
		load('write_add_filter_gzip', 'ptr', unset)
		load('write_close', 'ptr', unset)
		load('write_data', 'ptr', , 'ptr', , 'uptr', unset)
		load('write_header', 'ptr', , 'ptr', unset)
		load('write_open_memory', 'ptr', , 'ptr', , 'uptr', , 'ptr', unset)
		load('write_set_format_raw', 'ptr', unset)
		load('write_set_options', 'ptr', , 'astr', unset)

		; load archive_entry_xx
		base := base_entry
		load('entry_set_filetype', 'ptr', , 'ushort', unset)

		load(name, args*) {
			argsize := 0
			loop is_32bit && (args.Length >> 1)
				argsize += args[A_Index * 2 - 1] = 'int64' ? 8 : 4
			base.DefineProp(name, { call: DllCall.Bind(p := get_proc_addr(name, argsize), args*) })
			if !p
				MsgBox
		}
	}
}

class fingerprint{

	retrieve(url, &post := "", outHeadersMap := Map(), &options := "", expiry?, forceBurn?){
		return this.generateFingerprint(url)
}


	generateFingerprint(url,headers?){
		;returns a concatonated hash of the outgoing url+headers
		;fingerprint is either 128 or 256 characters, depending on if headers has content
		; msgbox url
		return this.hash(&url,"SHA512") . (!IsSetRef(&headers)?"":this.hash(&headers,"SHA512")) 
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