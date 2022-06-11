# class_apiCache
fast and flexible api caching library for AHK


##TODO, IN NO REAL ORDER:
- [ ] implement libcurl instead of WinHttpRequest
- [ ] bulk download+import   [probably needs libcurl first]
- [ ] bulk record fetch
- [x] implement sideloading
- [ ] optimize reliable sizing on inserts [currently using valid but slightly inefficient method]
- [x] implement extracting fingerprints to disk
- [x] implement bulk extraction to disk
- [ ] transition to prepared statements  [probably after the rest of the features are stable]
- [x] enable exporting uncompressed dbs [done, but needs polish]
- [ ] bundle dlls in auto-extracting functions [single file library] [partially implemented, needs significant optimization and polish]
