@signtool.exe sign /v /fd sha256 /f sign_app_cer.pfx /kc "[{{0000}}]=te-da1715c3-4d28-4660-bf73-84258fd37e19" /csp "eToken Base Cryptographic Provider"  /tr http://timestamp.digicert.com?td=sha256 /td sha256 %1

