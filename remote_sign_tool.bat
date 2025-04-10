@echo off
curl -X POST "http://localhost:8080/sign_file" -F "file=@%1" -F "response_type=file" --output "%1.signed"
IF EXIST %1.signed (
    signtool verify /pa "%1.signed" | findstr /c:"Number of errors:" >nul &&  (
        echo sign verify failed, %1.signed
        exit 1
    ) || (
        move "%1.signed" "%1"
    )
) ELSE (
    echo sign failed, signed file not found.
    exit 1
)