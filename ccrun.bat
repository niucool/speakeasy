@echo off
:: Check if a file parameter was provided
if "%~1"=="" (
    echo Error: No file parameter provided.
    echo Usage: ccrun.bat [filename]
    exit /b 1
)

:: Run abc.exe with the parameter and redirect output
build\debug\speakeasy-cli.exe -v -t "%~1" > "%~1.cpp.log"
echo "%~1.cpp.log"
