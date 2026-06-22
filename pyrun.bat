@echo off
:: Check if a file parameter was provided
if "%~1"=="" (
    echo Error: No file parameter provided.
    echo Usage: pyrun.bat [filename]
    exit /b 1
)

:: Run abc.exe with the parameter and redirect output
python sptest.py -v "%~1" > "%~1.py.log" 2>&1
echo "%~1.py.log"
