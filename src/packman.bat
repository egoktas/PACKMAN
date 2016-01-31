echo off
@SETLOCAL
cls
echo.

REM #####################
REM set global variables:
REM #####################
set TOOL_NAME=packman
set WF_ROOT=C:\Users\pmat\Desktop\packman
set PIN_ROOT=C:\Users\pmat\Desktop\pin

REM set TIMESTAMP
For /f "tokens=2-4 delims=/ " %%a in ('date /t') do (set mydate=%%c-%%a-%%b)
For /f "tokens=1-2 delims=/:" %%a in ("%TIME%") do (set HOURS=%%a& set MINS=%%b)
  if %HOURS% ==  0 (set HOURS=00)
  if %HOURS% ==  1 (set HOURS=01)
  if %HOURS% ==  2 (set HOURS=02)
  if %HOURS% ==  3 (set HOURS=03)
  if %HOURS% ==  4 (set HOURS=04)
  if %HOURS% ==  5 (set HOURS=05)
  if %HOURS% ==  6 (set HOURS=06)
  if %HOURS% ==  7 (set HOURS=07)
  if %HOURS% ==  8 (set HOURS=08)
  if %HOURS% ==  9 (set HOURS=09)
set mytime=%HOURS%-%MINS%
set TIMESTAMP=%mydate%_%mytime%

REM check first argument
if "%~1"=="clean" GOTO CLEAN
if "%~1"=="compile" GOTO COMPILE
if "%~1"=="analyze" GOTO ANALYZE
if "%~1"=="" GOTO EMPTY

:COMPILE
echo ^>^> Compiling PACKMAN! ^<^<
nmake.exe /NOLOGO /f Nmakefile %TOOL_NAME%
GOTO DONE

:ANALYZE
if "%~2"=="" GOTO EMPTY
echo ^>^> Analyzing %2 ^<^<

set EXE_FILE=%2
For %%A in ("%EXE_FILE%") do (
	REM %%~nxA = filename WITH    extention
	REM %%~nA  = filename withOUT extention
    Set EXE_FILE_NAME_NO_EXT=%%~nA
)

nmake.exe /NOLOGO /f Nmakefile
GOTO DONE

:CLEAN
echo ^>^> Cleaning! ^<^<
nmake.exe /NOLOGO /f Nmakefile clean 
GOTO DONE

:EMPTY
echo ^> Missing parameters! 
echo ^> - Analyze an executable:   packman analyze ^<exe_file_location^> 
echo ^> - Compile PACKMAN:         packman compile
echo ^> - Clean compilation files: packman clean
GOTO DONE

:DONE
echo.
echo ^>^> Done! ^<^<
