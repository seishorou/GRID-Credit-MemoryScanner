@echo off
setlocal
cd /d "%~dp0"

where cl >nul 2>nul
if errorlevel 1 (
  echo.
  echo ERRO: compilador CL nao encontrado.
  echo Abra o "Developer Command Prompt for Visual Studio" e execute este BAT novamente.
  echo.
  pause
  exit /b 1
)

echo Compilando GRID_Credit_MemoryScanner.exe...
cl /nologo /EHsc /O2 /MT /D_WIN32_WINNT=0x0601 /DWINVER=0x0601 ^
  GRID_Credit_MemoryScanner.cpp /link /SUBSYSTEM:CONSOLE /OUT:GRID_Credit_MemoryScanner.exe psapi.lib

if errorlevel 1 (
  echo.
  echo A compilacao falhou.
  pause
  exit /b 1
)

echo.
echo Compilacao concluida:
echo %CD%\GRID_Credit_MemoryScanner.exe
echo.
pause
