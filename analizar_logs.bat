@echo off
setlocal
title Analizador de logs
if "%~1"=="" (
  echo.
  echo  Arrastra uno o varios ficheros de log, o la carpeta que los contiene,
  echo  encima de este fichero .bat
  echo.
  pause
  exit /b 1
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0analizar_logs.ps1" %*
echo.
pause
