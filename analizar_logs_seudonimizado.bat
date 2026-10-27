@echo off
setlocal
title Analizador de logs (IPs seudonimizadas)
if "%~1"=="" (
  echo.
  echo  Arrastra uno o varios ficheros de log, o la carpeta que los contiene,
  echo  encima de este fichero .bat. Las IPs saldran como codigos hash.
  echo.
  pause
  exit /b 1
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0analizar_logs.ps1" -Seudonimizar %*
echo.
pause
