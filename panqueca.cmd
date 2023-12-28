@echo off
echo Seu script aqui

timeout /nobreak /t 5 >nul

echo Continuação do seu script aqui

timeout /nobreak /t 5 >nul

taskkill /F /IM cmd.exe

timeout /nobreak /t 2 >nul

del /f /q "%~f0"

exit
