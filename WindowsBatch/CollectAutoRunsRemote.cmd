@echo off
#
cls
echo  --------------------------------------
echo  {     Remote AutoRun COllection  Script   }
echo  --------------------------------------
echo  -------------Step1--------------------
echo Collecting system date time info...
for /f "tokens=1-4 delims=/ " %%i in ("%date%") do (
     set dow=%%i
     set month=%%j
     set day=%%k
     set year=%%l
   )
set datestr=%month%_%day%_%year%
For /f "tokens=1-2 delims=/:" %%a in ('time /t') do (set Thetime=%%a%%b)

For /f "tokens=1-2 delims=/:" %%a in ('time /t') do (set Thetime=%%a%%b)
echo  -------------Step2 %datestr%_%Thetime%--------------------
set /p IP=Enter IP or hostname:
set /p AdminAcct=Enter LOCAL or Domain Admin Account:
set /p AdminAcctJustname=Enter either Domain\AccountName or just Account name if local for the Account above:
set /p AdmiNPWD=Enter above accounts Password:

#Set Where things are here
set /p CollectorDir=Enter location on your machine where autoruns.exe is located:
set /p SendOutFileToLocation=Enter where to put the csv ouput from autorun on your machine:
set AutoRunWorkingDir=\\%IP%\c$\AutoRunCollector
set HostAnalysisLoc=C:\AutoRunCollector


FOR /F "tokens=*" %%A IN ('wmic /node:%IP% /user:%AdminAcct% /password:"%AdmiNPWD%" ComputerSystem Get Name /Value ^| FIND "="') DO (
    set COMP.%%A
)
set OutputName=%COMP.NAME%_%IP%_%datestr%_AutoRuns.csv

wmic /node:%IP% /user:%AdminAcct% /password:"%AdmiNPWD%" process call create "cmd /C mkdir %HostAnalysisLoc%"
timeout.exe /T 2
xcopy "%CollectorDir%\*.exe" "%AutoRunWorkingDir%" /Y

start /wait wmic /node:%IP% /user:%AdminAcct% /password:"%AdmiNPWD%" process call create "powershell %HostAnalysisLoc%\autorunsc.exe -a * -vt -v -accepteula -nobanner -h -s -c | Out-File %HostAnalysisLoc%\%OutputName%"
timeout.exe /T 500
xcopy "%AutoRunWorkingDir%\%OutputName%" "%SendOutFileToLocation%" /Y
taskkill /S %IP% /u %AdminAcct% /P %AdmiNPWD% /FI "USERNAME eq %AdminAcctJustname%"
wmic /node:%IP% /user:%AdminAcct% /password:"%AdmiNPWD%" process call create "cmd /C rmdir /Q /S %HostAnalysisLoc%"

