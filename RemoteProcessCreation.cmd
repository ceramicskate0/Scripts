@ echo off
echo --------------------------------------
echo 	Remote Process X
echo --------------------------------------
set /p TargetMachineIP=TARGET IP:
set /p AdminAccount=RUN option local/domain and ADMIN:
set /p AdminAccountName=Enter account
set /p pass=Admin PASSWORD:
for /f "tokens=1-4 delims=/ " %%i in ("%date%") do (
     set dow=%%i
     set month=%%j
     set day=%%k
     set year=%%l
   )
set datestr=%month%_%day%_%year%
set OutPutFileName=%TargetMachineName%_%datestr%_AdminCMDOutput.txt
echo --------------------------------------
echo Getting Machine Name...
echo --------------------------------------
set TargetMachineName = wmic /AUTHLEVEL:Pktprivacy /node:%TargetMachineIP% /user:%AdminAccount% /password:"%pass%" computersystem get name
echo --------------------------------------
echo Creating Process on %TargetMachineName% Remote Machine...
:loop
	echo --------------------------------------
	echo Enter Commandline Args: 'q', when done
	set /p command=Enter Commandline Args:
if /I NOT %command%==q (	
	if %command%==q goto end
	wmic /AUTHLEVEL:Pktprivacy /node:%TargetMachineIP% /user:%AdminAccount% /password:"%pass%" process call create "cmd.exe /c %command% >> \\%TargetMachineIP%\c$\Users\%AdminAccountName%\%OutPutFileName%"
	goto loop
	) else goto end
	
:end
echo --------------------------------------
echo Killing C2 process...
echo --------------------------------------
wmic /AUTHLEVEL:Pktprivacy /node:%TargetMachineIP% /user:%AdminAccount% /password:"%pass%" process where name="cmd.exe" call terminate
echo --------------------------------------
set /p end=Press enter when done...
