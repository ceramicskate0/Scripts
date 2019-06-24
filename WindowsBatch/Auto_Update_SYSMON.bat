@echo on
cd C:\ProgramData\sysmon\
@powershell (new-object System.Net.WebClient).DownloadFile('https://raw.githubusercontent.com/ceramicskate0/sysmon-config/master/sysmonconfig-export.xml','C:\ProgramData\sysmon\sysmonconfig-export.xml')"
sysmon -c sysmonconfig-export.xml
exit
