@echo on
cd C:\Windows
@powershell (new-object System.Net.WebClient).DownloadFile('https://raw.githubusercontent.com/ceramicskate0/sysmon-config/master/sysmonconfig-export.xml','C:\Windows\sysmonconfig-export.xml')"
sysmon -c sysmonconfig-export.xml
rm sysmonconfig-export.xml
exit
