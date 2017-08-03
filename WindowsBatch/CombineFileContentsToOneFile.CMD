echo off
::folder to combine into file
set /p ScanDir=Enter Dir that only has the Files to combine:
set /p FileToCombineTo=Enter the full path of the file to combine to:

cd %ScanDir%

FOR %%a IN (*) do (
type %%a >> %FileToCombineTo%
)
