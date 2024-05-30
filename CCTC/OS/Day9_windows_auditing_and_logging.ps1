# Find the questionable website that a user browsed to (using Chrome), that appears to be malicious. *Note: There are more than one users on the box.
get-localuser | select-object name,sid
net use * http://live.sysinternals.com
Z:\strings.exe 'C:\users\student\AppData\Local\Google\Chrome\User Data\Default\History' -accepteula

# There is a file that was recently opened that may contain PII. Get the flag from the contents of the file.
Get-Item 'Registry::\HKEY_USERS\*\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.*'
Get-Item "REGISTRY::HKEY_USERS\*\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.txt" | select -Expand property | ForEach-Object {[System.Text.Encoding]::Default.GetString((Get-ItemProperty -Path "REGISTRY::HKEY_USERS\*\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.txt" -Name $_).$_)}
get-content c:\users\student\documents\3-14-24.txt

# Enter the full path of the program that was run on this computer from an abnormal location.
Get-ComputerInfo | select osname,osversion,OsHardwareAbstractionLayer
Get-Item HKLM:\SYSTEM\CurrentControlSet\Services\bam\UserSettings\*  
get-itemproperty HKLM:\SYSTEM\CurrentControlSet\Services\bam\UserSettings\S-1-5-21-2881336348-3190591231-4063445930-1001

# Enter the name of the questionable file in the prefetch folder.
Get-Childitem -Path 'C:\Windows\Prefetch' -ErrorAction Continue

# Recover the flag from the Recycle Bin. Enter the name of the recycle bin file that contained the contents of the flag, and the contents of the deleted file. Include the file extension in your answer.
Get-Childitem 'C:\$RECYCLE.BIN' -Recurse -Verbose -Force | select FullName
get-content 'C:\$RECYCLE.BIN\S-1-5-21-2881336348-3190591231-4063445930-1003\*.txt'


# Check event logs for a "flag" string.
Get-Eventlog -LogName System | ft -wrap | findstr /i flag
