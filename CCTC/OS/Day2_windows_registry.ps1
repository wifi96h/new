# What registry subkey runs every time the machine reboots? The flag is the full path, using PowerShell.
HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

# What registry subkey runs every time a user logs on? The flag is the full path, using PowerShell.
HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

# What registry subkey runs a single time, then deletes its value once the machine reboots? The flag is the full path, using PowerShell.
HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce

# What registry subkey runs a single time, then deletes its value when a user logs on? The flag is the full path, using PowerShell.
HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce

# What is the suspicious value inside of the registry subkey that loads every time the "Student" user logs on?
wmic useraccount get name,sid 
New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS
get-item hku:\S-1-5-21-2881336348-3190591231-4063445930-1003\software\microsoft\windows\currentversion\run

#What is the value inside of the registry subkey that loads a single time when the "student" user logs on?
wmic useraccount get name,sid 
New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS
get-item hku:\S-1-5-21-2881336348-3190591231-4063445930-1003\software\microsoft\windows\currentversion\runonce

# Figure out the manufacturer's name of the only USB drive that was plugged into this machine.
# lots of ways to get this one
get-disk | where-object -filterscript {$_.bustype -eq 'USB'}
Get-CimInstance -ClassName Win32_DiskDrive | where{$_.InterfaceType -eq 'USB'}
gwmi win32_diskdrive | where{$_.Interfacetype -eq "USB"}
GET-WMIOBJECT win32_diskdrive | Where { $_.InterfaceType –eq ‘USB’ }

