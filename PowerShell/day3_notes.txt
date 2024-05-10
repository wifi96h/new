
PNS Public
Day 3 PowerShell Facilitation Guide WOBC
Table of Contents

    Output Formatting
        Sort-Object
        Filter Left, Sort Right
        Select-Object
        Where-Object
        Group-Object
    Script Constructs (Conditional Loops and Switches)
        If/Elseif/Else
        Switch
        While Loop
        Do While
        Do Until
        Foreach
        ForEach-Object
    Windows Management Instrumentation (WMI) and Common Information Model (CIM)
    PowerShell Remoting (PS Remoting)
        Just Enough Administration (JEA)
        Windows Remote Management (WinRM)
        Enter-PSSession
        Invoke-Command
    Summary
        Today we discussed

Output Formatting

When you are working with large amounts of data, sometimes it is hard to find what you are looking for. Performing output formatting on the data reduces the amount of unwanted data to pinpoint what you are searching for in a more efficient manner.
Sort-Object

    Sort-Object sorts the data by user defined property values

List the contents of a directory and sort the files by name, alphabetically

PS C:\> Get-ChildItem | Sort-Object

Sort files by size, largest to smallest

PS C:\> Get-ChildItem | Sort-Object -Property Length -Descending

Sort the output of a Get-NetTCPConnection and return the first 10 results, descending by remote IP address.

PS C:\> Get-NetTCPConnection | Select-Object -Property RemoteAddress, RemotePort, State | Sort-Object -Property RemoteAddress -Descending | Select-Object -First 10
    RemoteAddress  RemotePort       State
    -------------  ----------       -----
    99.83.228.14          443 Established
    99.83.228.14          443 Established
    99.83.228.14          443 Established
    99.83.228.14          443 Established
    75.2.84.65            443 Established
    75.2.116.105          443 Established
    52.159.126.152        443 Established
    52.127.72.34          443 Established
    52.127.72.34          443 Established
    52.127.64.27          443 Established

Filter Left, Sort Right

In order to maximize efficiency in your PowerShell code, always filter before sorting. This ensures that PowerShell eliminates the amount of data it has to parse before displaying the data. Below are some examples of an inefficient command and an efficient command measured by time to complete.
Low efficiency command

PS C:\> Get-Process | Sort-Object -Property Id | Select-Object Name, Id

PS C:\> Measure-Command { Get-Process | Sort-Object -Property Id | Select-Object Name, Id }
    Days              : 0
    Hours             : 0
    Minutes           : 0
    Seconds           : 0
    Milliseconds      : 22
    Ticks             : 227313
    TotalDays         : 2.6309375E-07
    TotalHours        : 6.31425E-06
    TotalMinutes      : 0.000378855
    TotalSeconds      : 0.0227313
    TotalMilliseconds : 22.7313

Higher efficiency command

PS C:\> Get-Process | Select-Object Name, Id | Sort-Object -Property Id

PS C:\> Measure-Command { Get-Process | Select-Object Name, Id | Sort-Object -Property Id }
    Days              : 0
    Hours             : 0
    Minutes           : 0
    Seconds           : 0
    Milliseconds      : 16
    Ticks             : 166182
    TotalDays         : 1.92340277777778E-07
    TotalHours        : 4.61616666666667E-06
    TotalMinutes      : 0.00027697
    TotalSeconds      : 0.0166182
    TotalMilliseconds : 16.6182

The performance difference seems minor in the above examples. However, when working with commands that gather data from multiple machines, or over the network, the difference in efficiency could be a significant factor in time to complete.
Select-Object

    Sometimes you may want to display only specific object properties. This may cut down on data that is displayed and help you find a needle in the haystack. You can do this with Select-Object.

        This command is like the Linux awk command whereas you can display columns of data

        This command also has Linux head/tail functionality

        This command requires you to pipe data to it

        Properties that will be displayed are comma separated

    This command also allows column headers to be stripped off data.

        Use the -ExpandProperty Parameter

Display properties of the Get-Process command, also demonstrates similarities with Linux head and tail commands.

PS C:\> Get-Process | Select-Object -Property Name, ID -First 5
    Name                         Id
    ----                         --
    AcrobatNotificationClient 15892
    acrotray                  17964
    AdobeCollabSync            8396
    AdobeCollabSync           15752
    AdobeNotificationClient    3860

PS C:\> Get-Process | Select-Object -Property Name, ID -Last 5
    Name                      Id
    ----                      --
    wininit                  836
    winlogon                1204
    WINWORD                14884
    WMIRegistrationService  4148
    WUDFHost                 904

Use -ExpandProperty to remove the column header.

PS C:\> Get-Process | Select-Object -ExpandProperty Name -First 5
    AcrobatNotificationClient
    acrotray
    AdobeCollabSync
    AdobeCollabSync
    AdobeNotificationClient

PS C:\> Get-Process | Select-Object -ExpandProperty Name -Last 5
    wininit
    winlogon
    WINWORD
    WMIRegistrationService
    WUDFHost

Where-Object

    PowerShell can filter data based on very specific criteria. To do this, use the Where-Object command

        Where-Object requires data be piped to it

        Where-Object statements can be written with and without the scriptblock { }

        Using the scriptblock allows having multiple conditions

        Can be used with the $_ special PowerShell pipeline current object variable

Where-Object with a single condition with and without the $_ special pipeline variable

PS C:\> Get-Service | Where-Object { $_.Status -eq 'running' } | Select-Object -First 5
    Status   Name               DisplayName
    ------   ----               -----------
    Running  AdobeARMservice    Adobe Acrobat Update Service
    Running  AdobeUpdateService AdobeUpdateService
    Running  Appinfo            Application Information
    Running  AppXSvc            AppX Deployment Service (AppXSVC)
    Running  AudioEndpointBuil… Windows Audio Endpoint Builder

PS C:\> Get-Service | Where-Object Status -eq 'running'| Select-Object -Last 5
    Status   Name               DisplayName
    ------   ----               -----------
    Running  WpnService         Windows Push Notifications System Ser…
    Running  WpnUserService_e9… Windows Push Notifications User Servi…
    Running  wscsvc             Security Center
    Running  WSearch            Windows Search
    Running  wuauserv           Windows Update

Where-Object with multiple conditions using the $_ special pipeline variable

PS C:\> Get-Service | Where-Object { $_.Status -eq 'running' -and $_.name -like 'WIN*'}
    Status   Name               DisplayName
    ------   ----               -----------
    Running  WinDefend          Microsoft Defender Antivirus Service
    Running  WinHttpAutoProxyS… WinHTTP Web Proxy Auto-Discovery Serv…
    Running  Winmgmt            Windows Management Instrumentation

Group-Object

    It may be helpful to gather files into groups to better track if large numbers of files have been added or removed.

    Use the Group-Object command to group objects.

	Malware could be introduced or 'dropped' into the C:\Windows\System32 directory due to the large number of .dll files located there. The Group-Object command can help group the files into manageable groups and help you keep track of or baseline the files in this directory.
Group files by extension and sort them by count, descending

PS C:\> Get-ChildItem -Path C:\Windows\System32 | Group-Object -Property Extension | Sort-Object -Property Count -Descending | Select-Object -First 5
    Count Name                      Group
    ----- ----                      -----
    3733 .dll                      {C:\Windows\System32\69fe178f-26e7-43a9-aa7d-2b616b672dde_eventlogservice.dll, C:\Wind…
    673 .exe                      {C:\Windows\System32\agentactivationruntimestarter.exe, C:\Windows\System32\AgentServi…
    147                           {C:\Windows\System32\0409, C:\Windows\System32\AdvancedInstallers, C:\Windows\System32…
    120 .NLS                      {C:\Windows\System32\C_037.NLS, C:\Windows\System32\C_10000.NLS, C:\Windows\System32\C…
    80 .png                      {C:\Windows\System32\@AdvancedKeySettingsNotification.png, C:\Windows\System32\@AppHel…

Script Constructs (Conditional Loops and Switches)

Think of a condition as a question with the answer being either positive (true) or negative (false). Nearly all questions are phrased with comparisons in PowerShell.
If/Elseif/Else

Where-Object is insufficient when longer code segments are needed. Once the condition is met, the If statement terminates. You can use an If/Elseif/Else statement to make decisions. You can also use it to evaluate data that you have queried or user input.
Standard If/Elseif/Else Syntax

If (condition) {
    # Code to be executed if condition applies
} Elseif (different condition) {
    # Code to be executed if different condition applies
} Else {
    # Code to be executed if none of the conditions apply
}

if/elseif/else statement to determine which address range an IP address falls within

PS C:\>
$ipAddressString = "172.64.0.100"
$ipAddress = [System.Net.IPAddress]::Parse($ipAddressString)

if ($ipAddress.AddressFamily -eq 'InterNetwork' -and (
    ($ipAddress.IPAddressToString -ge [System.Net.IPAddress]::Parse("10.0.0.0").IPAddressToString -and $ipAddress.IPAddressToString -le [System.Net.IPAddress]::Parse("10.255.255.255").IPAddressToString) -or
    ($ipAddress.IPAddressToString -ge [System.Net.IPAddress]::Parse("172.16.0.0").IPAddressToString -and $ipAddress.IPAddressToString -le [System.Net.IPAddress]::Parse("172.31.255.255").IPAddressToString) -or
    ($ipAddress.IPAddressToString -ge [System.Net.IPAddress]::Parse("192.168.0.0").IPAddressToString -and $ipAddress.IPAddressToString -le [System.Net.IPAddress]::Parse("192.168.255.255").IPAddressToString)))
{
    Write-Output "The IP $ipAddressString is in the private IP address space."
} elseif ($ipAddress.AddressFamily -eq 'InterNetwork' -and (
    ($ipAddress.IPAddressToString -ge [System.Net.IPAddress]::Parse("0.0.0.0").IPAddressToString -and $ipAddress.IPAddressToString -le [System.Net.IPAddress]::Parse("9.255.255.255").IPAddressToString) -or
    ($ipAddress.IPAddressToString -ge [System.Net.IPAddress]::Parse("11.0.0.0").IPAddressToString -and $ipAddress.IPAddressToString -le [System.Net.IPAddress]::Parse("172.15.255.255").IPAddressToString) -or
    ($ipAddress.IPAddressToString -ge [System.Net.IPAddress]::Parse("172.32.0.0").IPAddressToString -and $ipAddress.IPAddressToString -le [System.Net.IPAddress]::Parse("192.167.255.255").IPAddressToString) -or
    ($ipAddress.IPAddressToString -ge [System.Net.IPAddress]::Parse("192.169.0.0").IPAddressToString -and $ipAddress.IPAddressToString -le [System.Net.IPAddress]::Parse("255.255.255.255").IPAddressToString)))
{
    Write-Output "The IP $ipAddressString is in the public IP address space."
} else {
    Write-Output "$ipAddressString is an Invalid IP address."
}

    The IP 172.64.0.100 is in the public IP address space.

	The above if/elseif/else statement will error out if an invalid IP address is stored in the variable. This can be solved using error handling, which will be covered in a lesson on Day 4.
If Statement using a stored variable from a PSDrive

PS C:\> $FreeSpace = (Get-PSDrive -PSProvider FileSystem | Select-Object -Property @{Name='GBFree'; Expression={[math]::Round($_.Free / 1GB, 2)}} -First 1).GBFree
PS C:\> if ($FreeSpace -lt 250) {
            Write-Host "You have less than 250GB of disk space available"
        }

If Else using a stored variable from a PSDrive

PS C:\> $FreeSpace = (Get-PSDrive -PSProvider FileSystem | Select-Object -Property @{Name='GBFree'; Expression={[math]::Round($_.Free / 1GB, 2)}} -First 1).GBFree
PS C:\> if($FreeSpace -gt 250) {
            Write-Host "You have more than 250GB of disk space available"
        } else {
            Write-Host "You have less than 250GB of disk space available"
        }

If Elseif Else using a user stored custom variable and multiple elseif conditions

PS C:\> $FreeSpace = .5
PS C:\> if($FreeSpace -gt 250) {
            Write-Host "You have more than 250GB of disk space available"
        } elseif (($FreeSpace -gt 100) -and ($FreeSpace -lt 250)){
            Write-Host "You have more than 100GB of disk space, but less then 250GB available"
        } elseif (($FreeSpace -lt 100) -and ($FreeSpace -gt 1)){
            Write-Host "You have less than 100GB of disk space available"
        } elseif ($FreeSpace -lt 1) {
            Write-Host "Get a new hard drive!"
        } else {
            Write-Host "You have less than 250GB of disk space available"
        }

    Get a new hard drive!

Switch

The Switch construct evaluates a single variable or item against multiple values and has a script block for each value. The script block for each value is run if that value matches the variable.
Simple Switch Syntax

PS C:\> Switch (3) {
            1 { Write-Host "You selected menu item 1" }
            2 { Write-Host "You selected menu item 2" }
            3 { Write-Host "You selected menu item 3" }
            Default { Write-Host "You did not select a valid option" }
        }

    You selected menu item 3

Switch using the -WildCard parameter for pattern matching

PS C:\> $ip = '172.64.0.100'
PS C:\> Switch -WildCard ($ip) {
            "192.168.*" { Write-Host "This computer is on the internal local area network" }
            "10.15.*" { Write-Host "This computer is in the Branch network" }
            "172.64.*" { Write-Host "This computer is in the DMZ network" }
            Default { Write-Host "This computer is not on the network" }
        }

    This computer is in the DMZ network

Switch using the Default value

PS C:\> $ip = '8.8.8.8'
PS C:\> Switch -WildCard ($ip) {
            "192.168.*" { Write-Host "This computer is on the internal local area network" }
            "10.15.*" { Write-Host "This computer is in the Branch network" }
            "172.64.*" { Write-Host "This computer is in the DMZ network" }
            Default { Write-Host "This computer is not on the network" }
        }

    This computer is not on the network

Switch using all values with an array

PS C:\> $ipArray = @('172.64.0.100', '10.50.35.169','10.15.0.100','22.25.55.255')
PS C:\> $ipArray | ForEach-Object {
            $ip = $_
            $index = $ipArray.IndexOf($ip)

            switch -Wildcard ($ip) {
                "192.168.*" { Write-Host ("$ip is on the internal local area network") }
                "10.15.*" { Write-Host ("$ip is in the Branch network") }
                "172.64.*" { Write-Host ("$ip is in the DMZ network") }
                Default { Write-Host ("$ip is not on the network") }
            }
        }

    172.64.0.100 is in the DMZ network
    10.50.35.169 is on the internal local area network
    10.15.0.100 is in the Branch network
    22.25.55.255 is not on the network

	An If statement terminates after the first condition is met. A Switch statement is used if there are multiple comparison values that meet the condition.
While Loop

    The while statement (also known as a while loop) is a language construct for creating a loop that runs commands in a script block as long as a conditional test evaluates to true.

While syntax

while (<condition>){<statement list>}

While Loop used to check running processes every 5 seconds for the msedge process

PS C:\> $processToMonitor = "msedge"
        while ($true) {
            if (Get-Process -Name $processToMonitor -ErrorAction SilentlyContinue) {
                Write-Host "Warning: $processToMonitor is running! Possible security threat."
            }

            Start-Sleep -Seconds 5
        }

PS C:\> .\WhileLoopDemo.ps1
    Warning: msedge is running! Possible security threat.
    Warning: msedge is running! Possible security threat.
    Warning: msedge is running! Possible security threat.
    Warning: msedge is running! Possible security threat.

Do While

    The Do/While statement runs through a collection of information based on whether or not the condition evaluates to $true. This type of loop is different from the while loop because it will run at least once.

Syntax

do {
    code block
}while(condition)

Do..While Loop used to check running processes every 5 seconds for the iexplore process

PS C:\> $processToMonitor = "iexplore"
        Write-Host "Checking if Internet Explorer is running on this host every 5 seconds..."
        Do {

            if(Get-Process -Name $processToMonitor -ErrorAction SilentlyContinue) {
                Write-Host "Warning: $processToMonitor is running! Don't use Internet Explorer!"
                Start-Sleep -Seconds 5
            }
        } While ($true)

PS C:\> .\DoWhileLoopDemo.ps1
    Checking if Internet Explorer is running on this host every 5 seconds...
    Warning: iexplore is running! Don't use Internet Explorer!
    Warning: iexplore is running! Don't use Internet Explorer!
    Warning: iexplore is running! Don't use Internet Explorer!
    Warning: iexplore is running! Don't use Internet Explorer!

Do Until

    Using Do/Until, PowerShell continues to execute the code statement until the condition evaluates to $false.

Syntax

do {
    code block
}until(condition)

Do..Until Loop that will continuously monitor a potential malicious process and gather details about it until it is no longer running

PS C:\> Write-Host "Monitoring Microsoft Edge process every 60 seconds." `n
        $FilePath = (Get-CimInstance Win32_Process | Select-Object -Property Name, ProcessID, ParentProcessID, Path | Where-Object {$_.Name -eq "msedge.exe"}).Path
        $processToMonitor = "msedge"
        do {
            $isProcessRunning = Get-Process -Name $processToMonitor

            if ($isProcessRunning) {
                Write-Host "Warning: $processToMonitor is running, performing analysis on the process." `n
                Write-Host "-------------Gathering Process Information...--------------"
                Start-Sleep -Seconds 3
                Write-Output (Get-CimInstance Win32_Process | Select-Object -Property Name, ProcessID, ParentProcessID, Path | Where-Object {$_.Name -eq "msedge.exe"} | Format-Table)

                Write-Host "-------------Gathering Process Filehash...--------------"
                Start-Sleep -Seconds 3
                $FileHash = (Get-FileHash -Algorithm SHA256 -Path $FilePath | Format-Table)
                Write-Output $FileHash

                Write-Host "-------------Gathering Network Information...--------------"
                Start-Sleep -Seconds 3
                $ProcessIDs = (Get-Process | Select-Object -Property Name, ID | Where-Object {$_.Name -eq "msedge"}).Id
                $Network = foreach ($ID in $ProcessIDs) {
                    Get-NetTCPConnection | Select-Object -Property LocalAddress, RemoteAddress, RemotePort, OwningProcess, State | Where-Object { $_.OwningProcess -eq $ID -and $_.State -ne "Bound" }
                }
                Write-Output $Network | Format-Table
            }
            Start-Sleep -Seconds 60
        } until (-not $isProcessRunning)

    Warning: msedge is running, performing analysis on the process.

    -------------Gathering Process Information...--------------

    Name       ProcessID ParentProcessID Path
    ----       --------- --------------- ----
    msedge.exe      8416            8808 C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe
    msedge.exe      8448            8416 C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe
    msedge.exe      5468            8416 C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe
    msedge.exe      4372            8416 C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe
    msedge.exe      8272            8416 C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe
    msedge.exe      5664            8416 C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe
    msedge.exe      1696            8416 C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe
    msedge.exe      5168            8416 C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe

    -------------Gathering Process Filehash...--------------

    Algorithm Hash                                                             Path
    --------- ----                                                             ----
    SHA256    065D2802A5069ABAF7C12EE356620643A121F72ACE223D505C32EE525F9B91D3 C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe
    SHA256    065D2802A5069ABAF7C12EE356620643A121F72ACE223D505C32EE525F9B91D3 C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe
    SHA256    065D2802A5069ABAF7C12EE356620643A121F72ACE223D505C32EE525F9B91D3 C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe
    SHA256    065D2802A5069ABAF7C12EE356620643A121F72ACE223D505C32EE525F9B91D3 C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe
    SHA256    065D2802A5069ABAF7C12EE356620643A121F72ACE223D505C32EE525F9B91D3 C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe
    SHA256    065D2802A5069ABAF7C12EE356620643A121F72ACE223D505C32EE525F9B91D3 C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe
    SHA256    065D2802A5069ABAF7C12EE356620643A121F72ACE223D505C32EE525F9B91D3 C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe
    SHA256    065D2802A5069ABAF7C12EE356620643A121F72ACE223D505C32EE525F9B91D3 C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe

    -------------Gathering Network Information...--------------

    LocalAddress RemoteAddress  RemotePort OwningProcess       State
    ------------ -------------  ---------- -------------       -----
    10.50.33.11  169.150.236.98        443          2088 Established
    10.50.33.11  185.152.66.243        443          2088 Established
    10.50.33.11  172.66.40.149         443          2088 Established
    10.50.33.11  151.101.17.188        443          2088 Established
    10.50.33.11  185.152.66.243        443          2088 Established
    10.50.33.11  20.42.73.28           443          2088 Established
    10.50.33.11  23.207.53.173         443          2088 Established

Foreach

The Foreach Loop is very similar to a For Loop in other languages. In PowerShell you can use the Foreach Loop to iterate through a collection of objects and pull information Foreach of the objects in the collection.
Syntax

$items = "objects"
Foreach ($item in $items){
    <Code to be executed>
}

Foreach Loop that iterates through each user on the host and displays if any administrator accounts are enabled

PS C:\> $Users = Get-LocalUser
        Foreach ($User in $Users){
            if ($User.Name -eq "Admin" -or $User.Name -eq "Administrator"){
                Write-Host ""$User.Name" is enabled:"$User.Enabled""
            }
        }

    Admin  is enabled: True
    Administrator  is enabled: True

ForEach-Object

The ForEach-Object cmdlet performs an operation on each item in a collection of input objects. The input objects can be piped to the cmdlet or specified using the InputObject parameter. Microsoft Docs: ForEach-Object
Syntax

PS C:\> $Objects = "Something"
        $Objects | Foreach-Object {<Code to be executed>}

Foreach-Object construct that performs an action on the objects in the pipeline and displays if any administrator accounts are enabled

PS C:\> $Users = Get-LocalUser
        $Users | ForEach-Object {
            if ($_.Name -ieq 'Admin' -or $_.Name -ieq 'Administrator'){
                Write-Host ""$_.Name" is enabled:"$_.Enabled""
            }
        }

    Admin  is enabled: True
    Administrator  is enabled: True

Display file sizes

Get-ChildItem | ForEach-Object { $_.Length / 1KB }

Foreach and ForEach-Object are very similar with the main difference being that ForEach-Object obtains its values from a pipeline while ForEach is used to iterate over a collection of objects. Another difference is that ForEach can only process objects that are completely available while ForEach-Object processes each result one at a time, so you get results in real-time. For example, if you were going to use the following:

ForEach ($item in gci C:\ -recurse){$item.name}

This command would take a long time because ForEach can’t process objects until Get-ChildItem is completely finished listing the directory. If you were to do the following:

Get-ChildItem C:\ -recurse | ForEach-Object{$_.name}

Then you would get the results one at a time in real-time as Get-ChildItem is processing them.
	There are several use-cases for both ForEach and Foreach-Object, it is important to know which one is better depending on the scenario.
Windows Management Instrumentation (WMI) and Common Information Model (CIM)

WMI and CIM are related technologies, both of which are based on industry standards. WMI is an older technology based on proprietary technology. CIM is a newer technology that is based on open, cross-platform standards.

You can learn more about WMI and CIM at https://learn.microsoft.com/en-us/training/modules/review-common-information-model-windows-management-instrumentation/1-introduction
	CIM commands use WS-MAN to establish remote connections. WMI uses DCOM which might require special firewall exceptions due to the way it randomly chooses ports to which it connects.
	Microsoft considers WMI within Windows PowerShell to be deprecated and recommends using CIM commands instead.

On previous days, CIM commands were demonstrated on multiple occasions to pull specific information about a process such as the Parent Process ID. It is important to understand and learn CIM commands as they provide valuable information that cannot be gained using standard PowerShell Cmdlets.
Searching CIM repository for a desired command

PS C:\> Get-CimClass -Namespace root\CIMv2 | Select-String "network"
    ROOT/CIMv2:CIM_NetworkAdapter
    ROOT/CIMv2:Win32_NetworkAdapter
    ROOT/CIMv2:Win32_NetworkConnection
    ROOT/CIMv2:Win32_NetworkProtocol
    ROOT/CIMv2:Win32_NetworkClient
    ROOT/CIMv2:Win32_SystemNetworkConnections
    ROOT/CIMv2:Win32_NetworkAdapterSetting
    ROOT/CIMv2:Win32_NetworkAdapterConfiguration

PS C:\> Get-CimInstance Win32_NetworkAdapterConfiguration | select -Property DNSHostName,InterfaceIndex,IPAddress,IPSubnet | format-list
    DNSHostName    :
    InterfaceIndex : 6
    IPAddress      :
    IPSubnet       :

    DNSHostName    : DESKTOP-DC1NSGJ
    InterfaceIndex : 5
    IPAddress      : {10.50.33.11, fe80::3326:f9c3:a42b:6fed}
    IPSubnet       : {255.255.0.0, 64}

A valuable resource for learning CIM commands can be found at https://learn.microsoft.com/en-us/training/modules/query-configuration-information/2-list-local-repository-namespaces-classes
PowerShell Remoting (PS Remoting)

PowerShell remoting is a very powerful tool at an administrator’s and an analyst’s disposal. However, if not configured properly, PSRemoting can create a large vulnerability for an attacker to live off the land. It is very important to know what good security configurations look like and how to implement them if they don’t exist.
Just Enough Administration (JEA)

JEA is a way we can reduce the attack surface created by PSRemoting being allowed on a network. JEA provides Windows Server and Windows client operating systems with Role Based Access Control (RBAC) functionality built upon PSRemoting.

JEA uses a special, privileged, virtual account rather than a standard user account. This has several benefits: the user’s credentials are not stored on the remote host, the user account that is used to connect to the endpoint doesn’t need to be privileged, the virtual account is limited to the system on which it is hosted, and it has local administrator privileges but is limited to performing only activities defined by JEA.
	Microsoft states that configuring JEA can be a complicated process. The Administrator configuring it should be very familiar with any PowerShell cmdlets, parameters, aliases, and values needed to perform administrative tasks.

You can learn more about JEA, including ways to configure it here https://learn.microsoft.com/en-us/training/modules/just-enough-administration-windows-server/
Windows Remote Management (WinRM)

WinRM is another Windows component that uses the WS-Management protocol (WSMan). WinRM is intended for use by remote management IT professionals who use scripts to automate the management of clients and servers remotely. However, it is also a very useful tool for Cyber Analysts if they are provided with access to use it.

WinRM has to be enabled on a host-by-host basis either manually or via group policy object (GPO) implementation. Working with servers and computers with WinRM enabled and configured will allow PSRemoting to take place.
Setting up WinRM using GPO

If you have the required access to do so, setting up WinRM via GPO is the more efficient method of doing so. Becoming familiar with the process of deploying group policy is a useful skill to know. However, demonstrating deployment of WinRM via GPO is outside the scope of this course.

To learn more about WinRM, you can read about it here https://learn.microsoft.com/en-us/windows/win32/winrm/portal

If you want to learn about configuring WinRM via GPO, please read more about it here https://support.auvik.com/hc/en-us/articles/204424994-How-to-enable-WinRM-with-domain-controller-Group-Policy-for-WMI-monitoring
Setting up WinRM manually using PowerShell

We did not demonstrate GPO deployment for WinRM, but we will demonstrate manual configuration using PowerShell.
Configuring and Testing WinRM and PSRemoting using PowerShell

# Enable PSRemoting and skip the network profile check to avoid errors
PS C:\> Enable-PSRemoting -SkipNetworkProfileCheck -Force
    WinRM is already set up to receive requests on this computer.
    WinRM has been updated for remote management.
    WinRM firewall exception enabled.

# Check trusted hosts file
PS C:\> Get-Item WSMan:\localhost\client\TrustedHosts

        WSManConfig: Microsoft.WSMan.Management\WSMan::localhost\Client

    Type            Name                           SourceOfValue   Value
    ----            ----                           -------------   -----
    System.String   TrustedHosts

# Set trusted hosts to allow your connection to a desired host or hosts. Multiple trusted hosts can be created in a comma separated list and stored in a variable for use with this command
# Enter "Y" when prompted
PS C:\> Set-Item WSMan:\localhost\Client\TrustedHosts -Value 10.50.22.50

    WinRM Security Configuration.
    This command modifies the TrustedHosts list for the WinRM client. The computers in the TrustedHosts list might not be authenticated. The client might send
    credential information to these computers. Are you sure that you want to modify this list?
    [Y] Yes  [N] No  [S] Suspend  [?] Help (default is "Y"): Y

# Check the trusted hosts file again to verify the change
PS C:\> Get-item WSMan:\localhost\Client\TrustedHosts

        WSManConfig: Microsoft.WSMan.Management\WSMan::localhost\Client

    Type            Name                           SourceOfValue   Value
    ----            ----                           -------------   -----
    System.String   TrustedHosts                                   10.50.22.50

# Verify that your changes worked by establishing a remote session to the trusted host
PS C:\> Enter-PSSession -ComputerName 10.50.22.95 -Credential Administrator
    [10.50.22.95]: PS C:\Users\Administrator\Documents>

# type exit to terminate the remote session
[10.50.22.95]: PS C:\Users\Administrator\Documents> exit
    PS C:\>

	Setting the WSMan:\localhost\Client\TrustedHosts Value to * will enable you to connect to ANY machine. However, this will also allow you to trust connections FROM any machine, thus bypassing ALL Windows security features!
Enter-PSSession

Using the Enter-PSSession cmdlet, you can enter an interactive PowerShell session with a remote host. This is a useful tool for performing analysis on a remote host without logging directly into the host, potentially exposing your credentials or storing a logon token.

When entering a PSSession, if your current user account is allowed to connect to the remote host, you will not have to provide credentials, showcased by the example in the previous section. However, if you want to authenticate to a different account with more or different permissions, you will need to provide credentials. It is a best practice to store the credentials as opposed to typing them into the command.
Entering a remote PowerShell Session using stored credentials

# Typing this command will cause a prompt to pop-up requesting a username and password which will be stored as a secure string in the variable
PS C:\> $Creds = Get-Credential

    PowerShell credential request
    Enter your credentials.
    User: Administrator
    Password for user Administrator: *************

PS C:\> $Creds

    UserName                                 Password
    --------                                 --------
    Administrator                            System.Security.SecureString

PS C:\> Enter-PSSession -ComputerName 10.50.22.95 -Credential $Creds

    [10.50.22.95]: PS C:\Users\Administrator\Documents>

Retrieving useful information from a remote host during an interactive PowerShell session

# From your remote PowerShell Session, you can run PowerShell cmdlets just like if you were physically using the host
[10.50.22.95]: PS C:\Users\Administrator\Documents> Get-Process | Select-Object -First 10

    Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
    -------  ------    -----      -----     ------     --  -- -----------
        88       6      912       4656       0.02   3956   0 AggregatorHost
        229      14    11104      11396       4.73   7156   2 conhost
        483      20     1868       6208       1.36    444   0 csrss
        462      17     2116      21232       3.22   1740   2 csrss
        162      11     1740       6060       0.05   2912   3 csrss
        423      16     4124      21260       1.91   1684   2 ctfmon
        409      34    24696      31672      62.00   3208   0 dfsrs
        204      14     2496       8764       3.06   3500   0 dfssvc
        240      17     3924      12880       0.22   6708   2 dllhost
      10510    7511   250364     242556      42.27   2908   0 dns

# Viewing network connection information for the remote host, showcasing the established connection over port 5985 (WinRM) from our local client to the remote server.
[10.50.22.95]: PS C:\Users\Administrator\Documents> Get-NetTCPConnection | Select-Object -Property LocalAddress,RemoteAddress,LocalPort,OwningProcess,State | Where-Object {$_.State -eq "Established" -and $_.LocalPort -eq '5985'}

    LocalAddress  : 10.50.22.95
    RemoteAddress : 10.50.33.11
    LocalPort     : 5985
    OwningProcess : 4
    State         : Established

    LocalAddress  : 10.50.22.95
    RemoteAddress : 10.50.33.11
    LocalPort     : 5985
    OwningProcess : 4
    State         : Established

    LocalAddress  : 10.50.22.95
    RemoteAddress : 10.50.33.11
    LocalPort     : 5985
    OwningProcess : 4
    State         : Established

# Querying Windows event logs on a remote computer to see successful logon attempts with partial output
[10.50.22.95]: PS C:\Users\Administrator\Documents> Get-WinEvent -Logname Security -MaxEvents 5 | Select-Object -Property Logname,Id,Message | Where-Object {$_.ID -eq '4624'} | format-list

    LogName : Security
    Id      : 4624
    Message : An account was successfully logged on.

            Subject:
                    Security ID:            S-1-0-0
                    Account Name:           -
                    Account Domain:         -
                    Logon ID:               0x0

            Logon Information:
                    Logon Type:             3
                    Restricted Admin Mode:  -
                    Virtual Account:                No
                    Elevated Token:         Yes

            Impersonation Level:          Delegation

            New Logon:
                    Security ID:            S-1-5-21-29133154-898414412-3934859756-1153
                    Account Name:           WINSVR2DMZNET2$
                    Account Domain:         505CAV.BDE
                    Logon ID:               0xACCAA52
                    Linked Logon ID:                0x0
                    Network Account Name:   -
                    Network Account Domain: -
                    Logon GUID:             {6d5f3c59-57b3-a628-caef-21ea81ade2e3}

# Querying Windows PowerShell operational logs on a remote computer
[10.50.22.95]: PS C:\Users\Administrator\Documents> get-winEvent -Logname Microsoft-Windows-PowerShell/Operational -MaxEvents 5 | Select-Object -Property TimeCreated,LevelDisplayName,Message

    TimeCreated          LevelDisplayName Message
    -----------          ---------------- -------
    1/24/2024 4:26:22 PM Warning          Error Message = The event log 'Microsoft-Windows-PowerShell/Operational' on computer '.' does not exist....
    1/24/2024 3:46:47 PM Warning          Creating Scriptblock text (1 of 1):...
    1/24/2024 3:46:47 PM Warning          Creating Scriptblock text (1 of 1):...
    1/24/2024 3:46:47 PM Warning          Creating Scriptblock text (3 of 3):...

# Querying Kerberos information in a remote PowerShell session, this may generate an error and requires a specific set of commands to ensure functionality to include creating a PSSession Configuration. To learn more, check here https://jebidiah-anthony.github.io/prjct/PTT-PSRemoting.html
PS C:\Users\defender\Desktop> Enter-PSSession -ComputerName 10.50.22.95 -Credential $Creds

# Start by creating the PSSession configuration file on the remote host
[10.50.22.95]: PS C:\Users\Administrator\Documents> Register-PSSessionConfiguration -Name KerbDemo -RunAsCredential Administrator

    PowerShell Credential Request: Windows PowerShell credential request
    Warning: A script or application on the remote computer 10.50.22.95 is requesting your credentials. Enter your credentials only if you trust the remote computer and the application or script that is
    requesting them.

    Enter your credentials.
    Password for user Administrator: *************

    WARNING: When RunAs is enabled in a Windows PowerShell session configuration, the Windows security model cannot enforce a security boundary between different user sessions that are created by using this endpoint. Verify that the Windows PowerShell runspace configuration is restricted to only the necessary set of cmdlets and capabilities.
    WARNING: Register-PSSessionConfiguration may need to restart the WinRM service if a configuration using this name has recently been unregistered, certain system data structures may still be cached. In that case, a restart of WinRM may be required.
    All WinRM sessions connected to Windows PowerShell session configurations, such as Microsoft.PowerShell and session configurations that are created with the Register-PSSessionConfiguration cmdlet, are disconnected.


    WSManConfig: Microsoft.WSMan.Management\WSMan::localhost\Plugin

    Type            Keys                                Name
    ----            ----                                ----
    Container       {Name=KerbDemo}                     KerbDemo
    WARNING: Register-PSSessionConfiguration may need to restart the WinRM service if a configuration using this name has recently been unregistered, certain system data structures may still be cached. In that case, a restart of WinRM may be required.
    All WinRM sessions connected to Windows PowerShell session configurations, such as Microsoft.PowerShell and session configurations that are created with the Register-PSSessionConfiguration cmdlet, are disconnected.

# Now run the klist command to display Kerberos information, you may get output as seen below
[10.50.22.95]: PS C:\Users\Administrator\Documents> klist

    Current LogonId is 0:0xb3f385b

    Cached Tickets: (0)

# If you got the above output, restart the WinRM service
[10.50.22.95]: PS C:\Users\Administrator\Documents> Restart-Service WinRM

# Your session will be terminated and you will need to run a new Enter-PSSession command with the configuration file that we created earlier specified this time
PS C:\Users\defender\Desktop> Enter-PSSession -ComputerName 10.50.22.95 -Credential $Creds -ConfigurationName "KerbDemo"

# Now run the klist command again to receive Kerberos information for the current logon session
[10.50.22.95]: PS C:\Users\Administrator\Documents> klist

    Current LogonId is 0:0xb4157aa

    Cached Tickets: (1)

    #0>     Client: administrator @ 505CAV.BDE
            Server: krbtgt/505CAV.BDE @ 505CAV.BDE
            KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
            Ticket Flags 0x40e10000 -> forwardable renewable initial pre_authent name_canonicalize
            Start Time: 1/24/2024 18:19:38 (local)
            End Time:   1/25/2024 4:19:38 (local)
            Renew Time: 1/31/2024 18:19:38 (local)
            Session Key Type: AES-256-CTS-HMAC-SHA1-96
            Cache Flags: 0x1 -> PRIMARY
            Kdc Called: DC-1

	Do not run the above Kerberos commands on a customer’s network unless they give you explicit permission to do so.
	To display the full message for event logs, use the Format-List cmdlet. Remember to use exclusion statements and sorting to limit the amount of results. Log messages contain a lot of information and just a couple of logs will fill your entire PowerShell window.

PowerShell allows for running commands on remote computers as well as connecting to remote machines.
Invoke-Command

Using the Invoke-Command cmdlet, you can remotely pull information from another computer using WSMan and WinRM. This is an alternative to entering a remote session on the computer and allows the user to easily save results to output files for later analysis.
	If running Invoke-Command on a computer that is not joined to a domain, you will have to use runas in order to authenticate to a remote domain joined computer. You will also require credentials for the target remote host. It is outside the scope of the course, but you can learn more about runas commands here https://www.jamesserra.com/archive/2011/08/how-to-run-programs-as-a-domain-user-from-a-non-domain-computer/
Using Invoke-Command to pull valuable information from a remote host and storing it locally

# Query the remote host for the desired information, testing with standard output
PS C:\Users\defender\Desktop> Invoke-Command -ComputerName 10.50.22.95 -Credential $Creds -ScriptBlock {Get-Process | Select-Object -Property Name,ID,Path | Where-Object {$_.Path -like "C:\Windows\System32\*"}} | Select-Object -First 5

    Name           : AggregatorHost
    Id             : 3956
    Path           : C:\Windows\System32\AggregatorHost.exe
    PSComputerName : 10.50.22.95
    RunspaceId     : 6e28f7ed-1ab9-4263-ab09-0494bab6bcf6

    Name           : conhost
    Id             : 7156
    Path           : C:\Windows\system32\conhost.exe
    PSComputerName : 10.50.22.95
    RunspaceId     : 6e28f7ed-1ab9-4263-ab09-0494bab6bcf6

    Name           : ctfmon
    Id             : 1684
    Path           : C:\Windows\system32\ctfmon.exe
    PSComputerName : 10.50.22.95
    RunspaceId     : 6e28f7ed-1ab9-4263-ab09-0494bab6bcf6

    Name           : dfsrs
    Id             : 3208
    Path           : C:\Windows\system32\DFSRs.exe
    PSComputerName : 10.50.22.95
    RunspaceId     : 6e28f7ed-1ab9-4263-ab09-0494bab6bcf6

    Name           : dfssvc
    Id             : 3500
    Path           : C:\Windows\system32\dfssvc.exe
    PSComputerName : 10.50.22.95
    RunspaceId     : 6e28f7ed-1ab9-4263-ab09-0494bab6bcf6

# Query the remote host for the same information, but store it locally for analysis
PS C:\Users\defender\Desktop> $Processes = Invoke-Command -ComputerName 10.50.22.95 -Credential $Creds -ScriptBlock {Get-Process | Select-Object -Property Name,ID,Path | Where-Object {$_.Path -like "C:\Windows\System32\*"} | Select-Object -First 10}; $Processes | Out-File -FilePath C:\Users\defender\Desktop\DomainControllerProcesses.txt

PS C:\Users\defender\Desktop> Get-Content .\DomainControllerProcesses.txt

    Name           : AggregatorHost
    Id             : 3956
    Path           : C:\Windows\System32\AggregatorHost.exe
    PSComputerName : 10.50.22.95
    RunspaceId     : 198b9c5a-5cd9-4e85-baba-b9c6b83864b8

    Name           : conhost
    Id             : 7156
    Path           : C:\Windows\system32\conhost.exe
    PSComputerName : 10.50.22.95
    RunspaceId     : 198b9c5a-5cd9-4e85-baba-b9c6b83864b8

    Name           : ctfmon
    Id             : 1684
    Path           : C:\Windows\system32\ctfmon.exe
    PSComputerName : 10.50.22.95
    RunspaceId     : 198b9c5a-5cd9-4e85-baba-b9c6b83864b8

    Name           : dfsrs
    Id             : 3208
    Path           : C:\Windows\system32\DFSRs.exe
    PSComputerName : 10.50.22.95
    RunspaceId     : 198b9c5a-5cd9-4e85-baba-b9c6b83864b8

    Name           : dfssvc
    Id             : 3500
    Path           : C:\Windows\system32\dfssvc.exe
    PSComputerName : 10.50.22.95
    RunspaceId     : 198b9c5a-5cd9-4e85-baba-b9c6b83864b8

# Using the same methodology, query and store network information. We can still see our remote WinRM connection, even though it is not persistent, using Invoke-Command
PS C:\Users\defender\Desktop> Invoke-Command -ComputerName 10.50.22.95 -Credential $Creds -ScriptBlock {Get-NetTCPConnection | Select-Object -Property LocalAddress,LocalPort,RemoteAddress | Where-Object {$_.LocalPort -eq '5985'}} | Select-Object -Last 2

    LocalAddress   : 10.50.22.95
    LocalPort      : 5985
    RemoteAddress  : 10.50.33.11
    PSComputerName : 10.50.22.95
    RunspaceId     : d1a12a86-ba41-42ac-a439-ef95734ffaa6

    LocalAddress   : 10.50.22.95
    LocalPort      : 5985
    RemoteAddress  : 10.50.33.11
    PSComputerName : 10.50.22.95
    RunspaceId     : d1a12a86-ba41-42ac-a439-ef95734ffaa6

PS C:\Users\defender\Desktop> $NetworkQuery = Invoke-Command -ComputerName 10.50.22.95 -Credential $Creds -ScriptBlock {Get-NetTCPConnection | Select-Object -Property LocalAddress,LocalPort,RemoteAddress | Where-Object {$_.LocalPort -eq '5985'}} | Select-Object -Last 2; $NetworkQuery | Out-File -FilePath C:\Users\defender\Desktop\DomainControllerNetwork.txt

PS C:\Users\defender\Desktop> Get-Content .\DomainControllerNetwork.txt

    LocalAddress   : 10.50.22.95
    LocalPort      : 5985
    RemoteAddress  : 10.50.33.11
    PSComputerName : 10.50.22.95
    RunspaceId     : 6a39bfc2-4a58-4820-859d-351964246e71

    LocalAddress   : 10.50.22.95
    LocalPort      : 5985
    RemoteAddress  : 10.50.33.11
    PSComputerName : 10.50.22.95
    RunspaceId     : 6a39bfc2-4a58-4820-859d-351964246e71

	Using Invoke-Command as opposed to Enter-PSSession on a known-compromised Windows host is the better alternative if you have no physical access to the host. Invoke-Command does not establish a persistent session, reducing the potential for exposure to an adversary.
Using Invoke-Command to create or modify files on a remote system

# Start by creating a saving a script on the remote computer using the Set-Content cmdlet
PS C:\Users\defender\Desktop> Invoke-Command -ComputerName 10.50.22.95 -Credential $Creds -ScriptBlock {$Content = "cmd.exe /c ping -n 1 10.50.35.169"; $FilePath = "C:\Users\Administrator\Desktop\pingme.ps1"; Set-Content -Path $FilePath -Value $Content}

# Execute the script using Invoke-Command and view the results
PS C:\Users\defender\Desktop> Invoke-Command -ComputerName 10.50.22.95 -Credential $Creds -ScriptBlock {powershell.exe "C:\Users\Administrator\Desktop\pingme.ps1"}

    Pinging 10.50.35.169 with 32 bytes of data:
    Reply from 10.50.35.169: bytes=32 time=6ms TTL=128

    Ping statistics for 10.50.35.169:
        Packets: Sent = 1, Received = 1, Lost = 0 (0% loss),
    Approximate round trip times in milli-seconds:
        Minimum = 6ms, Maximum = 6ms, Average = 6ms

# Altering the code within the script to receive different results using Set-Content to overwrite the previous code
PS C:\Users\defender\Desktop> Invoke-Command -ComputerName 10.50.22.95 -Credential $Creds -ScriptBlock {$NewContent = "cmd.exe /c ping -n 5 10.50.35.169"; $FilePath = "C:\Users\Administrator\Desktop\pingme.ps1"; Set-Content -Path $FilePath -Value $NewContent}

PS C:\Users\defender\Desktop> Invoke-Command -ComputerName 10.50.22.95 -Credential $Creds -ScriptBlock {powershell.exe "C:\Users\Administrator\Desktop\pingme.ps1"}

    Pinging 10.50.35.169 with 32 bytes of data:
    Reply from 10.50.35.169: bytes=32 time=9ms TTL=127
    Reply from 10.50.35.169: bytes=32 time=11ms TTL=127
    Reply from 10.50.35.169: bytes=32 time=1ms TTL=127
    Reply from 10.50.35.169: bytes=32 time=1ms TTL=127
    Reply from 10.50.35.169: bytes=32 time=1ms TTL=127

    Ping statistics for 10.50.35.169:
        Packets: Sent = 5, Received = 5, Lost = 0 (0% loss),
    Approximate round trip times in milli-seconds:
        Minimum = 1ms, Maximum = 11ms, Average = 4ms

# Appending new code to the script with the Add-Content cmdlet to receive the original and new results, you may need the back tick "`" escape character for some special characters to work properly in a ScriptBlock
PS C:\Users\defender\Desktop> Invoke-Command -ComputerName 10.50.22.95 -Credential $Creds -ScriptBlock {$NewContent = "Get-Process | Select-Object -Property Name,Path | Where-Object {`$_.Name -like `"pwsh`"}"; $FilePath = "C:\Users\Administrator\Desktop\pingme.ps1"; Add-Content -Path $FilePath -Value $NewContent}

PS C:\Users\defender\Desktop> Invoke-Command -ComputerName 10.50.22.95 -Credential $Creds -ScriptBlock {powershell.exe "C:\Users\Administrator\Desktop\pingme.ps1"}

    Pinging 10.50.35.169 with 32 bytes of data:
    Reply from 10.50.35.169: bytes=32 time=13ms TTL=127
    Reply from 10.50.35.169: bytes=32 time=6ms TTL=127
    Reply from 10.50.35.169: bytes=32 time=1ms TTL=127
    Reply from 10.50.35.169: bytes=32 time=1ms TTL=127
    Reply from 10.50.35.169: bytes=32 time=1ms TTL=127

    Ping statistics for 10.50.35.169:
        Packets: Sent = 5, Received = 5, Lost = 0 (0% loss),
    Approximate round trip times in milli-seconds:
        Minimum = 1ms, Maximum = 13ms, Average = 4ms

    Name Path
    ---- ----
    pwsh C:\Program Files\PowerShell\7\pwsh.exe

Summary
Today we discussed

    Output Formatting

    Script Constructs (Loops and Switches)

    Windows Management Instrumentation (WMI)

    PowerShell Remoting (PS Remoting)

        Enter-PSSession

        Invoke-Command

The Instructor will provide you with the start flag to begin working on Day 3 Practical Exercises.

END OF LESSON

This page was built using a slightly modified version of the Antora default UI.
The source code for this UI is licensed under the terms of the MPL-2.0 license and can be found at https://git.cybbh.space/common/contributing
