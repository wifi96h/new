# There is malware on the system that is named similarly to a legitimate Windows executable. There is a .dll in the folder that the malware runs from. The flag is the name of the .dll.
get-process | select name, id, path | sort name

# You notice that there is an annoying pop up happening regularly. Investigate the process causing it. The flag is the name of the executable.
search task scheduler

# Determine what is sending out a SYN_SENT message. The flag is the name of the executable.
.\tcpview.exe # opens tcpview gui

# Malware uses names of legit processes to obfuscate itself. Give the flag located in Kerberos’ registry subkey.
