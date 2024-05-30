# What Volatility plugin will dump a process to an executable file sample?
procdump

# What Volatility plugin will extract command history by scanning for _COMMAND_HISTORY?
cmdscan

# What Volatility plugin will show driver objects?
driverscan

# What plugin do you run to find which memory profile to use with a memory image?
imageinfo

# What switch/argument will list all plugins for Volatility?
-h

# In terms of Volatile Data, what locations are the MOST volatile?
registry, cache

# What is the 12th plugin listed in the Volatility help menu?
.\volatility_2.6_win64_standalone.exe -h

# What profile do you use in conjunction with this memory image?
.\volatility_2.6_win64_standalone.exe -f .\0zapftis.vmem imageinfo

# What command did the attacker type to check the status of the malware?
.\volatility_2.6_win64_standalone.exe -f .\0zapftis.vmem cmdscan

# What are the last 7 digits of the memory offset for the driver used by the malware?
.\volatility_2.6_win64_standalone.exe -f .\0zapftis.vmem driverscan

# The process running under PID 544 seems malicious. What is the md5hash of the executable?
.\volatility_2.6_win64_standalone.exe -f .\0zapftis.vmem pstree
.\volatility_2.6_win64_standalone.exe -f .\0zapftis.vmem procdump -p 544 -D .
get-filehash -algorithm md5 .\executable.544.exe

# What remote IP and port did the system connect to?
.\volatility_2.6_win64_standalone.exe -f .\0zapftis.vmem connscan
