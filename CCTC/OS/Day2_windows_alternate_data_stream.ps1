# Which group has ReadandExecute (RX) permissions to the file listed in the previous challenge, File_System_Basics_6?
get-acl -path c:\Windows\System32\Drivers\etc\hosts | format-table

# Find the last five characters of the MD5 hash of the hosts file.
get-filehash -path c:\Windows\System32\Drivers\etc\hosts -algorithm md5

# Examine the readme file somewhere in the CTF user’s home directory.
get-childitem readme* -recurse
get-content readme

# There is a hidden directory in the CTF user's home directory. The directory contains a file. Read the file.
get-childitem -force

# Find a file in a directory on the desktop with spaces in it. FLAG is the contents of the file
cd z*
get-content spaces.txt

# Find the Alternate Data Stream in the CTF user's home, and read it.
get-item * -stream * | select-object -property filename, stream
get-content nothing_here -stream hidden

# "Fortune cookies" have been left around the system so that you won't find the hidden password...

# There are plenty of phish in the C:\Users\CTF, but sometimes they're hidden in plain site.

