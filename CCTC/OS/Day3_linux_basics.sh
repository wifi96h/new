# legit ip 000-255; format ip 000-999

# Identify all members of the lodge group. List their names in alphabetical order with a comma in between each name.
cat /etc/group | grep lodge

# Read the file that contains the user database for the machine. Identify a strange comment.
cat /etc/passwd | awk -F: '{print $5}'

# Find the user with a unique login shell.
cat /etc/passwd | awk -F: '{print $7}'
cat /etc/passwd | head -n 20

# Find the directory named Bibliotheca. Enter the absolute path to the directory.
find -iname bibliotheca

# Identify the number of users with valid login shells, who can list the contents of the Bibliotheca directory.
ls -la /media/bibliotheca
ls -la /media
cat /etc/group | grep chapter
ls -la /media/Bibliotheca/Bibliotheca_unus

# Identify the file within /media/Bibliotheca where the owning group has more rights than the owning user.
ls -la /media/Bibliotheca/Bibliotheca_tribus

# Using the commands ls and grep, identify the number of directories in /etc/ that end in .d
ls /etc/ | grep -E '\.d$' | wc -l

# Use regular expressions to match patterns similar to valid and invalid IP addresses.
# The answer is the count/number of lines that match in the file.
grep -P '^[[:digit:]]{1,3}.[[:digit:]]{1,3}.[[:digit:]]{1,3}.[[:digit:]]{1,3}$' numbers | wc -l

# Use regular expressions to match valid IP addresses. The flag is the number of addresses.
grep -P '^((25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)$' numbers | wc -l

# Use regular expressions to match patterns that look similar to a MAC Address. Flag is a count of the number of matches.
grep -P '^([0-9A-Za-z]{2}-){5}([0-9A-Za-z]{2})$' numbers | wc -l

