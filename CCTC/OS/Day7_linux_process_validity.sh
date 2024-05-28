# How many child processes did SysV Init daemon spawn?
ps --ppid 2

# htop works better than top for in depth process analysis

# Locate the strange open port on the SysV system. Identify how the process persists between reboots.
nc -ano
cat /etc/inittab
