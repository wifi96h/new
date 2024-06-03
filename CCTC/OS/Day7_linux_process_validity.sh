# How many child processes did SysV Init daemon spawn?
ps --ppid 2

# htop works better than top for in depth process analysis

# Locate the strange open port on the SysV system. Identify how the process persists between reboots.
nc -ano
cat /etc/inittab  # 91:2345:respawn:/bin/netcat -lp 9999
#                   ^    ^      ^          ^      
#            priority  run lvl  to-do    command               

# Examine the process list to find the ssh process. Then, identify the symbolic link to the absolute path for its executable in the /proc directory. The flag is the absolute path to the symbolic link, and the file it is linked to.
ps -elf | grep sshd
sudo ls -l /proc/1888    # look for the exe -> /file/path

# Identify the file that contains udp connection information. Identify the process using port 123.
netstat -alonut | grep 123


# Identify one of the human-readable file handles by the other program that creates a zombie process.
htop    # /bin/funk  !!!!!, i'm, rick, james; /usr/local/bin/thenine, nazgul, thenine


# The Villains group has been chanting offerings to their new leader at regular intervals over a TCP connection.
# Task: Identify their method of communication and how it is occurring. Locate the following artifacts: ** The chant/text used by each villain (include spaces) ** The new Lord receiving the offering ** The IP address and port that the offering is received over
htop  # /home/blog/offering /home/witch_king/camlindon / nc -lw10 127.0.0.1 1234 / 
      # /home/Balrog/chant
cat /home/Balrog/chant      # Mausan ukoul for avhe mubullat goth
cat /home/Balrog/offering    # nc -lw10 127.0.0.1 1234 

# Someone or something is stealing files with a .txt extension from user directories. Determine how these thefts are occurring. Identify the command being ran and how it occurs.
