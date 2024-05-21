# What are the values contained in hex positions 0x00000001 through 0x00000008?
 sudo cat /dev/vda | xxd -l 32 -c 0x10 -g 1

# The file /home/bombadil/mbroken is a copy of an MBR from another machine.
# Hash the first partition of the file using md5sum. The flag is the hash.
# 0x01BE (446)    Partition Entry #1    Partition table(for primary partitions)    16 bytes
dd if=mbroken bs=1 count=16 skip=446 | md5sum

# The file /home/bombadil/mbroken is a copy of an MBR from another machine.
# You will find the "word" GRUB in the output, hash using md5sum.
# 0x0188 (392) 4 bytes
dd if=mbroken bs=1 count=4 skip=392 | md5sum

# The file /home/bombadil/mbroken is a copy of an MBR from another machine.
# Hash only the Bootstrap section of the MBR using md5sum. The flag is the entire hash.
# 0x000 (0) 446 bytes
dd if=mbroken bs=1 count=446 | md5sum

# Identify the default run level on the SysV Init Linux machine.
cat /etc/inittab | grep init # search for default run level

# What is the last script to run when the command init 6 is executed?
ls -la /etc/rc6.d # follow the last script in the relative path

# Identify the file that init is symbolically-linked to, on the SystemD init machine.
ls -la /sbin/init # -> /lib/systemd/systemd

# What is the default target on the SystemD machine and where is it actually located?
cat /lib/systemd/system/default.target # description=graphical interface
ls /lib/systemd/system | grep graphical

# How many wants dependencies does SystemD actually recognize for the default.target
systemctl show -p Wants graphical.target | pr -w 8

# What is the full path to the binary used for standard message logging?
systemctl | grep log # outputs all log related services/sockets >> rsyslog.service
systemctl status rsyslog.service # lives in /usr/sbin/rsyslogd

# Identify the Linux Kernel being loaded by the Grub, by examining its configuration.
cat /boot/grub/grub.cfg | grep linux
