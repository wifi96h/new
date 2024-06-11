# The start flag is an encoded string that is in a record associated with your CTFd server. Decode this string for the flag
dig networking-ctfd-1.server.vta TXT

# Utilizing the intelligence already provided, what is it’s hostname of their boundary router?
ssh vyos@172.16.120.1:password

# How many host(s) did you discover on the DMZ Net? (excluding the router)
show interface # dmz is on eth2
show arp # count number of active devices on eth2

#  What is the ip address of the host device(s) in the DMZ network?
show arp # get ip address

# How many well-known open TCP ports did you discover on the device(s)?

