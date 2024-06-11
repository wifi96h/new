# red jump box
# net3_student11@10.50.21.8
# password11

Target Section:

T1
Hostname: networking-ctfd-1.server.vta
Record Type: TXT
IP: UNKNOWN
Ports: 53
Action: interrogate DNS records
Red Boundry Router
Hostname:
IP: 172.16.120.1
Ports: 22
Username: vyos
Password: password
Action: Use as start point and Perform Passive/Active Reconnaissance
T2
Hostname: UNKNOWN
IP: 172.16.182.110
Action: Perform Active Reconnaissance

T3
Hostname: UNKNOWN
IP: 172.16.140.33
Action: Perform Active Reconnaissance

T4
Hostname: UNKNOWN
IP: 172.16.182.106
Action: Perform Active Reconnaissance

T5
Hostname: UNKNOWN
IP: 172.16.182.114
Action: Perform Active Reconnaissance

T6
Hostname: UNKNOWN
IP: 172.16.182.118
Action: Perform Active Reconnaissance

T7
Hostname: UNKNOWN
IP: 172.16.140.35
Action: Perform Active Reconnaissance

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

