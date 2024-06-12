T1
Hostname: INTERNET_HOST
External IP: 10.50.XXX.XXX (ALREADY PROVIDED) Internal IP: 10.10.0.40 (ALREADY PROVIDED) (accessed via FLOAT IP)
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

2. T1 C -> S Relay S <- C T2

3. T1 C -> S Relay C -> S T2

4. T1 C -> S Relay C -> S T2
