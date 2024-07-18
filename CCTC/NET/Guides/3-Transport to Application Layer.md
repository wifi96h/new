# 3.0 Outcomes
- Explain OSI Layer 4 ports, protocols and headers
  - Describe Transport Layer Protocols
  - Review Well-known, Registered and Dynamic port ranges
  - Describe TCP reliability using sequence and acknowledgement numbers
  - Analyze TCP and UDP headers
  - Explain TCP Options
  - Identify hexadecimal representations of transport layer protocol headers
- Explain OSI Layer 5 protocols and headers
  - Understand Virtual Private Networks (VPN)
  - Examine L2TP and PPTP tunning protocols
  - Understand proxies
  - Examine SOCKS protocol
  - Examine Network Basic Input Output System (NETBIOS) protocol
  - Recognize well-known NetBIOS suffixes (services) and their potential for operational impact
  - Examine Server Message Block protocol
  - Examine Remote Procedure Call (RPC) protocol
- Explain OSI Layer 6 functions and responsibilities
  - Explain the presentation layer functions and responsibilities
- Explain OSI Layer 7 protocols and headers
  - Analyze Telnet protocol
  - Analyze Secure Shell Protocol (SSH)
  - Analyze Hypertext Transfer Protocol (Secure) (HTTP(s))
  - Analyze Domain Name System (DNS) protocol
  - Examine DNS usage with UDP and TCP
  - Explain DNS Records
  - Explain DNS architecture
  - Analyze File Transfer Protocol (FTP)
  - Analyze Trivial File Transfer Protocol (TFTP)
  - Analyze Simple Mail Transfer Protocol (SMTP)
  - Analyze Post Office Protocol (POP)
  - Analyze Internet Message Access Protocol (IMAP)
  - Analyze Dynamic Host Configuration Protocol (DHCP) version 4 and 6 protocol
  - Explain DHCP Vulnerabilities
  - Analyze Network Time Protocol (NTP) and vulnerability
  - Analyze Terminal Access Controller Access-Control System Plus (TACACS+) Protocol
  - Analyze Remote Authentication Dial-In User Service (RADIUS) protocol
  - Analyze Diameter Protocol
  - Analyze Simple Network Management Protocol (SNMP)
  - Analyze Real-time Transport Protocol (RTP)
  - Analyze Remote Desktop Protocol (RDP)
  - Analyze Kerberos
  - Analyze Lightweight Directory Access Protocol (LDAP)


The functions and protocols at Layers 4 through 7 of the OSI model are instrumental in cybersecurity for their roles in facilitating end-to-end communication, managing network traffic, and providing various application-layer services. Layer 4 (Transport layer) protocols such as TCP (Transmission Control Protocol) and UDP (User Datagram Protocol) play a vital role in ensuring reliable and efficient data transmission across networks. TCP provides connection-oriented communication, error detection, and flow control, making it suitable for applications requiring guaranteed delivery, while UDP offers connectionless communication, making it ideal for real-time and latency-sensitive applications. Understanding these protocols enables cybersecurity professionals to optimize network performance, troubleshoot connectivity issues, and implement security measures such as firewall rules based on TCP or UDP port numbers.

Moving up the OSI model, Layer 5 (Session layer) protocols are responsible for establishing, maintaining, and terminating sessions between communicating devices. While less commonly implemented as distinct protocols, the concepts of session management are crucial in cybersecurity for ensuring secure and authenticated communication between endpoints. By understanding session management principles, cybersecurity professionals can implement secure authentication mechanisms, manage session timeouts, and detect and mitigate session hijacking attacks.

Layer 6 (Presentation layer) is primarily concerned with data representation and encryption, ensuring that data exchanged between applications is formatted and interpreted correctly. Protocols such as SSL/TLS (Secure Sockets Layer/Transport Layer Security) operate at this layer to provide encryption, authentication, and data integrity for secure communication over the internet. Knowledge of presentation layer protocols enables cybersecurity professionals to implement secure communication channels, protect sensitive data from eavesdropping, and ensure interoperability between different systems and applications.

Finally, Layer 7 (Application layer) protocols encompass a wide range of application-specific functions and services, including email, web browsing, file transfer, and remote access. Protocols such as HTTP (Hypertext Transfer Protocol), SMTP (Simple Mail Transfer Protocol), and SSH (Secure Shell) operate at this layer to enable communication between end-user applications and network services. Understanding Layer 7 protocols is essential for identifying and mitigating application-layer attacks such as SQL injection, cross-site scripting (XSS), and phishing. Additionally, knowledge of application layer protocols allows cybersecurity professionals to implement security controls, such as web application firewalls (WAFs) and intrusion detection systems (IDS), to protect against these threats.

In summary, the functions and protocols at Layers 4 through 7 of the OSI model are critical components of cybersecurity, enabling secure and reliable communication, managing network traffic, and providing essential application-layer services. By understanding and leveraging these protocols effectively, cybersecurity professionals can enhance network security, protect against cyber threats, and ensure the confidentiality, integrity, and availability of critical assets and information.


## 3.1 Explain OSI Layer 4 ports, protocols and headers
Layer 4 of the OSI (Open Systems Interconnection) model is the Transport Layer. The Transport Layer is responsible for providing end-to-end communication between hosts, ensuring that data is reliably delivered and that communication sessions are established, maintained, and terminated.

- The two main protocols at this layer are:

  - TCP (Transmission Control Protocol) provides reliable, connection-oriented communication by establishing a connection, ensuring data delivery, and handling error detection and recovery. TCP is commonly used for applications that require reliable and ordered delivery of data, such as web browsing, email, and file transfer.

    - The protocol data unit (PDU) for TCP is Segment.

    - TCP Header: The TCP header contains fields such as source port, destination port, sequence number, acknowledgment number, checksum, and control flags (e.g., SYN, ACK, FIN). These fields are used to establish connections, manage data transmission, and handle flow control and error recovery.

  - UDP (User Datagram Protocol) provides unreliable, connectionless communication by sending data packets without establishing a connection or ensuring delivery. UDP is commonly used for real-time applications, multimedia streaming, DNS, and other applications where low overhead and minimal delay are preferred over reliability.

    - The protocol data unit (PDU) for UDP is Datagram.

    - UDP Header: The UDP header contains fields such as source port, destination port, length, and checksum. Unlike TCP, UDP does not include sequence numbers, acknowledgment numbers, or control flags, as it provides a simple, connectionless transport mechanism without reliability features.

- Addressing used at this layer are ports.

    - Ports are communication endpoints that allow multiple applications or services to run on a single device and communicate over a network. Ports are identified by numbers ranging from 0 to 65535.

    - Well-known ports (0-1023) are reserved for specific services, such as HTTP (port 80) and SMTP (port 25).

    - Registered ports (1024-49151) are used by applications and services registered with the Internet Assigned Numbers Authority (IANA).

    - Dynamic or private ports (49152-65535) are available for temporary use by client applications when establishing connections. 


### 3.1.1 Describe Transport Layer Protocols
The Transport layer (Layer 4) is responsible for the transfer of data, ensuring that data is error-free and in order.

Transport layer communication falls under two categories:



Connection-oriented (TCP-Segments-Unicast traffic)

- Requires that a connection with specific agreed-upon parameters be established before data is sent.

- Provides segmentation and sequencing.

- Provides connection establishment and acknowledgments to provide reliability.

- Provides flow control (or windowing).

- Common application layer protocols or functions that rely on TCP are SSH, Telnet, FTP, SMTP, POP, IMAP, and HTTP(s).

- Get more information in [RFC 793](https://datatracker.ietf.org/doc/html/rfc793)



Connection-less (UDP-Datagrams-Broadcast, Multicast, Unicast Traffic)

- Requires no connection before data is sent.

- Provides no ordering, duplicate protection or delivery guarantee.

- Application layer protocols will normally provide the reliability if needed.

- Does provide integrity checking using the checksum.

- Common application layer protocols or functions that rely on UDP are DNS, TFTP, and QUIC (Quick UDP Internet Connections).

- Get more information in [RFC 768](https://www.ietf.org/rfc/rfc768.txt)



References:

https://datatracker.ietf.org/doc/html/rfc793
https://www.ietf.org/rfc/rfc768.txt


### 3.1.2 Review Well-known, Registered and Dynamic port ranges
Ports are used in computer networking to facilitate communication between different applications, services, or devices. They serve as endpoints for network communication and help distinguish between multiple concurrent communication channels.

- Identifying Applications and Services:

  - Ports are numbered identifiers assigned to specific applications or services running on a device.

  - Each application or service that communicates over a network uses one or more ports to send and receive data.

  - Ports help network devices understand which application or service should receive incoming data packets.

- Multiplexing and Demultiplexing:

  - Ports enable multiplexing, which allows multiple applications or services to share a single network connection or network interface.

  - When data packets arrive at a device, the operating system uses the destination port number to demultiplex the packets and forward them to the appropriate application or service.

  - Without ports, computers would be limited to engaging in only one communication session at a time, severely constraining their ability to multitask and efficiently handle network traffic.

- Establishing Communication Channels:

  - Ports play a crucial role in establishing communication channels between devices on a network.

  - In client-server communication, a client application connects to a server application by specifying the server’s IP address and port number.

  - Once the connection is established, data can be exchanged between the client and server through the designated port.

- Network Security:

  - Ports are essential for configuring network security policies, such as firewalls and access control lists (ACLs).

  - Firewall rules can be configured to allow or block traffic based on specific port numbers, helping to protect network resources from unauthorized access or malicious activity.

- Network Troubleshooting:

  - Ports are often used in network troubleshooting to diagnose connectivity issues or analyze network traffic.

  - By examining the port numbers associated with network traffic, network administrators can identify the applications or services involved and pinpoint the source of network problems.



![image](https://github.com/ruppertaj/WOBC/assets/93789685/36444982-69a9-41d0-9500-37452dabdc7f)
Port Ranges


Well-known (System) port numbers (0-1023), which are assigned by IANA are responsible for maintaining the official assignments of port numbers for specific uses. This range is dedicated for common protocols and services across all operating systems. Changes to systems well-known port numbers require elevated or root privileges.

Registered (User) port numbers (1024-49151) can be registered with IANA for a specific service by a requesting entity. This range is loosely controled by IANA. Some operating systems may use this range as dynamically assigned source ports. There are services and protocols that have ports in this range such as Remote Desktop Protocol (RDP on port 3389). Many services and protocols in this port range may be limited to specific operating systems. Changes to systems registered port numbers do not need elevated or root privileges.

Dynamic (Private) port numbers (49152-65535) can not be registered with IANA. These ports are for use as temporary, private, or/and for automatic allocation of ephemeral ports. This range is not controlled in any way by IANA for any protocols and services. Changes to systems dynamic port numbers do not need elevated or root privileges.

- Important to note that binding is an integral step for server side socket (IP address + port number) that provides an address to a end-user to request services. Restrictions to the well-known port numbers is needed to protect major network services such as HTTP, HTTPS, SSH, FTP, etc. Without these restrictions a unauthorized user could run a program that listened on these ports for login (access) details or could run a unauthorized server application.



- Source Port:

  - When a client initiates communication, it selects a source port to use for outgoing packets.

  - The source port helps the client device identify which application or service on the sending device originated the communication.

  - Source ports are typically chosen from the dynamic port range (49152-65535) by the operating system or application.

  - The server however will use the service port as its source port.

- Destination Port:

  - The client specifies the destination port as the number used by the receiving application or service.

  - It client specifies the port on the destination server where the communication is intended to be delivered.

  - When the server receives incoming packets, it uses the destination port number to determine which application or service should handle the data.

  - Destination ports are typically well-known (1-1023) or registered port numbers (1024-49151) that are associated with specific services or applications.

  - The server however will use the client’s dynamically assigned source port as its destination port to send replies back to the client.



References:

https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml
https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers


### 3.1.3 Describe TCP reliability using sequence and acknowledgement numbers


![image](https://github.com/ruppertaj/WOBC/assets/93789685/cdfe47c3-1f71-4301-9515-b7d9ae9c3883)
TCP Connection Sequence


TCP is a connection oriented protocol and therefore is divided into one of 3 phases.

1. Connection establishment

  - 3-way Handshake. Any system can initiate the connection but is typically initiated from a client to request connection to a server.

    - `SYN` - Client initiates the connection by setting the SYN flag and sending his initial starting SEQ number in the SEQ number field. The ACK flag and field are set to zero. The client can additionally specify other communication parameters. These parameters can only be negotiated during the SYN phase and can not be changed later in the communication.

      - Maximum Segment Size (MSS) (Kind=2). Largest amount of data that can be transmitted in a single TCP segment.

      - Window scale factor (Kind=3). Extends the window size field in TCP headers to support larger data transfers by multiplying the window size value by a power of two, effectively expanding the range of available window sizes.

      - Selective Acknoledgement (SACK) (Kind=5). Option allowing a receiver to inform the sender about specific segments that have been received successfully, enhancing performance by enabling retransmission of only missing segments rather than entire blocks of data.

    - `SYN-ACK` - Server responds to the client by turning on the ACK flag and adding 1 to client’s SEQ number and placing the value in the ACK field. The server will turn on the SYN flag and insert its own SEQ number in the SEQ number field. The server can additionally specify other communication parameters such as its Window scale factor, Maximum Segment Size (MSS), and Selective Acknoledgement (SACK).

    - `ACK` - Client will then set the ACK flag add 1 to the server’s SEQ number and place in the ACK field and send to server. The SEQ number will be the next number in sequence from the starting. The SYN flag however will not be turned on. This completes the handshake and both sides are now in the ESTABLISHED state and all data transfer is bi-directional.
      
    - Sequence number can start at any number, and is determined by the sending device. 
```
C       SYN          S
 ------------------>
 syn #100, ack #0

      SYN/ACK   
 <-----------------
  syn #400, ack #101

         ACK
  ----------------->
  syn #101, ack #401

     Established
 <----------------->
```


2. Data Transfer

  - During the ESTABLISHED state communication can go in either direction. Data can be either set to or pulled from the server.

    - `PSH-ACK` - Server is sending data to client so it turns on the PSH flag. It will insert its next incrementing SEQ number in the SEQ field. In the payload, it will send either the amount of bytes its able to send, or the amount the client is able to receive, depending on which is smaller. This is determined by the window size of each side. This can increase or decrease during the communication. The ACK flag will also be set to ACK the last SEQ number from the Client +1.

    - `ACK` - The client will set his incrementing SEQ number in the SEQ field and then set the ACK flag and ACK field to the next expected byte number from the server in the ACK field.

3. Connection Termination

  - 4-way termination. Either the client or server can initiate the connection termination. Each end can only close its half of the connection which means that each end needs to request to close. Whichever initiates it follows this process:

    - `FIN-ACK` - Initiator will set the FIN flag to inform the other end that it is closing its end of the connection. It will set its SEQ number to the next incrementing number.

    - `ACK` - Receiver will set the ACK flag and ACK the initiator’s SEQ number +1 in the ACK field.

    - `FIN-ACK` - Receiver then initiates its connection termination buy setting the FIN flag and setting its own SEQ number in the SEQ field.

      - If the close was initiated by the client, the server can respond to the `FIN-ACK` sent by the client in one of two ways.

        - Passive Close by Server: The server receives the FIN segment from the client and sends back an ACK segment to acknowledge the termination request but does not sent a `FIN-ACK` itself.

        - Active Close by Server: The server does send a `FIN-ACK`.

      - `ACK` - Original initiator then sets the ACK flag and ACKs the receiver’s SEQ number +1 in the ACK field. SEQ number will be the next incrementing SEQ number.

   - Can also close the connection by S sending RST flag, or C send CLOSE/FIN and S does a passive close.

References:

https://packetlife.net/blog/2010/jun/7/understanding-tcp-sequence-acknowledgment-numbers/


### 3.1.4 Analyze TCP and UDP headers
This section will cover the two main headers, TCP and UDP. A greater understanding of the headers will help provide you information on how to modify or to identify abnormal TCP segments and UDP datagrams.


3.1.4.1 TCP Headers


![image](https://github.com/ruppertaj/WOBC/assets/93789685/d82dac11-8f7e-42bb-8ebb-0168205702ea)
TCP Header

```
Byte Number	Field Name	              Bit Range    Length	   Description
0-1             Source Port                   0-15         16 bits         Specifies the port that localhost is listening on for traffic during this communication.
2-3            Destination Port               16-31        16 bits         Specifies the port on the receiving(destination) host that it is listening on for this communication.
4-7            Sequence Number                32-63        32 bits         If SYN flag set: this is the initial(starting) sequence number; If SYN flag is not set: this is the sequence number of the current segment that has incremented from the starting sequence number.
8-11           Ack Number (if ACK is set)     64-95        32 bits         If ACK flag is set, it specifies the next sequence number the sender is expecting. Sender’s Sequence Number +1.
12            Data Offset                     96-99        High 4 bits     The size of TCP header in 32-bit WORDS. Minimum=5, Max=15. Used if there are TCP options.
12            Reserved                        100-102      Low 3 bits      Reserved for future use and should be set to zero.
12            NS                              103          Low 1 bit       Optional addition to the L3 ECN. Reference [RFC 3540](https://tools.ietf.org/html/rfc3540).
13            Flags                           104-111      8 bits          Control bits: CWR, ECE, URG, ACK, PSH, RST, SYN, FIN
14-15         Window Size                     112-127      16 bits         Size (in bytes) that this host is able to receive. This can be different on each end and can change during the course of the connection. Reference Wikipedia ([Flow Control](https://en.wikipedia.org/wiki/Transmission_Control_Protocol#Flow_control)) ([Window Scaling](https://en.wikipedia.org/wiki/Transmission_Control_Protocol#Window_scaling))
16-17         Checksum                        128-143      16 bits         Calculation done using the TCP header, Payload, and the Pseudo-Header (Source IP, Destination IP, and Protocol number (0x06))
18-19         Urgent Pointer (if URG is set)  144-159      16 bits         If URG is set then this is an offset (range) from the sequence number indicating the last urgent data byte.
20-59         Options                         variable     0-320 bits & /by 32  Variable options. Reference [www.networksorcery.com](http://www.networksorcery.com/enp/protocol/tcp.htm#Options) for examples.
```


![image](https://github.com/ruppertaj/WOBC/assets/93789685/4acc2965-5f42-445a-a9de-a7e7beb31a16)
TCP Header 2


- TCP segments will have the Protocol field set to 6 in the IPv4 Header or the Next Header field set to 6 in the IPv6 Header.
```
00 1f 29 5e 4d 26 00 50　56 bb 3a a0 08 00 45 00
00 3c 83 1b 40 00 40 06　15 0a c0 a8 14 46 4a 7d
83 1b d5 1d 00 19 6b 7f　c7 2d 00 00 00 00 a0 02
72 10 a2 b5 00 00 02 04　05 b4 04 02 08 0a 0a 99
44 36 00 00 00 00 01 03　03 07
```

- Ethernet Header:

  - `00 1f 29 5e 4d 26` is the destination MAC

  - `00 50 56 bb 3a a0` is the source MAC

  -`08 00` is the ethertype for IPv4

- IPv4 Header:

  - `45` to identify the Version is 4 and the IHL is 5 which means the IP header is 20 bytes in length. (IHL x 4)

  - `00` is the DSCP. Used for Quality of Service (QoS).

  - `00 3c` is the Total length of 60 bytes. This includes the 20 byte header and 40 bytes of payload.

  - `83 1b` is the Identification field. Value is 33563.

  - `40 00` is the Flags and fragmentation offset field. This value has the Dont Fragement (DF) turned on and no fragmentation offset.

    - `80 00` is the value for the Reserved (Evil bit).

    - `20 00` to `3F FF` is the range for the More Fragements (MF) bit and fragmentation offset.

  - `40` is the Time to Live field. Currently set to 64.

  - `06` is the Protocol field. Currently set to identify TCP.

    - `01` is for ICMPv4

    - `11` is for UDP

  - `15 0a` is the Checksum field

  - `c0 a8 14 46` is the source IP address. Currently set to 192.168.20.70.

  - `4a 7d 83 1b` is the destination IP address. Currently set to 74.125.131.27.

- TCP Header:

  - `d5 1d` is the source port field. Currently set to 54557.

  - `00 19` is the destination port field. Currently set to 25.

  - `6b 7f c7 2d` is the sequence number field. Currently set to 1803536173.

  - `00 00 00 00` is the acknowledgement field. Currently set to 0.

  - `a0` is the offset and reserved fields.

    - `a` is the offset field to identify the length of the TCP header. The a means that the TCP header is 40 bytes in length. (offset x 4)

    - `0` is the reserved field. This should always be 0.

  - `02` is the TCP flags field. Currently the SYN flag is set.

    - `80` is the Congestion window reduced (CWR) flag. ** Not used **

    - `40` is the ECN-Echo (ECE) flag. ** Not used ** 

    - `20` is the Urgent pointer flag. If set then system should check Urgent pointer field. ** Rarely used ** 

    - `10` is the Acknowledgment flag. Used to inform sender of received data.

    - `08` is the Push flag. Used to inform recipient that data is in payload.

    - `04` is the Reset flag. Sent to close connection.

    - `02` is the Synchronize flag. Used to synchronize starting sequence numbers at the start of the conneciton during the 3-way handshake.

    - `01` is the Finish flag. Used to inform other end that connection is being terminated.

  - `72 10` is the window size field. Currently set to 29200. Size can be different for each device based on what it can buffer. Once negotiated, it will not change during transaction.

  - `a2 b5` is the checksum field.

  - `00 00` is the urgent pointer field. Should only be set if URG flag is on. This is not commonly used in modern networking. Currently set to 0. 

- TCP Options:

  - `02 04　05 b4` is the Maximum segment size (MSS) option field. Used to determine the MSS for the communicaiton. Kind = 2. Length = 4. MSS = 1460
    - Different from MTU (layer 2 packed size); will decrease if using tunneling or VPNs

  - `04 02` is the Selective Acknowledgement (SACK) permitted option. Used to determine if SACK is permitted or not. Kind - 4. Length = 2.

  - `08 0a 0a 99 44 36 00 00 00 00` is the timestamps option. Used to measure TCP roundtrip time (RTT). Kind = 8. Length = 10. Timestamp = 177816630. Timestamp echo reply = 0.

  - `01` is the No-Operation (NOP) option. Kind = 1

  - `03 03 07` is the window scale option. Used to to increase the maximum window size from 65,535 bytes to 1 Gigabyte. Kind = 3. Length = 3. Shift count = 7 (multiply by 128).

- Anything after this will be payload.



References:

https://tools.ietf.org/html/rfc3540
https://en.wikipedia.org/wiki/Transmission_Control_Protocol#Flow_control
https://en.wikipedia.org/wiki/Transmission_Control_Protocol#Window_scaling
http://www.networksorcery.com/enp/protocol/tcp.htm#Options


##### 3.1.4.1.1 TCP Flags


![image](https://github.com/ruppertaj/WOBC/assets/93789685/9dc181c5-7a08-4dc5-ba6a-faa0bf4498a5)
TCP Flags


CWR: Congestion Windows Reduced - The congestion window reduced flag is used by the sending host to indicate it received a packet with the ECE flag set. (Not comonly used unless Explicit Congestion Notification (ECN) is used in the TCP header.)

ECE: Explicit Congestion Notification (ECN) Echo - This flag is responsible for indicating if the TCP peer is ECN capable. (Not comonly used unless Explicit Congestion Notification (ECN) is used in the TCP header.)

URG: Urgent - Indicates that the urgent pointer field is valid and contains urgent data. The urgent flag is used to notify the receiver to process the urgent packets before processing all other packets. Has become less relevant for modern TCP communications.

ACK: Acknowledgment - The acknowledgment flag is used to acknowledge the successful receipt of a packet.

PSH: Push - The push flag is somewhat similar to the URG flag and tells the receiver to process these packets as they are received instead of buffering them. This flag is only used during the established phase when sending data. Should be sent with an ACK flag.

RST: Reset - The reset flag gets sent from the receiver to the sender when a packet is sent to a particular host that was not expecting it. Most commonly used in response to a TCP connection on a closed port.

SYN: Synchronize - The synchronization flag is used as a first step in establishing a three way handshake between two hosts. Is only legitimately used during the 3-way handshake.

FIN: Finished - The finished flag means no more data from sender. Used as part of the 4-way TCP connection termination. Should be sent with an ACK flag.



Two mnemonics to remember the TCP flags are:

- Collection of Exceptionally Unskilled Attackers Pester Real Security Folks

- Coach Explained to the University of Alaska to Play Really Snowy Football



RFC recommended response to illegal flag combinations:

- Some illegal flag combinations may include null (no flags), URG-PSH-FIN (x-mas tree scan), FIN without ACK. Per the RFC, operating systems should silently discard packets containing illegal combinations.

- Most Linux distributions follow the RFC’s guidance which is to not respond.

- Windows and MacOS often reply to these combinations with a RST-ACK. This can make those OSes harder to enumerate via TCP scanning, since open/closed ports illicit the same response.

When and why are illegal flag combinations or TCP options used?

- Illegal flag combinations are often used during network scanning or enumeration to find out what ports are open through a firewall, services a host is running, or information about the OS.

- TCP options are also commonly used in identifying OSes by tools such as P0f. This is because different operating systems can use different Window sizes, windows scaling and MSS values.



References:

https://datatracker.ietf.org/doc/html/rfc793
https://datatracker.ietf.org/doc/html/rfc3168


##### 3.1.4.1.2 TCP States


![image](https://github.com/ruppertaj/WOBC/assets/93789685/1abf5e4e-9623-4522-9e55-32a765df2394)
TCP Connection States Chart


LISTEN - represents waiting for a connection request from any remote TCP and port.

SYN-SENT - represents waiting for a matching connection request after having sent a connection request.

SYN-RECEIVED - represents waiting for a confirming connection request acknowledgment after having both received and sent a connection request.

ESTABLISHED - represents an open connection, data received can be delivered to the user. The normal state for the data transfer phase of the connection.

FIN-WAIT-1 - represents waiting for a connection termination request from the remote TCP, or an acknowledgment of the connection termination request previously sent.

FIN-WAIT-2 - represents waiting for a connection termination request from the remote TCP.

CLOSE-WAIT - represents waiting for a connection termination request from the local user.

CLOSING - represents waiting for a connection termination request acknowledgment from the remote TCP.

LAST-ACK - represents waiting for an acknowledgment of the connection termination request previously sent to the remote TCP (which includes an acknowledgment of its connection termination request).

TIME-WAIT - represents waiting for enough time to pass to be sure the remote TCP received the acknowledgment of its connection termination request.

CLOSED - represents no connection state at all.

References:

https://datatracker.ietf.org/doc/html/rfc793


#### 3.1.4.2 UDP Headers

![image](https://github.com/ruppertaj/WOBC/assets/93789685/ad586b90-ef1b-4d8d-8939-4319a730acf6)
UDP Header

Byte Number	Field Name      	Bit Range	Length	      Description
0-1             Source Port             0-15            16 bits       Specifies the port that localhost is listening on for traffic during this communication.
2-3             Destination Port        16-31           16 bits       Specifies the port on the receiving(destination) host that it is listening on for this communication.
4-5             Length                  32-47           16 bits       Specifies the length of the UDP header and data.
6-7             Checksum                48-63           16 bits       Used for error checking of the header and data. This is optional for IPv4 and mandatory in IPv6.



- Some attributes that UDP does not have, which makes it a protocol better suited for certain applications like VoIP, Streaming Media or DNS.

  - UDP has a much smaller header. It does not address sequencing of datagrams (although Protocols like RTP riding over UDP can help to assist with this). It also does not have windowing, flow control, or a re-transmission mechanism.

  - These attributes make the protocol more lightweight and suited for latency sensitive applications, or applications that do not benefit from a stateful connection.

- UDP scans are difficult to use since the protocol is not stateful, no response is required from the target when a datagram is sent. ** UDP scanning is possible however because of the helper protocol ICMP. ICMP will provide "port unreachable" messages if the port being scanned is closed.

  - Due to the lack of flow control, UDP scans can easily overwhelm a host. This can result in the target being unable to process and provide ICMP messages response to all the probes sent, therefore skewing the results.

![image](https://github.com/ruppertaj/WOBC/assets/93789685/aae741d1-cb5e-4f83-b61d-c34d19f72ddf)
UDP Header


* UDP datagrams will have the Protocol field set to 17 in the IPv4 Header or the Next Header field set to 17 in the IPv6 Header.
```
00 1f 29 5e 4d 26 00 50　56 bb 3a a0 08 00 45 00
00 3c 83 1b 40 00 40 11　15 0a c0 a8 14 46 4a 7d
83 1b dc de 00 35 00 36　7c 15 03 c4 01 20 00 01
00 00 00 00 00 01 04 6f　63 73 70 08 76 65 72 69
73 69 67 6e 03 6e 65 74　00 00 1c 00 01 00 00 29
10 00 00 00 00 00 00 00
```

* Ethernet Header:

  - `00 1f 29 5e 4d 26` is the destination MAC

  - `00 50 56 bb 3a a0` is the source MAC

  - `08 00` is the ethertype for IPv4

- IPv4 Header:

  - `45` to identify the Version is 4 and the IHL is 5 which means the IP header is 20 bytes in length. (IHL x 4)

  - `00` is the DSCP. Used for Quality of Service (QoS).

  - `00 3c` is the Total length of 60 bytes. This includes the 20 byte header and 40 bytes of payload.

  - `83 1b` is the Identification field. Value is 33563.

  - `40 00` is the Flags and fragmentation offset field. This value has the Dont Fragement (DF) turned on and no fragmentation offset.

    - `80 00` is the value for the Reserved (Evil bit).

    - `20 00` to `3F FF` is the range for the More Fragements (MF) bit and fragmentation offset.

  - `40` is the Time to Live field. Currently set to 64.

  - `11` is the Protocol field. Currently set to identify UDP.

    - `01` is for ICMPv4

    - `06` is for TCP

  - `15 0a` is the Checksum field

  - `c0 a8 14 46` is the source IP address. Currently set to 192.168.20.70.

  - `4a 7d 83 1b` is the destination IP address. Currently set to 74.125.131.27.

- UDP Header:

  - `dc de` is the source port field. Currently set to 56542.

  - `00 35` is the destination port field. Currently set to 53.

  - `00 36` is the length field. Currently set to 54 bytes. This includes 8 bytes of UDP header and 46 bytes of payload.

  - `7c 15` is the checksum field.

- Anything after this will be payload.



Get more information in [RFC 768](https://tools.ietf.org/html/rfc768)



[(Well Known ports)](http://www.meridianoutpost.com/resources/articles/well-known-tcpip-ports.php)



DEMO Use Wireshark to demo layer 4. Show the TCP and UDP headers.



TCP DEMO Example

![image](https://github.com/ruppertaj/WOBC/assets/93789685/6e90a414-98ed-412a-b79e-53a85f80f353)
TCP DEMO Example


UDP DEMO Example

![image](https://github.com/ruppertaj/WOBC/assets/93789685/ee387829-77d9-4b5f-96aa-24d80c98fb4f)
UDP DEMO Example


References:

https://tools.ietf.org/html/rfc768
http://www.meridianoutpost.com/resources/articles/well-known-tcpip-ports.php



Instructor Note
Identify well-known port range and how they are used (0-1023). Ensure you discuss privilege required for a OS to bind a well-known port. Compare and discuss ephemeral ports and their use in communications.



### 3.1.5 Explain TCP Options
TCP Options:

- Kind 0 - End of Options List: Indicates the end of the TCP options list. This option is a single byte with the value 0, serving as a delimiter for the end of the options.

- Kind 1 - No Options or NOP: The NOP option is used for padding and alignment purposes. It has no operational effect but allows for the proper alignment of subsequent options. NOP is 1 byte in length and is used with other options to ensure they are in even 32-bit (4 byte) WORDS.

- Kind 2 - Maximum Segment Size (MSS): The MSS option is specified during the 3-way handshake when the SYN flag is set. This identifies how many bytes of data that it can receive in a single segment. This is typically small enough to avoid the need for IP fragmentation. This is different from MTU which is the maximum packet size in bytes. The MTU is determined primarily by the network the host is connected to. The MSS should typically not exceed the value of the MTU minus the IP/TCP headers. Setting a MSS to a smaller value will then reflect a smaller packet size and can be less than 1500. For example: If you set the MSS to 1400 bytes, this will then have a minimum of 20 bytes of TCP header and 20 bytes of IP header (assuming no options). This will make the maximum packet size of 1440 bytes. This is less than the 1500 MTU so it gives room for other headers such as encryption or options. Reference [RFC 793](https://tools.ietf.org/html/rfc793#page-18), [Youtube Video](https://www.youtube.com/watch?v=XMcYwr-yJGA)

- Kind 3 - TCP Window Scaling: The window size field in the TCP header is a 16 bit field so the value of this field can only be from 0-65,535. This means that the sender of this segment can only theoretically receive between 0 bytes to 65,535 bytes of data before 1 ACK is sent. This is due to its receive buffers ability to hold and process data. Because of more modern computers having the feature of larger memory buffers, it can request to receive more data than what the window size field is able to be set to. Using the TCP Window scale option, the segment sender can set a multiplier (i.e. 0, 1, 2, 4, up to 14 etc). This will adjust a calculated window size that you can see in Wireshark to the window size multiplied by the multiplier setting. If the sender using this option it will enable it for use on the receiver’s end. During the transfer process the receiver’s window size can decrease. This is typically due to its buffer becoming filled faster than it can process the data. Once the receive buffer is filled it will set its window size to zero until the data can be sufficiently processed. During the wait the sender will send keep-alives to keep connection open to avoid any timeouts and the receiver will ACK these messages to let sender know they are still active but window size will stay at zero. Once the receiver’s buffers are cleared it will then send a message with the window size and scaling set to what it can now receive. Reference [RFC 7323](https://tools.ietf.org/html/rfc7323#page-8), [Youtube video 1](https://www.youtube.com/watch?v=Qpkr_12RQ7k), [Youtube Video 2](https://www.youtube.com/watch?v=2PJVHvthrNU)

- Kind 4 - SACK Permitted: Indicates that the sender is willing to receive Selective Acknowledgment (SACK) information from the receiver. The length is typically 2 bytes.

- Kind 5 - SACK (Selective Acknowledgment): Contains information about segments that have been received successfully. SACK allows for more efficient recovery from lost or out-of-order segments. The length is variable, depending on the number of SACK blocks.

- Kind 8 - Timestamps: Used for timestamp synchronization between TCP peers. The sender includes a timestamp value in the TCP header, and the receiver echoes it back. Timestamps are useful for calculating round-trip times and can be used in congestion control algorithms. The length is typically 10 bytes.

- Kind 14 - TCP Alternate Checksum Request: Requests an alternative checksum for the TCP header and data. This option is not widely used, and the length is typically 3 bytes.

- Kind 15 - TCP Alternate Checksum Data: Contains the alternative checksum for the TCP header and data. Like the request option, this option is not commonly used, and the length is typically variable.

DEMO TCP Open wireshark and capture traffic while you browse to www.espn.com

Below images are shown for reference and explanation of the traffic capture.

SYN

![image](https://github.com/ruppertaj/WOBC/assets/93789685/cfe86c90-edbe-417d-a5a9-cf2a658da24c)
TCP Options1 DEMO Example

Actucal client’s(192.168.65.20) window size, in bits, is 28200(Window size value) x 128(window scale 2^7)(TCP Option Multplier)=3609600

![image](https://github.com/ruppertaj/WOBC/assets/93789685/1ff0fa39-1814-4ad1-951b-077134f9ff97)
MTU MSS Frame1 DEMO Example

Above image shows MTU and MSS relationship.



SYN, ACK

![image](https://github.com/ruppertaj/WOBC/assets/93789685/85e709d4-bb8e-42da-9fb8-014ce0caf787)
TCP Options2 DEMO Example

Actucal server’s(13.107.21.200) window size, in bits, is 65535(Window size value) x 256(window scale 2^8)(TCP Option Multplier)=16776960

![image](https://github.com/ruppertaj/WOBC/assets/93789685/60076b48-ec0f-4d03-a31e-2125508502e6)
MTU MSS Frame2 DEMO Example

Above image shows MTU and MSS relationship.

[Indepth on TCP Options](http://www.networksorcery.com/enp/protocol/tcp.htm#Options)

References:

https://datatracker.ietf.org/doc/html/rfc793#page-18
https://www.youtube.com/watch?v=XMcYwr-yJGA
https://datatracker.ietf.org/doc/html/rfc7323#page-8
https://www.youtube.com/watch?v=Qpkr_12RQ7k
https://www.youtube.com/watch?v=2PJVHvthrNU


### 3.1.6 Identify hexadecimal representations of transport layer protocol headers
Quick Review:

[Hexadecimal](https://en.wikipedia.org/wiki/Hexadecimal) – base 16: From Wikipedia

“In mathematics and computer science, hexadecimal (also base 16, or hex) is a positional numeral system with a radix, or base, of 16. It uses sixteen distinct symbols, most often the symbols 0–9 to represent values zero to nine, and A, B, C, D, E, F (or alternatively a–f) to represent values ten to fifteen. For example, the hexadecimal number 2AF3 is equal, in decimal, to (2 × 163) + (10 × 162) + (15 × 161) + (3 × 160), or 10995.

Each hexadecimal digit represents four binary digits (bits), and the primary use of hexadecimal notation is a human-friendly representation of binary-coded values in computing and digital electronics. One hexadecimal digit represents a nibble (4 bits), which is half of an octet. For example, byte values can range from 0 to 255 (decimal), but may be more conveniently represented as two hexadecimal digits in the range 00 to FF. Hexadecimal is also commonly used to represent computer memory addresses.”

![image](https://github.com/ruppertaj/WOBC/assets/93789685/497613c2-e588-430c-8b4c-9b07eac4e0c9)
TCP Flags Breakout

In the image above, a hex representation of 0x02 in a hex output at byte 13 would identify a SYN flag being set to ON. A 0x12 at that same byte number would indicate that a SYN, ACK flags are set to ON. Finally a 0x10 on byte 13 would identify a ACK flag.


```
TCP Flags:

              8       4        2        1       8        4       2       1
              128     64       32       16      8        4       2       1
              URG     CWR      ECE      ACK     PSH      RST     SYN     FIN
SYN           0       0        0        0       0        0       1       0       0x02
SYN/ACK       0       0        0        1       0        0       1       0       0x12
ACK           0       0        0        1       0        0       0       0       0x10
Established   -       -        -        -       -        -       -       -       
PSH/ACK       0       0        0        1       1        0       0       0       0x18
ACK           0       0        0        1       0        0       0       0       0x10
PSH/ACK       0       0        0        1       1        0       0       0       0x18
ACK           0       0        0        1       0        0       0       0       0x10
Graceful      
Termination   -       -        -        -       -        -       -       -       
FIN/ACK       0       0        0        1       0        0       0       1       0x11
ACK           0       0        0        1       0        0       0       0       0x10
FIN/ACK       0       0        0        1       0        0       0       1       0x11
ACK           0       0        0        1       0        0       0       0       0x10
UnGraceful
Termination   -       -        -        -       -        -       -       -
RST           0       0        0        0       0        1       0       0      0x04
```


References:

https://en.wikipedia.org/wiki/Hexadecimal


## 3.2 Explain OSI Layer 5 protocols and headers

Layer 5 of the OSI (Open Systems Interconnection) model is the Session Layer. The Session Layer is responsible for managing communication sessions between devices, including establishing, maintaining, and terminating these sessions. Unlike lower layers, which focus on the transmission of data, the Session Layer deals with the organization and synchronization of communication sessions. While the OSI model defines the Session Layer, it’s worth noting that in many practical network implementations, the functions of the Session Layer are often combined with those of the Presentation Layer or are implemented within application-layer protocols. Therefore, Layer 5 protocols are not as prevalent or standardized as those in lower layers.

- Session Layer — The main purpose of this layer is to maintain the state of your ongoing connections. This state is not used in a connection-less protocol. Functions for managing sessions, including session synchronization, checkpointing, and recovery in the event of communication failures. These functions ensure that communication sessions remain synchronized and consistent between devices.

  - This layer provides the capabilities to open, close and manage sessions between the application layer processes. The communication at this layer consist of requests and responses that occur between the local and remote applications. Session-layer makes use of remote procedure calls (RPCs), Net-Beui, SOCKS, SMB, WINS, named-pipes, PPTP and other protocols.
    - Use `netstat` or `ss` to view open sessions

### 3.2.1 Understand Virtual Private Networks (VPN)
Virtual Private Networks (VPN) allows connections through a network that is not accessible to everyone else. This "private" connection makes is look like a direct connection, when in fact it is not. VPNs work by encapsulating an IP packet into another IP packet for traversal across a (generally) public network. The outer IP packet headers used for the traversal is then removed and the original packet headers are then used for further routing decisions.

![image](https://github.com/ruppertaj/WOBC/assets/93789685/4ff9a2d1-70ed-4212-8e07-23e8319c29ba)
VPN Connection

VPN connections are typically unencrypted but can be secured using encryption, such as IPSEC or TLS/SSL, to make it more secure for sensitive information. Some protocols used to provide confidentiality for VPN tunnels.

- IPsec: Provides a suite of protocols for secure IP communication, including Authentication Header (AH), Encapsulating Security Payload (ESP), and Internet Key Exchange (IKE).

- SSL/TLS: Utilizes the SSL/TLS protocol suite to create secure connections between clients and servers, commonly used in SSL VPNs.

- OpenVPN: An open-source VPN protocol that uses SSL/TLS for encryption and authentication, known for its flexibility and cross-platform compatibility.

When using VPNs, the overhead of additional optional packet headers and security features (GRE, PTP, IPSEC, etc) must be taken in account for the MTU and MSS sizes. Some communications do not handle the tunneling automatically and reduce its MTU size. These communication methods may require manual MTU configurations.

- Types of VPNs:

  - Remote Access VPN:

    - Allows individual users to securely connect to a private network from remote locations over the internet.

    - These VPNs are commonly used by employees working from home or while traveling to access company resources such as files, applications, and internal systems.

    - Remote access VPNs typically use protocols like SSL/TLS or IPsec to create encrypted tunnels between the user’s device and the corporate network.

  - Site-to-Site VPN: (aka router-to-router VPN)

    - Connects multiple sites or networks together over the internet, creating a secure communication link between them.

    - Site-to-site VPNs are commonly used to connect branch offices to a central headquarters, or to connect geographically distributed data centers.

    - Can be configured as point-to-point or point-to-multipoint.

  - Client-to-Site VPN: (aka endpoint-to-site VPN)

    - Similar to remote access VPNs, client-to-site VPNs allow individual clients or devices to securely connect to a private network over the internet.

    - However, unlike remote access VPNs, client-to-site VPNs typically require the installation of VPN client software on the user’s device.



References:

https://en.wikipedia.org/wiki/Virtual_private_network

https://nvd.nist.gov/vuln/detail/CVE-2024-3661

https://www.helpnetsecurity.com/2024/05/08/tunnelvision-cve-2024-3661/

https://www.helpnetsecurity.com/2023/08/14/vpn-vulnerabilities-tunnelcrack-attacks/


#### 3.2.1.1 L2TP (TCP 1701)
- Layer Two Tunneling Protocol (L2TP) serves as an extension of the Point-to-Point Tunneling Protocol (PPTP) commonly employed by internet service providers (ISPs) to establish virtual private networks (VPNs). The primary objective of L2TP is to enable secure data transmission through the creation of tunnels. To uphold security and privacy standards, L2TP necessitates the use of an encryption protocol within the established tunnel.

- L2TP exhibits the capability to transport a diverse range of Layer 2 (L2) data types across an Internet Protocol (IP) or Layer Three (L3) network. The initiation of this process involves the establishment of a tunnel connecting an L2TP Access Concentrator (LAC) and an L2TP Network Server (LNS) on the internet. This configuration facilitates the implementation of a Point-to-Point Protocol (PPP) link layer, which is encapsulated and seamlessly transferred across the internet for secure and efficient communication.



![image](https://github.com/ruppertaj/WOBC/assets/93789685/2532c65c-2b0b-411d-9b3a-c00bee2c2478)
L2TP

- Specified in [RFC 2661](https://tools.ietf.org/html/rfc2661) Has origins from Cisco’s L2F and Microsoft’s PPTP. Does not provide any encryption itself. Relies on other encryption methods for confidentiality.

- [L2TP Wiki Reference](https://en.wikipedia.org/wiki/Layer_2_Tunneling_Protocol)

- [L2TP Example PCAP from Cloudshark](https://www.cloudshark.org/captures/42d07a525b55)

References:

https://tools.ietf.org/html/rfc2661
https://en.wikipedia.org/wiki/Layer_2_Tunneling_Protocol
https://www.cloudshark.org/captures/42d07a525b55


#### 3.2.1.2 PPTP (TCP 1723)
- Point-to-Point Tunneling Protocol (PPTP) stands as a foundational networking protocol that empowers the secure deployment of Virtual Private Networks (VPNs) over the Internet. Conceived by Microsoft and collaborative contributors, PPTP is intricately designed to forge a private and encrypted communication conduit between clients and servers, guaranteeing the secure transmission of data.

- Authentication Mechanisms: PPTP boasts support for a range of robust authentication mechanisms, including Password Authentication Protocol (PAP), Challenge Handshake Authentication Protocol (CHAP), and Microsoft CHAP (MS-CHAP). These mechanisms play a pivotal role in fortifying the verification processes, ensuring the genuine identity of the connecting parties.

- Encapsulation and Encryption Expertise: PPTP demonstrates its prowess by encapsulating data within its proprietary packets, establishing a secure tunnel for data transmission. Furthermore, it incorporates encryption protocols such as Microsoft Point-to-Point Encryption (MPPE) to safeguard the confidentiality of the transmitted data. This dual-layered approach enhances the privacy and integrity of the communication channel.

- Awareness of Limitations: Recognizing its historical prevalence, it’s crucial to acknowledge the limitations associated with PPTP. While it was widely adopted in the past, PPTP has exhibited security vulnerabilities, prompting a gradual decline in usage. Organizations and users have increasingly favored more secure VPN protocols like L2TP/IPsec and OpenVPN to address evolving security standards and ensure a higher level of data protection.



![image](https://github.com/ruppertaj/WOBC/assets/93789685/47f17098-3797-44cd-abba-b4583ddf841f)
PPTP

- Specified in [RFC 2637](https://tools.ietf.org/html/rfc2637) Developed by Microsoft. Obsolete method to create VPN tunnels. Has many well know vulnerabilities.

- [PPTP Wiki Reference](https://en.wikipedia.org/wiki/Point-to-Point_Tunneling_Protocol)

- [PPTP Example PCAP from Cloudshark](https://www.cloudshark.org/captures/7a6644ad437e)



References:

https://en.wikipedia.org/wiki/Virtual_private_network
https://tools.ietf.org/html/rfc2637
https://en.wikipedia.org/wiki/Point-to-Point_Tunneling_Protocol
https://www.cloudshark.org/captures/7a6644ad437e


#### 3.2.1.3 IP Security (IPSec)
IPsec (Internet Protocol Security) is a suite of protocols used to secure IP communications by providing encryption, authentication, and integrity protection at the network layer (Layer 3) of the OSI model. It is widely used to establish Virtual Private Networks (VPNs) and secure data transmission over IP networks, including the internet.

Transport mode and Tunnel mode are two operational modes of IPsec (Internet Protocol Security) used to provide security for IP communications.



![image](https://github.com/ruppertaj/WOBC/assets/93789685/673fc0a9-4d6d-4b6b-86bc-6b6943eea0a0)
ipsectrans

- Transport Mode:

  - In Transport mode, IPsec only encrypts the payload (data) of the original IP packet, leaving the original IP header intact.

  - Transport mode is typically used for end-to-end communication between two hosts or devices.

  - When using Transport mode, only the data portion of the IP packet is protected by IPsec, while the original IP header, including the source and destination IP addresses, remains visible to intermediate devices.

  - Transport mode is often used for scenarios where the communicating endpoints need to establish a secure connection while maintaining direct communication with each other.

  - Example use cases for Transport mode include securing communication between individual hosts or devices within a private network or securing VoIP (Voice over IP) traffic between two endpoints.



![image](https://github.com/ruppertaj/WOBC/assets/93789685/e87a6cb4-d097-46c3-ae59-ae852986d076)
ipsectunnel

- Tunnel Mode:

  - In Tunnel mode, IPsec encapsulates the entire original IP packet within a new IP packet, adding an additional IP header. Tunnel mode is commonly used to create secure VPN (Virtual Private Network) connections between networks or network devices, such as routers or firewalls.

  - When using Tunnel mode, the original IP packet, including its header and payload, is encrypted and encapsulated within a new IP packet.

  - The new IP header contains the IP addresses of the VPN gateway devices (tunnel endpoints), which are responsible for encrypting and decrypting the data as it passes through the VPN tunnel.

  - Tunnel mode provides network-level security, ensuring that all traffic between the VPN gateway devices is encrypted and protected from eavesdropping or tampering.

  - Example use cases for Tunnel mode include connecting branch offices to a central headquarters network over the internet, creating secure connections between remote users and a corporate network, or establishing site-to-site VPN connections between data centers.



- Headers used by IPSec:

  - ESP Header (Encapsulating Security Payload):

    - Uses IP protocol number 50 to indicate IPSec with ESP Header payload.

    - The Encapsulating Security Payload provides confidentiality, integrity, and optional authentication for IP packets.

    - It encrypts the payload of IP packets to protect the confidentiality of the data being transmitted.

    - The ESP header includes fields for the Security Parameters Index (SPI), sequence number, padding, authentication data (MAC), and other parameters.

    - ESP can operate in either Transport mode (encrypts only the IP payload) or Tunnel mode (encrypts the entire IP packet).

    - Performs integrity check only on ESP header and payload. Not the outer IP header.

    - Does support protocols like NAT that alter the outer header.

    - Modification or changes to the outer header does not affect ESP.

  - AH Header (Authentication Header):

    - Uses IP protocol number 51 to indicate IPSec with AH Header payload.

    - The Authentication Header provides data integrity, authentication, and anti-replay protection for IP packets.

    - It is used to ensure that the data received has not been altered or tampered with during transmission.

    - The AH header includes fields for the Security Parameters Index (SPI), sequence number, authentication data (Message Authentication Code, MAC), and other parameters.

    - AH can operate in either Transport mode (protects only the IP payload) or Tunnel mode (protects the entire IP packet).

    - Performs integrity check on entire packet to include outer IP header.

    - Integrity done only on immutable fields: Version, Length, Next Header/protocol, Source address, Destination address

    - Mutable fields: DSCP/Traffic Class, Flow Label, TTL/Hop Limit

    - Does not support protocols like NAT that alter the outer header.

    - "mostly" obsolete

  - IKE Header (Internet Key Exchange):

    - IKE typically uses UDP port 500 for its main communication channel.

    - IKEv2 may use UDP port 4500 for NAT traversal (UDP encapsulation) to overcome NAT (Network Address Translation) issues.

    - IKE is used to establish Security Associations (SAs) and negotiate cryptographic parameters for IPsec.

    - It operates at the application layer (Layer 7) and is used to exchange keying material, negotiate encryption and authentication algorithms, and authenticate IPsec peers.

    - The IKE header includes fields for message type, exchange type, cryptographic algorithms, key exchange data, and other parameters.

    - IKE is typically used in conjunction with IPsec to establish secure VPN connections.



References:

https://en.wikipedia.org/wiki/IPsec


#### 3.2.1.4 OpenVPN
OpenVPN is an open-source VPN (Virtual Private Network) software that provides secure communication over the internet by creating encrypted tunnels between devices or networks. It is widely used for remote access VPNs, site-to-site VPNs, and other secure networking applications.

OpenVPN requires special software that implements the OpenVPN protocol. There are client and server versions. The client software runs on your device (computer, phone, etc.) and the server software runs on the VPN provider’s server. This software creates the encrypted tunnel and manages the data transmission.

It’s known for being very secure due to strong encryption algorithms and multiple authentication methods. OpenVPN uses the OpenSSL library to provide encryption of both the data and control channels.

It offers a high degree of customization, making it suitable for a wide range of uses. Because of the customization options, setting up OpenVPN can be more complex for non-technical users compared to some other VPN solutions.

- OpenVPN can be configured to use UDP or TCP as it’s transport layer protocols:

  - UDP Protocol (Default):

    - OpenVPN often uses UDP for communication, providing a lightweight and connectionless transport protocol suitable for VPNs.

    - The default UDP port number for OpenVPN is 1194.

  - TCP Protocol:

    - OpenVPN can also be configured to use TCP for communication, which can be useful in scenarios where UDP traffic is restricted or blocked.

    - The default TCP port number for OpenVPN is 1194, but it can be configured to use other port numbers such as port 443.



References:

https://en.wikipedia.org/wiki/OpenVPN

https://en.wikipedia.org/wiki/OpenSSL


### 3.2.2 Understand proxies
- A proxy, or proxy server, functions as a vital intermediary that stands between a user’s device, be it a computer or smartphone, and the vast expanse of the internet. Operating as a sophisticated gateway, it expertly facilitates the exchange of requests and responses between the user and the destination server, seamlessly navigating the intricate web of online communication. Proxies, with their multifaceted capabilities, empower users and organizations by delivering anonymity, content filtering, and performance optimization. In this dynamic role, proxies serve as instrumental guardians of privacy, gatekeepers for access control, and enhancers of overall internet efficiency.

- This allows for your device’s information, such as IP address and possibly your MAC address, to stay hidden. Besides privacy, a proxy can provide additional benefits such as load balancing or security.

- When utilizing proxies for secure communications, we must remember that the client only creates a secure connection to the proxy, and the proxy will create the secure connection with the remote server. This means that if the proxy server should be compromised, the data communication can be intercepted.

- Typical communication with a proxy server is done over TCP port 1080 but The Onion Router (TOR) browsing uses TCP port 9050 by default.

- Here are key aspects of a proxy:

  - Anonymity: One of the primary functions of a proxy is to provide anonymity for the user. When you connect to a website through a proxy, the website sees the IP address of the proxy server rather than your actual IP address. This can be useful for privacy and security reasons.

  - Content Filtering: Proxies can be configured to filter and block access to specific content or websites. This is often employed in organizations and institutions to control and monitor internet usage.

  - Access Control: Proxies can control access to certain resources based on predefined rules. This allows administrators to restrict or grant access to specific websites, services, or content.

  - Improved Performance: In some cases, proxies can improve network performance by caching frequently requested content. When a user requests a resource that has been cached, the proxy can deliver it directly, reducing the load on the destination server and improving response times.

  - Security: Proxies can enhance security by acting as a barrier between the user and the internet. They can filter out malicious content, block access to known malicious websites, and provide an additional layer of defense against cyber threats.

  - Load Balancing: Proxies can distribute incoming network traffic across multiple servers, helping to balance the load and ensure efficient utilization of resources. This is known as load balancing and can improve the overall performance and reliability of a network.

- Types of Proxies:

  - Forward Proxy: Acts on behalf of clients, typically used to access the internet.

  - Reverse Proxy: Acts on behalf of servers, often used to distribute incoming client requests to multiple servers.

  - Transparent Proxy: Operates without altering the request or response, providing anonymity.

  - Anonymous Proxy: Hides the user’s IP address but informs the server that a proxy is being used.

  - Elite or High-Anonymous Proxy: Provides the highest level of anonymity by not disclosing the use of a proxy.



![image](https://github.com/ruppertaj/WOBC/assets/93789685/41446193-b735-4a4e-814f-85fd1bb627fa)
Basic Proxy


References:

https://en.wikipedia.org/wiki/Proxy_server

https://en.wikipedia.org/wiki/Tor_(network)


#### 3.2.2.1 Examine SOCKS protocol
Socks 4/5 (TCP 1080)

![image](https://github.com/ruppertaj/WOBC/assets/93789685/24609042-0dd4-48c8-9564-14f7c8e68c23)
socks

- SOCKS (Socket Secure) is a protocol that facilitates communication between clients and servers through a proxy server.

  - Initiates connections through a proxy

  - Uses various Client / Server exchange messages

  - Client can provide authentication to server

  - Client can request connections from server

  - Defined in RFC 1928

  - Versions:

    - SOCKS4

      - Initial version of the SOCKS protocol, introduced in the early 1990s.

      - No Authentication, meaning that it does not require clients to authenticate themselves before connecting to the proxy server.

      - Only IPv4

      - Only TCP support. No UDP support.

      - No Proxy binding. Client’s IP is not relayed to destination.

    - SOCKS5

      - Support for Authentication, allowing clients to authenticate themselves using various methods, such as username/password, GSS-API (Generic Security Services Application Program Interface), or digital certificates.

      - IPv4 and IPv6 support

      - TCP and UDP support

      - Supports Proxy binding. Client’s IP is relayed to destination.



References:

https://en.wikipedia.org/wiki/SOCKS

https://datatracker.ietf.org/doc/html/rfc1928


### 3.2.3 Examine Network Basic Input Output System (NetBIOS) protocol

- NetBIOS, an acronym for Network Basic Input/Output System, emerged as a protocol suite crafted by IBM during the early 1980s. This suite offers a collection of services along with an application programming interface (API), facilitating network communication across local area networks (LANs). Initially conceived for IBM’s PC Network, NetBIOS eventually evolved into a de facto standard for LAN communication within the Microsoft Windows ecosystem.

- NetBIOS provides services related to the session layer of the OSI model allowing applications on separate computers to communicate over a local area network. The outputs from NetBIOS can provide computer names, group assignments, and MAC addresses of nodes.

- NetBIOS vs. DNS: The Domain Name System (DNS) is a directory for communication between devices over the internet. An internet connection is required to use DNS, but NetBIOS is available to all machines on a local area network. If a windows system is unable to resolve a name via DNS, then it will look for a WINS server, then finally uses NetBIOS.

For more indepth information [NetBIOS](https://isc.sans.edu/forums/diary/Is+it+time+to+get+rid+of+NetBIOS/12454/)

- Windows:
```
nbtstat -A <IP Address>
```

Output will provide the NetBIOS Remote Machine Name Table which has Name, Type(group), and MAC Address.

- Linux:
```
nbtscan -r <IP Address>
```

References:

https://en.wikipedia.org/wiki/NetBIOS
https://isc.sans.edu/forums/diary/Is+it+time+to+get+rid+of+NetBIOS/12454/


#### 3.2.3.1 Recognize well-known NetBIOS suffixes (services) and their potential for operational impact
- NetBIOS names typically consist of two parts: a 15-character computer name and a 16th character, known as the NetBIOS suffix. The NetBIOS suffix helps identify the type or purpose of the resource. While any 16-bit value can be used as a NetBIOS suffix, some suffixes have become well-known and are commonly associated with specific services.

- Here are a few well-known NetBIOS suffixes:

  - 00 (Hex): The "00" suffix is often associated with the workstation service. It identifies the primary computer name for a device.

  - 03 (Hex): The "03" suffix is commonly used for the Messenger service. This service enables users to send pop-up messages to each other on a Windows network.

  - 06 (Hex): The "06" suffix is often linked to the Remote Access Service (RAS) server. RAS allows users to connect to a network remotely.

  - 1B (Hex): The "1B" suffix is used for the domain master browser. It helps in maintaining a list of available resources in a Windows workgroup or domain.

  - 1C (Hex): The "1C" suffix is associated with the domain controller. It indicates the presence of a Windows domain controller on the network.

  - 1D (Hex): The "1D" suffix is related to the Master Browser service. It helps in maintaining a list of available resources in a Windows workgroup or domain.

  - 20 (Hex): The "20" suffix is often used for the File Service, indicating that the resource is a file server.

  - 21 (Hex): The "21" suffix is associated with the Remote Access Service (RAS) client. It identifies a RAS client on the network.

  - 2F (Hex): The "2F" suffix is commonly linked to the Windows Internet Naming Service (WINS).

- NetBIOS provides three distinct services:

  - Name service (NetBIOS-NS) for name registration and resolution. (UDP/137)

  - Datagram distribution service (NetBIOS-DGM) for connectionless communication. (UDP/138)

  - Session service (NetBIOS-SSN) for connection-oriented communication. (TCP/139)



References:

https://miloserdov.org/?p=4261


### 3.2.4 Examine Server Message Block (SMB) protocol
SMB/CIFS (TCP 139/445 AND UDP 137/138)

- The Server Message Block (SMB) protocol serves as a communication protocol predominantly utilized by Microsoft Windows-equipped computers. Its primary function is to facilitate the sharing of files, printers, serial ports, and various communications among network nodes. For user authentication, SMB employs either the NTLM or Kerberos protocols.

- Additionally, SMB offers an authenticated inter-process communication (IPC) mechanism. Originally conceived in 1983 by Barry A. Feigenbaum at IBM, SMB aimed to provide shared access to files and printers within a network of systems running IBM’s OS/2.

- Subsequently, in 1987, Microsoft and 3Com implemented SMB in LAN Manager for OS/2. During this period, SMB utilized the NetBIOS service atop the NetBIOS Frames protocol as its foundational transport. Over time, Microsoft integrated SMB into Windows NT 3.1, continuously updating it to function with newer underlying transports, such as TCP/IP and NetBT. A notable development is the introduction of SMB over QUIC, which made its debut in Windows Server 2022.

![image](https://github.com/ruppertaj/WOBC/assets/93789685/042b93dc-d5c2-40de-827f-5278817d23bc)
smb

```
smbclient -L <IP Address>
```

- Allowed devices to establish connections to other devices on network to share files, printers and other things.

- Several versions since its release in 1984:

  - SMBv1 was released in 1984 by IBM for file sharing in DOS. Modified by Microsoft in 1990 for integration into Windows GUI.

  - CIFS was released in 1996. Microsoft launched an initiative to rename SMB to Common Internet File System (CIFS). Included more features and support for symbolic links, hard links, larger file sizes. Rolled out with Windows 95.

  - SMBv2.0 debuted in 2006 for Windows Vista. It featured a notable boost in performance because of increased efficiency — fewer commands and subcommands meant better speeds.

  - SMBv2.1 released with Windows 7, bringing improved performance.

  - SMBv3.0 released with Windows 8 with many updates. Most notable of which is enhanced security — the protocol started supporting end-to-end encryption.

  - SMBv3.0.2 released with Windows 8.1. It offered the ability to increase security and performance by completely disabling SMBv1.

  - SMBv3.1.1 was released in 2015 with Windows 10. It added more security elements to the protocol, like AES-128 encryption, protection from man-in-the-middle attacks, and session verification.

- SMB Rides over Netbios - allows applications to communicate over a LAN using a NetBIOS name. Depricated due to DNS. [Netbios Wiki](https://en.wikipedia.org/wiki/NetBIOS)

  - Netbios Dgram Service - UDP 138

  - Netbios Session Service - TCP 139

- Third-Party SMB Implementations:

  - SAMBA

    - [Samba Wiki](https://en.wikipedia.org/wiki/Samba_(software))

    - Developed to offer file and print services for Windows clients on Unix-based systems, including Linux and other Unix variants.

    - Facilitates seamless interaction between Unix-based systems and Windows networks, providing features like file sharing, printer services, and authentication.

    - Enables Unix-based servers to function as file and print servers within a Windows network, ensuring compatibility and interoperability.

    - Samba is compatible with a wide range of Unix-based operating systems, encompassing Linux, Solaris, AIX, and various BSD variants, including Apple’s macOS Server and macOS client (Mac OS X 10.2 and later).

    - Supports various versions of the SMB protocol, allowing non-Windows systems to actively participate in Windows networking environments.

  - Netsmb

    - NSMB, which encompasses Netsmb and SMBFS, constitutes a group of in-kernel SMB client implementations within BSD operating systems. * Originally introduced by Boris Popov in FreeBSD 4.4, this family of implementations has proliferated across various BSD systems, including NetBSD and macOS.

    - Over time, these implementations have undergone significant divergence.

  - NQ

    - NQ stands as a suite of portable SMB client and server implementations crafted by Visuality Systems, an Israel-based company founded in 1998 by Sam Widerman, who previously served as the CEO of Siemens Data Communications.

  - MoSMB

    - MoSMB is a proprietary SMB implementation designed for Linux and other Unix-like systems, created by Ryussi Technologies. It exclusively supports SMB versions 2.x and 3.x.

    - [SMB Wiki Reference](https://en.wikipedia.org/wiki/Server_Message_Block)

    - [SMB Example PCAP from Cloudshark](https://www.cloudshark.org/captures/3ad3ce05a027)



References:

https://en.wikipedia.org/wiki/NetBIOS
https://en.wikipedia.org/wiki/Samba_(software)
https://en.wikipedia.org/wiki/Server_Message_Block
https://www.cloudshark.org/captures/3ad3ce05a027


#### 3.2.4.1 Examine Server Message Block (SMB) protocol Vulnerabilities
Many vulnerabilities to SMB have been discovered since it was developed in 1984. Over the years, several vulnerabilities have been discovered in the SMB protocol that could potentially be exploited by attackers. Here are a few notable SMB protocol vulnerabilities:

- EternalBlue (CVE-2017-0144): EternalBlue is a vulnerability in the SMBv1 protocol that gained significant attention following its use in the WannaCry ransomware attack of 2017. It enabled remote code execution on Windows systems vulnerable to the exploit and quickly propagated through networks.

- Vulnerabilities in SMBv1: The SMBv1 protocol has been found to have multiple vulnerabilities, including flaws that allow remote code execution. It is recommended to disable SMBv1 due to its inherent security weaknesses.

- SMB Signing Downgrade (CVE-2017-0290): This vulnerability enables an attacker to downgrade the SMB signing negotiation process, potentially facilitating the interception and modification of SMB communications.

- SMB Relay Attack: SMB relay attacks exploit the authentication mechanism of SMB, allowing an attacker to relay user credentials and gain unauthorized access to network resources. This attack is particularly effective when SMB signing is disabled or weak.

- Denial of Service (DoS) Attacks: Various vulnerabilities in the SMB protocol have been discovered that could lead to denial of service attacks. By sending specially crafted requests, an attacker can overwhelm an SMB server, causing it to become unresponsive or crash.

- Man-in-the-Middle Attacks: In certain scenarios, attackers can intercept SMB traffic using a man-in-the-middle (MITM) position. This allows them to capture and manipulate sensitive data transmitted over the SMB protocol.

To mitigate these vulnerabilities, it is crucial to maintain up-to-date SMB implementations, disable older versions like SMBv1, enforce secure configurations (such as enabling SMB signing), and regularly apply security patches provided by vendors. Additionally, implementing network segmentation, strong authentication mechanisms, and monitoring systems can aid in detecting and preventing potential attacks targeting the SMB protocol.

Many organizations are moving away from SMB file and printer sharing and moving to cloud or enterprise based solutions.

Some alternatives to file storage:

1. Enterprise Content Management (ECM) Systems

  a. Microsoft Sharepoint

  b. OpenText Content Suite

  c. IBM FileNet

2. Cloud Storage Services

  a. Onedrive

  b. Google Drive

  c. Amazon S3

  d. Microsoft Azure Blob Storage

Some alternatives to printer sharing are:

1. Printing directly to the printer

2. Print Management Software

  a. PaperCut

  b. Equitrac

  c. Pharos

3. Managed Print Services (MPS)

  a. Xerox

  b. HP

  c. Lexmark

  d. Ricoh

4. Enterprise Output Management (EOM)

  a. HP Exstream

  b. OpenText Output Management

  c. ISIS Papyrus.

5. Cloud-Based Printing Solutions

  a. Google Cloud Print

  b. PrinterLogic

6. Mobile Printing Solutions ..HP ePrint

  a. Apple AirPrint



References:

https://www.malwarebytes.com/blog/news/2018/12/how-threat-actors-are-using-smb-vulnerabilities


### 3.2.5 Examine Remote Procedure Call (RPC) Protocol
RPC (Any Port)

- Remote Procedure Call (RPC) is a protocol that allows a program to request a service from another program located on the same system or on remote computer. It allows these programs to request services without having to understand details of the program. In essence, it standardizes the inter-communication with formalized requests for information. A procedure call is also sometimes known as a function call or a subroutine call.

- In essence, Remote Procedure Call (RPC) serves as a method for computer programs to communicate across a network as if they were in close proximity. This enables one program to ask another program on a different computer to perform a service or function. Picture it as requesting a favor from a friend, but in the realm of computers where programs work together to accomplish tasks. RPC simplifies the intricacies of communication, creating the illusion that the distant program is actually a local one. This approach finds extensive use in activities such as distributed computing and networked applications.

  - RPC is a request/response protocol.

  - [RPC Wiki Reference](https://en.wikipedia.org/wiki/Remote_procedure_call)

  - User application will:

    - Sends a request for information to a external server

    - Receives the information from the external server

    - Display collected data to User

  - Examples of RPC are:

    - [SOAP](https://en.wikipedia.org/wiki/SOAP) - [SOAP Example PCAP from Cloudshark](https://www.cloudshark.org/captures/74a6deb7aa4e?filter=frame%20and%20eth%20and%20ip%20and%20tcp%20and%20http%20and%20xml)

    - [XML](https://en.wikipedia.org/wiki/XML-RPC)

    - [JSON](https://en.wikipedia.org/wiki/JSON-RPC)

    - [NFS](https://en.wikipedia.org/wiki/Network_File_System)



Use the netstat command (Linux/Windows) to show established connections and sockets.



Some examples of RPCs are:

1. XML-RPC: Uses XML for data encoding, HTTP as the transport protocol.

2. XML-RPC.NET: An RPC protocol based on XML-RPC but specifically designed for use with the .NET framework.

3. JSON-RPC: Uses JSON for data encoding, typically over HTTP.

4. JSON-WSP (JSON Web Service Protocol): Similar to JSON-RPC, JSON-WSP is an RPC protocol that uses JSON for data encoding and typically operates over HTTP.

5. gRPC: Developed by Google, uses Protocol Buffers, supports HTTP/2.

6. Thrift: Open-source framework by Facebook, supports multiple languages, uses a binary protocol.

7. DCOM (Distributed Component Object Model): Developed by Microsoft, supports various transport protocols.

8. ONC RPC (Open Network Computing RPC): Used in UNIX/Linux environments, based on RPC/XDR standards.

9. SOAP (Simple Object Access Protocol): A widely used RPC protocol that uses XML for data encoding and typically operates over HTTP or other transport protocols.

10. REST (Representational State Transfer): Although not a traditional RPC protocol, RESTful APIs can be considered a form of RPC where remote resources are accessed and manipulated using HTTP methods such as GET, POST, PUT, and DELETE. RESTful APIs follow the principles of resource-oriented architecture.

11. Avro RPC: Developed as part of the Apache Avro project, Avro RPC is a fast and efficient RPC protocol that uses Avro’s binary serialization format.

12. MQTT (Message Queuing Telemetry Transport): Although primarily a messaging protocol, MQTT can also be used for RPC-like communication patterns.



References:

https://en.wikipedia.org/wiki/Remote_procedure_call
https://en.wikipedia.org/wiki/SOAP
https://www.cloudshark.org/captures/74a6deb7aa4e?
https://en.wikipedia.org/wiki/XML-RPC
https://en.wikipedia.org/wiki/JSON-RPC
https://en.wikipedia.org/wiki/Network_File_System


### 3.2.6 Application Programming Interface (API)
- An Application Programming Interface (API) is a set of rules and tools that allows different software applications to communicate with each other. It defines the methods and data formats that applications can use to request and exchange information. APIs are used to enable the integration of different software systems, making it easier for developers to build on top of existing functionalities without needing to understand the internal workings of the underlying software.

- Application Programming Interface, acts as a mediator between different software applications, facilitating their communication and interaction. It consists of a set of regulations, protocols, and tools that govern how software components should interact. By defining methods and data formats, an API enables the exchange of information between applications.

- APIs play a crucial role in enabling diverse software systems, services, or platforms to seamlessly interact and share data. They establish a standardized approach for developers to access and leverage the functionality and resources of a specific software system or service, eliminating the need to delve into the intricate details of its internal implementation.

 - Overall framework that uses RPC to do the "thing"

Some examples of APIs are:

1. Social Media APIs: (Facebook Graph API, Twitter API, Instagram API, LinkedIn API)

2. Payment Gateway APIs: (PayPal API, Stripe API, Braintree API, Square API)

3. Maps and Geolocation APIs: (Google Maps API, Mapbox API, OpenStreetMap API, Bing Maps API)

4. Weather APIs: (OpenWeatherMap API, Weatherbit API, AccuWeather API, Dark Sky API)

5. Cloud Services APIs: (Amazon Web Services (AWS) API, Microsoft Azure API, Google Cloud Platform (GCP) API, IBM Cloud API)

6. E-commerce APIs: (Shopify API, WooCommerce API, BigCommerce API, Magento API)

7. Email and Messaging APIs: (SendGrid API, Twilio API, Mailchimp API, Nexmo API)

8. Payment Processor APIs: (Visa Developer API, Mastercard Developers API, American Express API, Discover Developer API)

9. News and Content APIs: (NewsAPI, New York Times API, Guardian API, Giphy API)

10. Music and Media APIs: (Spotify API, YouTube API, SoundCloud API, Last.fm API)

11. Travel and Transportation APIs: (Amadeus API, Skyscanner API, Uber API, FlightAware API)

12. Financial Data APIs: (Alpha Vantage API, Yahoo Finance API, Xignite API, Intrinio API)

13. Government APIs: (NASA API, OpenFDA API, Census Bureau API, OpenWeatherMap API)

14. Machine Learning and AI APIs: (TensorFlow API, Microsoft Azure Cognitive Services API, IBM Watson API, Google Cloud Machine Learning API)

15. Cryptocurrency APIs: (CoinGecko API, CoinMarketCap API, Binance API, Kraken API)



APIs and RPC are mechanisms for communication and interaction between software components.

- APIs provide a standardized interface for developers to access and use functionalities of a system or service, often language-agnostic and implemented using various protocols. They focus on exposing functions, operations, or endpoints for clients to interact with the system or service. APIs are versatile and widely used in web development, mobile apps, and third-party service integration.

- RPC, on the other hand, is a specific approach for remote procedure calls within a distributed system, treating remote components as local. They are esentially how the communication happens.

Both APIs and RPC involve communication and interaction between software components. API is a set of rules enabling communication between software applications, while RPC is a protocol facilitating the execution of procedures on remote systems.


#### 3.2.6.1 RPC vs API
- While Remote Procedure Call (RPC) and Application Programming Interface (API) are related concepts and are often used together in the context of distributed systems and software development, they are not the same thing.

  - Remote Procedure Call (RPC):

    - RPC is a communication protocol that allows a program to execute procedures or functions on a remote server or service as if they were local. It enables distributed applications to communicate and work together seamlessly across network boundaries. RPC abstracts the details of network communication, allowing clients to invoke remote procedures on servers and receive results as if the procedures were executed locally.

  - Application Programming Interface (API):

    - API refers to a set of rules and protocols that define how software components or services interact with each other. APIs define the methods, data structures, and protocols that developers can use to interact with a software component, service, or system. APIs can be used to access functionality provided by libraries, frameworks, operating systems, web services, or other software components. APIs can be local (e.g., library APIs) or remote (e.g., web service APIs), and they define the contract between the client and the provider of the service.

    - While RPC can be used to implement APIs for remote procedure invocation, not all APIs are implemented using RPC. APIs can be implemented using various technologies and communication protocols, including RESTful HTTP, SOAP, GraphQL, messaging protocols (e.g., MQTT, AMQP), and others. RPC is just one of many possible approaches for implementing APIs for remote communication.


## 3.3 Explain OSI Layer 6 functions and responsibilities
Layer 6 of the OSI (Open Systems Interconnection) model is the Presentation Layer. The Presentation Layer is responsible for the syntax and semantics of the data exchanged between two systems. It ensures that the data presented to the application layer is in a format that the application layer can understand.


### 3.3.1 Explain the presentation layer functions and responsibilities

- Presentation Layer - This layer deals with the Translating, Formatting, Encryption, and Compression of data.

  - Data Translation and Transformation:

    - The Presentation Layer can translate data between different character encoding schemes, such as ASCII, Unicode, EBCDIC, etc., ensuring compatibility between systems with different encoding requirements.

      - ASCII Encoding: American Standard Code for Information Interchange represents text characters using 7 or 8 bits, mapping each character to a numeric value.

      - Unicode Encoding: A character encoding standard that encompasses most of the world’s writing systems, assigning unique numerical values to characters, emojis, and symbols.

      - UTF-8 Encoding: A variable-width character encoding capable of encoding all Unicode characters using one to four bytes, commonly used in web pages and email.

      - UTF-16 Encoding: A character encoding capable of encoding all Unicode characters using two or four bytes, often used in programming languages like Java and JavaScript.

      - UTF-32 Encoding: A fixed-width encoding scheme that represents each Unicode code point with four bytes, ensuring straightforward indexing but resulting in larger file sizes compared to UTF-8 and UTF-16.

      - Base64 Encoding: Converts binary data into ASCII characters, useful for encoding binary data such as images or attachments in emails or transmitting binary data over text-based protocols.

      - URL Encoding: Converts special characters into a format that can be transmitted over the Internet, replacing reserved characters with percent-encoded representations.

  - Data Formatting and Syntax Parsing:

    - The Presentation Layer can format data according to predefined standards or protocols, ensuring that the data conforms to the expected syntax and structure. It parses the incoming data to extract relevant information and present it to the application layer in a meaningful way.

      - Text-Based Formats:

        - Plain Text (.txt): Simplest format containing unformatted text without any styling or formatting.

        - Comma-Separated Values (.csv): Tabular format where data values are separated by commas, commonly used for storing and exchanging spreadsheet or database data.

        - Extensible Markup Language (.xml): Markup language for encoding structured data in a human-readable format, widely used in web services, configuration files, and data exchange.

        - JavaScript Object Notation (.json): Lightweight data interchange format commonly used for transmitting data between a server and a web application, as well as storing configuration data.

      - Document Formats:

        - Portable Document Format (.pdf): A format developed by Adobe that preserves document formatting and layout across different platforms, widely used for sharing and distributing documents.

        - Microsoft Word Document (.docx): Word processing format developed by Microsoft, used for creating and editing text-based documents with rich formatting, images, and other multimedia elements.

        - Rich Text Format (.rtf): Cross-platform document format that supports text formatting, images, and other media, compatible with various word processors.

      - Image Formats:

        - Joint Photographic Experts Group (.jpg/.jpeg): Commonly used format for storing compressed digital images, suitable for photographs and complex images with many colors.

        - Graphics Interchange Format (.gif): Format supporting animated images and short video clips, widely used for web animations and memes.

        - Portable Network Graphics (.png): Lossless image format that supports transparency and compression, commonly used for web graphics and digital images.

      - Audio Formats:

        - MP3 (.mp3): Compressed audio format that reduces file size while preserving audio quality, widely used for storing and sharing music and audio files.

        - Waveform Audio File Format (.wav): Uncompressed audio format that preserves original audio data without loss of quality, commonly used for professional audio editing and recording.

        - Advanced Audio Coding (.aac): Format for encoding digital audio data, known for its high compression efficiency and widespread support in multimedia applications.

      - Video Formats:

        - Moving Picture Experts Group-4 (.mp4): Standard format for storing digital video and multimedia content, widely supported by video playback software and devices.

        - Audio Video Interleave (.avi): Multimedia container format developed by Microsoft, capable of storing audio and video data in a single file, commonly used for video editing and playback.

        - Flash Video (.flv): Format developed by Adobe for streaming video content over the internet, commonly used for web-based video players and online streaming platforms.

  - Data Encryption and Decryption:

    - The Presentation Layer can perform encryption and decryption of data to ensure its confidentiality and integrity during transmission. It encrypts data before transmission and decrypts it upon receipt, allowing secure communication between systems.

      - Symetric: AES, Blowfish, Twofish, DES, and RC4

      - Asymetric: PKI, Diffie-Hellman, DSS, RSA, Elliptic curve

      - TLS (Transport Layer Security):

        - TLS is primarily a transport layer protocol that provides secure communication over a network. However, cryptographic algorithms used in TLS (such as RSA, Diffie-Hellman, and AES) may be invoked at the presentation layer for encrypting data before presentation to the user.

        - In web browsers, TLS encryption ensures secure communication between the client and server, protecting sensitive data such as login credentials, payment information, and personal details during transmission.

      - SSL (Secure Sockets Layer):

        - SSL is the predecessor to TLS and operates similarly to TLS in providing secure communication over a network. Like TLS, SSL may involve cryptographic operations at the presentation layer to encrypt data before rendering.

        - Although SSL has been largely deprecated in favor of TLS, some legacy systems and applications may still use SSL for securing data.

      - PGP (Pretty Good Privacy):

        - PGP is an encryption program that provides cryptographic privacy and authentication for data communication. It can be used for encrypting and decrypting emails, files, and other forms of data.

        - While PGP is commonly associated with email encryption (which operates at the application layer), it may also involve cryptographic operations at the presentation layer for rendering encrypted messages in email clients.

      - S/MIME (Secure/Multipurpose Internet Mail Extensions):

        - S/MIME is a standard for secure email messaging that provides encryption and digital signature functionality. It enables users to send encrypted and digitally signed emails using cryptographic algorithms such as RSA and AES.

        - S/MIME operations may involve cryptographic processing at the presentation layer for rendering encrypted email messages and verifying digital signatures.

      - OpenPGP (Open Pretty Good Privacy):

        - OpenPGP is an open-source standard that builds upon PGP for secure communication. It defines formats for encrypted messages, digital signatures, and key management.

        - OpenPGP implementations may involve cryptographic operations at the presentation layer for rendering encrypted messages and verifying digital signatures.

      - End-to-End Encryption (E2EE):

        - E2EE is a method of secure communication that ensures only the communicating users can read the messages. Encryption and decryption occur exclusively at the endpoints, providing strong confidentiality guarantees.

        - While E2EE is typically implemented at the application layer, cryptographic techniques used for encryption and decryption may involve operations at the presentation layer for data rendering.

  - Data Compression and Decompression:

    - The Presentation Layer can compress data to reduce its size before transmission, optimizing network bandwidth and speeding up data transfer. It decompresses the data upon receipt, restoring it to its original format.

    - Sometimes data gets to big to transmit over the network so the Presentation layer handles compression.The primary role of Data compression is to reduce the number of bits to be transmitted. It is important in transmitting multimedia such as audio, video, text etc.

      - Zip, TAR, RAR, 7zip, CAB

    - Lossless Compression:

      - Lempel-Ziv (LZ) Compression: This family of algorithms, including LZ77 and LZ78, identifies repeated patterns in the data and replaces them with shorter codes, achieving compression without loss of information.

      - DEFLATE Compression: DEFLATE combines LZ77 with Huffman coding and is used in popular formats like ZIP, gzip, and PNG for lossless compression.

      - Run-Length Encoding (RLE): RLE replaces sequences of repeated data with a single value and a count, making it effective for compressing data with long runs of identical values.

      - Burrows-Wheeler Transform (BWT): BWT rearranges the characters in the input data to facilitate compression. It’s often used in conjunction with other techniques like Move-to-Front (MTF) and Huffman coding.

      - Huffman Coding: Huffman coding generates variable-length codes for characters based on their frequencies in the input data, achieving efficient compression without loss of information.

      - Arithmetic Coding: Arithmetic coding encodes a sequence of symbols into a single floating-point number within a specified range, offering high compression ratios for lossless data.

      - Bzip2 Compression: Bzip2 uses the Burrows-Wheeler Transform (BWT) and Huffman coding to achieve high compression ratios, particularly effective for compressing text files.

      - Delta Encoding: Delta encoding compresses data by encoding the differences between consecutive values in a sequence, suitable for compressing data with predictable patterns or incremental updates.

      - PPM (Prediction by Partial Matching): PPM predicts the next symbol in a sequence based on its context, achieving high compression ratios for text and structured data.

      - LZMA (Lempel-Ziv-Markov chain Algorithm): LZMA combines LZ77 with additional modeling techniques like Markov chains for high compression ratios, commonly used in formats like 7z and XZ.

      - LZ77 and LZ78: These are foundational algorithms in the LZ family, used for identifying and encoding repeated patterns in data for compression.

      - Shannon-Fano Coding: Similar to Huffman coding, Shannon-Fano coding generates prefix codes based on symbol probabilities to achieve lossless compression.

      - Gzip Compression: Gzip uses DEFLATE compression and is commonly used for compressing files on Unix-based systems.

      - Zstandard (Zstd): Zstd is a modern compression algorithm that offers a good balance between compression speed and ratio, suitable for various types of data.

      - LZW (Lempel-Ziv-Welch) Compression: LZW is used in formats like GIF and compresses data by replacing repeating patterns with codes from a dictionary.

      - CAB (Cabinet File Format): CAB is a Microsoft-developed file archive format commonly used for software installation packages and system files, often employing the LZX compression algorithm.

    - Lossy Compression:

      - JPEG Compression: JPEG (Joint Photographic Experts Group) is widely used for compressing digital images. It achieves compression by discarding high-frequency information and optimizing color representation, resulting in smaller file sizes but some loss of image quality.

      - GIF Compression: Although GIF (Graphics Interchange Format) primarily supports lossless compression, it can also be used in a lossy mode by reducing the color palette or by discarding color information. This can result in smaller file sizes but may degrade image quality, particularly for complex images.

      - MPEG Compression: MPEG (Moving Picture Experts Group) is a suite of standards for compressing audio and video data. It typically uses lossy compression techniques such as motion compensation, discrete cosine transform (DCT), and quantization to achieve compression while maintaining perceptual quality.

      - MP3 Compression: MP3 is a popular lossy compression algorithm for audio data. It achieves compression by removing parts of the audio signal that are less audible to humans, such as frequencies outside the normal hearing range and quiet sounds masked by louder ones.

      - AAC (Advanced Audio Coding): AAC is a more advanced audio compression format compared to MP3. It offers better sound quality at lower bit rates and is commonly used for streaming audio and digital music distribution.

      - OGG Compression: OGG is a container format that typically uses lossy compression for audio data. It’s often associated with the Vorbis codec, which offers high-quality audio compression at lower bit rates compared to formats like MP3.

      - WebP Compression: WebP is an image format developed by Google that uses both lossy and lossless compression techniques. It’s designed to offer smaller file sizes and faster loading times for web images compared to formats like JPEG and PNG.

      - HEVC (High-Efficiency Video Coding): HEVC, also known as H.265, is a video compression standard that offers better compression efficiency compared to previous standards like H.264. It’s widely used for streaming video and digital television.

      - FLAC (Free Lossless Audio Codec): Although FLAC is primarily a lossless compression format, it can also be used in a lossy mode where certain non-essential audio data is discarded to achieve smaller file sizes while still retaining high audio quality.

      - WAVPACK: WAVPACK is a hybrid audio compression format that offers both lossy and lossless compression modes. It’s capable of achieving high compression ratios while preserving audio quality through its lossy mode.

      - DCT (Discrete Cosine Transform) Compression: DCT is commonly used in lossy compression algorithms for images and video, such as JPEG and MPEG. It transforms spatial data into frequency domain coefficients, allowing for efficient compression while sacrificing some image or video quality.



References:

https://en.wikipedia.org/wiki/Presentation_layer


## 3.4 Explain OSI Layer 7 protocols and headers
- Layer 7 of the OSI (Open Systems Interconnection) model is the Application Layer. It is the topmost layer of the OSI model and is responsible for providing network services directly to end-users or applications. Layer 7 protocols operate at the highest level of abstraction, dealing with the actual data that users work with.

- Within this layer, protocols such as HTTP (Hypertext Transfer Protocol), SMTP (Simple Mail Transfer Protocol), and FTP (File Transfer Protocol) govern the intricate communication between software applications and the network. These protocols are intricately linked with application-level headers, meticulously managing metadata and control information, thereby fostering highly efficient communication between the application and the underlying network infrastructure.


### 3.4.1 Analyze Telnet protocol
Telnet (TCP 23)

Developed in 1969, Telnet is a protocol used for remotely accessing and managing network devices, servers, and computers over a TCP/IP network. It allows a user to establish a terminal session on a remote host, providing command-line access to the remote system as if the user were physically present at the console. It has fallen out of favor with the development of packet sniffers being able to capture the usernames and passwords of systems. Newer (more secure) protocols like SSH are preferred.

- Starts with TCP handshake before converting to Telnet protocol
- Cleartext
- telnet <ip> <port>

![image](https://github.com/ruppertaj/WOBC/assets/93789685/6878a26a-046b-4e34-8c66-c094e566018d)
telnet

[Telnet Commands and options from networksorcery.com](http://www.networksorcery.com/enp/protocol/telnet.htm)

[Telnet options from iana.org](https://www.iana.org/assignments/telnet-options/telnet-options.xhtml)

[Telnet pcap from www.cloudshark.org](https://www.cloudshark.org/captures/000809f1a9d5)



References:

http://www.networksorcery.com/enp/protocol/telnet.htm
https://www.iana.org/assignments/telnet-options/telnet-options.xhtml
https://www.cloudshark.org/captures/000809f1a9d5


### 3.4.2 Analyze Secure Shell Protocol (SSH)
SSH (TCP 22)

The Secure Shell (SSH) protocol is a cryptographic network protocol used for secure remote login and command execution over an unsecured network. SSH provides strong encryption, authentication, and integrity protection, making it a widely used and trusted method for remote access and secure communication.

Delveloped by Tatu Ylönen in Finland 1995 who was a researcher for Finland’s Helsinki University of Technology. Due to packet sniffing attacks of protocols like telnet, rlogin, and FTP, a more secure protocol was needed.



![image](https://github.com/ruppertaj/WOBC/assets/93789685/d1141943-2290-4e9d-a07c-b36672e5c37f)
ssh

- [SSH reference from networksorcery.com](http://www.networksorcery.com/enp/protocol/ssh.htm)

- [SSH reference from wikipedia](https://en.wikipedia.org/wiki/Secure_Shell)

- [List of SSH RFC’s](https://en.wikipedia.org/wiki/Secure_Shell#Standards_documentation)

- [SSH pcap from www.cloudshark.org](https://www.cloudshark.org/captures/849d3c7f09d3)

SSH Protocol
SSH is an open protocol with many different implementations. Examples include PuTTy, Solaris Secure Shell, Bitvise, and OpenSSH. OpenSSH is the open source implementation that is most common and the focus of this course as it is widely found in Linux and Unix. Support for Windows was introduced when OpenSSH was ported to run in Windows Power Shell in 2015. It is included in Windows 10 as of 2018, though it must be enabled in settings.

History of the protocol and implementations:
Due to the way SSH was created it has many implementations and therefore is open to vulnerabilities across those different implementations. This course will focus mainly on the OpenSSH implementation.

SSH was developed in 1995 after a password sniffing attack occurred at the University of Technology in Finland. A researcher at the university created SSH1 for himself, which rapidly gained popularity with over 20,000 users by the end of 1995. The creator also founded the SSH Communications Security Corp (SCS) to maintain and develop SSH. That same year, an IETF was drafted describing operation of the SSH1 software and assigned a working group (SECSH). The group submitted a draft for SSH-2.0 in February 1997 which was then released by SCS as a software product with a restrictive license. Due to restrictions many people continued to use SSH1 until OpenSSH was released. OpenSSH came from the OpenBSD project and is based on the last free release of SSH, 1.2.12, but due to the open source community it has been updated regularly and ported to many platforms.

Usage and features:
SSH was initially created to replace insecure rsh suite of Unix programs; the syntax and user interface is identical. These services included the following:

```
rsh Suite	SSH replacement	      Description
rsh             ssh                   Provides a channel for running a shell on a remote computer
rlogin          slogin                Provides remote login capability
rcp             scp                   Login programs such as telnet, remote login (rlogin), and rsh (remote shell). Though the initial use was logging into and running remote terminal sessions, capabilities were expanded to replace FTP (file transfer protocol) and RCP (remote copy protocol) with SFTP and SCP respectively.
```


SSH uses these encryption techniques:

- Asymmetric Encryption:

  - Key Exchange: When an SSH connection is initiated, the client and server perform a key exchange protocol (such as Diffie-Hellman key exchange). This protocol allows them to securely establish a shared secret key over an insecure network. Asymmetric encryption algorithms (such as RSA or Elliptic Curve Cryptography) are used during this process.

    - Key Exchange Algorithms:

      - Diffie-Hellman (DH): A key exchange algorithm used to establish a shared secret key between the client and server during the initial connection setup.

      - Elliptic Curve Diffie-Hellman (ECDH): A variant of Diffie-Hellman that uses elliptic curve cryptography for key exchange, offering strong security with smaller key sizes compared to traditional DH.

      - Curve25519: A specific elliptic curve algorithm designed for efficient and secure key exchange.

  - Authentication: SSH also employs asymmetric encryption for user authentication. The client and server exchange public keys during the key exchange phase, and the client uses its private key to sign a challenge provided by the server. The server verifies the client’s identity by checking the signature against the client’s public key.

    - Public Key Algorithms:

      - RSA (Rivest-Shamir-Adleman): A widely used public key algorithm for digital signatures and encryption. SSH uses RSA for key authentication and digital signatures.

      - DSA (Digital Signature Algorithm): An older public key algorithm, less commonly used in SSH compared to RSA.

      - ECDSA (Elliptic Curve Digital Signature Algorithm): A variant of DSA that uses elliptic curve cryptography for digital signatures, offering strong security with smaller key sizes.

- User Keys:

  - User keys are associated with individual users and are used for user authentication. They are typically generated by the client (user) and stored on the client-side.

  - User keys are asymmetric, consisting of a public key and a private key pair.

  - The user’s private key is kept securely on the client’s machine, while the public key is uploaded to the remote server.

  - Clients send their asymmetric public keys to the server to identify themselves to the server.

- Host Keys:

  - Host keys, also known as server keys, are associated with SSH servers.

  - They serve as an identifier and ensure the integrity of the server during the initial connection.

  - Host keys are generated on the server-side and are used to verify the server’s identity and protect against man-in-the-middle attacks.

  - Servers send their asymmetric public keys to the client to identify themselves to the client.

  - These host keys are saved by the Linux client into the /home/<user>/.ssh/know_hosts file.

```
cat .ssh/known_hosts
|1|voaTVh+n/cFF1kCHeGOIvYJyzZI=|OHW8MvjJKbXtz4206XKMhOu7Z/E= ecdsa-sha2-nistp256 AAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOL4Sc7GLI1htC5YQ2hUxlccyMfYgb6V6bepcA/Q0qjHKm4jsUBAWsKEBsEYcIdtrdxjeZNVkt7CNXF1lvAneYA=
|1|IVSSd1OaAX+vroyputoJ8qgsLX4=|W/cqcLfYAbD/mP4ufyUyddwCdEo= ecdsa-sha2-nistp256 AAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJT7f9kS7c8di9K9OXJR+e6W1VqbRvQMmOqa+SJCZnuBnMQRBeR9zmzuo2UHbYZVLr5O5sFpVt85sj3fo/FbO+k=
|1|NeuQqRczuLmN9SvKgSj5rSNdvDE=|oPluHqNGY4kPxdECbyF4WvbEqCo= ecdsa-sha2-nistp256 AAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBP8ILwUTgzYMDliuvazgr6NIw5mT2kLGtaCISuLYkAEwxQgnJgEEOSVbfT9tz7yRHNeO9IfgDVABOtt/UeglTk=
|1|6dh8InsHAn30v2yrVPW2tOjsZbg=|qBOvcgzpuaBSTAjNjhfLWloQLug= ecdsa-sha2-nistp256 AAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNFRD7lOYQAgW9YY8tbIV31NicQ5z7/wliSmHWy1YcpDacg8wg/F8ySZsEWI9uvOyJjoyxmxrsGQk9CiGmh9dDw=
|1|ETuK+oK/5i2uVOtulSwNmJGvVv8=|Rb0PRAFUbHvJkFjLWJcqwKUQoOQ= ecdsa-sha2-nistp256 AAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBC0WLuLmQjq3CG4P9D3E7hXgZ6Yam5Nm31KK3+23JynNTpd77HA3qvfwbdVhsDmUxBzc1yG8gjwX56LMyDiyF9A=
|1|zp7h1Nik6ko/66OYkSPmxkOxrRk=|rOUiqayoZSG6qrAW9kef3jv37kU= ecdsa-sha2-nistp256 AAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBK2a2sJ5EFQaA0mnPWT2QAfC29SiDAaWnGWEIBZUgR/czd0f5/btR95Y+BA6ptAc0OG5BkLJWEg9cEBaju0Ieg=
|1|vbIpYWPMNXGEwwCO7+LY1E1ZNQA=|aE69K8YxEz6utIrejwoJKurZZk4= ecdsa-sha2-nistp256 AAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPqwtBYlvXabMCfwXp0JS6JkFEqLcTxPstYcOCirVDCFVwnW3hYnTSuFl1Kh/qNE7fwZ/YUXdpDLR6+B94VuMXk=
|1|gtoiF9ZyPHdXYXPxi8+Z5Meigcw=|6HhWxyEuB5xspoI+iO+gehIwFoQ= ecdsa-sha2-nistp256 AAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBGWwTKf3P5M6QjAa8g0XPry6CCt3T88iTuMFQIcta3z0q24JUiFBOXqwoROAPGroGhe6crKCAYY0M/1I7DRL+DI=
|1|rQ/r6OowpK/dFEYgs11UpACQmU8=|/l7cWAOHFsfug2Pcrfec3CoT+Gg= ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBI/twUHpNoKMj6lfOvWZaPZ5DSX9soXMT1+ZlVMuYJnVFbJgJtqhO/iiyRSk+lHDHFEb/0SIqQApAg18nf1fJg=
|1|1jZRhTRnetXtvNGSVGfJEFlVlyw=|/hETA90qKL6L/eRqZUJ3Nmgfgi4= ecdsa-sha2-nistp256 AAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBI7XZbqN0d/IB1dw8h2KXFH5GlWklR0VGtxNmlZ/P7LyTM7SB3AWiK8T8WoS7XBpKwP8qoKF6QZGPkyXJUHn92A=
|1|40m8ZYQW8CXhO1ZuHVGAIPkdWek=|Zvqn2Uhc3GtZEN5BTw6d1Nk20KA= ecdsa-sha2-nistp256 AAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIsZNsAO8X7iLAShoGWEChCi16w9c5k75hJbMBr/ebxC40hFcZo33rzM+BqANylinDbyXg2b5FjKIzC8aNCe8gU=
|1|7WHkFlCZgnpvYzZNK4TkdeHAPIU=|YbMo31dZtXw6B3Pp2HCZ6JFfw6U= ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBE1oUgWMa2/YUegZQL1mFwAHLuxd9ipJ4Hv3X+q2XjmGqovv7yh5qzNvBQyYoNxekdqgYumLbEX4N8+66haGPmg=
|1|ASIva5Y66eW/mo98cD8PX08oQMo=|ME5YF7H7BUyDfTPEM8OohjDv8LM= ecdsa-sha2-nistp256 AAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOsPsFbJneC14fsnlATa/qJI1K/dc7iLQ7VlwTvjRQZlMO92wo4oRDC8l2kXi45i5xPrrFloHqZDF4DnOG2VCc8=
|1|PFkudLVDvJWHEvi9uCdTRNPaoAI=|a1crvxOaHmJU9JOeFuzVZWE2RMw= ecdsa-sha2-nistp256 AAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBGxu6L7a/LbmRnfXFjdhmMliQrt5ZrurttfYxKSpv+1MXGr8Ofp1pyagdCZXd4hqGhMSfBUeElBWImtH7m9aCGM=
```

Servers send their asymmetric public keys to the client to identify themselves to the client. Clients will save these keys in the .ssh/known_hosts file in their home directory. Should connection to a remote server receive a different HOST key the system will generate a warning to the client.

```
  ssh student@172.16.82.106
  @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
  @    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @
  @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
  IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!
  Someone could be eavesdropping on you right now (man-in-the-middle attack)!
  It is also possible that a host key has just been changed.
  The fingerprint for the ECDSA key sent by the remote host is
  SHA256:RO05vd7h1qmMmBum2IPgR8laxrkKmgPxuXPzMpfviNQ.
  Please contact your system administrator.
  Add correct host key in /home/student/.ssh/known_hosts to get rid of this message.
  Offending ECDSA key in /home/student/.ssh/known_hosts:1
  remove with:
  ssh-keygen -f "/home/student/.ssh/known_hosts" -R "172.16.82.106"
  ECDSA host key for 172.16.82.106 has changed and you have requested strict checking.
  Host key verification failed.
```

- Symmetric Encryption:

  - Session Key:

    - Once the asymmetric public key exchange is completed, the client will derive the shared symmetric session key.

    - The client encrypt the session key using the public key (host key) of the server and send it to the server.

    - Once the server decrypts the session key using its private key they will use symmetric encryption for the remaining duration of the SSH session.

    - A symmetric encryption algorithm (such as AES) is commonly used to encrypt the session data.

    - The shared secret key is securely generated from the key exchange process and shared only between the client and server.

    - Symmetric Encryption Algorithms:

      - AES (Advanced Encryption Standard): A widely used symmetric encryption algorithm known for its security and efficiency. SSH supports various key lengths (e.g., AES-128, AES-192, AES-256) for AES encryption.



References:

http://www.networksorcery.com/enp/protocol/ssh.htm
https://en.wikipedia.org/wiki/Secure_Shell
https://en.wikipedia.org/wiki/Secure_Shell#Standards_documentation
https://www.cloudshark.org/captures/849d3c7f09d3


#### 3.4.2.1 SSH Architecture
Components of SSH Architecture
In order for ssh to work properly between a client and server, several components are required:

- Server
Known as sshd in most linux SSH implementations, this allows incoming SSH connections and handles authentication and authorization.

- Clients
This is the program that connects to the SSH server for a request, examples include scp and ssh

- Sessions
The client and server conversation that begins after successful mutual authentication.

- Keys
There are several keys that are used in SSH:

  - User Key - Asymmetric Public key created used to identify the user to a server (generated by the user)

  - Host Key - Asymmetric Public key created to identify a server to a user (generated by an administrator)

  - Session Key - Symmetric Key created by the client and the server that protects the communication for a particular session

- Key Generator
Creates user keys and host keys via ssh-keygen

- Known-hosts database
Collection of host keys that the client and server refer to for mutual authentication.

- Agent
Stores keys in memory as a convenience for users to not input pass-phrases repetitively.

- Signer
This is a program that signs the host-based authentication packets.

- Random Seed
Random data used for entropy in creating pseudo-random numbers

- Configuration File
Settings that exist on either the client or server that dictate functionality for ssh or sshd respectively

![image](https://github.com/ruppertaj/WOBC/assets/93789685/afb1c686-0767-402f-9dac-3fb211d3cf8d)
ssh_architecture

Defined in [RFC4251](https://tools.ietf.org/html/rfc4251), there are three major protocols are run on top of TCP to facilitate an SSH Connection:



SSH Protocol Components

- SSH-TRANS
This can be thought of as the building block that provides initial connection, server authentication, basic encryption, integrity services, and compression if needed. Once this is established, a client has a secure full duplex stream to an authenticated remote peer.

- SSH-USERAUTH
This component is sent over the SSH-TRANS connection and used to authenticate with the client with the server. During this stage the client learns about format of authentication requests, conditions, and available methods of authentication. SSH uses algorithms in compliance with DSS defined in [FIPS PUB 186-4](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.186-4.pdf). (RSA, DSA, etc.) Most commonly this will be RSA.

- SSH-CONNECT
This component provides the exciting things over a single pipe that is provided by SSH-TRANS. It includes support for multiple interactive and non-interactive sessions. It multiplexes several channels through the underlying connections to allow for TCP, X, and agent forwarding, terminal handling, remote program execution.

![image](https://github.com/ruppertaj/WOBC/assets/93789685/a7074a1b-fed1-4a63-8d59-eb547397d66b)
ssh_protocol



References:

https://tools.ietf.org/html/rfc4251
https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.186-4.pdf


#### 3.4.2.2 SSH Implementation Concerns
Authentication

There are several methods used by SSH for authentication, the following are the most common implementations:

- Password Authentication:
This is performed with help from the host operating system, which maintains the user and password association. The password must be transmitted to the remote server during authentication. This is the traditional way SSH works in most situations.
  - Can be brute-forced

- Cryptographic Key Authentication:
This is performed using the "ssh-keygen" command to generate a public and private key pair. The public key must be installed on the SSH server, while the private key remains on the host machine. It is extremely important to create a passphrase when prompted during the key generation process. If this is not performed and the key is stolen, credentials are compromised and anyone can perform actions on behalf of the owner of the key.



Password Authentication Debug Demo
```
ssh john@10.50.x.x -vv -E ssh.log
exit
cat ssh.log
```

```
Debug Output	Explanation	Protocol Component
Connecting to 10.50.x.x port 22

Opening a socket connection to the server

SSH-TRANS

Protocol version determination

Determines remote and local SSH version compatibility

SSH-TRANS

Authenticating to 10.50.x.x as 'username'

Authenticating as user username

SSH-AUTH

SSH2_MSG_KEXINIT(key exchange initialization)

Initializing Symmetric Key Exchange

SSH-TRANS

kex algorithm

Key exchange algorithm

SSH-TRANS

kex stoc and ctos cipher

Server to client and client to server cipher exchange

SSH-TRANS

server host key: ecdsa-sha2-nistp256 sha256: ryNrRtgifo+89a0p8

server’s host key algorithm and SHA256 signature

SSH-TRANS

rekey after 1342217728 blocks

Notification to perform another symmetric key exchange after specified blocks

SSH-TRANS

Authentications that can continue: publickey, password

Specifies authentication modes supported

SSH-AUTH

Next authentication method: public key

SSH tries public key first due to supporting both, and prefering public key over password

SSH-AUTH

trying private key /home/bob/.ssh/id_rsa

SSH looks for the private key in the directory listed

SSH-AUTH

Next authentication method: password

Authentication via password

SSH-AUTH

Authenticated

Successful authentication with remote host

SSH-AUTH

channel 0: new [client-session]

Channel for session opened

SSH-CONN

Enter interactive session

creates interactive session waiting for client input over the established channel

SSH-CONN

Sending environment LANG=en_US.UTF-8

Establishes environment language for user input

SSH-CONN

Client_input_channel_req: Channel 0 rtype

Client input received on channel 0

SSH-CONN
```


#### 3.4.2.3 SSH Usage
SSH is used on a client to remotly authenticate to a server. The basic syntax is as such:

```
$ ssh {user}@{ip}

$ ssh student@172.16.82.106
```

If the `{user}` username is not specified then the currently logged in username is assumed. So if all the accounts were the same on each computer then the username is not needed. However, if any system does not use the currently logged in user account then it must be specified.

Some additional switches that can be added to the SSH syntax are (more information can be found in the ssh manual):

- `-p {port}` = This specifies the alternate port to be used. When connecting to a server the assumed default port to connect to is port 22. Should you need to specify a different port then the `-p` switch is used followed by the port.

  - Assuming the SSH port of 172.16.82.106 was 1234. `ssh student@172.16.82.106 -p 1234`

  - If you already had an SSH tunnel created you can call on that port to authenticate to the server on the other end. `ssh student@localhost -p 1234`

- `-l {username}` = This is to specify the username to use when authenticating to the remote server. This is the same as `{username]@{ip}. ssh 172.16.82.106 -l student`

`{command}` = Optional command to execute on the remote host after establishing the SSH connection. If provided, SSH will execute the command on the remote host and then return the output to the local terminal. If not provided, SSH will start an interactive shell session on the remote host. `ssh student@172.16.82.106 cat /etc/passwd`

`-X` = This will enable X11 graphics to be forwarded from the server to the client. This will allow you to open graphical applications such as `pcmanfm`, `gimp`, `eog`, `eom`, `firefox`, `terminator`, and more. `ssh student@172.16.82.106 -X`

`-v` = Enables verbose mode, which provides detailed debugging information about the SSH connection process. This can be helpful for diagnosing connection issues or troubleshooting SSH configuration problems. `ssh student@172.16.82.106 -v`

`-f` = Requests SSH to go to the background just before command execution. This is useful when running SSH commands as part of scripts or automation tasks. This is not to be confused with the & option which is used to background most applications. `ssh student@172.16.82.106 -f`

`-i {identity file}` = Selects a file from which the identity (private key) for RSA or DSA authentication is read. The default is ~/.ssh/identity for protocol version 1, and ~/.ssh/id_rsa and ~/.ssh/id_dsa for protocol version 2. `ssh student@172.16.82.106 -i idfile.pub`

`-F {config file}` = Specifies an alternative per-user configuration file. If a configuration file is given on the command line, the system-wide configuration file (/etc/ssh/ssh_config) will be ignored. The default for the per-user configuration file is ~/.ssh/config. ssh student@172.16.82.106 -F my.config

`-N` = Requests that no command be executed on the remote server after establishing the SSH connection. This can be useful when setting up port forwarding or establishing a tunnel without running a command on the remote server. `ssh student@172.16.82.106 -NT`

`-T` = Disables pseudo-terminal allocation, preventing the allocation of a terminal on the remote server. This can be useful when executing commands that do not require interaction or terminal emulation. `ssh student@172.16.82.106 -NT`

`-C` = Enables compression of data during transmission over the SSH connection, reducing bandwidth usage, especially over slow or high-latency connections. `ssh student@172.16.82.106 -C`

`-J user@host` = Specifies a jump host to connect through when establishing the SSH connection. This simplifies the process of connecting to a remote host that is not directly accessible from the local machine. `ssh -J student@10.10.0.40, student@172.16.1.15, student@172.16.40.10 student@172.16.82.106`

`-L [bind_address:]port:host:hostport` = Sets up local port forwarding, allowing connections to a local port to be forwarded over the SSH tunnel to a specified host and port on the remote server. This can be useful for accessing services running on a remote server through a secure tunnel. `ssh student@172.16.82.106 -L 1234:192.168.1.10:22`

`-R [bind_address:]port:host:hostport` = Sets up remote port forwarding, allowing connections to a specified port on the remote server to be forwarded over the SSH tunnel to a host and port on the local machine or another remote server. This can be useful for exposing services running on the local machine to the remote server or other remote machines. `ssh student@10.10.0.40 -L 1234:172.16.40.10:22`

`-D {port}` = Specifies a local "dynamic" port forwarding port. This creates a SOCKS proxy on the specified port, allowing other applications to tunnel their traffic through the SSH connection securely. `ssh student@172.16.1.15 -D 9050`



References:

https://linux.die.net/man/1/ssh


#### 3.4.2.4 SSH First Time Connecting
When connecting to an SSH server for the first time, the client will try to verify the server’s Host key. The client will check the ~/.ssh/known_hosts file to see if the public key is already known. If it is not then the system will prompt the client if they trust this system. The user is required to type 'yes' or 'no'. Should the user say 'yes' then that public key will be save in the ~/.ssh/known_hosts file.

```
student@internet-host:~$ ssh student@172.16.82.106
The authenticity of host '172.16.82.106 (172.16.82.106)' can't be established.
ECDSA key fingerprint is SHA256:749QJCG1sf9zJWUm1LWdMWO8UACUU7UVgGJIoTT8ig0.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '172.16.82.106' (ECDSA) to the list of known hosts.
student@172.16.82.106's password:
student@blue-host-1:~$
```


#### 3.4.2.5 SSH Re-Connect
When re-connecting to the server it will no longer prompt to verify or save the server’s public key. This is because the server’s public key will match a key in the ~/.ssh/known_hosts file.

```
ssh student@172.16.82.106
student@172.16.82.106's password:
student@blue-host-1:~$
```


#### 3.4.2.6 SSH Host Key Changed
Should you try to connect to a known server and you get prompted with a warning that the remote host identification has changed. This can be for two possible reasons.

1. The server’s public key changed due to a system reload.

2. Someone is impersonating the server using their IP and does not have the same public key to verify their identity.
- Use `ssh-keygen -f "/home/student/.ssh/known_hosts" -R "172.16.82.106"` to remove

```
ssh student@172.16.82.106
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!
Someone could be eavesdropping on you right now (man-in-the-middle attack)!
It is also possible that a host key has just been changed.
The fingerprint for the ECDSA key sent by the remote host is
SHA256:RO05vd7h1qmMmBum2IPgR8laxrkKmgPxuXPzMpfviNQ.
Please contact your system administrator.
Add correct host key in /home/student/.ssh/known_hosts to get rid of this message.
Offending ECDSA key in /home/student/.ssh/known_hosts:1
remove with:
ssh-keygen -f "/home/student/.ssh/known_hosts" -R "172.16.82.106"
ECDSA host key for 172.16.82.106 has changed and you have requested strict checking.
Host key verification failed.
```


#### 3.4.2.7 SSH Host Key Changed Fix
If you are able to verify that the server’s key change was due to a reload, you can remove the conflicting Host key using the provided ssh-keygen command. After removing the key entry it will then prompt you to save the new key again.

```
ssh-keygen -f "/home/student/.ssh/known_hosts" -R "172.16.82.106"
student@internet-host:~$ ssh student@172.16.82.106
The authenticity of host '172.16.82.106 (172.16.82.106)' can't be established.
ECDSA key fingerprint is SHA256:749QJCG1sf9zJWUm1LWdMWO8UACUU7UVgGJIoTT8ig0.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '172.16.82.106' (ECDSA) to the list of known hosts.
student@172.16.82.106's password:
student@blue-host-1:~$
```


#### 3.4.2.8 SSH Files

- Known-Hosts Database:

  - The ~/.ssh/known_hosts file is a file used by SSH clients to store the fingerprints of remote hosts that the user has connected to. Each time you connect to a remote SSH server, the client checks the server’s fingerprint against the entries in the known_hosts file to ensure that you’re connecting to the correct server.

```
cat ~/.ssh/known_hosts
```

- Configuration Files

  - `/etc/ssh/ssh_config`:

    - This file is the system-wide configuration file for the SSH client. It contains configuration options that apply to all users on the system when they use SSH to connect to remote servers.

    - Typical settings in the ssh_config file include options like specifying default usernames, enabling or disabling SSH features such as X11 forwarding or agent forwarding, configuring proxy settings, setting default encryption algorithms, and defining custom SSH aliases.

    - Users can also have their own ~/.ssh/config file in their home directory, which overrides settings from the system-wide ssh_config file for their individual SSH sessions.

  - `/etc/ssh/sshd_config`:

    - This file is the system-wide configuration file for the SSH server (sshd). It contains configuration options that apply to the SSH server daemon running on the system.

    - Typical settings in the sshd_config file include options for configuring SSH server authentication methods (e.g., password authentication, public key authentication), specifying which users or groups are allowed to access the SSH server, setting restrictions on SSH sessions (e.g., maximum number of concurrent connections, idle session timeout), and configuring logging and auditing options.

    - Changes made to the sshd_config file usually require restarting the SSH server for the new settings to take effect.

      - `sudo systemctl restart ssh`
      - `cat /etc/ssh/sshd_config | grep port`

```
cat /etc/ssh/ssh_config

# This is the ssh client system-wide configuration file.  See
# ssh_config(5) for more information.  This file provides defaults for
# users, and the values can be changed in per-user configuration files
# or on the command line.

# Configuration data is parsed as follows:
#  1. command line options
#  2. user-specific file
#  3. system-wide file
# Any configuration value is only changed the first time it is set.
# Thus, host-specific definitions should be at the beginning of the
# configuration file, and defaults at the end.

# Site-wide defaults for some commonly used options.  For a comprehensive
# list of available options, their meanings and defaults, please see the
# ssh_config(5) man page.

Host *
#   ForwardAgent no
#   ForwardX11 no
#   ForwardX11Trusted yes
#   PasswordAuthentication yes
#   HostbasedAuthentication no
#   GSSAPIAuthentication no
#   GSSAPIDelegateCredentials no
#   GSSAPIKeyExchange no
#   GSSAPITrustDNS no
#   BatchMode no
#   CheckHostIP yes
#   AddressFamily any
#   ConnectTimeout 0
#   StrictHostKeyChecking ask
#   IdentityFile ~/.ssh/id_rsa
#   IdentityFile ~/.ssh/id_dsa
#   IdentityFile ~/.ssh/id_ecdsa
#   IdentityFile ~/.ssh/id_ed25519
#   Port 22
#   Protocol 2
#   Ciphers aes128-ctr,aes192-ctr,aes256-ctr,aes128-cbc,3des-cbc
#   MACs hmac-md5,hmac-sha1,umac-64@openssh.com
#   EscapeChar ~
#   Tunnel no
#   TunnelDevice any:any
#   PermitLocalCommand no
#   VisualHostKey no
#   ProxyCommand ssh -q -W %h:%p gateway.example.com
#   RekeyLimit 1G 1h
    SendEnv LANG LC_*
    HashKnownHosts yes
    GSSAPIAuthentication yes
```

```
cat /etc/ssh/sshd_config

#	$OpenBSD: sshd_config,v 1.103 2018/04/09 20:41:22 tj Exp $

# This is the sshd server system-wide configuration file.  See
# sshd_config(5) for more information.

# This sshd was compiled with PATH=/usr/bin:/bin:/usr/sbin:/sbin

# The strategy used for options in the default sshd_config shipped with
# OpenSSH is to specify options with their default value where
# possible, but leave them commented.  Uncommented options override the
# default value.

Port 22
Port 2222
#AddressFamily any
#ListenAddress 0.0.0.0
#ListenAddress ::

#HostKey /etc/ssh/ssh_host_rsa_key
#HostKey /etc/ssh/ssh_host_ecdsa_key
#HostKey /etc/ssh/ssh_host_ed25519_key

# Ciphers and keying
#RekeyLimit default none

# Logging
#SyslogFacility AUTH
#LogLevel INFO

# Authentication:

#LoginGraceTime 2m
PermitRootLogin yes
#StrictModes yes
#MaxAuthTries 6
#MaxSessions 10

#PubkeyAuthentication yes

# Expect .ssh/authorized_keys2 to be disregarded by default in future.
#AuthorizedKeysFile	.ssh/authorized_keys .ssh/authorized_keys2

#AuthorizedPrincipalsFile none

#AuthorizedKeysCommand none
#AuthorizedKeysCommandUser nobody

# For this to work you will also need host keys in /etc/ssh/ssh_known_hosts
#HostbasedAuthentication no
# Change to yes if you don't trust ~/.ssh/known_hosts for
# HostbasedAuthentication
#IgnoreUserKnownHosts no
# Don't read the user's ~/.rhosts and ~/.shosts files
#IgnoreRhosts yes

# To disable tunneled clear text passwords, change to no here!
#PasswordAuthentication yes
#PermitEmptyPasswords no

# Change to yes to enable challenge-response passwords (beware issues with
# some PAM modules and threads)
ChallengeResponseAuthentication no

# Kerberos options
#KerberosAuthentication no
#KerberosOrLocalPasswd yes
#KerberosTicketCleanup yes
#KerberosGetAFSToken no

# GSSAPI options
#GSSAPIAuthentication no
#GSSAPICleanupCredentials yes
#GSSAPIStrictAcceptorCheck yes
#GSSAPIKeyExchange no

# Set this to 'yes' to enable PAM authentication, account processing,
# and session processing. If this is enabled, PAM authentication will
# be allowed through the ChallengeResponseAuthentication and
# PasswordAuthentication.  Depending on your PAM configuration,
# PAM authentication via ChallengeResponseAuthentication may bypass
# the setting of "PermitRootLogin without-password".
# If you just want the PAM account and session checks to run without
# PAM authentication, then enable this but set PasswordAuthentication
# and ChallengeResponseAuthentication to 'no'.
UsePAM yes

#AllowAgentForwarding yes
#AllowTcpForwarding yes
#GatewayPorts no
X11Forwarding yes
#X11DisplayOffset 10
#X11UseLocalhost yes
#PermitTTY yes
PrintMotd no
#PrintLastLog yes
#TCPKeepAlive yes
#PermitUserEnvironment no
#Compression delayed
#ClientAliveInterval 0
#ClientAliveCountMax 3
#UseDNS no
#PidFile /var/run/sshd.pid
#MaxStartups 10:30:100
#PermitTunnel no
#ChrootDirectory none
#VersionAddendum none

# no default banner path
#Banner none

# Allow client to pass locale environment variables
AcceptEnv LANG LC_*

# override default of no subsystems
Subsystem	sftp	/usr/lib/openssh/sftp-server

# Example of overriding settings on a per-user basis
#Match User anoncvs
#	X11Forwarding no
#	AllowTcpForwarding no
#	PermitTTY no
#	ForceCommand cvs serve
```


#### 3.4.2.9 SSH-Keygen
The ssh-keygen command is a tool used to generate SSH key pairs for authentication purposes. SSH keys are cryptographic keys used to authenticate and establish secure connections between a client (your local machine) and a server without the need for a password.

```
ssh-keygen -t rsa -b 4096 -C "Student"
    Generating public/private rsa key pair.
    Enter file in which to save the key (/home/student/.ssh/id_rsa):
    Enter passphrase (empty for no passphrase):
    Enter same passphrase again:
    Your identification has been saved in /home/student/.ssh/id_rsa.
    Your public key has been saved in /home/student/.ssh/id_rsa.pub.
    The key fingerprint is:
    SHA256:hYXK1AXWasbCenSXR0jDLi9JXgbn2C2YL0K59cUjuSY Student
    The key's randomart image is:
    +---[RSA 4096]----+
    |       .oB=.     |
    |      ..+o=..    |
    |     + +.@.*     |
    |      O &.% *    |
    |     + XSX * .   |
    |    . + E *      |
    |     . . =       |
    |                 |
    |                 |
    +----[SHA256]-----+
```

- Create your own SSH Public/Private keys

  - -t Specify the Encryption to use (rsa|dsa|ecdsa|ed25519)

  - -b Specify the Bit length (1024|2048|4096)

  - -C Adds an optional comment to better identify each key

- Specify Key File Location (Optional): If you want to save the key pair to a specific location, you can specify the file path when prompted.

- Set Passphrase (Optional): You can choose to set a passphrase for the private key to add an extra layer of security. If you set a passphrase, you’ll need to enter it every time you use the private key.

```
cat ~/.ssh/id_rsa       #private
cat ~/.ssh/id_rsa.pub   #public
```


#### 3.4.2.10 SSH-Copy-ID
`ssh-copy-id` is a convenient script used to copy the public SSH key of your local machine to a remote server’s ~/.ssh/authorized_keys file. This allows you to easily set up SSH key-based authentication for accessing the remote server without needing to manually copy and paste the public key.

```
ssh-copy-id student@172.16.82.106
```

After copying the key you will be able to ssh to the remote server without needing to provide a password.

```
ssh student@172.16.82.106
student@blue-host-1:~$
```


### 3.4.3 Analyze Hypertext Transfer Protocol (Secure) (HTTP(s))
HTTP(S) (TCP 80/443)

![image](https://github.com/ruppertaj/WOBC/assets/93789685/1e9a0a86-9335-4e86-a262-23be29b457bd)
http.png

- The Hypertext Transfer Protocol (HTTP) is an application layer protocol used for communication between web browsers and web servers. It serves as the foundation for data communication on the World Wide Web, enabling the retrieval and display of web pages, images, videos, and other resources.

- Key characteristics and features of HTTP include:

  - Client-Server Architecture: HTTP follows a client-server model, where the client (usually a web browser) sends requests to the server, and the server responds with the requested data or performs the requested actions.

  - Stateless Protocol: HTTP is stateless, meaning each request from the client to the server is independent and does not retain any information about previous requests.

  - Request-Response Paradigm: Communication in HTTP is based on a request-response paradigm. The client sends an HTTP request to the server, specifying the desired action (such as retrieving a web page or submitting a form). The server processes the request and sends an HTTP response back to the client, containing the requested data or an appropriate status code.

    - Request Methods - performed by the client to a server.

      - GET - Most common method used. Used to retrieve data from a server.

      - POST - Used to send data to the API server. Generally used with storing a file or form.

      - PUT - Similar to POST. Used to send data to the API to update or create a resource. It differs from POST in that it is used only on a particular resource.

      - PATCH - used to apply partial modifications to the resource.

      - DELETE - used to delete the resource at the specified URL.

      - HEAD - Similar to GET except it does not return the message body.

      - OPTIONS - used to return data describing what other methods and operations the server supports at the given URL.

      - [HTTP Methods from iana.org](https://tools.ietf.org/html/rfc7231#page-21)

    - HTTP server status Codes - server response to a request method.

      - 1xx - Informational

      - 2xx - Successful

      - 3xx - Redirection

      - 4xx - Client error

      - 5xx - Server error

      - [HTTP status codes from iana.org](https://www.iana.org/assignments/http-status-codes/http-status-codes.xhtml)

  - Uniform Resource Identifiers (URIs): HTTP uses URIs to identify resources on the web. A URI is a broader concept that encompasses both URLs and URNs. It is a string of characters that identifies or names a resource on the internet. A URI provides a unique and standardized way to refer to a resource, regardless of its location or retrieval mechanism. URIs can be used to identify web pages, files, services, email addresses, telephone numbers, and more.

```
foo://example.com:8042/over/there?name=ferret#nose
```

  - Uniform Resource Locator (URL): A URL is a specific type of URI that provides the complete address and access mechanism for a resource on the internet. It specifies the location of a resource and the protocol required to access it.

```
http://www.ietf.org/rfc/rfc2396.txt
```

  - Governed by the these RFCs: [RFC 7230](https://tools.ietf.org/html/rfc7230), [RFC 7231](https://tools.ietf.org/html/rfc7231), [RFC 7232](https://tools.ietf.org/html/rfc7232), [RFC 7233](https://tools.ietf.org/html/rfc7233), [RFC 7234](https://tools.ietf.org/html/rfc7234), [RFC 7235](https://tools.ietf.org/html/rfc7235), [5785](https://tools.ietf.org/html/rfc5785), [RFC6266](https://tools.ietf.org/html/rfc6266), [RFC 6585](https://tools.ietf.org/html/rfc6585), [RFC 2817](https://tools.ietf.org/html/rfc2817), [RFC 2818](https://tools.ietf.org/html/rfc2818), [RFC 5246](https://tools.ietf.org/html/rfc5246), [RFC 6101](https://tools.ietf.org/html/rfc6101)

  - [HTTP pcap from www.cloudshark.org](https://www.cloudshark.org/captures/4a3b7c2a3230)



References:

https://tools.ietf.org/html/rfc7231#page-21

https://www.iana.org/assignments/http-status-codes/http-status-codes.xhtml


#### 3.4.3.1 Quick UDP Internet Connections (QUIC)
HTTPs QUIC (UDP 443)

- QUIC (Quick UDP Internet Connections): Developed by Google, QUIC serves as a cutting-edge transport layer protocol meticulously crafted to elevate the speed and security of web applications, strategically designed to surmount limitations inherent in conventional transport protocols like TCP (Transmission Control Protocol).

- UDP-Based Operation: Functioning over the User Datagram Protocol (UDP), QUIC introduces a nimble and connectionless communication paradigm, optimizing the transmission of data.

- Latency Reduction Engineering: At its core, QUIC is an engineering marvel dedicated to mitigating latency compared to TCP. This achievement is realized through innovative mechanisms, including connection multiplexing and a streamlined round-trip handshake process.

- Integration with HTTP/3: Inextricably linked with the HTTP/3 protocol, QUIC seamlessly provides a secure and highly efficient transport layer, propelling the evolution of the Hypertext Transfer Protocol into its next generation.



References:

https://peering.google.com/#/learn-more/quic

https://en.wikipedia.org/wiki/QUIC


#### 3.4.3.2 HTTP Vulnerabilities
- HTTP (Hypertext Transfer Protocol) is a fundamental protocol for communication on the World Wide Web. While it is the foundation for data communication on the web, it has had historical vulnerabilities that could pose risks to security.

- HTTP is vulnerable to various Denial of Service (DoS) attacks.

  - Flooding the HTTP Server:

    - HTTP flood: floods the target server with a high volume of legitimate-looking HTTP requests, consuming its resources and causing it to become unresponsive.

    - HTTP GET/POST Flood: The attacker sends a large number of HTTP GET or POST requests to overwhelm the server and exhaust its resources.

    - SYN Flood: The attacker sends massive amounts of SYNs to try to consume all the connections.

  - HTTP Amplification: the attacker leverages misconfigured or vulnerable web servers to amplify the attack traffic, making it appear as if the requests are originating from multiple sources.

  - Low and Slow attacks:

    - Slow Loris: attack functions by opening connections to a targeted Web server and then keeping those connections open as long as it can.

    - R U Dead Yet? (RUDY): aims to keep a web server tied up by submitting form data at an absurdly slow pace.

  - Drive by Downloads: is the unintentional downloading of malicious software onto a user’s device when visiting a website or clicking on a compromised advertisement or link. The term "drive-by" implies that the download happens automatically and without the user’s knowledge or consent. Drive-by downloads take advantage of vulnerabilities in web browsers, browser plugins, or operating systems to initiate the download of malicious files.

  - BeEF Framework: The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser. It is a tool designed to enable an attacker to use a target’s browser as an attack point.

- Man-in-the-Middle Attack: Attackers can intercept and alter communication between a client and server, leading to unauthorized access, data manipulation, or eavesdropping.

- Session Hijacking: Attackers may steal session identifiers, allowing them to impersonate a user and gain unauthorized access to sensitive information.

- Cross-Site Scripting (XSS): Malicious scripts are injected into web pages viewed by other users, potentially leading to the theft of sensitive information or session hijacking.

- Cross-Site Request Forgery (CSRF): Unauthorized commands are transmitted from a user that the web application trusts, potentially leading to actions performed on behalf of the user without their consent.

- Directory Traversal Attacks: Attackers exploit insufficient security controls to access files or directories beyond the intended scope, potentially exposing sensitive data.

  - http://example.com/view?file=../../etc/passwd



References:

https://www.cloudflare.com/learning/ddos/http-flood-ddos-attack/

https://www.cloudflare.com/learning/ddos/ddos-attack-tools/slowloris/

https://www.cloudflare.com/learning/ddos/ddos-attack-tools/slowloris/

https://www.cloudflare.com/learning/ddos/ddos-attack-tools/r-u-dead-yet-rudy/

https://www.cloudflare.com/learning/ddos/ddos-attack-tools/r-u-dead-yet-rudy/

https://www.ericom.com/glossary/what-is-a-drive-by-attack/

https://en.wikipedia.org/wiki/Drive-by_download

https://owasp.org/www-community/attacks/xss/

https://owasp.org/www-community/attacks/csrf

https://owasp.org/www-community/attacks/Path_Traversal

https://www.kali.org/tools/beef-xss/

https://www.techtarget.com/searchsecurity/tutorial/How-to-use-BeEF-the-Browser-Exploitation-Framework


### 3.4.4 Analyze Domain Name System (DNS) protocol
DNS (QUERY/RESPONSE) (TCP/UDP 53)

- Used as a means to resolve domain names to an IP addresses usable by the client system. Typically used to resolve IP addresses of web domains.

- Client queries and server responses are typically sent using UDP port 53.

- TCP is used when DNS responses are larger than 512-bytes.

  - DNS Zone transfers are typicaly over 512-bytes so TCP is used for the transmission.

![image](https://github.com/ruppertaj/WOBC/assets/93789685/bf190fa8-bee5-4b2c-9cd8-1c3dc465d2a0)
dns

- [DNS reference from wikipedia](https://en.wikipedia.org/wiki/Domain_Name_System)

- [List of DNS RFC’s](https://en.wikipedia.org/wiki/Domain_Name_System#RFC_documents)

- [DNS pcap from www.cloudshark.org](https://www.cloudshark.org/captures/0320b9b57d35)

- [DNS zone transfer pcap from www.cloudshark.org](https://www.cloudshark.org/captures/7ee39c3b583f)



References:

https://en.wikipedia.org/wiki/Domain_Name_System
https://en.wikipedia.org/wiki/Domain_Name_System#RFC_documents
https://www.cloudshark.org/captures/0320b9b57d35
https://www.cloudshark.org/captures/7ee39c3b583f


#### 3.4.4.1 Examine DNS usage with UDP and TCP
DNS-over-UDP/53 ("Do53")

- DNS has primarily answered queries using UDP 53, queries consist of a clear-text request sent in a single UDP packet from the client, responded to with a clear-text reply sent in a single UDP packet from the server. Lacks transport-layer encryption, authentication, reliable delivery, and message length.

DNS-over-TCP/53 ("Do53/TCP")

- DNS can use TCP for DNS queries, replies but particularly is used in zone transfers. Transfer of DNS records between a Primary and Secondary DNS Servers require the use of TCP protocol. The requirement here is that TCP, due to its reliability makes sure zone data is consistent across DNS servers. When a client doesn’t receive a response from DNS, it re-transmits the query using TCP after 3-5 seconds of interval.



References:

https://en.wikipedia.org/wiki/Domain_Name_System#DNS_transport_protocols


#### 3.4.4.2 Explain DNS Records
A DNS servers contains a "zone file" for each domain, and the zone file is made up of "resource records" (RRs) which acts as instructions for the DNS server.

Common list of records are:

Type A

- IPv4 Address record, used to map hostnames to an IP address of the host.

Type AAAA

- IPv6 address record, used to map hostnames to an IPv6 address of the host.

Type MX

- Mail exchange record, Maps a domain name to a list of message transfer agents for that domain.

Type TXT

- Text record, human-readable text in a DNS record, but can also store machine-readable data. Often used for verification and authentication.

Type NS

- Name Server record, specifies the authoritative name servers for a domain.

Type SOA

- Start of authority, provides authoritative information about the zone, including administrative details and zone-level settings.

Type AXFR

- AXFR facilitates the transfer of the entire DNS zone data, including all resource records, from one DNS server (the master) to another DNS server (the slave).

Type CNAME

- Canonical Name creates an alias for a domain name, pointing it to another canonical domain.

Type PTR

- Used for reverse DNS lookups to map an IP address to a domain name.

A extended list of records can be found here: [DNS record types](https://en.wikipedia.org/wiki/List_of_DNS_record_types)

Linux command to view records: `dig`
Example: `dig stackoverflow.com`

Windows command to view records: `ipconfig /displaydns`



References:

https://en.wikipedia.org/wiki/List_of_DNS_record_types


#### 3.4.4.3 Explain DNS architecture

![image](https://github.com/ruppertaj/WOBC/assets/93789685/ac3ee60c-6e7c-40a4-a539-33bfff01de0d)
DNS Architecture

- DNS Root Zone. Authoritative name servers managed by IANA with 13 root servers around the world.

  - a.root-servers.net 198.41.0.4, 2001:503:ba3e::2:30 Verisign, Inc.

  - b.root-servers.net 199.9.14.201, 2001:500:200::b University of Southern California,

  - c.root-servers.net 192.33.4.12, 2001:500:2::c Cogent Communications

  - d.root-servers.net 199.7.91.13, 2001:500:2d::d University of Maryland

  - e.root-servers.net 192.203.230.10, 2001:500:a8::e NASA (Ames Research Center)

  - f.root-servers.net 192.5.5.241, 2001:500:2f::f Internet Systems Consortium, Inc.

  - g.root-servers.net 192.112.36.4, 2001:500:12::d0d US Department of Defense (NIC)

  - h.root-servers.net 198.97.190.53, 2001:500:1::53 US Army (Research Lab)

  - i.root-servers.net 192.36.148.17, 2001:7fe::53 Netnod

  - j.root-servers.net 192.58.128.30, 2001:503:c27::2:30 Verisign, Inc.

  - k.root-servers.net 193.0.14.129, 2001:7fd::1 RIPE NCC

  - l.root-servers.net 199.7.83.42, 2001:500:9f::42 ICANN

  - m.root-servers.net 202.12.27.33, 2001:dc3::35 WIDE Project

- Top Level Domains (Level 1). Top-Level Domains (TLDs) are the highest level of domain names in the hierarchical Domain Name System (DNS) structure.

  - Generic:

    - .com: Commercial organizations

    - .org: Non-profit organizations

    - .net: Network infrastructure providers

    - .edu: Educational institutions

    - .gov: U.S. government agencies

    - .mil: U.S. military organizations

    - .int: International organizations

    - .info: General information websites

    - .biz: Business-related websites

    - .name: Personal websites

  - Country Code:

    - .us: United States

    - .uk: United Kingdom

    - .de: Germany

    - .fr: France

    - .jp: Japan
 
    - .au: Australia

    - .ca: Canada

    - .in: India

    - .br: Brazil

    - .cn: China

    - .ru: Russia

- 2nd Level Domains. Second-level domains are commonly used to identify specific organizations, businesses, or individuals on the internet.

  - .com TLD:

    - google.com

    - amazon.com

    - microsoft.com

    - apple.com

  - .org TLD:

    - wikipedia.org

    - mozilla.org

    - redcross.org

    - eff.org

  - .net TLD:

    - stackoverflow.net

    - behance.net

    - etsy.net

    - change.org

  - Country Code TLDs (ccTLDs):

    - bbc.co.uk (United Kingdom)

    - alibaba.cn (China)

    - naver.com (South Korea)

    - lefigaro.fr (France)

- DNS Sub-Domain. A subdomain is a part of a larger domain, placed to the left of the main domain name, that allows further organization and subdivision of the DNS hierarchy. It allows website owners to create additional sections or subdivisions under their primary domain.

  - Organization-based Subdomains:

    - sales.example.com

    - hr.companyname.com

    - support.domainname.com

  - Geographic-based Subdomains:

    - us.example.com

    - uk.domainname.com

    - ca.website.com

  - Service-based Subdomains:

    - blog.domainname.com

    - shop.example.com

    - forum.domainname.com

  - Product-based Subdomains:

    - product1.domainname.com

    - product2.example.com

    - app.domainname.com

  - Mobile-specific Subdomains:

    - m.domainname.com

    - mobile.example.com

    - mobileapp.domainname.com

  - Language-based Subdomains:

    - en.example.com

    - fr.domainname.com

    - es.website.com



DNS delegates the responsibility of assigning domain names and mapping those names to Internet resources by designating authoritative name servers for each domain. Network administrators may delegate authority over sub-domains of their allocated name space to other name servers. This mechanism provides distributed and fault-tolerant service and was designed to avoid a single large central database.

DNS record lookup process starts when a host machine types in a website to browse to. 1. The computer will check it’s local "DNS cache" for a record.

1. If a record is not found, then the request will go to a "recursive resolver" normally located at the ISP.

2. If a record is not found, then the request will go to 1 of the 13 global "root name servers". These servers are named A through M.

3. If a record is not found, then the request will go to the respective "Top Level Domain (TLD) nameserver". TLDs are divided into two distinct sub-categories organizational hierarchy (commercial for .com, organizational for .org, etc) and geographical (New Zealand for .nz, Georgia for .ga, etc) hierarchy.

4. If a record is not found, then the request will go to the "authoritative nameserver" within the zone. For www.google.com, Google will be the authoritative nameserver. The record will be located here and a response will be set back to the requestor(s).

![image](https://github.com/ruppertaj/WOBC/assets/93789685/6746e2a5-f824-4b71-9af8-a1407c3f73b3)
DNS request


References:

https://datatracker.ietf.org/doc/html/rfc1034

https://dev.to/blake/dns-explained-hierarchy-and-architecture-18pj

https://www.iana.org/domains/root/servers


### 3.4.5 Analyze File Transfer Protocol (FTP)
FTP (TCP 20/21)

![image](https://github.com/ruppertaj/WOBC/assets/93789685/e4cda6d3-5484-4c41-917d-de24b5454bdd)
ftp

- [FTP Reference from networksorcery.com](http://www.networksorcery.com/enp/protocol/ftp.htm)

- [FTP pcap from www.cloudshark.org](https://www.cloudshark.org/captures/abdc8742488f)

Published in [RFC 959](https://tools.ietf.org/html/rfc959), File Transfer Protocol is a standard network protocol that is used for file transfer between a client and a server. Authentication is performed via a username and password, but can also be disabled in favor of anonymous mode if the FTP server is configured for it. The drawback with FTP is that all communication is clear text, including the initial authentication.

FTP has two modes of operation, Active and Passive.


#### 3.4.5.1 FTP Active


- Active
A client initiates a connection with a server on port 21 from the client’s ephemeral high port. The three way handshake is completed and the client listens on its ephemeral high port + 1, the client sends the port N+1 command to the server on port 21 (control port). Ex: if the command to the server is from ephemeral port 1026, it would listen on port 1027. Once that is done, the server initiates a connection to the client’s ephemeral high (1027) from the server’s data port (20) and the data is transferred.

Example 1: Active FTP

![image](https://github.com/ruppertaj/WOBC/assets/93789685/a690bd11-bca2-4b11-ac6f-d637a8a02de1)
ftp_active

Example 1. Active FTP Diagram Walk-through
1. The client’s command port contacts the server’s command port and sends a command for the client’s ephemeral high port + 1

2. The FTP server responds to the client with an ACK to the client’s command port

3. The FTP server initiates a connection from its data port 21 to the client’s specified data port (ephemeral high + 1)

4. The FTP client sends an ACK back to the server’s data port 20 from the client’s ephemeral high data port. This also leads to issues when using ftp through an SSH tunnel which will be discussed later.

- Wireshark does not innately follow the cmd and data flows
  - ftp for cmd
  - ftp-data for data

- FTP Active Issues
  - NAT & Firewall traversal issues
  - Complications with tunneling through SSH
  - Passive FTP

```
**Important**
Active FTP Issues
Why might the active FTP mode pose a problem when a firewall exists between a client and server?

1. A stateful firewall would pass along the FTP traffic initially over port 21 (control port)

2. The server later tries connects back to the client over the port specified during the control communication (ephemeral high +1) from it’s data port 20.

The FTP client never makes the actual data connection, the client tells the server what port it is listening on for the data connection. On the client side, this would appear to be a system initiating a connection to an internal client that was unsolicited. This also presents issues with FTP through SSH tunnels.
```


#### 3.4.5.2 FTP Passive
- Passive
Passive FTP sidesteps the issue of Active mode by reversing the conversation. The client initiates both the command and data connections.

Example 2: Passive FTP

![image](https://github.com/ruppertaj/WOBC/assets/93789685/dfda9864-9934-4100-8314-8bab32ed4d83)
ftp_passive

Example 2. Passive FTP Diagram Walk-through
1. The client’s command port (1029) contacts the server’s command port (20) and sends the PASV command.

2. The FTP server responds to the client with an ACK to the client’s ephemeral high command port (1029) letting the client know the server’s listening data port (2020).

3. The FTP client initiates the data connection from its ephemeral high port (1030) to the FTP server’s listening data port (2020)

4. The FTP server sends an ACK back to the client’s ephemeral high data port (1030)


### 3.4.6 Analyze Trivial File Transfer Protocol (TFTP)
TFTP (UDP 69)

- Trivial File Transfer Protocol (TFTP) is a simple File Transfer Protocol which allows a client to get/put a file from/to a remote host. One of its primary uses is in the early stages of nodes booting from a local area network.

- TFTP has been popular due to its simple easy of implementation.

- IT pros and Sys Admins typically use TFTP configuration for:

  - Transferring files

  - Remote-booting without hard drives

  - Upgrading codes

  - Backing up network configurations

  - Backing up router configuration files

  - Saving IOS images

  - Booting PCs without a disk

 
![image](https://github.com/ruppertaj/WOBC/assets/93789685/0f06ddd1-bd23-451e-9ed9-8ae65f06b942)
tftp

- [TFTP reference from wikipedia](https://en.wikipedia.org/wiki/Trivial_File_Transfer_Protocol)

- [List of TFTP RFC’s](https://en.wikipedia.org/wiki/Trivial_File_Transfer_Protocol#IETF_standards_documentation)

- [TFTP pcap from www.cloudshark.org](https://www.cloudshark.org/captures/07ebe14c792b)



References:

https://en.wikipedia.org/wiki/Trivial_File_Transfer_Protocol
https://en.wikipedia.org/wiki/
https://www.cloudshark.org/captures/07ebe14c792b


### 3.4.7 Analyze Simple Mail Transfer Protocol (SMTP)
SMTP (TCP 25)

Simple Mail Transfer Protocol (SMTP) is an internet standard used for **sending** electronic mail. SMTP is not encrypted and will require other methods to secure the data.

![image](https://github.com/ruppertaj/WOBC/assets/93789685/acb37eed-4b0b-4ace-8884-70a01fcdfad8)
smtp

- [SMTP Reference from Wikipedia](https://en.wikipedia.org/wiki/List_of_SMTP_server_return_codes)

- [SMTP Reference from networksorcery.com](http://www.networksorcery.com/enp/protocol/smtp.htm)

- [SMTP pcap from www.cloudshark.org](https://www.cloudshark.org/captures/923901f326f8)



References:

https://en.wikipedia.org/wiki/List_of_SMTP_server_return_codes
http://www.networksorcery.com/enp/protocol/smtp.htm
https://www.cloudshark.org/captures/923901f326f8


### 3.4.8 Analyze  Post Office Protocol (POP)
POP (TCP 110)

Post Office Protocol (POP) is an older internet standard used to **retrieve** electronic mail from a server. Most implementations of POP will **delete the server stored mail once the client downloads them**. This meant that the client can only read the email from the system that was used to download them. The latest version is POP3.

![image](https://github.com/ruppertaj/WOBC/assets/93789685/a2c7edf6-3d8b-46b8-bc0b-e383a67cdb0e)
pop

- [POP3 reference from RFC 1939](https://tools.ietf.org/html/rfc1939)

- [POP3 Zip PCAP form asecuritysite.com](https://asecuritysite.com/log/pop3.zip)



References:

https://tools.ietf.org/html/rfc1939
https://asecuritysite.com/log/pop3.zip


### 3.4.9 Analyze Internet Message Access Protocol (IMAP)
IMAP (TCP 143)

Similar to POP in that it is used to **download** electronic mail from a server. It differs from POP in that it typically **synchronizes** with the server so that the client can download the mail but have it still stored on the server. This allowed clients to retrieve their emails from multiple systems. The current implementation is IMAP4.

![image](https://github.com/ruppertaj/WOBC/assets/93789685/04b66ff6-852f-4f70-bfe7-22d7a9e92801)
imap

- [IMAP4 reference from RFC 3501](https://tools.ietf.org/html/rfc3501)

- [IMAP pcap from wireshark.org](https://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=get&target=imap.cap)



References:

https://tools.ietf.org/html/rfc3501
https://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=get&target=imap.cap


### 3.4.10 Analyze Dynamic Host Configuration Protocol (DHCP) version 4 and 6 protocol
DHCP (UDP 67/68)

Dynamic Host Configuration Protocol (DHCP) is an internet standard used to assign IP address parameters across an enterprise. This prevent administrators from having to manually assign IP configuration on each host individually. Clients communicate with the server over UDP port 67 and the server communicates with the client over UDP port 68.

- IPv4 DHCP process (D.O.R.A)

  - Discover - Sent as a L2 and L3 broadcast by the client to discover a DHCP server. Broadcast can only reach devices on the same network. If the DHCP server is not on the local network then the router must use the ip helper command to relay these requests to a centralized DHCP server.

  - Offer - Sent as a unicast to the client. The offer will contain the offered IP address configurations.

  - Request - Sent as a broadcast back to the server. This is broadcasted because the client could have received 2 or more offers. The broadcast will announce to all DHCP servers as to which offer was accepted. The client will send a gratuitous ARP to attempt to determine if the IP address is already in use.

  - Acknowledge - Final response from the server sent as a unicast to the client to confirm the lease reservation. Will contain the expiration timeframe of the lease.

- IPv6 DHCP process - Similar to the process of DHCPv4 except the names and communication methods differ.

  - Solicit - Sent to the server as a multicast.

  - Advertise - Unicast response from server.

  - Request - Multicast to the server.

  - Reply - Unicast server response.

![image](https://github.com/ruppertaj/WOBC/assets/93789685/6cfd7f29-e108-4c39-a30f-9a78dab67e38)
dhcp

- [DHCP reference from wikipedia](https://en.wikipedia.org/wiki/Dynamic_Host_Configuration_Protocol)

- [List of DHCP RFC’s](https://en.wikipedia.org/wiki/Dynamic_Host_Configuration_Protocol#IETF_standards_documents)

- [DHCP pcap from www.cloudshark.org](https://www.cloudshark.org/captures/c109b95db0af)



References:

https://en.wikipedia.org/wiki/Dynamic_Host_Configuration_Protocol
https://en.wikipedia.org/wiki/Dynamic_Host_Configuration_Protocol#IETF_standards_documents
https://www.cloudshark.org/captures/c109b95db0af
https://en.wikipedia.org/wiki/DHCPv6


#### 3.4.10.1 Explain DHCP Vulnerabilities
DHCP is a very useful protocol but is not impervious to its share of attacks and vulnerabilities.

- Rogue DHCP - (Sometimes referred to as Pineapple) - This is where a malicious person places their own DHCP server on a victim’s network. The IP address assignments will still be in the valid scope for the network but the attacker can use himself as the gateway to easily perform MitM attacks. The attacker can also assign their own DNS server address for domain to IP resolution. This means that the attacker can resolve and valid domain name to an IP address of their choosing. This can cause victims to go to the attacker’s specially crafted websites to steal credentials and other information.

- DHCP Starvation - The attacker may not want to compete with a valid DHCP server for address assignments. To ensure that their configurations are accepted they will attempt to send numerous fake DHCP requests to the valid server to exhaust their pool of addresses. This will force all users to get their IP configurations from the rogue DHCP.



References:

https://en.wikipedia.org/wiki/Rogue_DHCP

https://www.cbtnuggets.com/blog/technology/networking/what-is-a-dhcp-starvation-attack


### 3.4.11 Analyze Network Time Protocol (NTP) and vulnerability
NTP (UDP 123)

The Network Time Protocol (NTP) is a networking protocol for clock synchronization between computer systems over packet-switched, variable-latency data networks. NTP is intended to synchronize all participating computers to within a few milliseconds of Coordinated Universal Time (UTC).

- Uses stratum levels to determine the distance from the "authoritative" time source.

  - Stratum 0 - Identifies the device as the "authoritative" time source.

  - Stratum 1 - Syncs their time from Stratum 0.

  - Stratum 2 - Syncs their time from Stratum 1.

  - Stratum 3 to 15 - Follows same scheme as above. Stratum 15 is the highest level.

  - Stratum 16 - Signifies that the device is unsynchronized.



Vulnerabilities:

Time synchronization is critical for certain communications. Microsoft Active Directory uses time synchronization for all hosts in the domain. It allows for a certain margin of time error and once that is exceeded the client is "disjoined" from the domain and users can no longer log in. Other systems and protocols also use time synchronization and can easily be exploited. A malicious person can craft NTP messages in attempt to throw off the domain timing and create issues.

![image](https://github.com/ruppertaj/WOBC/assets/93789685/3847234a-dcf9-4455-92b9-0d242ac5787a)
ntp

- [NTP reference from wikipedia](https://en.wikipedia.org/wiki/Network_Time_Protocol)

- [PCAP with NTP traffic from www.cloudshark.org](https://www.cloudshark.org/captures/0983ffff2870)



References:

https://en.wikipedia.org/wiki/Network_Time_Protocol
https://www.cloudshark.org/captures/0983ffff2870


### 3.4.12 Analyze Terminal Access Controller Access-Control System Plus (TACACS+) Protocol
TACACS (TCP 49) SIMPLE/EXTENDED

The Terminal Access Controller Access-Control System Plus (TACACS+) is a network security protocol used for centralized authentication, authorization, and accounting (AAA) services in network devices such as routers, switches, and firewalls. Developed by Cisco Systems, TACACS+ provides a robust framework for controlling access to network resources and enforcing security policies.

![image](https://github.com/ruppertaj/WOBC/assets/93789685/adfe88dc-1fe0-4ab6-abfb-daa0e485155c)
tacacs s


![image](https://github.com/ruppertaj/WOBC/assets/93789685/56bd80fd-00ed-4f27-86fd-9b286414088c)
tacacs e

- [TACACS reference from wikipedia](https://en.wikipedia.org/wiki/TACACS)

- [TACACS reference from networksorcery.com](http://www.networksorcery.com/enp/protocol/tacacs.htm)

- [TACACS+ pcap from www.cloudshark.org](https://www.cloudshark.org/captures/6dc111a8f7ee)



References:

https://en.wikipedia.org/wiki/TACACS
http://www.networksorcery.com/enp/protocol/tacacs.htm
https://www.cloudshark.org/captures/6dc111a8f7ee
https://en.wikipedia.org/wiki/AAA_(computer_security)


### 3.4.13 Analyze Remote Authentication Dial-In User Service (RADIUS) protocol
RADIUS (UDP 1645/1646 AND 1812/1813)

Remote Authentication Dial-In User Service (RADIUS) is a open standard networking protocol used for centralized authentication, authorization, and accounting (AAA) services in network environments. It enables devices like network access servers (NAS), VPN gateways, and wireless access points to authenticate users and authorize their access to network resources.

![image](https://github.com/ruppertaj/WOBC/assets/93789685/f86d4b54-5b85-42a2-82a5-c8b779869ba8)
radius

- [RADIUS reference from wikipedia](https://en.wikipedia.org/wiki/RADIUS)

- [List of RADIUS RFC’s](https://en.wikipedia.org/wiki/RADIUS#Standards_documentation)

- [RADIUS pcap from www.cloudshark.org](https://www.cloudshark.org/captures/b5755ffb2e59)



References:

https://en.wikipedia.org/wiki/RADIUS
https://en.wikipedia.org/wiki/RADIUS#Standards_documentation
https://www.cloudshark.org/captures/b5755ffb2e59


### 3.4.14 Analyze Diameter Protocol
DIAMETER (TCP 3868)

![image](https://github.com/ruppertaj/WOBC/assets/93789685/1c563678-8724-47f5-8816-87af26affcd0)
Diameter Header

Diameter is a networking protocol used for Authentication, Authorization, and Accounting (AAA) functions in network systems, primarily in telecommunications networks. It is an evolution of the older RADIUS (Remote Authentication Dial-In User Service) protocol, providing enhanced features and capabilities.

Diameter protocol was develop to enhance the AAA capablities that RADIUS does not support. Such as:

- Supports application-layer acknowledgements and defines failover algorithms and the associated state machine.

- Transmission-level security support via TLS/TCP and DTLS/SCTP. Diameter can work over TCP, Stream Control Transmission Protocol (SCTP), or UDP. SCTP is recommended.

- Diameter includes support for error handling, capability negotiation, and mandatory/non-mandatory Attribute-Value Pairs (AVPs).

Header information:

- Version - field MUST be set to 1 to indicate Diameter Version 1.

- Message Length - indicates the length message including the header fields and the padded AVPs. Message Length field is always a multiple of 4.

- Command Flags - R(equest), P(roxiable), E(rror), T(Potentially retransmitted message), or r(eserved).

- Command Code - used in order to communicate the command associated with the message.

- Application ID - enables the base protocol stack to route the message to the Accounting, Authentication, or the other Diameter applications.

- Hop-by-Hop Identifier - correlates the information with the peer (next-hop or neighbor) entity.

- End-to-End Identifier - correlates the information with the endpoint for the transaction, which may be several hops away.

- AVPs - are a method of encapsulating information relevant to the Diameter message.



References:

https://datatracker.ietf.org/doc/html/rfc6733

https://en.wikipedia.org/wiki/Diameter_(protocol)


### 3.4.15 Analyze Simple Network Management Protocol (SNMP)
SNMP (UDP 161/162)

Simple Network Management Protocol (SNMP) is an Internet Standard protocol for collecting and organizing information about managed devices on IP networks. Devices that typically support SNMP include cable modems, routers, switches, servers, workstations, printers, and more.

- 3 Key SNMP Components

  - SNMP Manager - It is a centralized system used to monitor the network. It is also known as Network Management Station (NMS)

  - SNMP agent - It is a software management software module installed on a managed device. Managed devices can be network devices like PC, router, switches, servers, etc.

  - Management Information Base - MIB consists of information on resources that are to be managed. This information is organized hierarchically. It consists of objects instances which are essentially variables.

- SNMP Versions

  - SNMPv1 – This was the first implementation, operating within the structure management information specification, and described in RFC 1157. It uses community strings for authentication and UDP only.

  - SNMPv2c – This version has improved support for efficiency and error handling and is described in RFC 1901. It was first introduced in RFC 1441 and is more appropriately known as SNMP v2c. It uses community strings for authentication. It uses UDP but can be configured to use TCP.

  - SNMPv3 – This version improves security and privacy. It was introduced in RFC 3410. It uses Hash-based MAC with MD5 or SHA for authentication and DES-56 for privacy. This version uses TCP. Therefore, the higher the version of SNMP, the more secure it will be.

    - noAuthNoPriv – This (no authentication, no privacy) security level uses community string for authentication and no encryption for privacy.

    - authNopriv – This security level (authentication, no privacy) uses HMAC with MD5 or SHA for authentication and no encryption is used for privacy.

    - authPriv – This security level (authentication, privacy) uses HMAC with MD5 or SHA for authentication and encryption uses DES-56(56-bit) algorithm, 3DES(168-bit), AES(128/192/256-bit).



Vulnerabilities:

SNMP v1 and v2 traffic is sent as clear text. It also has generally weak passwords. This means that attackers can potentially sniff the network this traffic and can be used to gather sensitive information about the network and its devices. Should the passwords be compromised, the attacker can probe SNMP enabled devices for information and disable SNMP traps that would otherwise trigger when certain actions occur.

![image](https://github.com/ruppertaj/WOBC/assets/93789685/b890410d-2bdd-4889-855c-979876d68be1)
snmp

- [SNMP reference from wikipedia](https://en.wikipedia.org/wiki/Simple_Network_Management_Protocol)

- [List of NTP RFC’s](https://en.wikipedia.org/wiki/Simple_Network_Management_Protocol#RFC_references)

- [SNMP pcap from www.cloudshark.org](https://www.cloudshark.org/captures/83a12fe184ff)



References:

https://en.wikipedia.org/wiki/Simple_Network_Management_Protocol
https://en.wikipedia.org/wiki/Simple_Network_Management_Protocol#RFC_references
https://www.cloudshark.org/captures/83a12fe184ff


### 3.4.16 Analyze Real-time Transport Protocol (RTP)
RTP (UDP any above 1023)

![image](https://github.com/ruppertaj/WOBC/assets/93789685/62fa3c21-7d3d-4d6a-a8c8-2ae067fd236c)
rtp

RTP (Real-time Transport Protocol) is primarily used for streaming real-time media over IP networks. It is a protocol specifically designed for transmitting audio and video data in a way that supports time-sensitive applications, such as voice and video communication, streaming media, and live broadcasts.

- Voice over IP (VoIP): RTP is widely used in VoIP applications to transport real-time voice data packets over IP networks. It works in conjunction with protocols like SIP (Session Initiation Protocol) to enable voice communication over the internet.

- Video Conferencing: RTP forms the basis of video conferencing systems, allowing participants to transmit and receive real-time video streams during live meetings or conferences.

- Streaming Media: RTP is commonly used for streaming media services, such as online video streaming platforms, live broadcasts, and webinars. It facilitates the efficient transmission of video and audio data to multiple clients in real-time.

- IPTV (Internet Protocol Television): RTP is used in IPTV systems to deliver television content over IP networks, enabling users to stream television programs and video-on-demand services over the internet.

- Multimedia Applications: RTP is utilized in various multimedia applications, including gaming, remote monitoring, video surveillance, and interactive multimedia services. It provides a reliable and efficient transport mechanism for transmitting time-sensitive media data.

- Real-time Data Transmission: RTP can be used for real-time data transmission scenarios where timely delivery is crucial. For example, it may be employed in sensor networks, control systems, or any application that requires the transmission of real-time data streams.

  - [RTP reference from wikipedia](https://en.wikipedia.org/wiki/Real-time_Transport_Protocol)

  - [List of RTP RFC’s](https://en.wikipedia.org/wiki/Real-time_Transport_Protocol#Standards_documents)

  - [RTP pcap from wireshark.org](https://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=get&target=sip-rtp-dvi4.pcap)



References:

https://en.wikipedia.org/wiki/Real-time_Transport_Protocol
https://en.wikipedia.org/wiki/Real-time_Transport_Protocol#Standards_documents
https://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=get&target=sip-rtp-dvi4.pcap


### 3.4.17 Analyze Remote Desktop Protocol (RDP)
RDP (TCP 3389)

Developed by Microsoft to offer remote access to a computer’s desktop GUI as if they was physically at the system rather than just a command-line interface.

The protocol is widely supported across most Windows, Unix, Linux, and macOS operating systems. Other proprietary options were developed to provide remote desktop support but the administrator typically must install the client software on each device before being able to remotely access devices with these 3rd party tools.

![image](https://github.com/ruppertaj/WOBC/assets/93789685/320d08a0-afa8-4781-9e33-4882cbf2ca40)
rdp

- [RDP reference from wikipedia](https://en.wikipedia.org/wiki/Remote_Desktop_Protocol)

- [RDP reference material from Microsoft](https://docs.microsoft.com/en-us/windows/win32/termserv/remote-desktop-protocol)

- [RDP references from wireshark](https://wiki.wireshark.org/RDP) (This includes PCAPS)



References:

https://en.wikipedia.org/wiki/Remote_Desktop_Protocol
https://docs.microsoft.com/en-us/windows/win32/termserv/remote-desktop-protocol
https://wiki.wireshark.org/RDP
https://blog.netop.com/what-to-know-about-rdp-vulnerability


### 3.4.18 Analyze Kerberos
Kerberos (UDP 88)

Kerberos is a network authentication protocol that ensures secure authentication for client-server applications. It was created by MIT as a network authentication protocol using secret-key cryptography. It relies on a trusted Key Distribution Center (KDC) server.

Here’s a simplified explanation of the Kerberos process:

- Authentication Request:

  - The client sends an authentication request to the KDC, providing its identity (username) and the desired server’s identity (service principal name).

- Ticket Granting Ticket (TGT) Request:

  - The KDC verifies the client’s identity and issues a TGT if the credentials are valid.

  - The TGT is encrypted using the client’s password or a shared secret key.

- TGT Issuance:

  - The KDC sends the encrypted TGT to the client, which stores it securely.

- Service Ticket Request:

  - When the client wants to access a specific service, it requests a Service Ticket (ST) for that service from the KDC.

  - The request includes the TGT and the desired service’s identity.

- ST Issuance:

  - The KDC verifies the TGT and issues an ST for the requested service if the TGT is valid.

  - The ST is encrypted using a session key shared between the client and the service.

- Service Access:

  - The client presents the ST to the service, proving its authenticity and intent to access the service.

  - The service decrypts the ST using the session key and verifies its validity.

  - If the ST is valid, the service grants access to the client.

Kerberos utilizes symmetric key cryptography for secure ticket encryption and decryption, ensuring data confidentiality and integrity. It also supports mutual authentication between the client and server.

Kerberos is widely used in enterprise environments, particularly in Microsoft Windows with Active Directory. It ensures secure authentication and access to network resources while protecting against unauthorized access and replay attacks.



References:

https://datatracker.ietf.org/doc/html/rfc4120
https://en.wikipedia.org/wiki/Kerberos_(protocol)


### 3.4.19 Analyze Lightweight Directory Access Protocol (LDAP)
LDAP (TCP 389 and 636)

The Lightweight Directory Access Protocol (LDAP) is an application protocol used for accessing and managing distributed directory information services. LDAP provides a standardized method for querying, modifying, and authenticating against directory services, such as Active Directory and OpenLDAP.

LDAPS (LDAP over SSL/TLS) is a secure communication protocol used to encrypt LDAP traffic between LDAP clients and servers. It provides a layer of security to LDAP authentication and directory access by encrypting data exchanged over the network, protecting it from eavesdropping and tampering.

- LDAP provides access to distributed directory services that act in accordance with X.500 data and service models. These protocol elements are based on those described in the X.500 Directory Access Protocol (DAP).

- LDAP as an authentication service follows the client/server model. The LDAP model has two main steps when a user requests non-TLS bind authentication. These are (in order):

  1. TCP three-way handshake (SYN, SYN/ACK, ACK)

  2. LDAP bind() function (performed synchronous or asynchronous)

LDAP:

1. LDAP (unencrypted): TCP Port 389

2. LDAPS (LDAP over SSL/TLS): TCP Port 636

3. follows a client-server model, where LDAP clients send requests to directory servers, which in turn provide responses.

4. hierarchical data stores that organize and store structured information, such as user profiles, organizational units, and network resources.

5. uses a directory schema to define the structure and attributes of directory entries, allowing for flexible data modeling.

6. supports various operations, including search, add, modify, delete, and bind (authentication).

7. uses a string-based query language called the LDAP Data Interchange Format (LDIF) to search and retrieve data from directory servers.

  -  LDAP servers are vulnerable from DoS attacks (SYN Flooding) and protecting user passwords from being discovered over a network.

[LDAP Vulnerabilities](https://www.scirp.org/pdf/JIS20110400007_36476949.pdf)



References:

https://datatracker.ietf.org/doc/html/rfc4511
https://en.wikipedia.org/wiki/Lightweight_Directory_Access_Protocol
https://www.scirp.org/pdf/JIS20110400007_36476949.pdf
