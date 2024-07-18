# 6.0 Outcomes
- Describe Network Traffic Sniffing
  - Explain the capture Libraries
  - Describe the use of sniffing tools and methods
  - Check on Learning

- Perform real-time network traffic sniffing
  - Explain TCPDUMP primitives
  - Define the function of a Berkley packet filter (BPF)
  - Compare primitives and BPFs
  - Construct a BPF
  - Use a BPF to filter packets entering a network interface
  - Understand Wireshark’s use of BPFs
  - Describe passive OS fingerprinting (p0f)
  - Use p0f to capture packets
  - Check on Learning



TCPdump, Wireshark, and Berkeley Packet Filters (BPF) are indispensable tools in the arsenal of cybersecurity professionals, offering powerful capabilities for network traffic analysis, monitoring, and troubleshooting. TCPdump, a command-line packet analyzer, provides real-time packet capture and analysis capabilities, allowing users to inspect network traffic on the fly. It is invaluable for diagnosing network issues, identifying suspicious activity, and capturing packets for further analysis. Wireshark, a graphical network protocol analyzer, builds upon TCPdump’s functionality by offering a user-friendly interface and advanced features such as packet visualization, protocol decoding, and packet filtering. Wireshark enables cybersecurity professionals to conduct in-depth analysis of network traffic, dissecting protocols, detecting anomalies, and uncovering potential security threats. Additionally, Wireshark’s extensibility through plugins and scripting allows for custom analysis and integration with other security tools.

Berkeley Packet Filters (BPF) are a low-level mechanism used by TCPdump and Wireshark to filter and capture packets efficiently at the kernel level. BPF filters allow users to specify criteria for capturing packets, such as source or destination IP addresses, port numbers, or protocol types. By leveraging BPF filters, cybersecurity professionals can focus on relevant network traffic, reducing the volume of data captured and improving analysis efficiency. BPF filters also play a crucial role in optimizing performance and scalability, ensuring that packet capture operations can keep pace with high-speed networks and large traffic volumes.

In summary, TCPdump, Wireshark, and Berkeley Packet Filters are essential tools for cybersecurity professionals, providing comprehensive capabilities for network traffic analysis, monitoring, and troubleshooting. By leveraging these tools, cybersecurity professionals can gain insights into network behavior, detect and investigate security incidents, and enhance overall network security posture.


## 6.1 Describe Network Traffic Sniffing
Traffic sniffing can be used interchangeably with terms like Packet sniffers or packet analyzers. It is the process of gathering, collecting, and capturing raw signals on a network medium like twisted Pair, fiber, or Wireless. Packets that are not encrypted can be reassembled and read. This process however is limited to only the traffic that can be seen from the collector device. Traffic not on the same shared network segment cannot be captured. Traffic can be diverted to the collector device by using devices like Taps, SPAN, software agents, or MitM attacks.


### 6.1.1 Explain the capture Libraries
Packets sent and received from a computer system are not able to be analyzed independently outside the operating system. Libpcap was developed as part of TCPDUMP in 1999 by Network Research Group at Lawrence Berkeley Laboratory for use with UNIX and Linux-based systems. This Libpcap library allowed users to capture packets that run over a network directly from their NICs. This innovation enabled developers to create applications to decode, display and log intercepted packets. Libpcap was soon made modular allow other packet capture programs to use it.

Packet Capture Libraries:

- Libpcap - https://www.tcpdump.org/ Libpcap is a portable C/C++ library that is used by Wireshark and TCPDump for network traffic capture. It is installed by default on Linux, BSD, and OS X. It is still being regularly updated and the updates can be tracked on its homepage. Windows uses a similar library named WinPcap that is not installed by default, which is why it must be installed during the Wireshark installation process on a Windows-based PC.

- WinPcap - https://www.winpcap.org/ Libpcap was ported over from its Linux/Unix roots by Riverbed Technology to be compatible with Windows-based systems. Has been the standard for Windows base systems for many years. On 8 March 2013, the final release (4.1.3) was released and all support ceased.

- NPcap - https://nmap.org/npcap/ With the ceased support for the discontinued WinPcap, the makers of NMAP created NPcap. Based on WinPcap, it is still supported today as a limited release. It does offer improvements over its WinPcap predecessor in terms of speed, portability, security, and efficiency.



References:

https://www.tcpdump.org/

https://www.winpcap.org/

https://nmap.org/npcap/


### 6.1.2 Describe the use of sniffing tools and methods
- Packet sniffing has many practical uses today such as:
  - Network troubleshooting
  - Diagnosing improper routing or switching
  - Identifying port/protocol misconfigurations
  - Monitor networking consumption
  - Intercepting usernames and passwords
  - Intercept and eavesdrop on network communications

- Disadvantages of Packet sniffing:
  - Requires elevated permissions on capture systems.
  - Can only capture packets that the NIC can see. Today, most networks are built with modern switches and routers that segment network traffic into separate collision and broadcast domains.
  - Only unencrypted traffic can be seen, read, and manipulated. Although some protocol analyzers allow you to decrypt this traffic if you have the encryption keys.
  - Cannot capture traffic sent locally on the system because they go thru the internal loopback.
  - Can consume massive amounts of local storage depending on how busy the network is and capture filters applied.
  - Busy networks can have packet capture loss due to the NIC or CPU limitations of the collector.


#### 6.1.2.1 Packets can be captured in two ways:
- Hardware Packet Sniffers - In the past, the process of traffic sniffing was typically done by using hardware devices because the act of capturing packets was too intensive for computers. It is a purpose-built device that is plugged into a network segment to collect and store network packets. Packets are forwarded to a separate system for further analysis. With the improvement of computer CPUs, stand-alone hardware-based sniffers are rarely used anymore.

- Software Packet Sniffers - remaining packet sniffers will fall into this category. The local system is used to collect the packets and the software then provides immediate analysis. Software-based sniffers rely on the network interface card (NIC) in the host system to pass traffic to the OS. NICs are set into one of two modes:

  - Non-promiscuous: Default for most NICs. NIC will only process traffic destined for its host MAC address. Multicast MAC address groups and broadcast addresses are also received and processed.

  - Promiscuous: Requires root/kernel permissions to enable. The NIC receives and processes all traffic. Most operating systems can support promiscuous mode. Support can be limited by the NIC hardware and/or drivers.


#### 6.1.2.2 Describe Socket Types


- Understanding socket types for network functions
  - User Space Sockets:

    - Stream socket - Normally used with TCP, SCTP, and Bluetooth. A stream socket provides a connection-oriented and sequenced flow of data which has methods for establishment and teardown of connections as well as error detection.

    - Datagram socket - Normally used with UDP. A datagram socket is connection-less by nature. Sockets built this way can send and receive data, but there is no mechanism to retransmit data if a packet is dropped.
    - Examples:
      - Using a User application such as a Web Browser, FTP, Telnet, SSH, netcat, etc to connect to any listening port.

```
nc 10.0.0.1 22
firefox http://10.0.0.1
wget -r http://10.0.0.1
curl ftp://10.0.0.1
ftp 10.0.0.1
telnet 10.0.0.1
ssh user@10.0.0.1

```

      - Using tcpdump or wireshark to read a file

```
tcpdump -r capture.pcap
```

      - Using nmap with no switches (-sS) or -sT

```
nmap 10.0.0.1
nmap -sT 10.0.0.1
```

      - Opening listening ports above the Well-Known range (1024+)

```
python -m SimpleHTTPServer 7800
nc -lvp 1234
```

      - Using /dev/tcp or /dev/udp to transmit data

```
cat /etc/passwd > /dev/tcp/10.0.0.1/1234
```

  - Kernel Space Sockets:
    - Raw socket - A raw socket allows for the direct sending and receiving of IP packets without automatic protocol-specific transport layer formatting, meaning that all headers are typically included in the packet and not removed when moving up the network stack.

      - Raw sockets tend to be specially crafted packets that do not follow normal communication methods.

      - Any traffic that does not have a transport layer header (TCP/UDP) can be a RAW Socket.

        - icmp - ping

        - OSPF

        - EIGRP

      - Packets that have to be crafted with various flag combinations and other header field manipulation must be created as RAW Sockets. Tools like HPING and Nmap needs to open raw sockets when attempting to set specific flags for performing certain scans.

```
nmap -sX 10.0.0.1
nmap -sN 10.0.0.1
nmap -sF 10.0.0.1
```
      - Tcpdump requires raw sockets in order to receive each packet, in its entirety, for total packet analysis. The operating system normally strips all the headers when receiving data so to examine these packets with their headers intact they have to be captured as RAW Sockets.

```
tcpdump -w capture.pcap
```
      - Using Scapy to craft or modify a packet for transmission

      - Using Python to craft or modify Raw Sockets for transmission

    - Opening well ports in the Well-Known range (0-1023) require kernel access.

```
python -m SimpleHTTPServer 80
nc -lvp 123

```

Instructor Note
Demonstrate these as needed for clarification.


#### 6.1.2.3 Capture Library (Image)

![image](https://github.com/ruppertaj/WOBC/assets/93789685/4858f75d-f04e-4577-9dcc-f37ce89798cc)
Figure 1. LibPcap


1. Data is captured off the 'wire' by a NIC in promiscuous mode.

2. Data is constructed into "Raw Sockets". This means that each 'packet' is captured in its original state with all its headers intact. This is not the typical operation of computers as they normally strip off the headers.

3. The Raw Sockets are then sent through the SO_ATTACH_FILTER or SO_ATTACH_BPF file to determine what messages need to be captured. This file is stored in Kernel-space and is a list of 'conditions' supplied by the root user to determine what traffic to capture or what traffic to "filter".

  a. Reference from https://man7.org/linux/man-pages/man7/socket.7.html
```
SO_ATTACH_FILTER (since Linux 2.2), SO_ATTACH_BPF (since Linux 3.19)
Attach a classic BPF (SO_ATTACH_FILTER) or an extended BPF (SO_ATTACH_BPF) program to the socket for use as a filter of incoming packets.
A packet will be dropped if the filter program returns zero.
If the filter program returns a nonzero value which is less than the packet's data length, the packet will be truncated to the length returned.
If the value returned by the filter is greater than or equal to the packet's data length, the packet is allowed to proceed unmodified.
```
4. The traffic that has passed through the filter is then captured by the LibPcap Library and is forwarded into the user-space application to "parse" the data into a readable format for the user.



References:

https://man7.org/linux/man-pages/man7/socket.7.html


#### 6.1.2.4 Types of sniffing
- Active sniffing – Traffic is not only captured but can be manipulated or altered in some way for a network attack.

  - Passive sniffing involves monitoring network traffic without actively injecting or modifying packets. It typically uses network monitoring tools or packet capture software to capture packets as they traverse the network. Passive sniffing is often used for network troubleshooting, security monitoring, and performance analysis.

  - Some examples of attacks that employ Active sniffing are:

    - MAC Flooding

    - DHCP Attacks

    - DNS Poisoning

    - Spoofing Attacks

    - ARP Poisoning

- Passive sniffing – Traffic is captured and not modified. This is the most common method of packet sniffing.

  - Active sniffing involves actively injecting packets into the network to elicit responses from other devices. Unlike passive sniffing, active sniffing requires the sniffer to send packets to specific destinations and analyze the responses. Active sniffing can be more intrusive and may raise security concerns, but it can also provide more detailed insights into network behavior.

  - Several applications that send data in clear text are vulnerable to this type of sniffing:

    - HTTP

    - SMTP

    - NNTP

    - FTP

    - POP

    - IMAP

    - TELNET

    - DNS


#### 6.1.2.5 Popular Software Packet Capture Programs
Here are several popular packet capture tools and applications used today to sniff and capture network packets.

- tcpdump (https://www.tcpdump.org/)

- Wireshark (https://www.wireshark.org/)

- tshark (https://www.wireshark.org/docs/man-pages/tshark.html)

- p0f (https://github.com/p0f/p0f) - passive OS fingerprinting tool

- NetworkMiner (https://www.netresec.com/?page=NetworkMiner)

- NetMiner (http://www.netminer.com/product/overview.do)

- SolarWinds Network Performance Monitor (https://www.solarwinds.com/network-performance-monitor)

- BetterCap (https://www.bettercap.org/)

- EtterCap (https://www.ettercap-project.org/)

- Paessler PRTG Network Monitor (https://www.paessler.com/packet_capture)

- ManageEngine NetFlow Analyzer (https://www.manageengine.com/products/netflow/)

- Savvius Omnipeek (https://www.liveaction.com/products/omnipeek-network-protocol-analyzer/)

- Telerik Fiddler (https://www.telerik.com/fiddler)

- Colasoft Capsa (https://www.colasoft.com/capsa-free/)

- Snort (https://www.snort.org/)


#### 6.1.2.6 Other packet Capture Programs
There are many other tools and applications that utilize the packet capture libraries with more being developed on the time. Below are several ones of note.

- Kismet (https://www.kismetwireless.net/) - packet sniffer for 802.11 wireless LANs

- L0phtCrack (https://www.l0phtcrack.com/) - password auditing and recovery application.

- McAfee ePolicy Orchestrator (https://www.mcafee.com/enterprise/en-us/products/epolicy-orchestrator.html)

- ngrep (https://github.com/jpr5/ngrep) - network capture tool similar to tcpdump

- Nmap (https://nmap.org/) - has port scanning and OS fingerprinting features

- Scapy (https://scapy.net/) - packet crafting tool built with python and can sniff packets

- Snort (https://www.snort.org/) - IDS/IPS

- Suricata (https://suricata-ids.org/) - IDS/IPS


#### 6.1.2.7 Understanding Linux Network Interface Naming Standards
- Traditional Naming Scheme:

  - Usage:

    - Older versions of Linux distributions often used the traditional naming scheme by default.

    - This includes distributions like CentOS 6 and earlier, Debian 8 (Jessie) and earlier, Ubuntu 14.04 (Trusty Tahr) and earlier, and so on.

    - Some users or administrators might still prefer to use the traditional naming scheme even in newer distributions due to familiarity or specific requirements.

  - In this scheme, network interfaces are named using the following conventions:

    - ethX: Ethernet devices are typically named ethX, where X is a number. For example, eth0, eth1, etc.

    - wlanX: Wireless LAN devices are named wlanX, where X is a number.

    - pppX: Point-to-Point Protocol devices are named pppX, where X is a number.

    - tunX or tapX: TUN/TAP devices are named tunX or tapX, where X is a number.
```
student@blue-internet-host-student:~$ ip address
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1450 qdisc pfifo_fast state UP group default qlen 1000
    link/ether fa:16:3e:53:fb:d3 brd ff:ff:ff:ff:ff:ff
    inet 10.10.0.40/27 brd 10.10.0.63 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::f816:3eff:fe53:fbd3/64 scope link
       valid_lft forever preferred_lft forever
```

- Consistent Network Device Naming:

  - Usage:

    - Many modern Linux distributions have transitioned to using predictable interface naming schemes by default, especially in recent releases.

    - This includes distributions like CentOS 7 and later, Debian 9 (Stretch) and later, Ubuntu 16.04 (Xenial Xerus) and later, Fedora, Arch Linux, and others.

    - Predictable naming schemes are designed to provide more consistent and understandable names for network interfaces, which can be particularly useful in environments with dynamic hardware configurations or virtualization.

  - This scheme was introduced to address the issues with the traditional naming scheme, especially in modern systems where interfaces might be dynamically added or removed. It aims to provide more consistent and predictable interface names. The most common predictable interface naming convention is based on the following attributes:

  - All names start with a two-character prefix that signifies the interface type.

    - en = Ethernet

    - ib = InfiniBand

    - sl = Serial line IP (slip)

    - wl = Wireless local area network (WLAN)

    - ww = Wireless wide area network (WWAN)

  - Naming Schemes Hierarchy

    - By default, systemd will name interfaces using the following policy to apply the supported naming schemes:

      - Scheme 1: Names incorporating Firmware or BIOS provided index numbers for on-board devices (example: eno1), are applied if that information from the firmware or BIOS is applicable and available, else falling back to scheme 2.

        - enoX: Ethernet interfaces embedded on the motherboard, where X is a number.

      - Scheme 2: Names incorporating Firmware or BIOS provided PCI Express hotplug slot index numbers (example: ens1) are applied if that information from the firmware or BIOS is applicable and available, else falling back to scheme 3.

        - ensX: Ethernet interfaces on add-on cards, where X is a number.

      - Scheme 3: Names incorporating physical location of the connector of the hardware (example: enp2s0), are applied if applicable, else falling directly back to scheme 5 in all other cases.

        - enpXsY: PCI network interfaces, where X is the bus number and Y is the slot number.

      - Scheme 4: Names incorporating interface’s MAC address (example: enx78e7d1ea46da), is not used by default, but is available if the user chooses.

      - Scheme 5: The traditional unpredictable kernel naming scheme, is used if all other methods fail (example: eth0).
```
student@lin-ops:~$ ip address
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
2: ens3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1450 qdisc fq_codel state UP group default qlen 1000
    link/ether fa:16:3e:c5:0a:7f brd ff:ff:ff:ff:ff:ff
    inet 192.168.65.20/27 brd 192.168.65.31 scope global dynamic ens3
       valid_lft 80605sec preferred_lft 80605sec
    inet6 fe80::f816:3eff:fec5:a7f/64 scope link
       valid_lft forever preferred_lft forever
```

References:

https://man7.org/linux/man-pages/man7/systemd.net-naming-scheme.7.html

https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/networking_guide/ch-consistent_network_device_naming

https://en.wikipedia.org/wiki/Consistent_Network_Device_Naming


## 6.2 Perform real-time network traffic sniffing


### 6.2.1 Explain TCPDUMP primitives
TCPDump is a tool used to capture and display the contents of packets traversing a network interface. TCPDump can use one or more native (primitives) and/or BPF filters. Filters allow you to search for patterns, ASCII, or HEX within a data packet and dissect a pcap to obtain a packet or packets of interest. TCPDump filters can be crafted to be broad to search for any packets that match a specific protocol. It can also be crafted to be very specific, such as filters for a TTL size, flag combinations, and keywords within a packet.


#### 6.2.1.1 TCPDUMP Primitive Qualifiers
TCPDUMP breaks down its filters into three (3) different capture qualifiers:

- type - specifies the 'kind of thing' that the id name or number refers to.

  - Possible types are:

    - host

    - net

    - port

    - portrange

  - Examples: `host 192.168.1.1`, `net 192.168.1.0/24`, `port 22`, `portrange 1-1023`. If there is no type qualifier, host is assumed.

- dir - specifies a particular transfer direction to and/or from id.

  - Possible directions are:

    - src

    - dst

    - src or dst

    - src and dst

    - ra

    - ta

    - addr1, addr2, addr3, and addr4.

  - Examples: `src 192.168.1.1`, `dst net 192.168.1.0/24`, `src or dst port ftp-data`. If there is no dir qualifier, `src or dst` is assumed. The ra, ta, addr1, addr2, addr3, and addr4 qualifiers are only valid for IEEE 802.11 Wireless LAN link layers.

- proto - restricts the match to a particular protocol(s).

  - Possible protos are: ether, fddi, tr, wlan, ip, ip6, icmp, icmp6, arp, rarp, decnet, tcp and udp.

  - Examples:

    - `ether src 192.168.1.1`

    - `arp net 192.168.1.0/24`

    - `tcp port 22`

    - `udp portrange 1-1023`

    - `wlan addr2 0:2:3:4:5:6`

  - If there is no proto qualifier, all protocols consistent with the type are assumed.

  - Examples: `src 192.168.1.1` means `(ip or arp or rarp) src 192.168.1.1`, `net 192.168.1.0/24` means `(ip or arp or rarp) net 192.168.1.0/24` and `port 53' means `(tcp or udp) port 53`.



References:

Source: https://www.tcpdump.org/manpages/pcap-filter.7.html

TCPDUMP Cheat Sheet from Packetlife.net https://packetlife.net/media/library/12/tcpdump.pdf


#### 6.2.1.2 Basic TCPDump options
- `-A` Prints the frame payload in ASCII.
```
tcpdump -A
```
- `-D` Print the list of the network interfaces available on the system and on which TCPDump can capture packets. For each network interface, a number and an interface name, followed by a text description of the interface, is printed. This can be used to identify which interfaces are available for traffic capture.
```
tcpdump -D
```
- `-i` Normally, eth0 will be selected by default if you do not specify an interface. However, if a different interface is needed, it must be specified.

tcpdump -i eth0
- `-e` Prints Data-Link Headers. Default is to print the encapsulated protocol only.
```
tcpdump -e
```
- `-X` displays packet data in HEX and ASCII.
- **`-XX` displays the packet data in HEX and ASCII to include the Ethernet portion.**
```
tcpdump -i eth0 -X
tcpdump -i eth0 -XX
```
- `-w` writes the capture to an output file
```
tcpdump -w something.pcap
```
- `-r` reads from the pcap
```
tcpdump -r something.pcap
```
- `-v` gives more verbose output with details on the time to live, IPID, total length, options, and flags. Additionally, it enables integrity checking.
```
tcpdump -vv
```
- `-n` Does not covert protocol and addresses to names
```
tcpdump -n
```

Tcpdump for specific protocol traffic.
```
tcpdump port 80 -vn
```

```
sudo tcpdump -rn /home/activity_resources/pcaps/BPFCheck.pcap 'ip[6] == 0xoaob' | wc -l
```

#### 6.2.1.3 Logical Operators
TCPDump can be used for live traffic capture, that much is apparent. Introducing filters with simple logic operators greatly enhances TCPDump’s capabilities. The truth table below represents all possible true-false relationships. Since both && and || each has two operands, there are four possible combinations of conditions for the given variables A or B.

- Primitives may be combined using:

  - Concatenation: 'and' (&&)

  - Alteration: 'or' (||)

  - Negation: 'not' (!)


```
Table 1. Logical Operators AND (&&) and OR (||)
Operand 1	Operand 2	Operand 1 AND Operand 2	    Operand 1 OR Operand 2
TRUE            TRUE            TRUE                        TRUE
TRUE            FALSE           FALSE                       TRUE
FALSE           TRUE            FALSE                       TRUE
FALSE           FALSE           FALSE                       FALSE
```

```
Table 2. Logical Operator NOT (!)
Operand	        Result
FALSE           TRUE
TRUE            FALSE
```

```
Table 3. Relational Operators
Operator	       Meaning
<                      less than
<=                     less than or equal to
>                      greater than
>=                     greater than or equal to
==                     equal to
!=                     not equal to
```


The logical and relational operators can be combined with primitives to perform specific criteria for traffic filtering.



tcpdump for specific protocol traffic of more than one type.
```
tcpdump port 80 or 22 -vn
```

tcpdump for a range of ports on 2 different hosts with a destination to a specific network
```
tcpdump portrange 20-100 and host 10.1.0.2 or host 10.1.0.3 and dst net 10.2.0.0/24 -vn
```

tcpdump filter for source network 10.1.0.0/24 and destination network 10.3.0.0/24 or dst host 10.2.0.3 and not host 10.1.0.3.
```
tcpdump "(src net 10.1.0.0/24  && (dst net 10.3.0.0/24 || dst host 10.2.0.3) && (! dst host 10.1.0.3))"" -vn
```


#### 6.2.1.4 TCPDump Primitive Examples
Simple:

- To print all ethernet traffic:
```
tcpdump ether
```

- To print all packets related to ARP:
```
tcpdump arp
```

- To print all packets related to ICMP:
```
tcpdump icmp
```

- To print all ICMP echo-request packets :
```
tcpdump 'icmp[icmptype] = icmp-echo'
```

- To print all ICMP echo-reply packets :
```
tcpdump 'icmp[icmptype] = icmp-reply'
```

- To print all packets arriving at or departing from 192.168.1.1:
```
tcpdump host 192.168.1.1
```

- To print all packets arriving at 192.168.1.1:
```
tcpdump dst host 192.168.1.1
```

- To print all packets departing from 192.168.1.1:
```
tcpdump src host 192.168.1.1
```

- To print all packets arriving at or departing from 192.168.1.0/24 network:
```
tcpdump net 192.168.1.0/24
```

- To print all packets departing from 192.168.1.0/24 network:
```
tcpdump src net 192.168.1.0/24
```

- To print all packets arriving at 192.168.1.0/24 network:
```
tcpdump dst net 192.168.1.0/24
```

- To print all packets related to IPv4:
```
tcpdump ip
```

- To print all packets related to IPv6:
```
tcpdump ip6
```

- To print all packets related to TCP:
```
tcpdump tcp
```

- To print all packets related to UDP:
```
tcpdump udp
```

- To print all packets arriving at or departing from TCP port 22:
```
tcpdump tcp port 22
```

- To print all packets arriving at TCP port 22:
```
tcpdump tcp dst port 22
```

- To print all packets departing from TCP port 22:
```
tcpdump tcp src port 22
```

- To print all packets arriving at or departing from TCP or UDP port 53:
```
tcpdump port 53
```

- To print all packets with TCP flag ACK set:
```
'tcp[tcpflags] = tcp-ack'
```

Complex:

- To print traffic between 192.168.1.1 and either 10.1.1.1 or 10.1.1.2:
```
tcpdump host 192.168.1.1 and \( 10.1.1.1 or 10.1.1.2 \)
```

- To print all IP packets between 10.1.1.1 and any host except 10.1.1.2:
```
tcpdump ip host 10.1.1.1 and not 10.1.1.2
```

- To print all traffic between local hosts and hosts at Berkeley:
```
tcpdump net ucb-ether
```

- To print all ftp traffic through internet gateway 192.168.1.1: (note that the expression is quoted to prevent the shell from (mis-)interpreting the parentheses):
```
tcpdump 'gateway 192.168.1.1 and (port ftp or ftp-data)'
```

- To print traffic neither sourced from nor destined for local hosts (if you gateway to one other net, this stuff should never make it onto your local net).
```
tcpdump ip and not net localnet
```

- To print the start and end packets (the SYN and FIN packets) of each TCP conversation that involves a non-local host.
```
tcpdump 'tcp[tcpflags] & (tcp-syn|tcp-fin) != 0 and not src and dst net localnet'
```

- To print the TCP packets with flags RST and ACK both set. (i.e. select only the RST and ACK flags in the flags field, and if the result is "RST and ACK both set", match)
```
tcpdump 'tcp[tcpflags] & (tcp-rst|tcp-ack) == (tcp-rst|tcp-ack)'
```

- To print all IPv4 HTTP packets to and from port 80, i.e. print only packets that contain data, not, for example, SYN and FIN packets and ACK-only packets. (IPv6 is left as an exercise for the reader.)
```
tcpdump 'tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)'
```

- To print IP packets longer than 576 bytes sent through gateway 192.168.1.1:
```
tcpdump 'gateway 192.168.1.1 and ip[2:2] > 576'
```

- To print IP broadcast or multicast packets that were not sent via Ethernet broadcast or multicast:
```
tcpdump 'ether[0] & 1 = 0 and ip[16] >= 224'
```

- To print all ICMP packets that are not echo requests/replies (i.e., not ping packets):
```
tcpdump 'icmp[icmptype] != icmp-echo and icmp[icmptype] != icmp-echoreply'
```

References:

https://linux.die.net/man/8/tcpdump

https://www.tcpdump.org/matcpdump -dnpages/pcap-filter.7.html

http://alumni.cs.ucr.edu/~marios/ethereal-tcpdump.pdf

https://www.cyberciti.biz/howto/question/man/tcpdump-man-page-with-examples.php

https://packetlife.net/media/library/12/tcpdump.pdf


#### 6.2.1.5 Verify TCPDUMP Primitive and BPF filters
When you run tcpdump -d, it takes the filter expression you provided, compiles it into BPF code, and then prints the compiled BPF code to the standard output. This allows you to see the low-level representation of the filter expression and understand how tcpdump processes and filters packets based on that expression.

-  `tcpdump -d "<expression>"`

  - Dump the compiled packet-matching code in a human readable form to standard output and stop.

  - Please mind that although code compilation is always DLT-specific, typically it is impossible (and unnecessary) to specify which DLT to use for the dump because tcpdump uses either the DLT of the input pcap file specified with -r, or the default DLT of the network interface specified with -i, or the particular DLT of the network interface specified with -y and -i respectively.

  - In these cases the dump shows the same exact code that would filter the input file or the network interface without -d.

  - However, when neither -r nor -i is specified, specifying -d prevents tcpdump from guessing a suitable network interface (see -i).

  - In this case the DLT defaults to EN10MB and can be set to another valid value manually with -y.

- Instruction Format: Each instruction consists of several parts:

  - `(xxx)`: Instruction number. Starting at (000) and incrementing until complete.

  - `instruction [offset]`: The offset indicates the position of the packet header field being examined or modified. It specifies the starting byte of the field within the packet header.

  - `instruction [#value]`: Operation to be performed on the packet data.

    - Instructions:

      - `ldh`: Load half-word. It loads a 16-bit (2-byte) value from the specified offset.

        - `ldh [20]`: Load a Half-Word (2 bytes) starting at byte 20 (20 and 21) from start of packet.

      - `ldb`: Load byte. It loads an 8-bit (1-byte) value from the specified offset.

        - `ldb [23]`: Load a byte at byte 23 from start of packet.

      - `jeq`: Jump if equal. It compares the loaded value with a specified constant value and jumps to the specified location if they are equal.

        - `jeq #0x800`: Jump if equal to the hexadecimal value 0x800.

        - `jeq #0x50`: Jump if equal to the hexadecimal value 0x50.

      - `jt (xxx)`: Jump to if true. Goto instruction number specified.

        - `jeq #0x6 jt 11 jf 19`: If value equals 0x06 then jump to line 11. If not then goto line 19.

      - `jf (xxx)`: Jump to if false. Goto instruction number specified.

        - `jeq #0x86dd jt 2 jf 8`: If value equals 0x86dd then jump to line 2. If not then goto line 8.

      - `jset [bit wise mask]`: Jump if set. If the offset contains any value.

        - `jset #0x1fff jt 19 jf 13`: If the value of the last 13 bits in this half-word contain any value then jump to line 19. If not then goto line 13.

      - `ldxb [formula]`: Discover value of x.

        - `ldxb 4*([14]&0xf)`: X will equal the value of the lower half of byte 14 multiplied by 4.

      - `ret [#value]`: Return. It specifies the action to be taken if the filter matches or does not match the packet.

        - `ret #65535`: Return with the value 65535, indicating a match.

        - `ret #0`: Return with the value 0, indicating no match.



- Primitive to find "arp":
```
root@linux-opstation-pysn:~# tcpdump -d arp
(000) ldh      [12]
(001) jeq      #0x806           jt 2 jf 3
(002) ret      #262144
(003) ret      #0
```

- BPF to find "arp":
```
root@linux-opstation-pysn:~# tcpdump -d ether[12:2]=0x0806
(000) ldh      [12]
(001) jeq      #0x806           jt 2 jf 3
(002) ret      #262144
(003) ret      #0
```

- Primitive to find "ip" and "icmp":
```
root@linux-opstation-pysn:~# tcpdump -d ip and icmp
(000) ldh      [12]
(001) jeq      #0x800           jt 2 jf 5
(002) ldb      [23]
(003) jeq      #0x1              jt 4 jf 5
(004) ret      #262144
(005) ret      #0
```
ldh = load a half-word [12] = Starting at byte 12. Starting from the start of the frame (byte 0) you count up to byte 12. In this case its the Ether-type field

jeq #0x800 = jump if equal to 0x0800. E-type 0x0800 means that the next header is IPv4. jt 2 jf 5 = jump to line 2 if true or jump to line 5 if false

ldb = load a byte [23] = Starting at byte 23. Byte 0-13 is the Ethernet Frame. Since the next header is IPv4 it will start at byte 14. Counting the bytes, 23 is the Protocol field.

jeq #0x1 = jump if equal to 0x1. Protocol 0x01 saying that the next header is ICMPv4. jt 4 jf 5 = jump to line 4 if true or jump to line 5 if false

ret #262144 = just needs to be a large number to capture packet ret #0 = a null value means to ignore packet

- BPF to find "ip" and "icmp":
```
root@linux-opstation-pysn:~# tcpdump -d 'ether[12:2]=0x0800 && ip[9]=0x01'
(000) ldh      [12]
(001) jeq      #0x800           jt 2 jf 6
(002) jeq      #0x800           jt 3 jf 6
(003) ldb      [23]
(004) jeq      #0x1             jt 5 jf 6
(005) ret      #262144
(006) ret      #0
```

(001) jeq #0x800 jt 2 jf 6 = This is the result of searching for E-type 0x0800. (002) jeq #0x800 jt 3 jf 6 = This second line is automatically searched for when specifiying a "ip" header BPF.



- Primitive to find "ip6" and "icmp6":
```
root@linux-opstation-pysn:~# tcpdump -d ip6 and icmp6
(000) ldh [12]                 = Here is loading a half word starting at byte 12.
(001) jeq      #0x86dd        jt 2 jf 8  = if its equal to 0x86dd then jump to line 2, else jump to line 8.
(002) ldb      [20]             = Load 1 byte at byte 20
(003) jeq      #0x3a          jt 7 jf 4  = Jump to line 7 if its 0x3a (58) which is the code for icmpv6. Goto line 4 if it is not.
(004) jeq      #0x2c          jt 5 jf 8 = jump to line 5 if its 0x2c (44) which is IPv6-Fragmentation extension header. Goto line 8 if not.
(005) ldb      [54]             = Load 1 byte at byte 54
(006) jeq      #0x3a          jt 7 jf 8 = Jump to line 7 if its 0x3a (58) which is the code for icmpv6. Goto line 8 if it is not.
(007) ret      #262144            = Has a number larger than the packet size so capture the packet.
(008) ret      #0               = Has a null value so discard this packet.
```

- BPF to find "ip6" and "icmp6":
```
root@linux-opstation-pysn:~# tcpdump -d 'ether[12:2]=0x86dd && (ip6[20]=0x3a || ip6[20]=0x2c)'                 =
(000) ldh      [12]
(001) jeq      #0x86dd          jt 2 jf 7 = like for 'ip' this line is because we are looking for E-type 0x86dd
(002) jeq      #0x86dd          jt 3 jf 7 = this line is also looking for the same because we specified 'ip6' so it will automatically look for E-type 0x86dd
(003) ldb      [34]
(004) jeq      #0x3a            jt 6 jf 5
(005) jeq      #0x2c            jt 6 jf 7
(006) ret      #262144
(007) ret      #0
```

- Primitive to find "tcp" and "src port 22":
```
root@linux-opstation-pysn:~# tcpdump -d tcp src port 22
(000) ldh      [12]               = Looks automatically for the E-type field
(001) jeq      #0x86dd          jt 2 jf 6  = Looks for 0x86dd goto 2 if true or 6 if false
(002) ldb      [20]               = Goto byte 20 in the ipv6 header
(003) jeq      #0x6             jt 4 jf 15 = goto 4 if it equals 0x06 (TCP) else goto 15
(004) ldh      [54]                = Load half-word at byte 54 (start of tcp header)
(005) jeq      #0x16            jt 14 jf 15 = Jump to 14 if its 0x16 (22)
(006) jeq      #0x800           jt 7 jf 15  = Secondly looks for 0x0800 if not 0x86dd from line 1. Goto 7 if true else 15.
(007) ldb      [23]                = Goto byte 23 of ipv4 header
(008) jeq      #0x6             jt 9 jf 15  = goto 9 if its 0x06 (TCP) else goto 15
(009) ldh      [20]                = Load half-word at byte 20
(010) jset     #0x1fff          jt 15 jf 11 = jset = jump if set. If the mask of 0x01fff had a value then goto 15. This is focusing on only the offset field. If there is a value here then its a fragment with no higher layer header encapsulated. Else goto 11
(011) ldxb     4*([14]&0xf)           = this loads byte 14 with a mask of 0x0f which focuses on the IHL. Performs the math operation of (4 x (IHL value)). If IHL is 5 then value is 20. If IHL is 7 then value is 28. IHL of 15 is 60.
(012) ldh      [x + 14]             = Load a half-word at X + 14. 14 is added to the value from line 11. 14 is the # of bytes from the Ethernet Header added to the size of the ip header.
(013) jeq      #0x16            jt 14 jf 15 = jump to 14 if it equals 0x16 (22) else 15
(014) ret      #262144              = Has a number larger than the packet size so capture the packet.
(015) ret      #0                 = Has a null value so discard this packet.
```

- BPF to find "tcp" and "src port 22". The process is similar as using primitives except that it does not check for ipv6 and always assumes ipv4.:
```
root@linux-opstation-pysn:~# tcpdump -d tcp[0:2]=22
(000) ldh      [12]
(001) jeq      #0x800           jt 2 jf 10
(002) ldb      [23]
(003) jeq      #0x6             jt 4 jf 10
(004) ldh      [20]
(005) jset     #0x1fff          jt 10 jf 6
(006) ldxb     4*([14]&0xf)
(007) ldh      [x + 14]
(008) jeq      #0x16            jt 9 jf 10
(009) ret      #262144
(010) ret      #0
```

- Primitive to find "udp" and "dst port 53":
```
root@linux-opstation-pysn:~# tcpdump -d udp dst port 53
(000) ldh      [12]
(001) jeq      #0x86dd          jt 2 jf 6
(002) ldb      [20]
(003) jeq      #0x11            jt 4 jf 15
(004) ldh      [56]
(005) jeq      #0x35            jt 14 jf 15
(006) jeq      #0x800           jt 7 jf 15
(007) ldb      [23]
(008) jeq      #0x11            jt 9 jf 15
(009) ldh      [20]
(010) jset     #0x1fff          jt 15 jf 11
(011) ldxb     4*([14]&0xf)
(012) ldh      [x + 16]             = Adds 16 to the value of line 11. 14 bytes for Ethernet header and 2 bytes of the source port field.
(013) jeq      #0x35            jt 14 jf 15
(014) ret      #262144
(015) ret      #0
```

- BPF to find "udp" and "dst port 53". Identical to using primitives except that it will not check for ipv6.:
```
root@linux-opstation-pysn:~# tcpdump -d udp[2:2]=53
(000) ldh      [12]
(001) jeq      #0x800           jt 2 jf 10
(002) ldb      [23]
(003) jeq      #0x11            jt 4 jf 10
(004) ldh      [20]
(005) jset     #0x1fff          jt 10 jf 6
(006) ldxb     4*([14]&0xf)
(007) ldh      [x + 16]
(008) jeq      #0x35            jt 9 jf 10
(009) ret      #262144
(010) ret      #0
```

- Primitive to find "tcp" and "port 80":
```
root@linux-opstation-pysn:~# tcpdump -d tcp port 80
(000) ldh      [12]
(001) jeq      #0x86dd          jt 2 jf 8
(002) ldb      [20]
(003) jeq      #0x6             jt 4 jf 19
(004) ldh      [54]
(005) jeq      #0x50            jt 18 jf 6
(006) ldh      [56]
(007) jeq      #0x50            jt 18 jf 19
(008) jeq      #0x800           jt 9 jf 19
(009) ldb      [23]
(010) jeq      #0x6             jt 11 jf 19
(011) ldh      [20]
(012) jset     #0x1fff          jt 19 jf 13
(013) ldxb     4*([14]&0xf)
(014) ldh      [x + 14]
(015) jeq      #0x50            jt 18 jf 16
(016) ldh      [x + 16]
(017) jeq      #0x50            jt 18 jf 19
(018) ret      #262144
(019) ret      #0
```

- BPF to find "tcp" and "port 80". This would have to be done with 2 separate statements. Can only check for IPv4.:
```
root@linux-opstation-pysn:~# tcpdump -d 'tcp[0:2]=80 || tcp[2:2]=80'
(000) ldh      [12]
(001) jeq      #0x800           jt 2 jf 12
(002) ldb      [23]
(003) jeq      #0x6             jt 4 jf 12
(004) ldh      [20]
(005) jset     #0x1fff          jt 12 jf 6
(006) ldxb     4*([14]&0xf)
(007) ldh      [x + 14]
(008) jeq      #0x50            jt 11 jf 9
(009) ldh      [x + 16]
(010) jeq      #0x50            jt 11 jf 12
(011) ret      #262144
(012) ret      #0
```

- BPF to find DSCP:
```
root@linux-opstation-pysn:~# tcpdump -d 'ip[1]&252=184'
(000) ldh      [12]
(001) jeq      #0x800           jt 2 jf 6
(002) ldb      [15]                = looks at byte 15 which is the TOS field (or DSCP and ECN).
(003) and      #0xfc               = Applies a mask of 0xfc (252) which only checks the high order 6 bits and ignores the low order 2 bits.
(004) jeq      #0xb8            jt 5 jf 6  = Jump to 5 if it equals 0xb8 (184) else goto 6.
(005) ret      #262144
(006) ret      #0
```

- BPF to check the TCP flags for SYN+ACK. This must be an exact match.
```
root@linux-opstation-pysn:~# tcpdump -d tcp[13]=17
(001) jeq      #0x800           jt 2 jf 10
(002) ldb      [23]
(003) jeq      #0x6             jt 4 jf 10
(004) ldh      [20]
(005) jset     #0x1fff          jt 10 jf 6
(006) ldxb     4*([14]&0xf)
(007) ldb      [x + 27]               = Load a byte at 27 + value of line 5. This will take you to the TCP flags field
(008) jeq      #0x11            jt 9 jf 10   = jump to 9 if it equals 0x11 (17) which is both the SYN and ACK flags turned on and rest of flags off.
(009) ret      #262144
(010) ret      #0
```

- This BPF will also check for SYN+ACK but other flags may/may not be set.
```
root@linux-opstation-pysn:~# tcpdump -d 'tcp[13]&17=17'
(000) ldh      [12]
(001) jeq      #0x800           jt 2 jf 11
(002) ldb      [23]
(003) jeq      #0x6             jt 4 jf 11
(004) ldh      [20]
(005) jset     #0x1fff          jt 11 jf 6
(006) ldxb     4*([14]&0xf)
(007) ldb      [x + 27]                = Load a byte at 27 + value of line 5. This will take you to the TCP flags field
(008) and      #0x11                 = Applies a mask to only check the SYN and ACK fields. Other bits are ignored.
(009) jeq      #0x11            jt 10 jf 11   = jump to 10 if it equals 0x11 (17) which is both the SYN and ACK flags turned on and rest of flags are ignored.
(010) ret      #262144
(011) ret      #0
```

- BPF will just check the SYN+ACK bits to ensure that the combined value do not equal 0. Other flags are not matched.
```
root@linux-opstation-pysn:~# tcpdump -d 'tcp[13]&17!=0'
(000) ldh      [12]
(001) jeq      #0x800           jt 2 jf 10
(002) ldb      [23]
(003) jeq      #0x6             jt 4 jf 10
(004) ldh      [20]
(005) jset     #0x1fff          jt 10 jf 6
(006) ldxb     4*([14]&0xf)
(007) ldb      [x + 27]
(008) jset     #0x11            jt 9 jf 10   = Checks the SYN+ACK bits to see if they have a value. Other flags are ignored.
(009) ret      #262144
(010) ret      #0
```

- BPF that will check for VLAN tag and VLAN 111
```
root@linux-opstation-pysn:~# tcpdump -d 'ether[12:2]=0x8100 && ether[14:2] & 0x0fff = 0x006f'
(000) ldh      [12]                  = load a half word at byte 1
(001) jeq      #0x8100          jt 2 jf 6     =  jump to 2 if it equals 0x8100 else jump to 6
(002) ldh      [14]                  = load a half word at byte 14 which will be the PCP/DEI and VLAN ID field.
(003) and      #0xfff                 = applies a mask of 0x0fff which will ignore the PCP/DEI field and only match on the VLAN ID field
(004) jeq      #0x6f            jt 5 jf 6     = jump to 5 if it equals 0x006f (111). Notice that this is showing the leading zero's that normally are removed to identify that we are looking for the value of the entire 2 bytes. Else goto 6.
(005) ret      #262144
(006) ret      #0
```


### 6.2.2 Define the function of a Berkley packet filter (BPF)
Berkeley Packet Filters were conceived in 1992 as a way to provide a way for filtering packets from kernel to userspace. It consists of bytecode that is injected from userspace to the kernel. In recent years it has been re-written as the eBPF virtual machine that closely resembles the previous BPF functions, yet allows for 64-bit registers and for increasing the number of registers from two to ten. This allows the BPF to take advantage of modern hardware.

TCPDUMP supports the use of BPFs just like primitives. However, BPFs can offer many improvements over primitives in terms of precision and speed. BPFs were engineered to help prevent redundant computations and minimize CPU bottlenecks that can be present when using primitives. However, these improvements come at a cost of potentially more complex expression creation.


### 6.2.3 Compare primitives and BPFs
- Primitives

  - CMU/Stanford Packet Filter (CSPF) Model commonly called Boolean Expression Tree

  - Simple and easy filter expressions

  - First user-level packet filter model

  - Memory-stack-based filter machine which can create bottlenecks on model CPUs

  - can have redundant computations of the same information

- Berkley Packet Filters (BPF)

  - Control Flow Graph (CFG) Model

  - Uses a simple (non-shared) buffer model which can make it 1.5 to 20 times faster than CSPF

  - Can be more complex to create expressions but offer far more precision



Source: https://www.tcpdump.org/papers/bpf-usenix93.pdf and https://allenplato.wiki/blog/2021/Dive-into-BPF/



Filter Format Example:
TCPDump uses two different formats for tcpdump filters, macro, and BPF format.



Macro:
```
<macro> <value>
not port 22
```

BPF:
```
<protocol header> [offset:length] <relation> <value>
tcp[2:2] !=22
```

References:

https://www.tcpdump.org/papers/bpf-usenix93.pdf

https://allenplato.wiki/blog/2021/Dive-into-BPF/


### 6.2.4 Construct a BPF


#### 6.2.4.1 Kernel API
TCPDump opens a network tap by requesting a SOCK_RAW socket and after setsockopt calls, a filter is set with the SO_ATTACH_FILTER option:
```
sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))
...
setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, ...)
```

Reference: https://man7.org/linux/man-pages/man7/socket.7.html
```
SO_ATTACH_FILTER (since Linux 2.2), SO_ATTACH_BPF (since Linux
3.19)
       Attach a classic BPF (SO_ATTACH_FILTER) or an extended BPF
       (SO_ATTACH_BPF) program to the socket for use as a filter
       of incoming packets.  A packet will be dropped if the
       filter program returns zero.  If the filter program
       returns a nonzero value which is less than the packet's
       data length, the packet will be truncated to the length
       returned.  If the value returned by the filter is greater
       than or equal to the packet's data length, the packet is
       allowed to proceed unmodified.
```

SO_ATTACH_FILTER allows us to attach a Berkley Packet Filter to the socket to capture incoming packets. Without any filters the NIC will capture all packets.

The BPF Filter is then running against all received packets on a network interface and those that match filtering criteria are passed on to the network tap file descriptor.

TCPDump asks the kernel to execute a BPF program that works within the kernel context.



BPF Virtual Machine
The BPF machine consists of an accumulator, an index register, a scratch memory store, and an implicit program counter. There is a small set of arithmetic, logical, and jump instructions given in a BPF program written in bytecode.

TCPDump filtering with BPF’s:


```
tcpdump "ether[12:2] = 0x800" -d
```
```
(000) ldh    [12]
(001) jeq   0x800,  jt 2  jf 3
(002) ret   #262144
(003) ret   #0
```

This reads as follows:

- ldh - loads half-word (16-bit) value in the accumulator from offset 12 in the ethernet header

- jeq - check if the value is "0x800" and if this is true "jump true" to line 2, if it is false "jump false" to line 3

- ret #262144 - returns the default snapshot length in bytes

- ret #0 - returns nothing, it didn’t meet the criteria in the jeq statement.



References:

https://man7.org/linux/man-pages/man7/socket.7.html


#### 6.2.4.2 Berkley Packet Filters
TCPDump filtering with BPF’s and bit-masking:
BPF’s in conjunction with TCPDump, operators, and bitmasking make for an extremely powerful traffic filtering and parsing tool.

- The smallest filter that BPF can understand easily is a byte.

- A span of bytes can be denoted as in the BPF Bytecode example "ether[12:2]", starts at byte offset 12 and span 2 bytes in to look at the ethertype field.

- Using BPFs with operators, bitmasking, and TCPDump creates a powerful tool for traffic filtering and parsing.



SYNTAX
```
tcpdump {A} [B:C] {D} {E} {F} {G}

A = Protocol (ether | arp | ip | ip6 | icmp | tcp | udp)
B = Header Byte number
C = optional: Byte Length. Can be 1, 2 or 4 (default 1)
D = optional: Bitwise mask (&)
E = Operator (= | == | > | < | <= | >= | != | () | << | >>)
F = Result of Expression
G = optional: Logical Operator (&& ||) to bridge expressions
```

Example:
```
tcpdump -rn 'ether[12:2] = 0x0800 && (tcp[2:2] != 22 && tcp[2:2] != 23)'  # IPv4 traffic that is not SSH or Telnet
sudo tcpdump 'ether[6:4]=0xfa163ef0 && ether[10:2]=0xcafc'  # Source MAC = 0xfa153ef0cafc or FA:15:3E:F0:CA:FC
sudo tcpdump 'tcp[13]=0x11'  # any TCP traffic with only ACK and FIN flags
```
This expression with look for any IPv4 traffic that is not SSH or Telnet.

1. First it will look at ether[12:2] which is typically the ethertype field. The expression tells the system to check if this field contains 0x0800.

2. Conjoins the first expression with the &&.

3. Using the () and || operators we can build two or more expressions to look for. In this case it checks the TCP destination field (tcp[2:2]) does not contain 22 or 23.
```
Most Exclusive  # Must only have ACK and FIN, 6.2.4.3.1
tcp[13] = 0x11
tcp[13] & 0xff = 0x11
tcp[13] & 255 = 17

Least Exclusive   # 6.2.4.3.2
tcp[13] & 0x11 = 0x11  # Must have any combination that includes ACK and FIN
tcp[13] & 0x11 != 0  # Must have any combination that includes ACK or FIN
```

#### 6.2.4.3 Bitwise Masking
When using Berkeley Packet Filters, we have the ability to specify capture filters with greater precision by using bit-wise masking. This enables us to specify filters down to the bit-level. After we specify the byte(s) to be examined, we would then need to apply a mask to specify which bits are significant (1) and which bits are insignificant (0).

- In this image we are applying a bitwise mask to byte [0] of the IP header. This byte contains both the Version and Internet Header Length (IHL) fields with each being 4-bits or 1 nibble. We know that all ipv4 traffic will contain a value of 4 (0x4) in the high nibble to signify the version. The IHL field is normally 5 to signify that the IP header is 5 WORDS (32-bits) in length. We can apply a filter to focus on only the IHL field and print any packets that this field is greater than 5.
```
ip[0] & 0x0F > 0x05
```

![image](https://github.com/ruppertaj/WOBC/assets/93789685/df1cf231-83e4-473f-a9d0-d0797122a8f0)
ver ihl bpf


- In this image we are applying a bitwise mask on the Fragmentation offset field in the IP header. This field consumes the lower 6-bits of byte [6] and the entirety of byte [7]. So to examine this field, we will need to read both bytes [6] and [7] but ignore the first 3-bits in byte [6].
```
ip[6:2] & 0x1fff > 0x0000
```

![image](https://github.com/ruppertaj/WOBC/assets/93789685/222dd6e4-e298-4081-bc1e-a72190278e99)
BPF Mask2


##### 6.2.4.3.1 Filter Logic - Most exclusive
All designated bit values must be set; no others can be set
```
tcp[13] = 0x11
--or--
tcp[13] & 0xFF = 0x11
```

![image](https://github.com/ruppertaj/WOBC/assets/93789685/a27ab273-2278-47f6-988a-38df6e1bf1bc)
most bpf

![image](https://github.com/ruppertaj/WOBC/assets/93789685/05e86f3c-1152-482e-be50-95e09d548c1f)
most bpf2

```
tcpdump "tcp[13] = 0x11" -r tcpflags.pcap
tcpdump "tcp[13] = 0x11" -r tcpflags.pcap | wc -l
```


##### 6.2.4.3.2 Filter Logic - Less exclusive
All designated bits must be set; all others may be set
```
tcp[13] & 0x11 = 0x11
```

![image](https://github.com/ruppertaj/WOBC/assets/93789685/0a52fe72-da56-4793-88c4-1139d1cabe08)
less bpf

```
tcpdump "tcp[13] & 0x11 = 0x11" -r tcpflags.pcap
tcpdump "tcp[13] & 0x11 = 0x11" -r tcpflags.pcap | wc -l
```


##### 6.2.4.3.3 Filter Logic - Least exclusive
At least one of the designated bits must be set to not equal 0; all others may be set
```
tcp[13] & 0x11 !=0
```

![image](https://github.com/ruppertaj/WOBC/assets/93789685/624a6383-59dd-43cc-9ac8-eb4c021e56d9)
least bpf

Least Exclusive:
Selects any packet that has ACK or FIN set and also has any other flag set.
```
tcpdump "tcp[13] & 0x11 !=0" -r tcpflags.pcap
tcpdump "tcp[13] & 0x11 !=0" -r tcpflags.pcap | wc -l
```


### 6.2.5 Use a BPF to filter packets entering a network interface


#### 6.2.5.1 BPFs at the Data-Link layer
- Using BPFs to print source and destination MAC addresses. Since the maximum amount of bytes that can be read with BPF is 4 and the size of a MAC address is 6 bytes, we may have to prepare the filter in 2 or more parts conjoined.

  - Here are 2 ways we can search for the destination broadcast MAC address.
```
tcpdump -i eth0 'ether[0:4] = 0xffffffff and ether[4:2] = 0xffff'
tcpdump -i eth0 'ether[0:2] = 0xffff and ether[2:2]= 0xffff and ether[4:2] = 0xffff'
```
  - Here are 2 ways we can search for the source MAC address of fa:16:3e:f0:ca:fc.
```
tcpdump -i eth0 'ether[6:4] = 0xfa163ef0 and ether[10:2] = 0xcafc'
tcpdump -i eth0 'ether[6:2] = 0xfa16 and ether[8:2]= 0x3ef0 and ether[10:2] = 0xcafc'
```

- Search the first byte of the source (ether[0]) and destination (ether[6]) MAC to determine if it’s a unicast (0x00) or multicast (0x01) MAC address.
```
tcpdump -i eth0 'ether[0] & 0x01 = 0x00'
tcpdump -i eth0 'ether[0] & 0x01 = 0x01'
tcpdump -i eth0 'ether[6] & 0x01 = 0x00'
tcpdump -i eth0 'ether[6] & 0x01 = 0x01'
```

- Using BPFs to print packets interface with the EtherType (ether[12:2]) field matching IPv4, ARP, VLAN Tag, and IPv6 respectively.
```
tcpdump -i eth0 ether[12:2] = 0x0800
tcpdump -i eth0 ether[12:2] = 0x0806
tcpdump -i eth0 ether[12:2] = 0x8100
tcpdump -i eth0 ether[12:2] = 0x86dd
```

- Print packets that belong to VLAN 100. Here we are masking out the 4-bit PCP/DEI field. It is unsure if this field will or will not have a value so it’s best to ignore these bits unless you are looking for a specific value here.
```
tcpdump -i eth0 'ether[12:2] = 0x8100 and ether[14:2] & 0x0fff = 0x0064'
tcpdump -i eth0 'ether[12:4] & 0xffff0fff = 0x81000064'
```

- Print packets that have a double VLAN Tag.
```
tcpdump -i eth0 'ether[12:2] = 0x8100 and ether[16:2] = 0x8100'
```

- Print packets that are potential Double tagging (VLAN Hopping) using VLAN 1 (native) to attack VLAN 999
```
tcpdump -i eth0 'ether[12:4] & 0xffff0fff = 0x81000001 && ether[16:4] & 0xffff0fff = 0x810003E7
```

- Print all ARP requests and Reply’s respectively.
```
tcpdump -i eth0 arp[6:2] = 0x01
tcpdump -i eth0 arp[6:2] = 0x02
```


#### 6.2.5.2 BPFs at the Network layer
- Print all ipv4 packets with the IHL greater than 5. This will indicate that there are IP options included after the IPv4 header but before the next encapsulated header.
```
tcpdump -i eth0 'ip[0] & 0x0f > 0x05'
tcpdump -i eth0 'ip[0] & 15 > 5'
```

- Print ipv4 packets with the DSCP value of 16.
```
tcpdump -i eth0 'ip[1] & 0xfc = 0x40'
tcpdump -i eth0 'ip[1] & 252 = 64'
tcpdump -i eth0 'ip[1] >> 2 = 16'
```

- Print ipv4 packets with various RES, DF or MF flags set.

  - Print ipv4 packets with ONLY the RES flag set. DF and MF must be off.
```
tcpdump -i eth0 'ip[6] & 0xE0 = 0x80'
tcpdump -i eth0 'ip[6] & 224 = 128'
```
  - Print ipv4 packets with ONLY the DF flag set. RES and MF must be off.
```
tcpdump -i eth0 'ip[6] & 0xE0 = 0x40'
tcpdump -i eth0 'ip[6] & 224 = 64'
```
  - Print ipv4 packets with ONLY the MF flag set. RES and DF must be off.
```
tcpdump -i eth0 'ip[6] & 0xE0 = 0x20'
tcpdump -i eth0 'ip[6] & 224 = 32'
```
  - Print ipv4 packets with any flag combination.
```
tcpdump -i eth0 'ip[6] & 0xE0 > 0'
tcpdump -i eth0 'ip[6] & 224 != 0'
```
  - Print ipv4 packets with the RES bit set. The other 2 flags are ignored so they can be on or off.
```
tcpdump -i eth0 'ip[6] & 0x80 = 0x80'
tcpdump -i eth0 'ip[6] & 128 = 128'
```
  - Print ipv4 packets with the DF bit set. The other 2 flags are ignored so they can be on or off.
```
tcpdump -i eth0 'ip[6] & 0x40 = 0x40'
tcpdump -i eth0 'ip[6] & 64 = 64'
```
  - Print ipv4 packets with the MF bit set. The other 2 flags are ignored so they can be on or off.
```
tcpdump -i eth0 'ip[6] & 0x20 = 0x20'
tcpdump -i eth0 'ip[6] & 32 = 32'
```

- Print ipv4 packets with the offset field having any value greater than zero (0).
```
tcpdump -i eth0 'ip[6:2] & 0x1fff > 0'
tcpdump -i eth0 'ip[6:2] & 8191 > 0'
```

- Print ipv4 packets with the TTL being equal to and less than 128.
```
tcpdump -i eth0 'ip[8] = 128'
tcpdump -i eth0 'ip[8] < 128'
```

- Print any ICMPv4, TCP, or UDP encapsulated within an ipv4 packet.
```
tcpdump -i eth0 'ip[9] = 0x01'
tcpdump -i eth0 'ip[9] = 0x06'
tcpdump -i eth0 'ip[9] = 0x11'
```

- Print ipv4 packets with the source and destination address of 10.1.1.1.
```
tcpdump -i eth0 'ip[12:4] = 0x0a010101'
tcpdump -i eth0 'ip[16:4] = 0x0a010101'
```

- Print ipv6 packets with the Traffic Class of any value.
```
tcpdump -i eth0 'ip6[0:2] & 0x0ff0 != 0'
```

- Print ipv6 packets with the Flow Label field of any value.
```
tcpdump -i eth0 'ip6[0:4] & 0x000FFFFF != 0'
```

- Print any ICMPv6, TCP, or UDP encapsulated within an ipv6 packet.
```
tcpdump -i eth0 'ip6[6] = 0x3a'
tcpdump -i eth0 'ip6[6] = 0x06'
tcpdump -i eth0 'ip6[6] = 0x11'
```

- Print ipv6 packets with the TTL being equal to and less than 128.
```
tcpdump -i eth0 'ip6[7] = 128'
tcpdump -i eth0 'ip6[7] < 128'
```

- Print ICMPv4 packets set to Destination Unreachable (Type 3) and Network Administratively Prohibited (Code 9). Note: ICMPv6 is not supported by BPFs.
```
tcpdump -i eth0 'icmp[0] = 3 and icmp[1] = 9'
```


#### 6.2.5.3 BPFs at the Transport layer
The limitations of BPFs is that it will always assume the L3 header is IPv4 whereas Primitives will check for both IPv6 and IPv4.

- Using the -d option we can see that using primitives, the expression will search for IPv6 with TCP source port 22 then check for IPv4 with TCP source port 22.
```
tcpdump -d tcp src port 22 =  Using a primitive to look for source port 22
(000) ldh      [12]
(001) jeq      #0x86dd          jt 2 jf 6
(002) ldb      [20]
(003) jeq      #0x6             jt 4 jf 15
(004) ldh      [54]
(005) jeq      #0x16            jt 14 jf 15
(006) jeq      #0x800           jt 7 jf 15
(007) ldb      [23]
(008) jeq      #0x6             jt 9 jf 15
(009) ldh      [20]
(010) jset     #0x1fff          jt 15 jf 11
(011) ldxb     4*([14]&0xf)
(012) ldh      [x + 14]
(013) jeq      #0x16            jt 14 jf 15
(014) ret      #262144
(015) ret      #0
```

- Using -d here we can see that using BPF’s it will always assume that IPv4 is the L3 header.
```
tcpdump -d tcp[0:2]=22
(000) ldh      [12]
(001) jeq      #0x800           jt 2 jf 10
(002) ldb      [23]
(003) jeq      #0x6             jt 4 jf 10
(004) ldh      [20]
(005) jset     #0x1fff          jt 10 jf 6
(006) ldxb     4*([14]&0xf)
(007) ldh      [x + 14]
(008) jeq      #0x16            jt 9 jf 10
(009) ret      #262144
(010) ret      #0
```

`Note: This limitation also applies to UDP.`


- Print ipv4 packets with TCP source port 3389.
```
tcpdump -i eth0 'tcp[0:2] = 3389'
```

- Print ipv4 packets with TCP destination port 3389.
```
tcpdump -i eth0 'tcp[2:2] = 0x0d3d'
```
- Print ipv4 packets with the TCP offset field greater than 5. This will indicate that there are TCP options included after the TCP header but before the data payload or next encapsulated header.
```
tcpdump -i eth0 'tcp[12] & 0xf0 > 5'
```

- Print ipv4 packets with the TCP Flags set to ACK+SYN. No other flags can be set.
```
tcpdump -i eth0 'tcp[13] = 0x12'
```

- Print ipv4 packets with the TCP Flags set to ACK+SYN. The other flags are ignored so they can be set or unset.
```
tcpdump -i eth0 'tcp[13] & 0x12 = 0x12'
```

- Print ipv4 packets with the TCP Flags ACK and SYN are either both on or at least one of them is on. If both are off then those packets are not printed. The other flags are ignored so they can be set or unset.
```
tcpdump -i eth0 'tcp[13] & 0x12 != 0'
```

- Prints ipv4 packets with the TCP Urgent Pointer field having a value.
```
tcpdump -i eth0 'tcp[18:2] > 0'
```


### 6.2.6 Understand Wireshark’s use of BPFs


References:

Wireshark Userguide reference can be found here: https://www.wireshark.org/docs/wsug_html_chunked/index.html


#### 6.2.6.1 Wireshark Display Filters vs Capture filters
Sometimes there can be confusion about the differences between these two filters.

- Display filters - allow you to change the view of what packets are displayed of those that are captured. Wireshark has specific display filters that it uses and it does not conform to TCPDUMP primitives or BPF format. More information can be found here: https://wiki.wireshark.org/DisplayFilters.

  - If you start a Wireshark Packet capture without specifying any capture filters then Wireshark will capture all packets it can regardless if the information is useful or not. ON busy networks you can quickly accumulate packets and all are saved to disk. It is entirely feasible to fill your entire hard drive very quickly causing your computer to freeze and crash if not carefully monitored.

![image](https://github.com/ruppertaj/WOBC/assets/93789685/ca6153ad-9cc2-47cf-80b0-fc7485e66f74)
w3

- Display filters can be applied to cut thru the captured data to find the information you want.

![image](https://github.com/ruppertaj/WOBC/assets/93789685/60d9f41b-2a4c-4a99-a0d4-29e552911468)
w4

- Capture filters - used to specify which packets should be saved to disk while capturing. By default, there are no capture filters applied so all packets will be captured if nothing is specified. TCPDUMP primitives and/or BPFs can be applied and conjoined to make capture filters. More information can be found here: https://wiki.wireshark.org/CaptureFilters.

  - Upon Wireshark start we will be prompted to enter any capture filters.

![image](https://github.com/ruppertaj/WOBC/assets/93789685/48f68b00-d777-41e1-a7cc-ae970d389577)
w1

- If Wireshark is already running you can optionally go to Capture → Options to start or modify a capture filter. Wireshark packet capturing must be stopped to add/change capture filters.

![image](https://github.com/ruppertaj/WOBC/assets/93789685/88f56af2-f10e-40a9-ae56-163dcda3b75d)
w2

- Here we can use primitives or BPFs to add a capture filter.

![image](https://github.com/ruppertaj/WOBC/assets/93789685/fc4c7c19-8a43-4618-9543-0d519c3ede8a)
w5

- Here we can see that the filter greatly reduced the amount of packets captured.

![image](https://github.com/ruppertaj/WOBC/assets/93789685/f94a40fb-3a58-4814-a09f-b4219396068f)
w6


References:

https://wiki.wireshark.org/CaptureFilters

https://wiki.wireshark.org/DisplayFilters


##### 6.2.6.1.1 Wireshark Display Filters
Wireshark display filters are a powerful feature that allows users to selectively view network traffic based on specific criteria. These filters enable users to focus on particular packets of interest while disregarding others, making it easier to analyze network communication and identify relevant information.

Here is a list of common and popular Wireshark Display filters.

- Filtering for a particular protocol will give all packets that have the protocol header in the packet payload.

  - This will NOT show the TCP setup, TCP teardown, or fragmented packets that are part of the communication but do not have the protocol header in payload.

  - We can filter for specific protocols such as:

    - Layer 2: `eth`, `arp`, `vlan`, `wlan`

    - Layer 3: `ip`, `ipv6`, `icmp`, `icmpv6`

    - Layer 4: `tcp`, `udp`

    - Layer 5: `smb`, `socks`, `rpc`

    - Layer 7: `telnet`, `ssh`, `http`, `ssl`, `tls`, `quic`, `dns`, `ftp`, `ftp-data`, `tftp`, `smtp`, `pop`, `imap`, `dhcp` or `bootp`, `ntp`, `tacplus`, `radius`, `rdp`

    - Routing protocols: `rip`, `ospf`, `bgp`

- We can filter for specific addresses:

  - Layer 2: `eth.addr`, `eth.dst ==`, `eth.src ==`

  - Layer 3: `ip.addr ==`, `ip.dst ==`, `ip.src ==`

  - Layer 4: `tcp.port ==`, `tcp.dstport ==`, `tcp.srcport ==`, `udp.port ==`, `udp.dstport ==`, `udp.srcport ==`

- IPv4 Filters:

  - IHL: `ip.hdr_len == 20`, `ip.hdr_len > 20`

  - DSCP: `ip.dsfield.dscp > 0`, `ip.dsfield.dscp == 48`

  - ECN: `ip.dsfield.ecn > 0`. `ip.dsfield.ecn == 2`

  - Flags: `ip.flags.rb == 1`, `ip.flags.df == 1`

  - Fragmentation: `(ip.flags.mf == 1) || (ip.frag_offset > 0)`

  - TTL: `ip.ttl == 64`, `ip.ttl == 128`, `ip.ttl ⇐ 64 && ip.ttl > 30 && !(ip.ttl > 64)`

  - Protocol: `ip.proto == 1`, `ip.proto == 6`, `ip.proto == 17`

  - 6-in-4 or 6-to-4 encapsulation: `ip.proto == 41`

- IPv6 Filters:

  - Traffic Class: `ipv6.tclass > 0`, `ipv6.tclass == 0xe0`

  - Next Header: `ipv6.nxt == 6`, `ipv6.nxt == 17`, `ipv6.nxt == 58`

  - 4-in-6 encapsulation: `ipv6.nxt == 4`

- TCP Specific Filters:

  - TCP Offset: `tcp.hdr_len == 32`, `tcp.hdr_len > 20`

  - TCP Flags:

    - Individual Flags: `tcp.flags.syn == 1`, `tcp.flags.ack == 0`, `tcp.flags.urg == 1`. `tcp.flags.reset == 1`

    - Flag Combinations: `tcp.flags == 0x002`, `tcp.flags == 0x012`, `tcp.flags == 0x010`, `tcp.flags == 0x018`

  - Urgent Pointer: `tcp.urgent_pointer > 0`

- HTTP specific filters:

  - `http.request`

  - `http.request.method == <method>`

    - <method> = GET, POST, HEAD, etc.

  - `http.response`

  - `http.response.code == <code>`

    - 100, 200, 300, 400, etc.

  - `http.user_agent`, `http.user_agent == "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.1.2) Gecko/20070219 Firefox/2.0.0.2"`, `!(http.user_agent == "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.1.2) Gecko/20070219 Firefox/2.0.0.2")`

- DNS filters:

  - Query: A = `dns.qry.type == 1`, NS = `dns.qry.type == 2`, SOA = `dns.qry.type == 6`, AAAA = `dns.qry.type == 28`, AXFR = `dns.qry.type == 252`

  - Response: A = `dns.resp.type == 1`, NS = `dns.resp.type == 2`, SOA = `dns.resp.type == 6`, AAAA = `dns.resp.type == 28`, AXFR = `dns.resp.type == 252`

- SSH Filters:

  - `ssh.protocol`, `ssh.protocol == "SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.1"`

- ARP Filters:

  - ARP Request/Reply: `arp.opcode == 1`, `arp.opcode == 2`

  - RARP Request/Reply: `arp.opcode == 3`, `arp.opcode == 4`

  - Gratutious ARP: `(arp.opcode == 2) && (eth.addr == ff:ff:ff:ff:ff:ff)`

- ICMP Filters:

  - Echo Request: `icmp.type == 0`

  - Echo Reply: `icmp.type == 8`

  - Time Exceeded: `icmp.type == 11`

  - Destination Unreachable and Port Unreachable: `(icmp.type == 3) && (icmp.code == 3)`

- DHCP Filters:

  - Client to Server: `(udp.srcport == 68) && (udp.dstport == 67)`

  - Server to Client: `(udp.srcport == 67) && (udp.dstport == 68)`

  - Discover: `dhcp.option.dhcp == 1`

  - Offer: `dhcp.option.dhcp == 2`

  - Request: `dhcp.option.dhcp == 3`

  - Ack: `dhcp.option.dhcp == 5`

- FTP Filters:

  - Commands: `ftp.request.command`

  - Sending username or password: `ftp.request.command == "USER"`, `ftp.request.command == "PASS"`

  - Download file: `ftp.request.command == "RETR"`

  - Upload file: `ftp.request.command == "STOR"`

  - Switch to passive mode: `ftp.request.command == "PASV"`

  - Directory listing: `ftp.request.command == "LIST"`

- Wildcard string filters:

  - `data contains "String"` - generic filter used to match packets based on the presence of specific data within the packet payload.

  - `ip contains "String"` - specifically targets the IP (Internet Protocol) layer for payload.

  - `http contains "String"` - specifically targets the HTTP (Hypertext Transfer Protocol) payload.

- Using the not feature:

  - Generally you can use any filter used above and surround it like this:

  - `!(filter)`

- Conjoining filter expressions:

  - both conditions must be true: `and` or `&&`

  - either the first condition or the second condition is true: `or` or `||`

- Following Protocol Streams:

  - In Wireshark, you can follow protocol streams to examine the communication between hosts using various protocols, including TCP, UDP, and others.

  - Analyze → Follow →

    - TCP Stream (ctrl+alt+shift+T)

    - UDP Stream (ctrl+alt+shift+U)

    - TLS Stream (ctrl+alt+shift+S)

    - HTTP Stream (ctrl+alt+shift+H)



- Apply as filter options:

  - In Wireshark, the "Apply as Filter" feature allows you to quickly create display filters based on specific packet attributes or values. This feature is useful for narrowing down the packets displayed in the packet list pane to focus on specific criteria of interest.

  1. Identify Packet Attribute: Start by identifying the packet attribute or value you want to create a filter for. This could be any field or value present in the captured packets, such as source or destination IP addresses, port numbers, protocols, packet content, or any other packet attribute.

  2. Select Packet: In the packet list pane of Wireshark, select the packet containing the attribute or value you want to create a filter for. This could be any packet in the packet list that contains the desired attribute.

  3. Right-Click Packet: Right-click on the selected packet to open the context menu.

  4. Apply as Filter: From the context menu, hover over the "Apply as Filter" option. A submenu will appear displaying different filtering options based on various packet attributes, such as IP addresses, protocols, and packet content.

  5. Analyze → Apply as Filter →

    a. Selected: This option applies a filter based on the attribute or value of the packet that you currently have selected in the packet list pane. Only packets matching filter is displayed.

    b. Not Selected: This option applies a filter based on the attribute or value of packets that are not currently selected in the packet list pane. All other packets are displayed except those matching filter.

    c. …​or Selected: This option combines the attribute or value of the packet that you currently have selected in the packet list pane with the attribute or value of other packets. Packets matching first filter or packets matching additional filters.

    d. …​and Selected: This option combines the attribute or value of the packet that you currently have selected in the packet list pane with the attribute or value of other packets. Packets matching each filter.

    e. ...or not Selected: This option applies a filter based on the attribute or value of packets that are not currently selected in the packet list pane, in combination with other attributes or values. Additional or conditional filters to exclude from view.

    f. …​and not Selected: This option combines the attribute or value of packets that are not currently selected in the packet list pane with the attribute or value of other packets. Packets matching each condition is excluded.



- Creating additional Columns in the Packet List view:

  - Drag and drop fields from the Packet Details View to the columns bar.

  - The rows can be dragged and dropped to arrange them in the desired order.



References:

https://wiki.wireshark.org/DisplayFilters


#### 6.2.6.2 Popular Wireshark Menus
Familiarize students with the various capabilities of Wireshark.

- Where the Packet List, Packet Details, and Packet Bytes can be seen

- How to capture traffic using a capture filter

- How to use the Display filter to target the header locations

- How to add columns

- How to use the search functionality



We will go through several useful Wireshark menu options:

![image](https://github.com/ruppertaj/WOBC/assets/93789685/b94ce305-851b-4773-b8f6-496381b24aa0)
w7


##### 6.2.6.2.1 Colorize traffic
- DEMO: Menu → View → Coloring Rules…​

  - Right click on item → Colorize Conversation → (L2 thru L4)

![image](https://github.com/ruppertaj/WOBC/assets/93789685/5c06553a-1abd-477c-a267-c9806092b801)
w12

Specifying packet coloring is useful to emphasize particular packets you might be interested if they match the rules specified. It helps them to stand out from other similar packet data.



References:

More information can be found here: https://www.wireshark.org/docs/wsug_html_chunked/ChCustColorizationSection.html


##### 6.2.6.2.2 Protocol Hierarchy
- DEMO: Menu→ Statistics → Protocol Hierarchy

![image](https://github.com/ruppertaj/WOBC/assets/93789685/26fb2eab-89a7-4871-8b30-6dc789f5b456)
w8

This consists of a tree of all the protocols found in the packet capture. Each row contains the statistical values of one protocol. Two of the columns (Percent Packets and Percent Bytes) serve double duty as bar graphs. This can be used to get an overall synopsis of the data in the capture to help you narrow your search.



References:

More information can be found here: https://www.wireshark.org/docs/wsug_html_chunked/ChStatHierarchy.html


##### 6.2.6.2.3 Firewall rules (Under "Tools". Assists in creating firewall rules)
- DEMO: Menu → Tools → Firewall ACL Rules

![image](https://github.com/ruppertaj/WOBC/assets/93789685/eb1e3037-a7f6-4d9c-95cd-1d908366c900)
w13

Based off the selected packet in the capture, this feature can help you create firewall rules on the following platforms:

- Cisco IOS standard/Extended ACLs

- Linux Netfilter (iptables)

- OpenBSD (pf)

- FreeBSD (ipfw)

- Windows Firewall (netsh)



References:

More information can be found here: https://www.wireshark.org/docs/wsug_html_chunked/ChUseToolsMenuSection.html


##### 6.2.6.2.4 Exporting objects
- DEMO: Menu → File → Export Objects

Can be a useful feature to download any unencrypted images or files sent during the packet capture.



References:

More information can be found here: https://www.wireshark.org/docs/wsug_html_chunked/ChIOExportSection.html#ChIOExportObjectsDialog


##### 6.2.6.2.5 Decrypt traffic
- DEMO: Menu → Edit → Preference → Protocols → SSL

Provided that you have the required decryption keys, you can decrypt any encrypted packets in the capture.

![image](https://github.com/ruppertaj/WOBC/assets/93789685/ebe99784-8639-4cd4-a598-6ab1eb3f50c2)
w15


References:

More information can be found here: https://wiki.wireshark.org/HowToDecrypt802.11


##### 6.2.6.2.6 Conversations
- DEMO: Menu → Statistics → Conversations

Useful to determine all the end-hosts that are involved in all the communications and how much data is passed between them. Can be used to identify high talkers or unusual communicating addresses.

![image](https://github.com/ruppertaj/WOBC/assets/93789685/2b11a576-1a83-460a-a3d1-f48eafff7fa9)
w9


References:

More information can be found here: https://www.wireshark.org/docs/wsug_html_chunked/ChStatConversations.html#ChStatConversationsWindow


##### 6.2.6.2.7 Endpoints
- DEMO: Menu → Statistics → Endpoints

Displays only the end-point addresses and the amount of data sent.

![image](https://github.com/ruppertaj/WOBC/assets/93789685/79064c31-5fd2-43e4-b6bc-cdb17cb0efd7)
w10


References:

More information can be found here: https://www.wireshark.org/docs/wsug_html_chunked/ChStatEndpoints.html#ChStatEndpointsWindow


##### 6.2.6.2.8 I/O Graph.
- DEMO: Menu → Statistics → I/O Graph

![image](https://github.com/ruppertaj/WOBC/assets/93789685/05f69e96-2d54-455f-9dd3-9b9a5ce64177)
w11

This can be used to determine packets sent over a period of time and to see low and high traffic periods.



References:

More information can be found here: https://www.wireshark.org/docs/wsug_html_chunked/ChStatIOGraphs.html


##### 6.2.6.2.9 ipv4 and ipv6 statistics
- DEMO: Menu → Statistics → ipv4 Statistics →

- DEMO: Menu → Statistics → ipv6 Statistics →

  - All Addresses - Divides data by IP address.

  - Destination and Ports - Divides data by IP address, and further by IP protocol type, such as TCP, UDP, and others. It also shows port number.

  - IP Protocol Types - Divides data by IP protocol type.

  - Source and Destination addresses - Divides data by source and destination IP address.



References:

More information can be found here: https://www.wireshark.org/docs/wsug_html_chunked/ChStatIPv4.html and https://www.wireshark.org/docs/wsug_html_chunked/ChStatIPv6.html



##### 6.2.6.2.10 Expert Information
- DEMO: Menu → Analyze → Expert Information

![image](https://github.com/ruppertaj/WOBC/assets/93789685/11bab230-ad84-4336-b9fa-9e2305a06cb9)
w16

Wireshark tracks packet anomalies and any other packets of interest and list them here.



References:

More information can be found here: https://www.wireshark.org/docs/wsug_html_chunked/ChAdvExpert.html


##### 6.2.6.2.11 Geo location
- DEMO: Menu → Edit → preferences → name resolution → GeoIP database directories "Edit"

![image](https://github.com/ruppertaj/WOBC/assets/93789685/b8b045a2-17d5-4202-9ed8-d1b23132e861)
w14


References:

[Maxmind](https://www.maxmind.com/) database can add useful IP geolocation data into the packet capture.

More information can be found here: https://wiki.wireshark.org/HowToUseGeoIP and https://www.wireshark.org/docs/wsug_html_chunked/ChMaxMindDbPaths.html


### 6.2.7 Describe passive OS fingerprinting (p0f)
Passive OS Finger-printer (p0f) is a tool that allows the passive scanning of network traffic. It is a traffic/packet sniffer like TCPDUMP and Wireshark. It makes use of the packet capture libraries like libpcap, winpcap, and NPCAP just as these other traffic sniffers to collect packets. The only thing that separates p0f from other collectors is how it uses and parses the captured data. Rather than capturing all packets, p0f only examines them and matches them to a signature database. This database allows p0f to make a "best guess" on the sending Operating system (OS) and/or application.

Passive OS fingerprinting (p0f) focuses on uniqueness in IP and TCP implementations to discover which OS sent the traffic. Specifically, p0f looks at header and payload items like initial TTL, fragmentation flag, default packet length of an IP header, Windows size, and TCP options in TCP SYN and SYN/ACK packets. The makers of p0f studied this uniqueness and developed a signature database (/etc/p0f/p0f.fp).



References:

Homepage: http://lcamtuf.coredump.cx/p0f3/

Kali repository: https://gitlab.com/kalilinux/packages/p0f


#### 6.2.7.1 Operating systems, web browsers, search-bots, and tools in database
```
Operating systems:	Web Browsers:	Search Robots:	Command Line Tools:
* Linux (2.4.x, 2.6.x, and 3.x and newer)
* Windows (XP, 7, and 8 and newer)
* FreeBSD (8.x and 9.x and newer)
* OpenBSD (5.x and newer)
* Mac OS X (10.x and newer)
* Solaris (6, 8, and 10 and newer)
* HP-UX (11 and newer)
* OpenVMS (7.x and newer)
* Tru64 (4.x and newer)

* Firefox (2.x - 10.x and newer)
* Microsoft Internet Explorer (6-8 and newer)
* Chrome (11.x - 27.x and newer)
* Opera (10.x - 19.x and newer)
* Android Browser (2.x and 4.x and newer)
* Safari (5.x - 7.x and newer)
* Konqueror ( up thru 4.7 and newer)

* BaiduSpider
* Googlebot
* Bingbot
* MSNbot
* Yandex
* Yahoo
* Yahoo Pipes
* Flipboard
* Spinn3r
* Facebook
* paper.li
* Twitter
* linkdex
* Yodaobot
* Tweetmeme
* Archive.org
* Google Web Preview

* wget
* Lynx
* curl
* links
* elinks
* JavaJRE
* Python urllib
* w3m
* libfetch
```


#### 6.2.7.2 p0f fingerprint signature file
Whenever p0f fingerprints traffic it reads from the "p0f.fp" file to identify the operating system and other details. Explore the p0f file with the students to explain the way in which the signatures work.


###### 6.2.7.2.1 P0f Signature Database
```
more /etc/p0f/p0f.fp
```


###### 6.2.7.2.2 Module Specifications
Formatted as follows:
```
[module: direction]
```

Table 4. Module Specifications
```
Name	                 Description
module                   name of the fingerprinting module (tcp, http, etc.)
direction                direction of the traffic, 'request' from client to server or 'response' for server to client
                         For the TCP module, 'client' matches initial SYN, and 'server' matches SYN+ACK
```


##### 6.2.7.2.3 Signature Groups
A signature must be preceded by a 'label' describing the fingerprinted information.
```
label = type:class:name:flavor
```

```
Table 5. Signature Groups
Name	            Description
type                typically an 's' for specific signatures and 'g' for more generic ones.
class               this provides the distinction between OS-identifying signatures (win, unix, cisco, etc.), if a '!' is indicated, that corresponds to more application-related signatures (NMap, Apache, Mozilla, etc.)
name                human-readable short name for what the fingerprint actually identifies (Linux, MacOS, Internet Explorer, Mozilla)
flavor              This is for any further information that needs to be appended to the label, such as "Xmas Scan" for NMap or version numbers for Linux "2.x"
```


###### 6.2.7.2.4 MTU Signatures
```
Table 6. MTU Signatures
Name	               Description
label = Ethernet       self explanatory
sig = 1500             MTU size specification
```


##### 6.2.7.2.5 TCP Signatures
```
sig = ver:ittl:olen:mss:wsize,scale:olayout:quirks:pclass
```

```
Table 7. TCP Signatures
Name	        Description
ver             IP version field. It is 4,6, or * if the version is unimportant to the signature
ittl            initial TTL of the IP packet
olen            IP options length. It is usually 0 for IPv4 and always 0 for IPv6
mss             maximum segment size (mss) that is specified in the TCP options. The * is used to designate that the mss varies
wsize           Windows’ size of the TCP segment. This is expressed as a fixed number, a multiple of the mss, or of the MTU. A rare but possible value is *
scale           is the Window scale (ws) value found in TCP options. If the ws option is not found, this value is 0
olayout         this field represents the TCP option types in the order they appear in the packet, separated by commas. When generating a signature for comparison with the database, this field should be the first that is generated. Eight possible options are:
```

```
Table 8. Olayout Options (continued from above)
Name	      Description
eol+n         explicit end of options followed by n bytes of padding
nop           No Operation (no-op) option
mss           maximum segment size option
ws            Window scaling option
sok           selective ACK permitted option
sack          selective ACK (rarely ever seen)
ts            timestamp option
?n            unknown option ID
quirks        properties observed in the IP or TCP headers. Two common quirks are df for the don’t-fragment flag being set and id+ for when the DF flag is set and the IP identification field is not zero.
pclass        is the payload size of the packet. This is almost always 0, because there is no payload in the three-way handshake.
```


##### 6.2.7.2.6 HTTP signatures
P0f can also determine http signatures based on user agent strings and other information contained within a packet.
```
sig = ver:horder:habsent:expsw
```

```
Table 9. HTTP Signatures
Name           Description
ver            0, for HTTP/1.0, 1 for HTTP/1.1, or * for any
horder         ordered list of headers that should appear in matching traffic.
habsent        list of headers that must not appear in the matching traffic. Useful for noting the absence of standard headers such as "host"
expsw          expected substrings in the 'user-agent' or 'server' field. This is used to detect dishonest software.
```


### 6.2.8 Use p0f to capture packets


#### 6.2.8.1 p0f help
```
root@kali:~# p0f -h
--- p0f 3.09b by Michal Zalewski <lcamtuf@coredump.cx> ---

p0f: invalid option -- 'h'
Usage: p0f [ ...options... ] [ 'filter rule' ]

Network interface options:

  -i iface  - listen on the specified network interface
  -r file   - read offline pcap data from a given file
  -p        - put the listening interface in promiscuous mode
  -L        - list all available interfaces

Operating mode and output settings:

  -f file   - read fingerprint database from 'file' (/etc/p0f/p0f.fp)
  -o file   - write information to the specified log file
  -s name   - answer to API queries at a named unix socket
  -u user   - switch to the specified unprivileged account and chroot
  -d        - fork into background (requires -o or -s)

Performance-related options:

  -S limit  - limit number of parallel API connections (20)
  -t c,h    - set connection / host cache age limits (30s,120m)
  -m c,h    - cap the number of active connections / hosts (1000,10000)

Optional filter expressions (man tcpdump) can be specified in the command
line to prevent p0f from looking at incidental network traffic.

Problems? You can reach the author at <lcamtuf@coredump.cx>.
```


#### 6.2.8.2 Run p0f on interface


Passively through traffic monitoring while interacting with a webserver:
```
instructor@net1:~$ p0f -i eth0

(in a separate tab)
instructor@net1:~$ wget 10.2.0.2
```

![image](https://github.com/ruppertaj/WOBC/assets/93789685/7ce29a30-2bea-48ec-ae69-7594ef47c725)
p0f1

![image](https://github.com/ruppertaj/WOBC/assets/93789685/b6834ac9-15c0-4916-86d1-1c0af2619dfb)
p0f2


#### 6.2.8.3 Run p0f on a pcap
Run TCPDump and perform the same wget command
```
instructor@net1:~$ tcpdump port 80 -w wget.PCAP

(in a separate tab)
instructor@net1:~$ wget 10.2.0.2
```

Passively determine traffic through reading in a packet capture:
```
instructor@net1:~$ p0f -r wget.pcap
```


#### 6.2.8.2 Output to greppable log file
Sending the output to a greppable log file for analysis:
```
instructor@net1:~$ sudo p0f -r wget.pcap -o /var/log/p0f.log
instructor@net1:~$ sudo nano /var/log/p0f.log
```
```
sudo cat /var/log/p0f.log | grep "mod=syn" | grep subj=cli | grep srv=10.2.0.2/80
```

![image](https://github.com/ruppertaj/WOBC/assets/93789685/4f51f299-6e2a-4768-8145-8ce84703ddb9)
p0f3

```
sudo cat /var/log/p0f.log | grep "mod=syn" | grep srv=10.1.0.2/80 | grep subj=srv
```

![image](https://github.com/ruppertaj/WOBC/assets/93789685/f54510d6-1ef5-49a4-ba82-1df126afb96c)
p0f4

The didn’t filter the results wanted (on purpose for demo), ask the students to troubleshoot this parsing method with you. Listed below is what is wrong:

mod=syn, we are looking for the web server which would respond with a syn+ack, as it isn’t the tcp session initiator.
srv=10.1.0.2/80, the web server should address is 10.2.0.2/80
```
sudo cat /var/log/p0f.log | grep "mod=syn+ack" | grep srv=10.2.0.2/80 | grep subj=srv
```

![image](https://github.com/ruppertaj/WOBC/assets/93789685/5390def9-d9d0-4a90-8a9b-f87f35d07125)
p0f5

It is evident from the output that it is a Linux server but what type of Linux web server? Dig a little deeper with what you know.



Change the module to http response, grep subject to server, and grep for the server equal to the server hosting the web service on port 80 (10.2.0.2/80)
```
sudo cat /var/log/p0f.log | grep "mod=http response" | grep srv=10.2.0.2/80 | grep subj=srv
```
This gives a bit more information and identifies the Ubuntu Linux Distribution.

![image](https://github.com/ruppertaj/WOBC/assets/93789685/e7834ec2-524f-4409-8879-73383d5a0e5d)
p0f6

If we want to view the interaction between the two devices for the entire web request, the following is performed:
```
sudo cat /var/log/p0f.log | grep srv=10.2.0.2/80 | grep cli=10.1.0.2
```
Now you will see the modules associated with the conversation, the MTU, syn, syn+ack, http request, and http response:

![image](https://github.com/ruppertaj/WOBC/assets/93789685/9a0c9865-1483-4543-a53a-8dca9c7c3109)
p0f7


Key Takeaways:

- P0f is an extremely valuable fingerprinting tool that utilizes an array of tcp/ip implementation variances, creating purely passive traffic fingerprinting mechanism to identify hosts behind any incidental TCP/IP communications without interfering in any way.

- Additionally, p0f can generate log files for easy parsing of information, further enhancing the recon effort.

- You can be as granular as needed with p0f analysis as long as there is a basic understanding of TCP conversation structure and specific context being searched for.



References:

[NullByte: Conduct Passive OS Fingerprinting with P0f](https://null-byte.wonderhowto.com/how-to/hack-like-pro-conduct-passive-os-fingerprinting-with-p0f-0151191/)
