# 10-Outcomes
- Describe the use of sniffing tools and methods
- Identify default characteristics for system identification
- Perform Network Traffic Baselining
- Determine traffic flow through protocol communication analysis
- Perform Network Forensics
- Determine network anomalies through traffic analysis


---
## 10.1 Describe the use of sniffing tools and methods
Sniffing tools are used to capture and analyze network traffic passing through a network interface. These tools are valuable for network administrators, security professionals, and researchers to monitor and troubleshoot network issues, analyze network performance, and detect security threats.

Tools: - Wireshark - tcpdump - p0f - tshark - Snort

Sniffing methods refer to techniques and approaches used to capture and analyze network traffic. These methods are employed to monitor, troubleshoot, or analyze network behavior, as well as to detect security threats or vulnerabilities.

Methods: - Enabling Promiscuous Mode - Port Mirroring (SPAN) - Test Access Point (TAP) - On path attacks (MitM) - Active packet sniffing - Passive packet sniffing


---
### 10.1.1 Tools
**Sensors**

Effective network information monitoring is performed through the data collected from multiple sensors on a network. The sensors on a network generate different types of data for specific purposes. A sensor can be many different things, such as a tap to a firewall log. A sensor is simply a mechanism that collects information about the network.

The more sensors on a network, the more man hours you need to monitor those sensors. While there are solutions out there that run a clustered set up where an analyst can monitor a frontend to read data from all the sensor nodes - this does not reduce the man hours required to accurately analyze the data. In large networks this could cost more man hours. In a large environment, multiple node / frontend setups are highly recommended.

---
- Types of Sensors
  - In-line Sensor

![image](https://github.com/ruppertaj/WOBC/assets/93789685/f191cf08-71b4-41ab-bff1-4368ab59d8ae)

    - Placed so the network traffic to be monitored must pass through the sensor enabling it the ability to stop attacks by blocking network traffic.
    - Normal method to deploy an Intrusion Prevention System (IPS).
    - This method has a direct impact on network latency, as all traffic that passes through the sensor has to be processed before continuing on.
  - Out of Band Sensors or Passive Sensors

![image](https://github.com/ruppertaj/WOBC/assets/93789685/4bb1a42c-9e41-4687-8c95-265bcf661315)

    - Monitors on network segments send it a copy of the actual traffic.
    - Deployed to monitor key network locations such as divisions between networks, key segments(activity on a DMZ).
    - Can detect attacks but cannot stop them.
    - Normal method to deploy an Intrusion Detection System (IDS).
    - As this is a copy of the network traffic, this method has zero impact on network latency. All traffic continues on as normal.
    - Malicious traffic that generates an alert will be seconds to minutes behind the actual attack.

---
**TAP (Test Access Point)**

![image](https://github.com/ruppertaj/WOBC/assets/93789685/5a58c4d9-1e2a-4121-ae5b-9530cce64f7f)

A hardware appliance tool that allows you to access and monitor the network when placed in-line. Taps can be used by active and passive sensors. Since taps are in-line, a low quality tap on a busy network segment can lead to network latency. Bad enough latency can be a problem for legitimate authorized users, but also is easily detected by malicious users. This might cause them to change their TTP’s, or find another way to move around the network to avoid detection. Taps are not generally scalable in networks. This is because they can only capture traffic on one network segment. To capture traffic on other network segments more taps must be installed.

There are two common places to locate taps - the edge of the network and the boundaries between network segments (ie before the gateway that leads out of the user lan and before the gateway that leads out of the admin lan, etc).

---
**MitM (Man in the Middle)**

Man-in-the-Middle (MitM) or On-path attacks represent a highly active form of sniffing, requiring the malicious agent to actively intervene and interject themselves between the two communicating devices. In MitM attacks, the attacker employs various techniques such as ARP spoofing, DNS spoofing, HTTPS stripping, rogue access points, and proxy servers to insert themselves into the communication flow. By successfully positioning themselves in the network path between the communicating devices, the attacker gains the ability to intercept and eavesdrop on all transmitted data. This clandestine monitoring can be executed using a variety of sophisticated sniffing tools, enabling the attacker to capture sensitive information, credentials, or other valuable data exchanged between the targeted devices.

---
**SPAN (Switch Port for Analysis)**

![image](https://github.com/ruppertaj/WOBC/assets/93789685/ef251405-5a4a-4cc5-be20-dc33f5d313e0)

A SPAN port (sometimes called a mirror port) is a software feature built into a switch or router that creates a copy of selected packets passing through the device and sends them to a designated SPAN port. Using software, the administrator can easily configure or change what data is to be monitored. Since the primary purpose of a switch or router is to forward production packets, SPAN data is given a lower priority on the device. The SPAN also uses a single egress port to aggregate multiple links, so it is easily oversubscribed.

Oversubscribing is if you have a 1 Gig port that is receiving spanned traffic from several other 1 Gig ports where those ports combined traffic is over 1 Gig, there will be packet loss. Your span port should always be bigger then the average bandwidth being used on the spanned ports.

SPAN may face scalability challenges, particularly in large or high-speed network environments where the volume of network traffic surpasses the capabilities of the switch or monitoring device. When mirroring network traffic to a monitoring port, the switch is tasked with duplicating all frames, leading to increased resource and bandwidth utilization. However, as the switch reaches its capacity, it may prioritize forwarding frames to their intended destinations over creating copies for monitoring purposes. This dynamic allocation of resources can result in potential packet loss, diminishing the effectiveness of network monitoring and analysis. Thus, in such scenarios, SPAN may struggle to provide comprehensive visibility into network traffic, hindering the detection and mitigation of performance issues, security threats, or network anomalies.

![image](https://github.com/ruppertaj/WOBC/assets/93789685/07922dbb-9834-44a0-b350-85e1ee9a29ea)

---
**When to Use SPAN Ports**

There are situations where a TAP is not practical. Consider using SPAN ports for the following exceptions:
- Limited ad hoc monitoring in locations with SPAN capabilities where a network TAP does not currently exist.
- Locations with limited light budgets where the split ratio of a TAP may consume too much light. (Another possibility here would be to use an active TAP or more powerful optics capable of longer distances.)
- Production emergencies where there is no maintenance window in which to install a TAP.
- Remote locations with modest traffic that cannot justify a full-time TAP on the link.
- Access to traffic that either stays within a switch or never reaches a physical link where the traffic can be tapped.
- As a low-cost troubleshooting alternative where links have low utilization.

In summary, both network TAPs and SPAN ports can provide valid access to data if properly positioned.

So TAP where you can, and SPAN where you must.

References:  
[Keysight: Tap vs Span](https://www.keysight.com/us/en/products/network-visibility/network-taps/taps-vs-spans.html)  
[Profitap: Tap vs Span](https://insights.profitap.com/tap-vs-span)


---
## 10.2 Identify default characteristics for system identification
Default characteristics for system identification are foundational properties or attributes inherent to each system within a network environment, enabling their distinct recognition and effective management by administrators and network management tools. These identifiers play a crucial role in tasks such as inventory management, monitoring, troubleshooting, and security enforcement. Whether collected passively or actively, obtaining this information can be challenging due to its subjective nature or the potential risk of detection. However, by meticulously collecting and deciphering the received data, administrators can overcome these challenges and gain valuable insights into networked systems, enhancing overall network visibility and security posture.


---
### 10.2.1 Fingerprinting

![image](https://github.com/ruppertaj/WOBC/assets/93789685/e427816e-967a-4d49-8d28-318c33e578d4)

Differences in RFC implementation across various operating systems and systems architecture provide the foundation for effective fingerprinting, enabling the identification of hosts within a network. Fingerprinting tools, employed either passively through sniffing or actively via scanning, serve as indispensable aids in host identification.

By discerning the operating systems running on specific target machines, attackers gain insights into the exact vulnerabilities ripe for exploitation. Each deployed OS harbors its unique set of bugs and vulnerabilities, facilitating targeted exploitation even before vendors receive bug reports and develop corresponding patches.

Consequently, fortifying defenses against OS fingerprinting holds the potential to thwart zero-day attacks. OS fingerprinting techniques encompass two overarching categories: active and passive methodologies. By understanding and strategically countering these techniques, organizations can bolster their security posture and mitigate potential threats more effectively.

---
- **Active OS fingerprinting**

Active fingerprinting is a lot easier than passive fingerprinting, and is much more likely to return the information an attacker wants. The main reason why an attacker may prefer a passive approach is to reduce the risk of being caught by an IDS, IPS, or a firewall.

It’s still important to harden against active fingerprinting. It’s the easier course of action for an attacker to execute, and they may decide to DoS (denial of service) attack network security systems first, in order to facillitate active fingerprinting.

Active fingerprinting works by sending packets to a target and analyzing the packets that are sent back.
- Tools:
  - Nmap
  - Xprobe2
  - sinfp3
  - Satori
  - Netcat Banner Grabbing

---
- **Passive OS fingerprinting**

Passive fingerprinting sniffs TCP/IP ports, rather than generating network traffic by sending packets to them. Hence, it’s a more effective way of avoiding detection or being stopped by a firewall.

Passive fingerprinting uses a pcap (packet capture) API. In GNU/Linux and BSD/Unix operating systems, pcap can be found in the libpcap library, and for Windows, there’s a port of libpcap called WinPcap.

While sniffing traffic, passive fingerprinting does its best to determine a target machine’s OS by analyzing the initial Time To Live (TTL) in packet IP headers, and the TCP window size in the first packet of a TCP session, which is usually either a SYN (synchronize) or SYN/ACK (synchronize and acknowledge) packet.

- Tools:
  - p0f
  - Ettercap
  - PRADS

---
- **Fingerprinting methods:**
  - IP and TCP implementations using p0f (Passive)
    - Default TTL
    - Fragmentation flags
    - Default packet length of an IP header
    - Windows size
    - IP/TCP options
    - SYN/ACK packets.
    - Open TCP/UDP ports
  - OS detection using NMap (Active)

References:  
[p0f homepage](https://lcamtuf.coredump.cx/p0f3/)  
[p0f documentation](https://lcamtuf.coredump.cx/p0f3/README)  
[nmap OS detection](https://nmap.org/book/osdetect.html)


---
### 10.2.2 Open Ports and Protocols
Banner grabbing open ports and protocols running on device can give you several important pieces of information.

- Service and version number

![image](https://github.com/ruppertaj/WOBC/assets/93789685/a1102091-e603-4481-8dce-2d5c48ac4f5c)

- OS type and version number

  - This could be given by the service directly, or infered by the program thats running. Such as a webserver that identifies iteself as IIS (Internet Information Services), which is a Windows only webserver.

![image](https://github.com/ruppertaj/WOBC/assets/93789685/045962f0-f772-4cec-a1ec-67e660489c1c)

  - This information can not only be used to determine if they are exploitable with further research, but compiled together could give a better picture of the devices function.

For example a machine we have identified as running a Windows OS that has UDP ports 88, 135, 138, 389, 445, 464, 53 and TCP ports 135, 139, 445, 464, 3268, 3269, 53 it would be an extremely strong indicator that this device was a Domain Controller.

- Domain Controller required ports
  - UDP Port 88 for Kerberos authentication
  - UDP and TCP Port 135 for domain controllers-to-domain controller and client to domain controller operations.
  - TCP Port 139 and UDP 138 for File Replication Service between domain controllers.
  - UDP Port 389 for LDAP to handle normal queries from client computers to the domain controllers.
  - TCP and UDP Port 445 for File Replication Service
  - TCP and UDP Port 464 for Kerberos Password Change
  - TCP Port 3268 and 3269 for Global Catalog from client to domain controller.
  - TCP and UDP Port 53 for DNS from client to domain controller and domain controller to domain controller.


---
#### 10.2.2.1 Known Windows and Linux ports
There are indeed several ports shared across Windows, Linux, and macOS systems, such as DNS (53), NTP (123), and RDP (3389). Due to their widespread usage, these ports alone may not provide sufficient evidence to accurately fingerprint operating systems.

However, certain ports are more specific to particular operating systems, and their presence can strongly indicate the OS running on a system. By recognizing these ports, we can gain valuable insights into the underlying operating system. Below, we’ve compiled a list of such ports that are typical for specific OS environments.

- Common Windows service ports
  - 88 - Kerberos and Windows Domain Controllers
  - 135 - Microsoft Remote Procedure Call (RPC) Endpoint Mapper.
  - 137 - NETBIOS Name Service
  - 138 - NETBIOS Datagram Service
  - 139 - NETBIOS Session Service
  - 161/162: SNMP (Simple Network Management Protocol), used for network monitoring and management.
  - 389 - LDAP
  - 445 - Windows Active Directory windows shares or SMB
  - 464 - Kerberos Change/Set Password protocol
  - 593 - RPC over HTTP; domain controller or Exchange server.
  - 636 - LDAP(s)
  - 808 - Microsoft Net.TCP Port Sharing Service
  - 1026 - Microsoft DCOM service
  - 1270 - Microsoft System Center Operations Manager (SCOM)
  - 1433 - Microsoft SQL Server database management system (MSSQL) server
  - 1434 - Microsoft SQL Server database management system (MSSQL) monitor
  - 1503 - Windows Live Messenger (Whiteboard and Application Sharing)
  - 1512 - Microsoft’s Windows Internet Name Service (WINS)
  - 1775 - Microsoft Media Server (MMS)
  - 1801 - Microsoft Message Queuing
  - 1863 - Microsoft Notification Protocol (MSNP)
  - 1900 - Simple Service Discovery Protocol (SSDP) used for Universal Plug and Play (UPnP)
  - 3074 - Xbox LIVE and Games for Windows – Live
  - 3268/3269 - Microsoft Global Catalog service in Active Directory
  - 5355 - Link-Local Multicast Name Resolution (LLMNR)
  - 5357 - Web Services for Devices (WSDAPI)
  - 5358 - WSDAPI Applications to Use a Secure Channel
  - 5985/5986 - WinRM (Windows Remote Management) over HTTP/HTTPS, used for remote management and PowerShell remoting.
  - 6571 - Windows Live FolderShare client
  - 6602 - Microsoft Windows WSS Communication
  - 6891-6900 - Windows Live Messenger (File transfer)
  - 6901 - Windows Live Messenger (Voice)
  - 8172 - Microsoft Remote Administration for IIS Manager
  - 9389 - Microsoft AD web service and Powershell
- Common Linux service ports
  - 22 - SSH. Commonly running by default on Linux
  - 111 - Open Network Computing Remote Procedure Call (ONC RPC, sometimes referred to as Sun RPC)
  - 199 - SNMP Unix Multiplexer (SMUX)
  - 540 - Unix-to-Unix Copy Protocol (UUCP)
  - 631 - Common Unix Printing System (CUPS) administration console (extension to IPP)
  - 694 - Linux-HA high-availability heartbeat
  - 2049 - Network File System (NFS)
  - 4045 - Solaris lockd NFS lock daemon/manager
  - 10000 - Webmin, Web-based Unix/Linux system administration tool (default port)
  - 11111 - RiCcI, Remote Configuration Interface (Redhat Linux)RiCcI, Remote Configuration Interface (Redhat Linux)RiCcI, Remote Configuration Interface (Redhat Linux)
  - 20000 - Usermin, Web-based Unix/Linux user administration tool (default port)

References:  
[IANA Service Names and Port Numbers](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml)


---
#### 10.2.2.2 Ephemeral Ports
Ephemeral ports also known as Random High Ports (RHP) are a possible indicator of the type of OS the machine is using. While the RHP alone isn’t enough to identify the OS of a machine, it can be a useful metric when there are several possible OS’s the traffic could be from.
- Common ranges:
  - The Internet Assigned Numbers Authority (IANA) suggests the range 49152–65535 for dynamic or private ports.
  - Many Linux kernels use the port range 32768–60999.
  - FreeBSD has used the IANA port range since release 4.6. Previous versions, including the Berkeley Software Distribution (BSD), use ports 1024–5000 as ephemeral ports.
  - Microsoft Windows operating systems through Windows XP use the range 1025–5000 as ephemeral ports by default.
  - Windows Vista, Windows 7, Windows 8, Windows 10 and Server 2008 use the IANA range by default.
  - Windows Server 2003 uses the range 1025–5000 by default, until Microsoft security update MS08-037 from 2008 is installed, after which it uses the IANA range by default.
  - Windows Server 2008 with Exchange Server 2007 installed has a default port range of 1025–60000.
  - In addition to the default range, all versions of Windows since Windows 2000 have the option of specifying a custom range anywhere within 1025–65535.
  - Mac OS X (up to 10.6 Snow Leopard): 49152 to 65535
  - macOS (10.7 Lion and later): 49152 to 65535
  - Solaris OS uses the 32768–65535 range.
  - AIX 5.3 and later: 49152 to 65535
  - HP-UX 11.00 and later: 32768 to 65535


---
### 10.2.3 Protocol specific identifiers
Most protocols have key markers in network traffic that makes them easy to identify, and can make malicious software masquerading as legitimate traffic stand out. Common examples are listed below.


---
#### 10.2.3.1 HTTP: User agent strings
Fingerprinting HTTP based on user-agent strings involves analyzing the user-agent header sent by web browsers and other client applications to identify and gather information about the client device, operating system, browser type, and version.

![image](https://github.com/ruppertaj/WOBC/assets/93789685/77f7aa77-29ed-40e3-81ec-cbc8bc694bfb)

User-agent strings are HTTP header fields sent by web browsers and other client applications to identify themselves to web servers. These strings provide information about the client’s operating system, browser type and version, rendering engine, and sometimes additional details such as device type or capabilities.

When a client (such as a web browser) sends an HTTP request to a web server, it includes a user-agent header in the request. This header contains information about the client software, including the name, version, and sometimes additional details such as the operating system and device type.

- Chrome User-Agent Strings:
```
Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36
Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36
Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.53 Safari/537.36
```
Opera User-Agent Strings:
```
Opera/9.80 (X11; Linux i686; Ubuntu/14.10) Presto/2.12.388 Version/12.16
Opera/9.80 (Macintosh; Intel Mac OS X 10.14.1) Presto/2.12.388 Version/12.16
```
Firefox User-Agent Strings:
```
Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0
Mozilla/5.0 (Macintosh; Intel Mac OS X 14.3; rv:123.0) Gecko/20100101 Firefox/123.0
Mozilla/5.0 (X11; Linux i686; rv:123.0) Gecko/20100101 Firefox/123.0
```

References:  
https://useragentstring.com/pages/useragentstring.php


---
#### 10.2.3.2 SSH: Initial connection
SSH fingerprinting during the initial connection involves identifying and analyzing various attributes of the SSH server to uniquely identify it. When a client attempts to connect to an SSH server, the server responds with a banner message containing information about the server, including its SSH version and possibly other details such as the operating system or software version. The client can capture this banner message as part of the initial connection process.

![image](https://github.com/ruppertaj/WOBC/assets/93789685/2be7b143-a952-457f-9e1c-eb1815b6e710)

A lot of new analysts or even sysadmins see traffic is over 22 and assume it is SSH and encrypted so they never actually look at it. Legit SSH traffic is easy to identify after its initial 3 way handshake. Both the client and server identify the version of SSH they are using before the key exchange. Using Wireshark this can be seen.

Ubuntu:
```
SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.7
```

Debian:
```
SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u4
```

Cisco:
```
SSH-2.0-Cisco-1.25
```

Putty:
```
SSH-2.0-PuTTY_Release_0.70
```

Rasbery Pi:
```
SSH-2.0-OpenSSH_7.4p1 Raspbian-10+deb9u3
```

Open SSH:
```
SSH-2.0-OpenSSH_5.3
```

References:  
https://goteleport.com/blog/ssh-handshake-explained/


---
#### 10.2.3.3 NetBIOS Name Service
NetBIOS Name Service (NBNS) is a networking protocol used in NetBIOS over TCP/IP (NBT) networking environments. It provides a method for resolving NetBIOS names to IP addresses. Systems running NetBIOS is almost guaranteed to be Windows of some sort. But typically the naming convention used in the naming can indicate what sort of system it is such as a workstation, file server, or Domain Controller.

The NetBIOS naming convention is a set of rules and guidelines used to assign names to devices and services in a NetBIOS network. NetBIOS names are alphanumeric identifiers that are up to 15 characters long and are used to identify computers, printers, shared resources, and other network entities.
- NetBIOS names can be up to 15 characters long, consisting of alphanumeric characters (A-Z, 0-9) and certain special characters such as hyphens (-). NetBIOS reserves the 16th character as a NetBIOS Suffix.
- NetBIOS names are case-insensitive, meaning that upper and lower case characters are treated as equivalent. For example, "COMPUTER1" and "computer1" would be considered the same NetBIOS name.
- NetBIOS names must be unique within the scope of the NetBIOS network. Each device or service on the network should have a unique NetBIOS name to avoid naming conflicts.
- NetBIOS names may contain only certain characters, including alphanumeric characters and certain special characters such as hyphens (-). Special characters like ! @ # $ % ^ & * ( ) - = + { } [ ] ; : ' " , < . > / ? \ are not allowed.
  - Periods (.) are allowed, but the name cannot start with a period.
- Create discriptive workstation names that reflect the purpose of the computer.
- The 16th character is reserved for a special purpose called the NetBIOS suffix.
  - 00: Workstation Service (default for client computers)
  - 03: Windows Messenger service
  - 06: Remote Access Service
  - 20: File Service (also called Host Record)
  - 21: Remote Access Service client
  - 1B: Domain Master Browser – Primary Domain Controller for a domain
  - 1C: Domain Controller
  - 1D: Master Browser

```
FILESERVER: Used to identify a file server on the network.
PRINTER1: Used to identify a printer connected to the network.
WORKSTATION1: Used to identify a user's workstation or computer.
MAILSERVER: Used to identify a mail server or email service.
DOMAINCTRL: Used to identify a domain controller in an Active Directory environment.
ROUTER1: Used to identify a network router or gateway device.
SWITCH1: Used to identify a network switch or hub.
DNS1: Used to identify a Domain Name System (DNS) server.
WEB1: Used to identify a web server hosting websites or web applications.
DATABASE: Used to identify a database server or database management system.
BACKUP: Used to identify a backup server or backup storage device.
LDAP: Used to identify a Lightweight Directory Access Protocol (LDAP) server.
VPN1: Used to identify a Virtual Private Network (VPN) server.
FIREWALL: Used to identify a network firewall or security appliance.
NAS1: Used to identify a Network-Attached Storage (NAS) device.
```

References:  
https://resources.infosecinstitute.com/topic/l-7-protocol-analysis/  
https://blogs.keysight.com/blogs/tech/nwvs.entry.html/2021/06/02/what_s_in_an_applica-zyu2.html  
https://learn.cnd.ca.gov/Microsoft/NamingConvention/#naming-standards-for-servers  
https://en.wikipedia.org/wiki/NetBIOS


---
## 10.3 Perform Network Traffic Baselining
Performing network traffic baselining involves establishing a benchmark or baseline for normal network traffic patterns, usage, and performance metrics. This baseline can then be used for comparison to detect anomalies, identify trends, and troubleshoot network issues.


---
### 10.3.1 What is Baselining?
Baselining is the process of establishing a benchmark or reference point for normal behavior, performance, or characteristics of a system, process, or environment. It involves collecting data over a period of time to create a baseline that represents typical or expected behavior. Baselining is commonly used in various fields, including IT, network management, performance monitoring, and cybersecurity, to measure, analyze, and detect deviations or anomalies from the established baseline. By comparing current data to the baseline, organizations can identify trends, troubleshoot issues, optimize performance, and enhance security posture. Overall, baselining provides valuable insights into the normal operation of systems and helps in decision-making, planning, and problem-solving.

Network Traffic Baselining is a set of metrics used to define the normal working conditions of an network infrastructure. Basically a "snapshot" of the network during a given time frame.

- No Industry standard
  - Each organisation can and will have different set of standards.
- Seven days of monitoring a given network establish your initial "snapshot".
  - Generally you want to snapshot every typical work day and night.

What are some of the "like to haves" you should have beforehand?
- Logical network map
- What devices are on the network - Inventory of Servers, workstations, routers, switches, etc. What should be on my network!
- What ports and protocols are being used - What ports and protocols are utilized in my environment? Which ones should I never see?


---
### 10.3.2 Network Baseline Objectives
- Current state and utilization of the network
  - Understanding baseline network traffic patterns and usage trends helps organizations make informed decisions about resource allocation and capacity management. By aligning resources with actual usage patterns, organizations can optimize resource allocation, improve network efficiency, and reduce unnecessary costs.
- Determines the current state of your network
  - Baselining helps assess the current performance of your network by analyzing metrics such as bandwidth utilization, latency, packet loss, and throughput. Understanding the current state of network performance allows organizations to identify areas for improvement, troubleshoot issues, and ensure optimal network operation.
  - Baselining provides insights into the utilization of network resources, including routers, switches, servers, and bandwidth. By monitoring resource usage patterns, organizations can identify over-utilized or under-utilized resources and take appropriate actions to balance the workload, optimize resource allocation, and avoid bottlenecks.
  - Baselining helps assess the security posture of your network by monitoring for suspicious or anomalous behavior. By establishing a baseline of normal network activity, organizations can detect deviations that may indicate security threats, such as malware infections, unauthorized access attempts, or data breaches. This allows organizations to respond promptly to security incidents and strengthen their network defenses.
- Ascertain the current utilization of network resources
  - Baseline data provides insights into opportunities for network optimization and tuning. By analyzing trends and patterns in network traffic, administrators can identify areas for improvement, fine-tune network configurations, and optimize the performance of critical applications and services.
- Peak network times and port/protocol use
  - By correlating peak network times with port and protocol usage, organizations can optimize resource allocation to meet demand. For example, during peak hours, administrators may prioritize critical applications or services by allocating more bandwidth or server resources to ensure smooth operation. Understanding which ports and protocols are most active during peak times helps in making informed decisions about resource allocation.
- Identify normal vs peak network traffic time frames
  - Understanding normal versus peak network traffic patterns helps organizations effectively plan and allocate resources. By identifying peak usage periods, such as during business hours or specific events, organizations can ensure that network infrastructure, bandwidth, and computing resources are appropriately provisioned to handle increased demand without degradation in performance.
- Verify port / protocol usage
  - Baseline data helps in identifying which ports and protocols are actively used in the network. By analyzing network traffic over time, administrators can determine which ports and protocols are frequently accessed and which ones are rarely or never used. This information is valuable for network security and policy enforcement.
  - Baseline data serves as a reference point for detecting unauthorized or unexpected port and protocol usage. Any deviation from the established baseline may indicate the presence of unauthorized applications, services, or network traffic that could pose security risks or compliance violations.


---
### 10.3.3 Perform Baseline
1. Preparation:
- Network Diagram:
  - Create or obtain a comprehensive network diagram that illustrates the topology, connections, and interrelationships between network devices.
  - This diagram serves as a visual reference for understanding the network infrastructure and identifying potential traffic flow paths.
- Known Servers, Hosts, and Networking Devices:
  - Compile a list of all known servers, hosts, and networking devices present in the network environment.
  - This includes devices such as routers, switches, firewalls, servers, workstations, printers, and other networked equipment.
  - Documenting this information helps in identifying the origin and destination of network traffic flows.
- Known IPs, Ports, and Protocols:
  - Document the IP addresses, ports, and protocols associated with each known server, host, or networking device.
  - This information provides insight into the expected communication patterns and traffic flows within the network.
  - Understanding the standard IP/port/protocol combinations used by each device facilitates the identification of abnormal or unauthorized traffic.
- Known Forbidden IPs, Ports, and Protocols:
  - Identify any IPs, ports, or protocols that are explicitly forbidden or restricted within the network environment.
  - This could include blocking access to certain external IP addresses, prohibiting specific ports for security reasons, or restricting the use of certain protocols that pose security risks.
  - Documenting forbidden IPs, ports, and protocols helps in identifying and mitigating unauthorized or malicious traffic.
- Known Traffic "Flows":
  - Define and document the expected traffic "flows" or communication paths between different network entities.
  - This includes identifying common communication patterns, such as client-server interactions, peer-to-peer connections, internal network traffic, and external internet traffic.
  - Understanding the expected traffic flows helps in distinguishing between normal and abnormal network behavior during traffic flow analysis.

2. Scope and Objectives:
- What traffic/protocols to capture?
  - Determine the specific types of traffic and protocols to capture during the analysis.
  - This includes identifying critical applications, services, or protocols that are essential for business operations or pose security risks if compromised.
  - Examples may include HTTP/HTTPS for web traffic, DNS for domain name resolution, SMTP for email communication, and SSH for secure remote access.
  - Additionally, consider capturing traffic associated with known vulnerabilities or suspicious activities to detect potential security threats.
- Which network segments?
  - Define the network segments or subnets to include in the traffic capture.
  - This involves identifying the areas of the network where traffic analysis is needed, such as LAN, WAN, DMZ, or specific departmental networks.
  - Consider the network architecture, traffic patterns, and critical assets when determining the scope of network segments to analyze.
  - It may be necessary to capture traffic from multiple segments to obtain a comprehensive view of network activity.
- Which days?
  - Specify the days of the week during which traffic capture will occur.
  - Consider factors such as business hours, peak usage periods, and scheduled maintenance windows when selecting the days for analysis.
  - Capturing traffic over a representative period, including weekdays and weekends, ensures that the analysis captures variations in network activity and usage patterns.
- What times?
  - Determine the specific times of day for traffic capture.
  - This includes identifying peak usage hours, off-peak periods, and times when network maintenance or updates are scheduled.
  - By capturing traffic at different times of the day, organizations can assess variations in network activity, identify trends, and detect anomalies or deviations from normal behavior.
  - Additionally, consider time zones and geographical locations to ensure comprehensive coverage of network activity across distributed environments.


---
## 10.4 Determine traffic flow through protocol communication analysis
Analyzing traffic flow through protocol communication involves examining the interactions and data exchanges between network devices and services using various protocols.

- Identify the protocols being used in the network traffic.
  - This can include common protocols like HTTP, HTTPS, DNS, TCP, UDP, ICMP, FTP, SSH, and others.
  - Protocol identification can be done using packet analysis tools like Wireshark or network monitoring solutions.
- Capture network traffic using packet capture tools or network monitoring solutions.
  - Using tools like sensors and traffic capture software (Wireshark, tshark, or tcpdump).
  - Ensure that the capture includes a representative sample of network traffic, covering different times of day, network segments, and types of communication.
- Analyze the captured traffic to understand the flow of data between network devices and services.
  - Look for patterns in protocol usage, such as which protocols are most commonly used, the frequency of communication, and the volume of data exchanged.
- Examine individual network sessions to understand the sequence of events and data exchanges between devices.
  - This includes analyzing TCP sessions for connection establishment, data transfer, and connection termination, as well as UDP sessions and other non-connection-oriented protocols.
- Visualize traffic flows using flow analysis tools or network visualization techniques.
  - This can help identify communication patterns, relationships between network devices, and potential bottlenecks or anomalies in traffic flow.
- Study the behavior of different protocols in the network, including their characteristics, typical usage patterns, and any deviations from expected behavior.
  - Pay attention to protocol-specific parameters, such as request/response patterns, message formats, and error handling mechanisms.
- Filter network traffic based on specific protocols, IP addresses, ports, or other criteria to focus on relevant communication patterns. This can help isolate traffic flows of interest and simplify analysis.
- Look for anomalies or irregularities in traffic flow that may indicate security threats, performance issues, or network misconfigurations.
  - This includes detecting unusual protocol usage, unexpected traffic patterns, or suspicious behavior that deviates from normal communication patterns.
- Use traffic flow analysis to identify opportunities for performance optimization, such as optimizing protocol configurations, adjusting network settings, or implementing traffic shaping policies to prioritize critical traffic.
- Document findings from traffic flow analysis, including observations, insights, and recommendations for improvement. Prepare reports summarizing key findings, trends, and actionable insights for stakeholders and decision-makers.


---
### 10.4.1 Using Wireshark
Wireshark is a network protocol analyzer. It allows you to analyze your network traffic and protocols communicating through your network. It is used across many commercial and non-profit enterprises, government agencies, and educational institutions.

Wireshark stands out not only for its familiar capture filters akin to tcpdump but also for its distinctive display filters tailored specifically to Wireshark’s capabilities. These filters are indispensable tools within Wireshark, empowering users to sift through vast capture files containing millions of packets and extract only the pertinent traffic they seek. The crux lies in discerning which filters to employ and how to wield them effectively.

1. Firstly, we must pinpoint the precise type of traffic we aim to isolate within the capture. This necessitates a clear understanding of the network’s architecture and the specific protocols at play.

2. Secondly, we delve deeper to grasp how this targeted traffic communicates—whether it’s through well-known protocols like HTTP, DNS, or bespoke communication methods specific to the network’s infrastructure.

3. Lastly, armed with this insight, we craft a tailored filter to fulfill our objectives. Wireshark’s rich array of display filters, coupled with a nuanced understanding of network protocols, enables us to construct filters that precisely capture the desired traffic while excluding extraneous noise.

By meticulously following these steps, Wireshark users can harness the full potential of display filters to unravel complex network traffic patterns and glean actionable insights from their packet captures.

References:  
[Wireshark Tutorial](https://www.wireshark.org/docs/wsug_html_chunked/ChapterIntroduction.html)


---
#### 10.4.1.1 Common Wireshark Display filters
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
  - ECN: `ip.dsfield.ecn > 0`, `ip.dsfield.ecn == 2`
  - Flags: `ip.flags.rb == 1`, `ip.flags.df == 1`
  - Fragmentation: `(ip.flags.mf == 1) || (ip.frag_offset > 0)`
  - TTL: `ip.ttl == 64`, `ip.ttl == 128`, `ip.ttl < = 64 && ip.ttl > 30 && !(ip.ttl > 64)`
  - Protocol: `ip.proto == 1`, `ip.proto == 6`, `ip.proto == 17`
  - 6-in-4 or 6-to-4 encapsulation: `ip.proto == 41`
- IPv6 Filters:
  - Traffic Class: `ipv6.tclass > 0`, `ipv6.tclass == 0xe0`
  - Next Header: `ipv6.nxt == 6`, `ipv6.nxt == 17`, `ipv6.nxt == 58`
  - 4-in-6 encapsulation: `ipv6.nxt == 4`
- TCP Specific Filters:
  - TCP Offset: `tcp.hdr_len == 32`, `tcp.hdr_len > 20`
  - TCP Flags:
    - Individual Flags: `tcp.flags.syn == 1`, `tcp.flags.ack == 0`, `tcp.flags.urg == 1`, `tcp.flags.reset == 1`
    - Flag Combinations: `tcp.flags == 0x002`, `tcp.flags == 0x012`, `tcp.flags == 0x010`, `tcp.flags == 0x018`
  - Urgent Pointer: `tcp.urgent_pointer > 0`
- **HTTP specific filters**:
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
  - Directory listing: ftp.request.command == "LIST"
- Wildcard string filters:
  - `data contains "String"` - generic filter used to match packets based on the presence of specific data within the packet payload.
  - `ip contains "String"` - specifically targets the IP (Internet Protocol) layer for payload.
  - `http contains "String"` - specifically targets the HTTP (Hypertext Transfer Protocol) payload.
- Using the `not` feature:
  - Generally you can use any filter used above and surround it like this:
  - `!(filter)`
- Conjoining filter expressions:
  - both conditions must be true: `and` or `&&`
  - either the first condition or the second condition is true: `or` or `||`

References:  
https://wiki.wireshark.org/DisplayFilters


---
#### 10.4.1.2 Protocol Hierarchy
Wireshark’s Protocol Hierarchy is a feature that provides a hierarchical view of the different network protocols present in captured packet data. This view allows users to understand the structure and composition of network traffic, showing how various protocols are encapsulated within each other.

To see this, select menu:[Statistics>Protocol Hierarchy].

![image](https://github.com/ruppertaj/WOBC/assets/93789685/04c2a55c-4b2a-47ec-9044-411e0f9aa5c2)

- Alone: This will tell you the most used protocols. Depending on what it is, seeing a lot of it can be very suspicious.
- With baseline: This allows you to compare so that major protocol differences can be seen. The benefit of this what may be a normal and/or acceptable protocol is being used in a different manner than intended. This traffic may not be noticed if you only have the compromised pcap.


---
#### 10.4.1.3 Conversations
Wireshark’s "Conversations" feature provides a comprehensive overview of the communications between different network hosts captured during a packet capture session. This feature organizes captured data into conversations based on source and destination IP addresses and port numbers, allowing users to analyze the flow of traffic between specific hosts and services.

To see this, select menu:[Statistics>Conversations].

![image](https://github.com/ruppertaj/WOBC/assets/93789685/b710e57f-6ab6-4d56-bf68-19c016cc5f6a)

- Alone: This will provide you with the computers that are talking to each other from most talkative to least. If there is a disparate amount of traffic between two machines that may be suspicious.
- With baseline: This will allow you to see if there is new conversations happening between computers that were not or should not be talking to each other. While it does not always provide any additional information it is a good place to check.


---
#### 10.4.1.4 Endpoints
In Wireshark, the "Endpoints" feature provides a summary of all the network endpoints involved in the captured traffic. An endpoint represents a unique network address, typically identified by an IP address and port number, and can be either a source or destination of network communication.

![image](https://github.com/ruppertaj/WOBC/assets/93789685/11e4bba9-d78d-4b71-bb89-0e6ced5c4b19)

To see this, select menu:[Statistics>Endpoints].
- Alone: This allows you to see each computer and it’s statistics individually. If one has a lot more traffic than the others the endpoint should be looked at.
- With baseline: This should allow two things to happen. First, any new computers should be seen. Second, computers that were there already can have their statistics compared to determine if the amount of traffic is abnormal.


---
#### 10.4.1.5 I/O Graph
The I/O Graph feature in Wireshark allows users to visualize network traffic patterns and trends over time. It provides a graphical representation of various statistics and metrics extracted from captured packet data, enabling users to analyze network performance, monitor traffic patterns, and identify anomalies.

To see this, select menu:[Statistics>IO Graph].

![image](https://github.com/ruppertaj/WOBC/assets/93789685/8f21accd-6815-43e5-b85e-f220bb77c8c7)

- Alone: This will reveal time periods during the capture with high traffic. Very large amounts of traffic in a small amount of time may be suspicious.
- With Baseline: Your baseline will show normal levels of traffic and time periods where higher levels of traffic are normal. Comparing the two will show where the traffic is too high and if there is unusual times for traffic, such as the middle of the night for a company that only has 9-5 workers.


---
#### 10.4.1.6 IPv4 and IPv6 Statistics
In Wireshark, you can analyze IPv4 and IPv6 traffic and view statistics related to these protocols.

To see this, select menu:[Statistics>IPv4 Statistics> All Addresses] or select menu:[Statistics>IPv6 Statistics> All Addresses]

![image](https://github.com/ruppertaj/WOBC/assets/93789685/af37059a-7b04-40f9-9794-2389a0270af3)

- Alone: This gives a packet breakdown per address for all options. It provides much of the same information as conversations and endpoints with some additional points as well. This is useful to see certain types of traffic to or from a single box.
- With Baseline: The numbers will not be exact like much of the options you should look at. However, there should not be drastic change in type or location. ie. if most of the traffic from your top box is email, dns, and web, then traffic drastically drops making it the least talkative box with mostly ssh traffic then it is something to look at.


---
#### 10.4.1.7 File Magic Numbers
File magic numbers, also known as file signatures or magic bytes, are unique sequences of bytes located at the beginning of a file that indicate its file type or format. These magic numbers are used by operating systems and applications to identify the type of file and determine how it should be processed or interpreted.

- In computer programming, a magic number refers to one of the following:
  - A singular value whose significance is not immediately evident or which appears multiple times in code and would ideally be substituted with a named constant.
  - A fixed numerical or textual value employed for recognizing a particular file format or protocol.
  - An exceptional, distinct value that is highly unlikely to be confused with other interpretations.

---
Magic Number: Signatures:
- Scripts and Executables:
  - DOS EXE/DLL - MZ - `0x4D 5A`
    - MZ executable files may also have the string phrase `This program cannot be run in DOS mode.`
  - Windows 32 exe - MZP - `0x4D 5A 50`
  - Linux Executable and Linkable Format - .ELF - `0x7F 45 4C 46`
  - "shebang" - "#!" - `0x23 21` (Path to interpreter will follow)
  - Postscript files - "%!" - `0x25 21`
- DLL files:
  - Can use either MZ - `0x4D 5A` or MZP - `0x4D 5A 50`
- Image Files:
  - GIF images:
    - GIF89a - `0x47 49 46 38 39 61`
    - GIF87a - `0x47 49 46 38 37 61`
  - JPEG:
    - Start with `0xFF D8` (FFDB) (FFE0) (FFEE) (FFE1)
    - Ends with `0xFF D9`
  - BMP - BM - `0x42 4D`
  - PNG - %PNG - `0x89 50 4E 47 0D 0A 1A 0A`
  - Tiff -
    - Intel: II `0x49 49`
    - Motorola: MM `0x4D 4D`
- PDF - %PDF - `0x25 50 44 46`
- Microsoft Office Documents (DOCX, XLSX, PPTX): `0x50 4B 03 04`
- MCompiled Java
  - `0xCA FE BA BE`
  - `0xCA FE D0 0D` (Mach-O)
  - `0xFE ED FE ED` (JKS)
- Audio:
  - MP3: ID3 `0x49 44 33`
  - MP4: …​ftyp `0x00 00 00 18 66 74 79 70`
- Video:
  - WAV Audio File: RIFF `52 49 46 46`
  - AVI Video File: RIFFFT `52 49 46 46 54`
  - MPEG Video: `00 00 01 BA`
- Compressed Files:
  - ZIP: PK `0x50 4B 03 04`
  - TAR Archive: `0x75 73 74 61 72`
  - GZIP Archive: `0x1F 8B 08`
  - RAR Archive: `0x52 61 72 21 1A 07 00`

---
To view magic numbers using Wireshark:

- Capture Traffic: Start by capturing network traffic using Wireshark. Ensure that you capture the traffic containing the file transfers or protocol exchanges you’re interested in analyzing.
- Apply Filters: If you’re interested in analyzing specific types of traffic, you can apply display filters in Wireshark to narrow down the packets displayed. For example, if you’re looking for HTTP traffic, you can use a display filter like "http" to only show packets related to HTTP.
- Use Wireshark Find Feature: In Wireshark click on the find button (typically the magnifying glass icon). Select to search for "Hex value". In the field, enter the Hex value of the magic number. This will find every match of the Hex value but will likely find alot of false positives.
- View Packet Details: Select a packet of interest from the packet list in Wireshark, and then examine the packet details in the middle pane. Look for the "Packet Bytes" section, which displays the hexadecimal representation of the packet’s payload. Analyze Payload: Analyze the payload of the packet to identify potential magic numbers. Look for byte sequences that match known magic numbers for file formats or protocols. You can refer to documentation or resources online to find the magic numbers associated with specific file formats or protocols.
- Follow TCP Stream: If you’re analyzing TCP traffic, Wireshark provides a "Follow TCP Stream" feature that allows you to reconstruct and view the entire TCP stream for a particular conversation. This can be useful for analyzing the payload of TCP packets in sequence and identifying magic numbers.
- Export Payload: You can export the payload of packets containing potential magic numbers to a file for further analysis using Wireshark’s "Export Packet Bytes" feature. This allows you to examine the payload in more detail using external tools or utilities.

References:  
https://www.garykessler.net/library/file_sigs.html  
https://en.wikipedia.org/wiki/List_of_file_signatures  
https://en.wikipedia.org/wiki/Magic_number_%28programming%29  
[Executable File Format](https://www.fileformat.info/format/exe/corion-mz.htm)


---
#### 10.4.1.8 Additional Wireshark Filters
- Following Protocol Streams:
  - In Wireshark, you can follow protocol streams to examine the communication between hosts using various protocols, including TCP, UDP, and others.
  - Analyze → Follow →
    - TCP Stream (ctrl+alt+shift+T)
    - UDP Stream (ctrl+alt+shift+U)
    - TLS Stream (ctrl+alt+shift+S)
    - HTTP Stream (ctrl+alt+shift+H)

---
Apply as filter options:
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
  e. .. or not Selected: This option applies a filter based on the attribute or value of packets that are not currently selected in the packet list pane, in combination with other attributes or values. Additional or conditional filters to exclude from view.
  f. …​and not Selected: This option combines the attribute or value of packets that are not currently selected in the packet list pane with the attribute or value of other packets. Packets matching each condition is excluded.

---
- Creating additional Columns in the Packet List view:
  - Drag and drop fields from the Packet Details View to the columns bar.
  - The rows can be dragged and dropped to arrange them in the desired order.

References:  
https://www.wireshark.org/docs/wsug_html_chunked/ChAdvFollowStreamSection.html


---
## 10.5 Perform Network Forensics
Performing network forensics involves systematically investigating and analyzing network traffic and activities to uncover evidence of security incidents, breaches, or unauthorized activities within a networked environment.

- Preparation:
  - Define the scope and objectives of the network forensics investigation, including the type of incident being investigated, the timeframe of the incident, and the resources available for the investigation.
  - Obtain necessary permissions and legal authorization to conduct the investigation, ensuring compliance with applicable laws, regulations, and organizational policies.
  - Identify and allocate resources, tools, and expertise required for the investigation, such as network monitoring solutions, packet capture tools, forensic analysis software, and skilled personnel.
- Data Collection:
  - Capture and collect relevant data sources that may contain evidence of security incidents, such as network traffic, log files, system logs, firewall logs, intrusion detection system (IDS) alerts, and other digital artifacts.
  - Use packet capture tools (e.g., Wireshark) or network monitoring solutions to capture network traffic from relevant network segments, ensuring that all packets are captured in a forensically sound manner.
  - Preserve the integrity of collected data by maintaining chain of custody, documenting the collection process, and ensuring that no data is tampered with or altered during the collection process.
- Analysis:
  - Analyze captured network traffic and digital artifacts to identify suspicious or malicious activity within the network. This may include unauthorized access attempts, malware infections, data exfiltration, command and control communications, and other indicators of compromise (IOCs).
  - Use network analysis tools and techniques to reconstruct network sessions, extract relevant metadata, and correlate events across multiple data sources to gain a comprehensive understanding of the security incident.
  - Examine network protocols, packet contents, and communication patterns to uncover evidence of unauthorized activities and identify potential sources of compromise or vulnerability within the network.
- Timeline Reconstruction:
  - Reconstruct a timeline of events leading up to and following the security incident by correlating timestamps from various data sources, including network traffic, logs, and system activities.
  - Identify the sequence of events, including the initial compromise, lateral movement within the network, data exfiltration, and other malicious activities, to understand the scope and impact of the security incident.
  - Document key findings, observations, and significant events in the investigation timeline to provide a chronological narrative of the security incident for reporting and analysis purposes.
- Forensic Analysis:
  - Conduct in-depth forensic analysis of captured network traffic and digital artifacts to identify and analyze evidence of unauthorized access, data tampering, or other malicious activities.
  - Use forensic analysis techniques to recover deleted files, extract hidden information, and reconstruct file transfers or communications conducted over the network to uncover additional evidence of the security incident.
  - Preserve and document forensic evidence in a forensically sound manner, ensuring that it maintains its integrity and admissibility in legal proceedings and follow-up investigations.
- Reporting and Documentation:
  - Compile a comprehensive report detailing the findings, analysis, and conclusions of the network forensics investigation. Include a summary of the security incident, timeline of events, analysis of forensic evidence, and recommendations for remediation and mitigation to prevent similar incidents in the future.
  - Present the report to stakeholders, including management, legal counsel, and law enforcement, as necessary, and provide support for any follow-up actions or investigations based on the findings of the investigation.
  - Document all aspects of the network forensics investigation, including the methodology, data sources, analysis techniques, findings, and conclusions, in a thorough and transparent manner for future reference or legal proceedings.


---
### 10.5.1 Methodologies
Understanding frameworks such as Lockheed Martin’s Cyber Kill Chain and Mitre’s ATT&CK framework provides cyber professionals with invaluable insights into the tactics, techniques, and procedures (TTPs) utilized by adversaries, enabling proactive threat detection and mitigation. These frameworks serve as mission-agnostic tools, catering to both industry and government sectors, facilitating comprehensive analyses and efficient communication of insights. By categorizing adversary behavior and detailing how defensive capabilities counter threats, these frameworks establish common ground for information sharing and operational collaboration. In an ever-evolving cyber landscape, where threats continually mutate and diversify, such frameworks play a crucial role in fostering a unified approach to cybersecurity, enabling organizations to adapt and respond effectively to emerging challenges.

Mitre’s D3FEND complements this knowledge by offering defensive strategies to counteract offensive techniques, while the Diamond model offers a structured approach to analyzing cyber threats by incorporating the motives, capabilities, infrastructure, and victims. Additionally, familiarity with the NIST Cybersecurity Framework equips professionals with a comprehensive framework for organizing and prioritizing cybersecurity efforts, ensuring alignment with industry standards and best practices. Overall, these frameworks collectively empower cyber professionals to effectively defend against evolving cyber threats, enhance organizational resilience, and safeguard critical assets and information.


---
#### 10.5.1.1 Hacker Methodology
Understanding hacker methodology is crucial for cyber professionals because it provides insights into how adversaries operate in cyberspace. By comprehending the tactics, techniques, and procedures (TTPs) employed by hackers, cybersecurity professionals can proactively detect, prevent, and respond to cyber threats. This understanding allows for the development of robust defense strategies, the identification of vulnerabilities within systems, and the implementation of appropriate security measures to safeguard networks, data, and infrastructure. Moreover, familiarity with hacker methodologies enables professionals to stay ahead of emerging threats, adapt their defenses accordingly, and continuously improve their cybersecurity posture to mitigate risks effectively.

- [Footprinting](https://www.greycampus.com/opencampus/ethical-hacking/footprinting-methodology) - Footprinting and reconnaissance represent the preparatory stage in which an attacker meticulously gathers information about the target before initiating an attack. During this phase, the attacker constructs a comprehensive profile of the target entity, acquiring details such as its IP address range, domain names, and employee roster. This reconnaissance serves as a crucial precursor to system hacking by unveiling potential vulnerabilities. For instance, details found on the organization’s website, like employee biographies or a directory, can be exploited for social engineering tactics. Additionally, conducting a Whois query online can yield valuable insights into the organization’s associated networks and domain names. The scope of footprinting extends to encompass various aspects of the target entity, including its clients, workforce, operational procedures, network infrastructure, and systems.
  - Network Footprinting - This is the process of collecting information related to a target network. Information like Domain name, subdomains, network blocks, IP addresses of reachable systems, IDSes running, Rouge websites/private websites, TCP & UDP services running, VPN points, networking protocols, ACL’s, etc are collected.
  - Collect System Information - The information related to the target system like user and group names, system banners, routing tables, SNMP information, system names etc are collected using various methods.
  - Collect Organization’s information – The information related to employee details, organization website, Location details, security policies implemented, the background of the organization may serve as an important piece of information for compromising the security of the target using direct or social engineering attacks.
- [Network scanning](https://www.greycampus.com/opencampus/ethical-hacking/network-scanning) - is used to recognize available network services, discover and recognize any filtering systems in place, look at what operating systems are in use, and to protect the network from attacks. It can also be used to determine the overall health of the network.
  - Port Scanning – detecting open ports and services running on the target.
  - Network Scanning – IP addresses, Operating system details, Topology details, trusted routers information etc
  - Vulnerability scanning – scanning for known vulnerabilities or weakness in a system
  - Scanning Methodology
    - Check for Live Systems: Ping scan checks for the live system by sending ICMP echo request packets. If a system is alive, the system responds with ICMP echo reply packet containing details of TTL, packet size etc.
    - Check for Open Ports: Port scanning helps us to find out open ports, services running on them, their versions etc.
      - Tools: Nmap
    - Banner Grabbing - a process of collecting information like operating system details, the name of the service running with its version number etc.
      - Tools: netcat or telnet
    - Vulnerability scanning - automated scanners scan the target to find out vulnerabilities or weakness in the target organization which can be exploited by the attackers. Vulnerabilities include application vulnerabilities, configuration vulnerabilities, network vulnerabilities, operating system vulnerabilities etc.
      - Tools: Nessus, Acunetix
    - Draw Network Diagrams - With the information gathered, the attacker can come up with a network diagram which might give him information about network and architecture of the target organization helping him to identify the target easily
      - Tools: Network View, Opmanager etc
- [Network Enumeration](https://www.greycampus.com/opencampus/ethical-hacking/enumeration-and-its-types) - is a computing activity in which usernames and info on groups, shares, and services of networked computers are retrieved. It should not be confused with network mapping, which only retrieves information about which servers are connected to a specific network and what operating system runs on them. Network enumeration is the discovery of hosts or devices on a network. Network enumeration tends to use overt discovery protocols such as ICMP and SNMP to gather information. It may also scan various ports on remote hosts for looking for well known services in an attempt to further identify the function of a remote host. The next stage of enumeration is to fingerprint the operating system of the remote host.
  - Types of information enumerated by intruders:
    - Network Resource and shares
    - Users and Groups
    - Routing tables
    - Auditing and Service settings
    - Machine names
    - Applications and banners
    - SNMP and DNS details
    - NetBIOS
    - LDAP
    - NTP
    - SMTP
  - Techniques for Enumeration
    - Extracting user names using email ID’s
    - Extract information using the default password
    - Brute Force Active Directory
    - Extract user names using SNMP
    - Extract user groups from Windows
    - Extract information using DNS Zone transfer
  - Services and Port to Enumerate
    - TCP 53: DNS Zone transfer
    - TCP 135: Microsoft RPC Endpoint Mapper
    - TCP 137: NetBIOS Name Service
    - TCP 139: NetBIOS session Service (SMB over NetBIOS)
    - TCP 445: SMB over TCP (Direct Host)
    - UDP 161: SNMP
    - TCP/UDP 389: LDAP
    - TCP/UDP 3368: Global Catalog Service
    - TCP 25: Simple Mail Transfer Protocol (SMTP)
- [Vulnerability Assessment](https://www.greycampus.com/blog/information-security/owasp-top-vulnerabilities-in-web-applications) - It is the process of identifying vulnerabilities in the computer systems, networks, and the communication channels. It is performed as a part of auditing and also to defend the systems from further attacks. The vulnerabilities are identified, classified and reported to the authorities so that necessary measures can be taken to fix them and protect the organization.
  - Injection - A code injection happens when an attacker sends invalid data to the web application with the intention to make it do something that the application was not designed/programmed to do.
  - Broken Authentication - A broken authentication vulnerability can allow an attacker to use manual and/or automatic methods to try to gain control over any account they want in a system – or even worse – to gain complete control over the system.
  - Sensitive Data Exposure - Sensitive data exposure is one of the most widespread vulnerabilities on the OWASP list. It consists of compromising data that should have been protected.
  - XML External Entities (XXE) - XML External Entity attack is a type of attack against an application that parses XML input. This attack occurs when XML input containing a reference to an external entity is processed by a weakly configured XML parser.
  - Broken Access control - In website security, access control means putting a limit on what sections or pages visitors can reach, depending on their needs. For example, if you own an e-commerce store, you probably need access to the admin panel in order to add new products or to set up a promotion for the upcoming holidays. However, hardly anybody else would need it. Allowing the rest of your website’s visitors to reach your login page only opens up your e-commerce store to attacks.
  - Security mis-configurations - At its core, brute force is the act of trying many possible combinations, but there are many variants of this attack to increase its success rate. Here are the most common:
    - Unpatched flaws
    - Default configurations
    - Unused pages
    - Unprotected files and directories
    - Unnecessary services
  - Cross Site Scripting (XSS) - widespread vulnerability that affects many web applications. XSS attacks consist of injecting malicious client-side scripts into a website and using the website as a propagation method. The risks behind XSS is that it allows an attacker to inject content into a website and modify how it is displayed, forcing a victim’s browser to execute the code provided by the attacker while loading the page.
  - Insecure De-serialization - Every web developer needs to make peace with the fact that attackers/security researchers are going to try to play with everything that interacts with their application–from the URLs to serialized objects. In computer science, an object is a data structure; in other words, a way to structure data. To make it easier to understand some key concepts:
    - The process of serialization is converting objects to byte strings.
    - The process of deserialization is converting byte strings to objects.
  - Using Components with known vulnerabilities - failing to update every piece of software on the back-end and front-end of a website will, without a doubt, introduce heavy security risks sooner rather than later.
  - Insufficient logging and monitoring - The importance of securing a website cannot be understated. While 100% security is not a realistic goal, there are ways to keep your website monitored on a regular basis so you can take immediate action when something happens.


---
#### 10.5.1.2 Cyber Kill Chain

![image](https://github.com/ruppertaj/WOBC/assets/93789685/fdd18586-745f-4712-84dd-b44b04f826a9)

The cyber kill chain is a security model that outlines the phases of a cyberattack. The kill chain breaks common cyber attacks into seven stages from reconnaissance to execution.

Understanding these stages allows defenders to then develop specific detection and/or counter-measures for each stage. Ideally a defender will want to identify and stop an attack during the first three stages.

- Reconnaissance: The attacker gathers information about the target, such as network architecture, system vulnerabilities, and potential entry points.
- Weaponization: The attacker creates or obtains malicious tools or payloads designed to exploit vulnerabilities identified during the reconnaissance phase.
- Delivery: The attacker delivers the weaponized payload to the target, often through methods like phishing emails, compromised websites, or malicious attachments.
- Exploitation: The malicious payload is executed on the target system, exploiting vulnerabilities to gain unauthorized access or control.
- Installation: The attacker establishes a foothold within the target’s environment, installing backdoors or malware to maintain persistence and facilitate further actions.
- Command and Control (C2): The attacker establishes communication channels with the compromised system, enabling remote control and the issuance of commands to carry out malicious activities.
- Actions on Objectives: With control established, the attacker proceeds to achieve their objectives, which may include stealing sensitive data, disrupting operations, or causing other forms of damage.

References:  
https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html


---
##### 10.5.1.2.1 Reconnaissance
Reconnaissance is all about data gathering. As much information about your target as you can get. What types of hardware, operating systems, external and internal IP spaces, installed software, key employees, contact info, etc. It is all useful to setting up and formulation a plan of attack.

As we have talked about in Module 7: Discovery, there are two types of reconnaissance, Active and Passive. Each of these are also broken further into sub categories of External and Internal types. While a majority of attacks you will see are external, more and more we are starting to see internal threats as well.

While in the reconnaissance stage attackers are looking for:
- Conduct OSINT to find information.
- Security vulnerabilities and weak points.
- The possibility of employing an insider accomplice.
- Tools, devices, verification protocols, and user hierarchy.
- A common tactic during reconnaissance is to gather employee email addresses and social media accounts. This information is useful if the attacker decides to use social engineering to access the network.

Possible defensive options for the reconnaissance stage:
- Set up firewalls to reinforce perimeter security.
- Monitor points of entry and visitor logs for suspicious behavior.
- Ensure employees report suspicious emails, calls, and social media messages.
- Prioritize protecting individuals and systems that are prime targets for reconnaissance.
- Educate employees about the risks of disclosing sensitive information online and implement policies to restrict the amount of information publicly available about the organization.
- Implement network segmentation and access controls to limit the attacker’s ability to gather information about the entire network.


---
##### 10.5.1.2.2 Weaponization
Based on the data collected during the reconnaissance phase the attackers will try to exploit a possible weakness they have found. This could be a technical vulnerability or social engineering. They will then design the exploit to target the weakness. If the attackers found a zero-day exploit, they work fast before it is discovered and the vulnerability is fixed.

While in the weaponization stage attackers are:
- Crafting or obtaining malicious tools, payloads, or exploits.
- Developing malware, ransomware, remote access Trojans (RATs), or exploit kits.
- Adapting the malicious payload to exploit identified vulnerabilities.
- Obfuscating or encrypting the payload to evade detection.
- Testing the effectiveness of the malicious payload in a controlled environment.
- Preparing the payload for delivery to the target system or network.

Possible defensive options for the weaponization stage:
- Use third-party to run penetration testing to identify vulnerabilities.
- Run security awareness training to help employees recognize social engeneering and weaponization tests.
- Analyze malware artifacts to check for suspicious timelines and similarities.
- Build detection tools for weaponized documents (automated tools that couple malicious software with exploits).
- Email filtering and anti-malware solutions to detect and block malicious attachments or links in phishing emails.
- User education and awareness training to teach employees how to recognize phishing attempts and avoid clicking on suspicious links or downloading attachments from unknown sources.
- Web filtering and application whitelisting to prevent users from accessing malicious websites or downloading unauthorized software from the internet.
- Regularly updating and patching software and systems to mitigate known vulnerabilities and reduce the attack surface.
- Implementing least privilege access controls to limit the impact of successful exploitation by restricting user privileges and system access rights.


---
##### 10.5.1.2.3 Delivery
The delivery phase of a cyber attack involves the transmission or dissemination of the malicious payload to the target system or network. During this phase, attackers employ various methods to deliver the weaponized payload to the intended victim, typically exploiting vulnerabilities or weaknesses in the target’s defenses.

The attackers execute the plan of attack at the target. The infection methods vary, but the most common techniques are:
- Phishing attacks.
- Infected USB devices.
- Exploiting a hardware or software flaw.
- Compromised user accounts.
- A drive-by download that installs malware alongside a regular program.
- Attackers distribute malicious links
- Direct hacking through an open port or other external access point.
- Watering Hole Attacks.
- Social Engineering.
- Physical Access.

The main objective of this stage is to compromise the system and silently establish a foothold. A popular tactic is to launch a simultaneous DDoS attack to distract the defenders and infect the network without alarming security controls.

Possible defensive options for the delivery stage:
- User training to identify and protect from phishing and other social engineering attacks.
- Use patch management tools.
- Flag and investigate changes to files and folders with file integrity monitoring (FIM).
- Monitor for strange user behavior such as odd login times or locations.
- Run penetration tests to identify risks and weak points proactively.


---
##### 10.5.1.2.4 Exploitation
The Exploitation phase, also known as the second stage of the cyber kill chain, involves attackers leveraging vulnerabilities or weaknesses in target systems or applications to gain unauthorized access or control. During this phase, attackers exploit security flaws such as software vulnerabilities, misconfigurations, or weak authentication mechanisms to execute malicious code or commands on the target system.

Once the payload is delivered, attackers exploit vulnerabilities in the target environment to gain access. This could involve exploiting software vulnerabilities, weak passwords, or misconfigured systems.

Possible defensive options for the lateral movement stage:
- Patch management by regularly apply security patches and updates to all software and systems.
- Vulnerability Management by conducting regular vulnerability assessments and penetration testing to identify and remediate weaknesses in your network, systems, and applications before attackers can exploit them.
- Network Segmentation to limit the spread of attacks.
- Least Privilege Access ensuring that users and systems have only the access and permissions necessary to perform their specific tasks.
- Endpoint Protection solutions such as antivirus, antimalware, and intrusion detection/prevention systems (IDS/IPS) to detect and block malicious activities on endpoints.
- Application Whitelisting to only allow approved applications to run on your systems.
- Network Traffic Monitoring and analysis tools to detect and block suspicious activities, such as unusual network traffic patterns or communication with known malicious domains.
- Multi-Factor Authentication (MFA) for remote access and sensitive systems to add an extra layer of security beyond passwords.


---
##### 10.5.1.2.5 Installation
The Installation phase, also known as the third stage of the cyber kill chain, involves attackers establishing a foothold within the targeted environment by installing malicious software or payloads on compromised systems. During this phase, attackers leverage vulnerabilities or weaknesses identified during the exploitation phase to gain unauthorized access and execute their malicious code.

Once the malware installs, intruders gain access to the network. With open access, intruders are free to:
- Install the necessary tools.
- Modify security certificates.
- Create script files.
- Look for further vulnerabilities to get a better foothold before starting the main attack. Keeping their presence secret is critical for attackers. Intruders typically wipe files and metadata, overwrite data with false timestamps, and modify documents to remain undetected.

Possible defensive options for the installation stage:
- Keep devices up to date.
- Use anti-virus software.
- Set up a host-based intrusion detection system to alert or block common installation paths.
- Conduct regular vulnerability scanning.
- Least Privilege Access


---
##### 10.5.1.2.6 Command and Control
The Command and Control (C2) phase is a critical stage in the cyber kill chain where attackers establish communication channels with compromised systems or networks to maintain control and issue commands to carry out malicious activities. During this phase, attackers leverage the compromised infrastructure to communicate with command and control servers (C2 servers) or other attacker-controlled endpoints, enabling remote access, data exfiltration, and further exploitation of the compromised environment.

Complex, APT-level malware requires manual interaction to operate, so attackers need keyboard access to the target environment. The last stage before the execution stage is to establish a command-and-control channel with an external server.

Attackers typically achieve this via a beacon over an external network path. Beacons are usually HTTP or HTTPS-based and appear as ordinary traffic due to falsified HTTP headers.

If data exfiltration is the attack’s goal, intruders start placing target data into bundles during the C2 phase. A typical location for data bundles is a part of the network with little to no activity or traffic.

Possible defensive options for the command-and-control stage:
- Look for C2 infrastructures when analyzing malware.
- Demand proxies for all types of traffic (HTTP, DNS).
- Continuously scan for threats.
- Set intrusion detection systems to alert on all new programs contacting the network.


---
##### 10.5.1.2.7 Actions on Objectives
The Actions on Objectives phase, also known as the final stage of the cyber kill chain, involves attackers achieving their ultimate goals or objectives within the compromised environment. During this phase, attackers leverage the access and control gained through earlier stages of the attack lifecycle to carry out specific actions that align with their malicious intent.

Attackers pursue their ultimate objectives, which could include stealing sensitive data, disrupting operations, or causing other forms of damage to the target organization.

Possible defensive options for the execution stage:
- Behavioral Analytics tools that can detect unusual or suspicious behavior within your network. These tools analyze user and system behavior to identify potential indicators of compromise, such as unauthorized access attempts or abnormal data exfiltration.
- Anomaly Detection techniques to identify deviations from normal patterns of activity. This could include abnormal login times, unusual file access patterns, or unexpected network traffic.
- Threat Intelligence about the latest threats and attack techniques by leveraging threat intelligence feeds and information sharing communities. This can help you identify and respond to known attacker tactics, techniques, and procedures (TTPs) more effectively.
- Incident Response Planning that outlines the steps to take in the event of a security breach. Ensure that your team is trained to recognize and respond to security incidents promptly to minimize their impact.
- Network Segmentation to limit the lateral movement of attackers within your environment. By separating critical systems and data from less sensitive areas, you can contain and mitigate the impact of a potential breach.
- Data Encryption of sensitive data both in transit and at rest to protect it from unauthorized access. Encryption helps mitigate the risk of data theft or tampering in the event of a security breach.
- Strong Access Controls and regular review of user permissions to ensure that only authorized individuals have access to sensitive systems and data. This helps prevent unauthorized users from carrying out malicious activities.
- Continuous Monitoring of your network and systems for signs of compromise using intrusion detection systems (IDS), security information and event management (SIEM) solutions, and other monitoring tools. Promptly investigate and respond to any suspicious activities or alerts.
- User Training and Awareness to employees on security best practices, including how to recognize and report potential security threats. Encourage a culture of security awareness and empower employees to play an active role in protecting the organization’s assets.
- Regular Security Audits and assessments to identify and address vulnerabilities in your systems and processes. This helps ensure that your security controls remain effective over time.

References:  
[Cyber Kill Chain](https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html#Resources)


---
#### 10.5.1.3 Mitre ATT&CK Matrix

![image](https://github.com/ruppertaj/WOBC/assets/93789685/7763a57b-1f22-4c84-8fbc-20d1fddaddff)

MITRE ATT&CK® is a globally-accessible knowledge base of adversary tactics and techniques based on real-world observations. The ATT&CK knowledge base is used as a foundation for the development of specific threat models and methodologies in the private sector, in government, and in the cybersecurity product and service community.

- Reconnaissance: This phase consists of techniques that involve adversaries actively or passively gathering information that can be used to support targeting.
- Resource Development: This phase consists of techniques that involve adversaries creating, purchasing, or compromising/stealing resources that can be used to support targeting.
- Initial Access: This stage focuses on the initial entry point used by attackers to gain a foothold in the target environment. Techniques in this stage include spear-phishing, exploiting vulnerabilities, and using stolen credentials.
- Execution: In this stage, attackers execute malicious code or commands on the victim’s system to achieve their objectives. Techniques may include running malware, scripts, or commands to establish persistence or escalate privileges.
- Persistence: Once inside the target environment, attackers aim to maintain a presence to ensure continued access. Techniques in this stage include creating new user accounts, installing backdoors, or modifying startup processes.
- Privilege Escalation: Attackers seek to escalate their privileges within the target environment to gain access to higher levels of access or sensitive data. Techniques in this stage include exploiting vulnerabilities, abusing misconfigurations, or stealing credentials.
- Defense Evasion: This stage involves techniques used by attackers to avoid detection by security defenses such as antivirus software, intrusion detection systems (IDS), or endpoint protection solutions. Techniques may include obfuscating code, disabling security features, or using rootkits.
- Credential Access: Attackers aim to steal or compromise credentials to gain unauthorized access to systems or accounts. Techniques in this stage include brute force attacks, password spraying, or credential dumping.
- Discovery: Attackers gather information about the target environment to identify potential targets, assets, or vulnerabilities. Techniques may include querying system information, enumerating network shares, or searching for sensitive files.
- Lateral Movement: Once inside the target environment, attackers move laterally across the network to expand their access and reach additional systems or resources. Techniques in this stage include using stolen credentials, exploiting vulnerabilities, or abusing trust relationships.
- Collection: Attackers gather data or information of interest from compromised systems or network resources. Techniques in this stage include exfiltrating files, capturing screenshots, or extracting credentials from memory.
- Exfiltration: Attackers transfer data or information out of the target environment to external servers or locations under their control. Techniques in this stage include using encrypted channels, hiding data within legitimate traffic, or staging data for exfiltration.
- Impact: This final stage involves actions taken by attackers to achieve their ultimate objectives, which may include disrupting operations, causing financial loss, or damaging the organization’s reputation. Techniques in this stage vary depending on the attacker’s goals and motivations.

References:  
[Mitre ATT&CK Matrix](https://attack.mitre.org/)


---
#### 10.5.1.4 Mitre D3FEND Matrix

![image](https://github.com/ruppertaj/WOBC/assets/93789685/6ca53fa3-31ee-4877-89a9-d98344906f26)

D3FEND, a framework for cybersecurity professionals to tailor defenses against specific cyber threats is now available through MITRE. NSA funded MITRE’s research for D3FEND to improve the cybersecurity of National Security Systems, the Department of Defense, and the Defense Industrial Base. The D3FEND technical knowledge base of defensive countermeasures for common offensive techniques is complementary to MITRE’s ATT&CK, a knowledge base of cyber adversary behavior.

D3FEND establishes terminology of computer network defensive techniques and illuminates previously-unspecified relationships between defensive and offensive methods. This framework illustrates the complex interplay between computer network architectures, threats, and cyber countermeasures.

MITRE released D3FEND as a complement to its existing ATT&CK framework, a free, globally-accessible knowledge base of cyber adversary tactics and techniques based on real-world observations. Industry and government use ATT&CK as a foundation to develop specific cyber threat models and methodologies.

Complementary to the threat-based ATT&CK model, D3FEND provides a model of ways to counter common offensive techniques, enumerating how defensive techniques impact an actor’s ability to succeed. By framing computer network defender complexity of countermeasure functions and techniques as granularly as ATT&CK frames computer network attacker techniques, D3FEND enables cybersecurity professionals to tailor defenses against specific cyber threats, thereby reducing a system’s potential attack surface. As a result, D3FEND will drive more effective design, deployment, and defense of networked systems writ large.

- Harden: Techniques and countermeasures focused on hardening systems, networks, and applications to reduce their susceptibility to cyber attacks. This phase involves implementing security controls, configurations, and best practices to strengthen the security posture of organizational assets and mitigate common attack vectors.
- Detect: Techniques and countermeasures aimed at detecting and identifying cyber threats and security incidents in a timely manner. This phase involves monitoring and analyzing network traffic, system logs, and other sources of telemetry to identify indicators of compromise (IOCs) and abnormal behavior that may indicate malicious activity.
- Isolate: Techniques and countermeasures focused on isolating and containing cyber threats to prevent their spread and minimize the impact on the broader environment. This phase involves implementing network segmentation, access controls, and isolation measures to contain compromised systems or limit the lateral movement of adversaries within the network.
- Deceive: Techniques and countermeasures aimed at deceiving or misleading adversaries to disrupt their operations and gather intelligence about their activities. This phase involves using deception tactics, such as honeypots, decoys, and false information, to lure adversaries into traps or mislead them about the target environment.
- Evict: Techniques and countermeasures focused on evicting or removing adversaries from compromised systems or networks. This phase involves conducting incident response activities, such as threat hunting, malware remediation, and user account management, to identify and remove persistent threats from the environment.
- Restore: Techniques and countermeasures aimed at restoring and recovering from cyber attacks and security incidents. This phase involves restoring affected systems, applications, and data to a known good state, restoring backups, and implementing remediation measures to prevent future incidents.

References:  
[Mitre D3FEND Matrix](https://d3fend.mitre.org/)


---
#### 10.5.1.5 The Diamond Model
The Diamond Model is a framework used in strategic analysis, particularly in the field of international relations and security studies. It helps in understanding the sources of competitive advantage in industries, as well as the sources of national power and security vulnerabilities. The model consists of four interrelated components, forming a diamond shape.

The Diamond Model was developed by Sergio Caltagirone, Andrew Pendergrast, and Christopher Betz. They identified shortcomings in linear cybersecurity intrusion models. They aimed to address these issues by emphasizing particular hacker behaviors and devising a model enabling cybersecurity experts to delineate connections among attackers, victims, and the technology deployed in attacks. Initially conceptualized in 2006, they officially presented the Diamond Model in 2013. This model comprises four primary elements: Adversary, Infrastructure, Capability, and Victim, forming a diamond-like structure with four distinct quadrants.

![image](https://github.com/ruppertaj/WOBC/assets/93789685/ca416dcd-7683-4c5d-9083-f7ed32a9f33f)

The four (4) corners of the Diamond model are:
- Actor:
  - This refers to the entities involved, such as nation-states, non-state actors, or corporations. In security studies, it often focuses on states and non-state actors like terrorist organizations or criminal networks.
- Strategy:
  - Strategy encompasses the goals and actions undertaken by the actors to achieve their objectives. This includes military strategies, economic policies, diplomatic efforts, and more. Understanding the strategies of various actors helps in predicting their behavior and responses.
- Capability:
  - Capability refers to the resources and abilities possessed by the actors. In military terms, this might include the size and strength of armed forces, technological advancements, economic resources, or intelligence capabilities. It’s crucial in assessing the potential impact of strategies and actions.
- Context:
  - Context encompasses the broader environment in which the actors operate. This includes geopolitical factors, economic conditions, cultural dynamics, technological advancements, and social trends. Context shapes the opportunities and constraints faced by actors and influences the effectiveness of their strategies.
---
This model took a set of axioms (a statement that everyone believes is true) relating to cyber security attacks and below are some of the common ones:
- Adversary-Centricity:
  - The model adopts an adversary-centric perspective, focusing on understanding the motivations, behaviors, and tactics of cyber adversaries. By centering analysis around the adversary, it aims to provide insights into their objectives and strategies.
- Action Orientation:
  - It emphasizes the actions taken by adversaries, victims, and their infrastructure during cyber incidents. Understanding the sequence and nature of these actions is crucial for mapping out the dynamics of cyber threats and responses.
- Victim Dependency:
  - The model recognizes the dependency of cyber adversaries on their victims' infrastructure and capabilities. Analyzing this dependency helps in understanding the vulnerabilities exploited by attackers and assessing the impact of cyber incidents on victims.
- Inherent Complexity:
  - Cyber threats are inherently complex, involving multiple actors, technologies, and motives. The model acknowledges this complexity and provides a structured framework for analyzing and understanding it effectively.
- Continuous Evolution:
  - Cyber threats evolve rapidly, with adversaries constantly adapting their tactics and techniques. The model acknowledges the dynamic nature of cyber threats and emphasizes the importance of continuous analysis and adaptation to effectively mitigate risks.

References:  
https://www.threatintel.academy/wp-content/uploads/2020/07/diamond_summary.pdf  
https://www.socinvestigation.com/threat-intelligence-diamond-model-of-intrusion-analysis/  
https://threatconnect.com/blog/applying-the-diamond-model-for-threat-intelligence-to-the-star-wars-battle-of-yavin/


---
#### 10.5.1.6 NIST Cyber Security Framework

![image](https://github.com/ruppertaj/WOBC/assets/93789685/88ad164a-4379-43a4-8950-7f9314ed5a3c)

The National Institute of Standards and Technology (NIST) Cybersecurity Framework is a comprehensive set of guidelines, standards, and best practices designed to help organizations manage and improve their cybersecurity risk management processes. It was created in response to Executive Order 13636, "Improving Critical Infrastructure Cybersecurity," issued by President Barack Obama in 2013. The framework was developed through collaboration between industry, government, and academia and is widely used by organizations of all sizes and sectors to strengthen their cybersecurity posture.

The NIST Cybersecurity Framework 2.0 (CSF 2.0) (February 26 2024) is a high-level framework that emphasizes continuous evolution and governance. It provides a set of recommendations and standards to help organizations identify, detect, prevent, respond to, and recover from cyber attacks.

The Core Functions provide a set of high-level cybersecurity activities and outcomes that organizations should aim to achieve. The framework is organized by these six core functions:
- Govern - The organization establishes, communicates, and monitors its cybersecurity risk management strategy, expectations, and policies. The GOVERN Function delivers results to guide what actions an organization might take to achieve and prioritize the outcomes of the remaining five Functions within the framework of its mission and stakeholder expectations. Governance activities are essential for integrating cybersecurity into an organization’s broader enterprise risk management (ERM) strategy. GOVERN focuses on comprehending the organizational context; setting cybersecurity strategy and managing cybersecurity supply chain risks; defining roles, responsibilities, and authorities; formulating policies; and supervising cybersecurity strategy.
- Identify - The organization comprehends its present cybersecurity risks. This understanding of the organization’s assets (such as data, hardware, software, systems, facilities, services, and personnel), suppliers, and associated cybersecurity risks allows the organization to align its efforts with its risk management strategy and the mission requirements outlined in the GOVERN Function. Additionally, this Function involves identifying opportunities for enhancing the organization’s policies, plans, processes, procedures, and practices that bolster cybersecurity risk management, thereby informing activities across all six Functions.
- Protect - The organization employs protective measures to mitigate its cybersecurity risks. Following the identification and prioritization of assets and risks, PROTECT facilitates the securing of these assets to minimize the occurrence or severity of negative cybersecurity incidents, while also enhancing the organization’s ability to capitalize on opportunities. This Function encompasses outcomes such as identity management, authentication, and access control; awareness and training initiatives; data security measures; platform security (including safeguarding physical and virtual platform hardware, software, and services); and the resilience of technology infrastructure.
- Detect - Potential cybersecurity attacks and compromises are identified and examined. DETECT facilitates the prompt detection and analysis of irregularities, signs of compromise, and other potentially harmful events that could signal ongoing cybersecurity attacks and incidents. This Function assists in executing effective incident response and recovery efforts.
- Respond - Measures are implemented upon detection of a cybersecurity incident. RESPOND aids in containing the repercussions of cybersecurity incidents. Outcomes under this Function encompass incident management, analysis, mitigation, reporting, and communication.
- Recover - Assets and operations impacted by a cybersecurity incident undergo restoration. RECOVER facilitates the prompt reinstatement of regular operations to mitigate the impact of cybersecurity incidents and enable effective communication during the recovery process.

References:  
https://www.nist.gov/cyberframework  
https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf


---
### 10.5.2 Indicators
It is important to recognize the difference between an indicator of attack and an indicator of compromise. Often what you are looking for is an indicator of compromise when you are doing network forensics. This is the pieces of information that you are used to looking for and they are easier to find. When your network has been compromised finding your indicators of compromise is your main goal.

Whenever possible you should look of indicators of attack as well. It is actions that could indicate an attack, and it is independent of the action taken itself. So instead of focusing on how persistence was established, looking at it and saying that persistence was established, that code was executed, etc. These are harder to find but they are steps that need to be taken to exploit a system.

IOA (Indicators of Attack) and IOC (Indicators of Compromise) are both important elements in cybersecurity for identifying potential threats and security incidents. While IOAs indicate suspicious behavior or patterns that may suggest an ongoing attack, IOCs are specific pieces of data that indicate a security incident has occurred.

---

- Indicator of Attack - *Proactive*
  - A series of actions together that are suspicious
  - Focuses on the intent not the tools
  - Focuses on pieces that must happen so will never change
    - code execution, persistence, lateral movement
---
- Indicator of Compromise - *Reactive*
  - Evidence that something has happened on a network/ host aka forensic evidence
  - Gives information that can change
    - Malware, IP addresses, exploits, signatures
---
Indicators:
- .exe/ executable files
  - Executable files function as programs. This includes stuff you use frequently like calculator. However, some malware is listed as an executable file. Seeing an executable file in network traffic is an indicator that should be looked at regardless of how legitimate it looks. It is possible to hide malware within a legitimate process or to give it a legitimate name.
- NOP sled
  - NOP is short for No OPeration. It is represented by sets of 0x90 in packets. The aim of a NOP sled is to deny the ability to run operations and erase the location of the pointer. When a system does not know where to return to, the attacker can then choose the location to send it to.
- letters
  - Sets of a single letter such as capital A serve the same purpose as the NOP sled. 0x90 became a very obvious indication of exploitation, so using letters became a more stealthy method of achieving the same goals.
- well known signatures
  - Signatures mean that the malware has already been found and documented. Seeing a signature generally can give you a lot of information very quickly, but since it has been around chances are high that it worked. Knowing a lot of information about what is in your system should provide a higher level of speed and efficiency in finding what has happened to your system.
- mismatched protocols
  - These are packets that often show up in a black color. This would be having a protocol like SMTP use UDP instead of TCP, or DHCP use TCP instead UDP. This is circumventing the RFC for the protocols to avoid security.
- unusual traffic
  - Like you have previously been taught baselines tell you what your network should look like, so large differences could be significant. This could mean many different things from computers to certain protocols. If nothing has been added or changed by the individuals who are in charge of the network there should not be a large amount of changes seen in traffic. Seeing a very active new IP or POP3 when you do not have a mail server can indicate that something malicious has happened in your network.
- large amounts of traffic/ unusual times
  - If you are seeing much larger amounts of traffic or traffic at times when there should be none/minimal traffic this is a strong indicator that something is wrong. In some cases it may be that something changed or broke but especially with the time, something is most likely happening or data is being ex-filtrated.

Any of these alone are indicators. Combinations of these increase the chances that something malicious has happened. The more indicators also increases the amount of information you can gain in most cases. This is useful for mitigation, remediation, security improvements, and in applicable cases investigations.*


---
#### 10.5.2.1 Signs of IOAs
Although they are able to conduct after-the-fact investigations to uncover the markings of a compromise, systems that detect IoAs work in real-time to detect exploits as they happen. Such systems:
- Detect exploitation techniques
- Provide real-time visibility across your environment
- Are agnostic to individual vulnerabilities
- Work proactively to identify unknown or emerging exploits and attacks
- Destinations: Hosts on your network are connecting to malicious destinations or countries that it should not be connecting to
- Ports: non-standard ports that you have not assigned are being used or the protocol does not match the standard port i.e 443 SSH
- Public Servers/DMZs: PS or DMZ is connecting or communicating with internal hosts
- Off-hours: traffic or alerts during non business hours
- Network scans: some external scans are expected since web crawling exists, but should not happen too frequently. However, scans of the network from within the network should not be happening
- Alarm events: multiple alarms from a single host in a short period of time, or identical alarms from different hosts in a short amount of time.
- Malware reinfection: hosts re-infected within minutes may mean there is a method of persistence on that host
- Remote logins: remote logons from users that should not need to or logons in general from unknown/wrong areas/regions may signal credentials have been stolen
- High levels of email protocols: Some malware uses email protocols as C2 channels
- DNS queries: internal hosts querying outside DNS servers or internal servers are being queried too frequently
- Excessive Failed Login Attempts: Multiple failed login attempts within a short period could indicate a brute force or credential stuffing attack.
- Unusual Outbound Network Traffic: Unexpected or unusual outbound network traffic patterns, especially to known malicious domains or IP addresses.
- Fileless Malware Execution: Techniques such as PowerShell or WMI used to execute commands or scripts without writing files to disk.
- Process Injection: Suspicious behavior where a process injects code into another process, often used by malware to evade detection.
- Lateral Movement: Unauthorized attempts to move laterally within a network, such as SMB or lateral WMI connections.
- Abnormal User Account Activity: Anomalous user account behavior, such as accessing unusual resources or performing actions outside of normal patterns.
- Domain Name System (DNS) Tunneling: Use of DNS requests to exfiltrate data or establish command and control channels.
- Suspicious Registry Changes: Unauthorized modifications to registry keys or values, which could indicate malware persistence or configuration changes.
- Data Encryption by Non-Approved Software: Encryption of data by unauthorized or unknown software applications.
- Unusual Process Spawning: Instances where legitimate processes spawn child processes in unexpected or abnormal ways, indicating potential malware activity.

IoA-based detection looks at an attacker’s behavior, regardless of whether the attacker is using a known or unknown attack. An attacker doesn’t need malware to compromise your system, so an IoA-based system is ideal for stopping perpetrators before they penetrate your defenses.


---
#### 10.5.2.2 Signs of IOCs
Systems that work by detecting IoCs are reactive. They look at events in retrospect—essentially flagging problems after they’ve happened. IoCs include specific after-the-fact markings to confirm a compromise to a company’s defenses, including:
- IP addresses, files, and other markers
- Specific behavior of known attacks
- A focus on post-exploitation tooling and command and control
- Unusual traffic outbound: Traffic outbound can be seen as an indicator of ex-filtration
- Anomalous user login or account use(normal or privileged): if remote use isn’t allowed this is suspicious by itself. However, if you have accounts accessing systems that they should not or normally do not, accounts being used in multiple places at once, many failed logins, or have accounts being used at irregular times, these are also indicators of compromise.
- Size of responses for HTML: unusually large responses may be an attack against the database behind it. Larger responses are a sign of data ex-filtration since more information than the normal response is being returned.
- High number of requests for the same file
- Using non-standard ports/ application-port mismatch: in some cases barriers to attacks can be avoided by using the non-standard port for a protocol. Looking at the non-resolved port and the type of traffic will make this very obvious.
- Writing changes to the registry/ system files: In the hex window writing to the registry or to system files is a large indicator of compromise. Without the data in the hex window it can be difficult to find the changes in these files.
- DNS requests: high numbers of DNS requests can indicate DNS data ex-filtration
- Unexpected/Unusual patching: Patching is expected at certain times on Windows machines and only if the user/administrator of *nix systems chooses to patch. Seeing a patch at an unexpected time can signify that an attacker is locking others out of the system.
- Unusual tasks: where activities that real people cannot complete or do not choose to complete, such as opening dozens of tabs at the same time.
- Malicious File Hashes: Unique cryptographic hashes (MD5, SHA-256, etc.) of known malicious files or executables.
- Malicious IP Addresses: IP addresses associated with known command and control servers, malware distribution points, or other malicious activity.
- Malicious Domains: Domains known to host malware, phishing sites, or other malicious content.
- Suspicious Registry Keys: Specific registry keys or values associated with malware persistence, configuration, or execution.
- Unusual Network Connections: Unexpected network connections or communication patterns indicative of malware or malicious activity.
- Anomalous DNS Queries: Unusual or suspicious DNS queries, such as domain generation algorithm (DGA) domains or known malicious domains.
- Abnormal File or Folder Changes: Unauthorized modifications to critical files or folders, such as system binaries or configuration files.
- Unusual Process Behavior: Processes exhibiting abnormal behavior, such as persistence mechanisms or attempts to evade detection.
- Security Alerts from Endpoint Detection Systems: Alerts generated by endpoint detection and response (EDR) systems or other security monitoring tools.
- Phishing Email Indicators: Email addresses, URLs, or email attachments associated with phishing campaigns or malicious emails.

Because of the way they are set up, systems that are based on IoCs, although they show that a threat actor has compromised a system, can also generate high false positives. Moreover, IoCs are reactive because, by their nature, they only spring into action once a compromise has happened, which can leave an operation vulnerable.

References:  
[Security Trails: Indicators of Attack](https://securitytrails.com/blog/indicators-of-attack)  
[gbhackers: Indicators of Attack](https://gbhackers.com/soc-indicator/)  
[Digital Guardian: Indicators of Compromise](https://digitalguardian.com/blog/what-are-indicators-compromise)  
[Crowdstrike: Indicators of Compromise](https://www.crowdstrike.com/cybersecurity-101/indicators-of-compromise/)


---
### 10.5.3 Types of Malware


---
#### 10.5.3.1 Adware
- Adware: Adware tracks a user’s surfing activity to determine which ads to serve them. Although adware is similar to spyware, it does not normally install any software on a user’s computer, nor does it capture keystrokes. The danger in adware is the erosion of a user’s privacy — the data captured by adware is collated with data captured, overtly or covertly, about the user’s activity elsewhere on the internet and used to create a profile of that person which includes who their friends are, what they’ve purchased, where they’ve traveled, and more. That information can be shared or sold to advertisers without the user’s consent.
  - While adware itself is not inherently malicious, it can become intrusive and disruptive, often causing annoyance to users by bombarding them with unwanted ads, pop-ups, or redirects. In some cases, adware may also collect and transmit user data to third-party advertisers without the user’s consent, raising privacy concerns.
  - Analogy: Adware malware is like a persistent salesman that bombards you with unwanted advertisements, pop-ups, and banners while you’re browsing the internet, disrupting your online experience and trying to convince you to buy or download things you don’t need.
  - IOA:
    - Browser Hijacking: Unauthorized changes to browser settings such as homepage, search engine, or default tabs.
    - Pop-up Ads: Sudden appearance of intrusive pop-up ads while browsing the web.
    - Click Fraud: Unusual clicking behavior on online ads to generate revenue for the attacker.
    - Browser Extensions: Installation of suspicious or unwanted browser extensions without user consent.
    - Tracking Cookies: Persistent tracking cookies placed on the user’s device to monitor online activities and preferences.
    - Ad Injection: Injection of unwanted advertisements into web pages, search results, or other online content.
    - Traffic Redirection: Redirecting web traffic to affiliate sites or malicious domains without user interaction.
    - Browser Performance Degradation: Sluggish performance or increased resource usage in the browser due to adware activities.
  - IOC:
    - File Hashes: MD5, SHA1, or SHA256 hashes of known adware executable files.
    - File Names: Common filenames associated with adware installers or payloads.
    - Registry Keys: Registry entries related to adware persistence or configuration settings.
    - Network Traffic: IP addresses, domains, or URLs associated with adware servers or command-and-control (C2) infrastructure.
    - Behavioral Patterns: Patterns of behavior indicative of adware activity, such as frequent ad injections or browser redirects.
    - Digital Signatures: Digital signatures associated with known adware publishers or developers.
    - Certificate Authorities: Certificate authorities used to sign adware executables or installers.
    - Malicious URLs: URLs hosting adware downloads or serving adware content.

References:  
[Fireball](https://www.wired.com/2017/06/hack-brief-dangerous-fireball-adware-infects-quarter-billion-pcs/)


---
#### 10.5.3.2 Spyware
- Spyware: Software that gathers information covertly from a person, system, or organization without consent.
  - Spyware is a type of malicious software (malware) designed to secretly monitor and collect information about a user’s activities on a computer or device without their knowledge or consent. This information can include browsing history, keystrokes, login credentials, email communications, and other sensitive data. Spyware is often used for surveillance, espionage, identity theft, fraud, or other malicious purposes.
  - Analogy: Spyware malware is like a nosy neighbor that secretly watches everything you do on your computer, tracking your online activities, recording keystrokes, and stealing personal information without your knowledge.
  - large amounts of traffic/ unusual traffic
  - IOA: 
    - Unauthorized Data Collection: Suspicious activities indicating the unauthorized gathering of sensitive information such as keystrokes, passwords, credit card numbers, or browsing history.
    - Covert Communication: Unusual network traffic patterns indicative of spyware communicating with command-and-control (C2) servers to exfiltrate stolen data or receive commands.
    - System Monitoring: Evidence of spyware monitoring system activities, including file access, application usage, microphone or camera usage, or system logins.
    - Browser Hijacking: Unauthorized changes to browser settings, homepages, or search engines to redirect users to malicious or unwanted websites.
    - Keylogging: Logging and recording of user keystrokes to capture sensitive information entered via the keyboard.
    - Screen Capture: Capturing screenshots of the user’s desktop or active windows to monitor user activities or capture sensitive information.
    - Webcam or Microphone Activation: Unauthorized activation of the webcam or microphone to record audio or video without the user’s knowledge or consent.
    - Persistence Mechanisms: Techniques used by spyware to maintain persistence on the infected system, such as registry modifications, startup entries, or scheduled tasks.
  - IOC:
    - File Hashes: MD5, SHA1, or SHA256 hashes of known spyware executables or payloads.
    - File Names: Common filenames associated with spyware installers, executables, or configuration files.
    - Registry Keys: Registry entries related to spyware persistence, configuration settings, or installation paths.
    - Network Traffic: IP addresses, domains, or URLs associated with spyware C2 servers, data exfiltration, or update mechanisms.
    - Behavioral Patterns: Patterns of behavior indicative of spyware activity, such as unusual system or network behavior, unauthorized access to sensitive information, or covert communication.
    - Digital Signatures: Digital signatures associated with known spyware publishers or developers.
    - Certificate Authorities: Certificate authorities used to sign spyware executables or installers.
    - Malicious URLs: URLs hosting spyware downloads or serving spyware payloads.
    
References:  
[Dark Hotel](https://www.wired.com/2014/11/darkhotel-malware/)


---
#### 10.5.3.3 Virus
- Virus: Self replicating; oldest kind of malware and have become less popular with the advent of the internet; typically attach to executables and duplicate themselves into as many executables as possible; they cannot replicate onto another computer by itself, it requires human interaction to spread i.e. sending an infected file to family and friends.
  - A computer virus is a type of malicious software (malware) that infects executable files or documents and spreads from one computer to another, often with the intent of causing damage, stealing information, or gaining unauthorized access to systems. Viruses are designed to replicate themselves and attach to other files or programs, allowing them to propagate and infect additional computers or devices.
  - Analogy: A virus malware is like a hidden thief that sneaks into your computer disguised as a harmless file or program and then silently starts causing damage, stealing your data, or spreading to other files.
  - IOA:
    - Unauthorized Code Execution: Suspicious activity indicating the execution of malicious code or programs on a system without user consent or interaction.
    - File Modification: Unusual changes to system files, executables, or critical system components indicative of virus activity.
    - Replication: Evidence of the virus attempting to replicate itself or spread to other systems through file sharing, email attachments, or removable media.  
    - Payload Delivery: Delivery of secondary payloads or malicious functions by the virus, such as keylogging, data theft, or system compromise.
    - System Degradation: Degradation of system performance or stability due to the presence of the virus, including crashes, freezes, or abnormal behavior.
    - Evasion Techniques: Techniques used by the virus to evade detection or bypass security controls, such as code obfuscation, encryption, or polymorphism.
    - Persistence Mechanisms: Methods used by the virus to maintain persistence on the infected system, such as registry modifications, startup entries, or scheduled tasks.
    - Exploitation of Vulnerabilities: Exploitation of known vulnerabilities or security weaknesses in the target system to facilitate virus infection or propagation.
  - IOC:
    - File Hashes: MD5, SHA1, or SHA256 hashes of known virus executables, payloads, or infected files.
    - File Names: Common filenames associated with virus executables, droppers, or infected files.
    - Registry Keys: Registry entries related to virus persistence, configuration settings, or installation paths.
    - Network Traffic: IP addresses, domains, or URLs associated with virus command-and-control (C2) servers, malware distribution, or data exfiltration.
    - Behavioral Patterns: Patterns of behavior indicative of virus activity, such as file modifications, network connections, process spawning, or unauthorized access to system resources.
    - Digital Signatures: Digital signatures associated with known virus publishers or developers.
    - Certificate Authorities: Certificate authorities used to sign virus executables or installers.
    - Malicious URLs: URLs hosting virus downloads or serving virus payloads.


---
#### 10.5.3.4 Worms
- Worms: self replicating using networks; required no direct human interaction; method 1 hide in OS or program vulnerabilities; method 2 email must be opened by the recipient.
  - A worm is a type of malicious software (malware) that is designed to spread rapidly across computer networks by exploiting vulnerabilities in software or operating systems. Unlike viruses, worms do not require a host file or user interaction to spread; instead, they propagate independently and can infect multiple systems without human intervention. Worms are often used by attackers to spread malware, steal sensitive information, or launch large-scale cyber attacks, such as distributed denial-of-service (DDoS) attacks or botnet recruitment.
  - Analogy: A worm malware is like a contagious bug that spreads rapidly from one person to another, infecting everyone it comes in contact with.
  - IOA:
    - Rapid Network Scanning: Unusual patterns of network traffic indicative of the worm scanning for vulnerable systems or devices to infect.
    - Exploitation of Vulnerabilities: Attempts to exploit known vulnerabilities or security weaknesses in target systems to facilitate worm propagation.
    - Self-Propagation: Autonomous replication and distribution of the worm’s code to other systems or devices within the network or across the internet.
    - Remote Code Execution: Unauthorized execution of code or commands on target systems by exploiting vulnerabilities or insecure configurations.
    - Payload Delivery: Delivery of secondary payloads or malicious functions by the worm, such as backdoors, remote access tools, or data exfiltration mechanisms.
    - System Resource Consumption: Abnormal consumption of system resources, such as CPU, memory, or network bandwidth, due to worm activity.
    - Lateral Movement: Movement of the worm across network segments or systems to propagate and infect additional targets.
    - Evasion Techniques: Techniques used by the worm to evade detection or bypass security controls, such as encryption, obfuscation, or polymorphism.
  - IOC:
    - File Hashes: MD5, SHA1, or SHA256 hashes of known worm executables, payloads, or infected files.
    - File Names: Common filenames associated with worm executables, droppers, or propagation scripts.
    - Registry Keys: Registry entries related to worm persistence, configuration settings, or installation paths.
    - Network Traffic: IP addresses, domains, or URLs associated with worm command-and-control (C2) servers, malware distribution, or data exfiltration.
    - Behavioral Patterns: Patterns of behavior indicative of worm activity, such as rapid network scanning, mass file creation or deletion, or anomalous process execution.
    - Digital Signatures: Digital signatures associated with known worm publishers or developers.
    - Certificate Authorities: Certificate authorities used to sign worm executables or installers.
    - Malicious URLs: URLs hosting worm downloads or serving worm payloads.

References:  
[Stuxnet](https://www.wired.com/2014/11/countdown-to-zero-day-stuxnet/)


---
#### 10.5.3.5 Trojans
- Trojan: Malware hidden in a file or executable; most are functional programs so user never knows; method one put in an innocent file; method two make user believe the malware is innocent.
  - A Trojan, short for Trojan horse, is a type of malicious software (malware) that disguises itself as a legitimate program or file to trick users into downloading and executing it on their computer systems. Once installed, Trojans can perform a variety of malicious activities, such as stealing sensitive information, compromising system security, or providing unauthorized access to attackers.
  - Analogy: A Trojan malware is like a deceptive gift that is beautifully wrapped, but inside, instead of a gift, there’s something harmful hidden.
  - IOA:
    - Unauthorized Access: Suspicious activities indicating unauthorized access or infiltration of the system by a Trojan, often disguised as a legitimate application or file.
    - System Modification: Unusual changes to system configurations, registry settings, or startup entries indicative of Trojan activity, such as disabling security features or creating backdoor access.
    - Data Theft: Unauthorized access or exfiltration of sensitive information, such as passwords, financial data, or intellectual property, by the Trojan.
    - Remote Access: Establishment of remote access capabilities by the Trojan, allowing attackers to control the infected system remotely or conduct malicious activities.
    - Keylogging: Logging and recording of user keystrokes by the Trojan to capture sensitive information entered via the keyboard, such as usernames, passwords, or credit card numbers.
    - Screen Capture: Capturing screenshots of the user’s desktop or active windows by the Trojan to monitor user activities or capture sensitive information.
    - Command-and-Control (C2) Communication: Communication between the Trojan-infected system and external C2 servers controlled by attackers for command execution, data exfiltration, or further instructions.
    - Payload Delivery: Delivery of secondary payloads or malicious functions by the Trojan, such as ransomware, spyware, or banking Trojans, to expand the scope of the attack.
  - IOC:
    - File Hashes: MD5, SHA1, or SHA256 hashes of known Trojan executables, payloads, or infected files.
    - File Names: Common filenames associated with Trojan executables, droppers, or malicious scripts.
    - Registry Keys: Registry entries related to Trojan persistence, configuration settings, or installation paths.
    - Network Traffic: IP addresses, domains, or URLs associated with Trojan C2 servers, malware distribution, or data exfiltration.
    - Behavioral Patterns: Patterns of behavior indicative of Trojan activity, such as suspicious process execution, file modifications, or network communication.
    - Digital Signatures: Digital signatures associated with known Trojan publishers or developers.
    - Certificate Authorities: Certificate authorities used to sign Trojan executables or installers.
    - Malicious URLs: URLs hosting Trojan downloads or serving Trojan payloads.

References:  
[Emotet](https://www.crowdstrike.com/blog/meet-crowdstrikes-adversary-of-the-month-for-february-mummy-spider/)


---
#### 10.5.3.6 Rootkits
- Rootkits: A root kit is software that gives malicious actors remote control of a victim’s computer with full administrative privileges. Rootkits can be injected into applications, kernels, hypervisors, or firmware. They spread through phishing, malicious attachments, malicious downloads, and compromised shared drives. Rootkits can also be used to conceal other malware, such as keyloggers.
  - Rootkits are a type of malicious software (malware) that allows unauthorized users to gain privileged access to a computer system or network while remaining undetected by security mechanisms. Rootkits are designed to conceal their presence and activities from users, administrators, and security tools, making them difficult to detect and remove. They are often used by attackers to maintain persistent access to compromised systems, steal sensitive information, or carry out other malicious activities without the knowledge or consent of the system owner.
  - Analogy: A rootkit malware is like a skilled burglar who sneaks into your home undetected, bypassing your locks and alarms. Once inside, it hides in the shadows, gaining complete control over your house without you even realizing it.
  - IOA:
    - Unauthorized Access: Suspicious activities indicating unauthorized access or infiltration of the system by a rootkit, often disguised as a legitimate application or system process.
    - Kernel Modification: Unusual changes to the operating system kernel or low-level system components indicative of rootkit activity, such as modification of system calls, hooks, or drivers.
    - File System Manipulation: Hidden files, directories, or processes created by the rootkit to conceal its presence and evade detection by security tools.
    - Privilege Escalation: Attempts by the rootkit to escalate privileges or gain elevated access rights on the infected system to bypass security controls or gain full control of the system.
    - Persistence Mechanisms: Methods used by the rootkit to maintain persistence on the infected system, such as registry modifications, boot sector changes, or installation of hidden services or drivers.
    - Backdoor Access: Creation of backdoor access points by the rootkit to enable remote control or command execution by attackers.
    - Stealth Techniques: Techniques used by the rootkit to hide its presence and evade detection by antivirus or security software, such as process hiding, memory manipulation, or stealth network communication.
    - System Integrity Violations: Evidence of system integrity violations or anomalies, such as unauthorized changes to system files, configurations, or critical system components.
  - IOC:
    - File Hashes: MD5, SHA1, or SHA256 hashes of known rootkit executables, payloads, or infected files.
    - File Names: Common filenames associated with rootkit executables, droppers, or configuration files.
    - Registry Keys: Registry entries related to rootkit persistence, configuration settings, or installation paths.
    - Network Traffic: IP addresses, domains, or URLs associated with rootkit command-and-control (C2) servers, malware distribution, or data exfiltration.
    - Behavioral Patterns: Patterns of behavior indicative of rootkit activity, such as hidden processes, network anomalies, or unusual system resource consumption.
    - Digital Signatures: Digital signatures associated with known rootkit publishers or developers.
    - Certificate Authorities: Certificate authorities used to sign rootkit executables or installers.
    - Malicious URLs: URLs hosting rootkit downloads or serving rootkit payloads.

References:  
[Zacinlo](https://www.eweek.com/security/more-nefarious-strain-of-zacinlo-malware-infecting-windows-10-machines)


---
#### 10.5.3.7 Backdoors
- Backdoors: creates an access channel(usually covert) that an attacker can use for connecting, spying, or interacting with the victim’s computer; can be a program or buried in legitimate program.
  - A backdoor is a hidden or undocumented method of bypassing normal authentication or security controls in a computer system, network, or software application. Backdoors are typically created by software developers for legitimate purposes, such as debugging, troubleshooting, or administrative access, but they can also be inserted maliciously by attackers to gain unauthorized access or control over a system.
  - Analogy: A backdoor malware is like a secret passage in a fortress. It’s a hidden entry point that cybercriminals use to sneak into your computer undetected, bypassing normal security defenses.
  - IOA:
    - Unauthorized Access: Suspicious activities indicating unauthorized access or infiltration of the system through a backdoor, often created by exploiting vulnerabilities or weak authentication mechanisms.
    - Remote Control: Evidence of remote control or command execution on the compromised system through the backdoor, allowing attackers to execute commands, upload/download files, or manipulate system configurations.
    - System Modifications: Unusual changes to system configurations, registry settings, or network settings indicative of backdoor installation or manipulation.
    - Evasion Techniques: Techniques used by attackers to evade detection or bypass security controls, such as encryption, obfuscation, or polymorphism of the backdoor code.
    - Persistence Mechanisms: Methods used by the backdoor to maintain persistence on the infected system, such as registry modifications, startup entries, or hidden files and directories.
    - Covert Communication: Communication between the compromised system and external command-and-control (C2) servers controlled by attackers, often using covert channels or encrypted protocols.
    - Lateral Movement: Movement of attackers within the network using the backdoor to propagate and infect additional systems, escalate privileges, or access sensitive data.
    - Data Exfiltration: Unauthorized transfer or exfiltration of sensitive data or intellectual property from the compromised system through the backdoor to external servers or locations controlled by attackers.
  - IOC:
    - File Hashes: MD5, SHA1, or SHA256 hashes of known backdoor executables, payloads, or malicious files associated with backdoor activity.
    - File Names: Common filenames or file paths associated with backdoor executables, configuration files, or installation scripts.
    - Registry Keys: Registry entries related to backdoor persistence, configuration settings, or installation paths.
    - Network Traffic: IP addresses, domains, or URLs associated with backdoor C2 servers, malware distribution, or data exfiltration. Behavioral Patterns: Patterns of behavior indicative of backdoor activity, such as unusual process execution, network connections, or system resource consumption.
    - Digital Signatures: Digital signatures associated with known backdoor publishers or developers.
    - Certificate Authorities: Certificate authorities used to sign backdoor executables or installers.
    - Malicious URLs: URLs hosting backdoor downloads or serving backdoor payloads.


---
#### 10.5.3.8 Botnets
- Botnets: A group of private computers that is controlled as a group with malicious software without the owner’s knowledge or consent.
  - A botnet is a network of compromised computers, often referred to as "bots" or "zombies," that are controlled by a central command and control (C2) server operated by a malicious actor or group. These compromised computers, also known as "bot-infected hosts," typically become part of the botnet without the knowledge or consent of their owners. Botnets are commonly used for a variety of malicious activities, including distributed denial-of-service (DDoS) attacks, spam email campaigns, information theft, cryptocurrency mining, and more.
  - Analogy: A botnet malware is like a swarm of bees. Each infected computer acts as a bee in the hive, following commands from a central controller.
  - IOA:
    - Network Scanning: Unusual patterns of network traffic indicative of bots scanning for vulnerable systems or devices to infect and recruit into the botnet.
    - Exploitation of Vulnerabilities: Attempts to exploit known vulnerabilities or security weaknesses in target systems to facilitate botnet propagation and recruitment.
    - Command-and-Control (C2) Communication: Communication between infected bots and external C2 servers controlled by botnet operators for command execution, data exfiltration, or further instructions.
    - Remote Control: Evidence of remote control or command execution on infected systems by botnet operators, allowing them to execute commands, launch attacks, or harvest sensitive information.
    - Lateral Movement: Movement of bots within the network to propagate and recruit additional systems into the botnet, often using compromised credentials or exploit kits.
    - Distributed Denial-of-Service (DDoS) Attacks: Coordinated DDoS attacks launched by the botnet against target systems or networks to disrupt services, overwhelm infrastructure, or extort victims.
    - Data Exfiltration: Unauthorized transfer or exfiltration of sensitive data or intellectual property from infected systems to external servers or locations controlled by botnet operators.
    - Spam and Phishing Campaigns: Use of bots to send spam emails, phishing messages, or malicious attachments to spread malware, harvest credentials, or deceive users into disclosing sensitive information.
  - IOC:
    - Botnet Command-and-Control Servers: IP addresses, domains, or URLs associated with botnet C2 servers used for communication and coordination among infected bots.
    - Botnet Controller Protocols: Network protocols, ports, or communication patterns associated with botnet C2 communications, such as IRC, HTTP, or custom protocols.
    - Botnet Payloads: File hashes, filenames, or URLs of known botnet payloads or malware samples used to infect and recruit systems into the botnet.
    - Botnet Infrastructure: IP addresses, domains, or hosting providers associated with botnet infrastructure, including hosting servers, proxy servers, or DNS servers used for C2 communications.
    - Behavioral Patterns: Patterns of behavior indicative of botnet activity, such as large volumes of outgoing network traffic, spikes in CPU or memory usage, or unusual system resource consumption.
     - Botnet Signatures: Signatures or patterns of network traffic, system events, or behavioral anomalies associated with botnet infections or botnet-related activities.
    - Malicious URLs: URLs hosting botnet payloads, exploit kits, or malicious content used to infect and recruit systems into the botnet.
    - Command-and-Control Channels: Unique identifiers, encryption keys, or communication channels used by bots to authenticate and communicate with C2 servers.

References:  
[Echobot](https://www.zdnet.com/article/new-echobot-malware-is-a-smorgasbord-of-vulnerabilities/)


---
#### 10.5.3.9 Polymorphic Malware
- Polymorphic Malware: Polymorphic malware is so named because it morphs, or mutates, into many forms, and does so very quickly—constantly creating new variations of itself. Because polymorphic malware can change so rapidly, it is very difficult for conventional, signature-based anti-malware tools to detect it. Each new iteration of the malware alters its own attributes in some way. Changes include a different filename, new encryption keys, or a unique compression signature. These changes, or any change to the code, alter the malware’s signature, making it very difficult or even impossible for anti-malware tools that rely on signatures–and most do–to effectively detect advanced polymorphic malware.
  - Analogy: Polymorphic Virus is like a Lepord that can change it’s spots.
  - Analogy: Polymorphic malware is like a chameleon. It can change its colors and patterns to blend in with its surroundings, making it hard to spot.
  - IOA:
    - Code Obfuscation: Techniques used by polymorphic malware to obfuscate or encrypt their code to evade static analysis and signature-based detection methods.
    - Dynamic Code Generation: Generation of polymorphic code variants or mutations at runtime to create unique instances of malware that are difficult to detect using traditional signature-based antivirus solutions.
    - Anti-Emulation Techniques: Techniques employed by polymorphic malware to detect virtual environments, sandboxes, or analysis tools and alter their behavior to avoid detection or analysis.
    - Fileless Execution: Execution of polymorphic malware directly in memory without writing to disk, making it harder to detect using traditional file-based antivirus solutions.
    - Evasion of Behavioral Analysis: Techniques used by polymorphic malware to mimic legitimate system behavior, delay execution, or evade detection by behavioral analysis tools.
    - Stealthy Persistence: Methods employed by polymorphic malware to maintain persistence on infected systems by disguising themselves as legitimate processes, services, or system components.
    - Command-and-Control (C2) Communication: Communication between polymorphic malware and external C2 servers controlled by attackers for command execution, data exfiltration, or further instructions.
    - Payload Delivery: Delivery of secondary payloads or malicious functions by polymorphic malware, such as ransomware, spyware, or banking Trojans, to expand the scope of the attack.
  - IOC:
    - Behavioral Anomalies: Anomalies in system behavior indicative of polymorphic malware activity, such as unusual process execution, network connections, or system resource consumption.
    - Code Patterns: Patterns or signatures associated with polymorphic malware variants, including code snippets, assembly instructions, or cryptographic algorithms used for obfuscation.
    - Runtime Artifacts: Runtime artifacts or traces left by polymorphic malware during execution, such as registry modifications, file system changes, or memory allocations.
    - Network Traffic: IP addresses, domains, or URLs associated with polymorphic malware C2 servers, malware distribution, or data exfiltration.
    - Malicious URLs: URLs hosting polymorphic malware downloads or serving malware payloads disguised as legitimate content.
    - Payload Signatures: Signatures or characteristics of polymorphic malware payloads, including file hashes, file sizes, or file headers used for identification and classification.
    - Cryptographic Keys: Encryption keys, certificates, or digital signatures used by polymorphic malware for code obfuscation or communication encryption.
    - Command-and-Control Channels: Unique identifiers, encryption keys, or communication channels used by polymorphic malware to authenticate and communicate with C2 servers.
   
References:  
[Storm Worm](https://www.schneier.com/blog/archives/2007/10/the_storm_worm.html)


---
#### 10.5.3.10 Metamorphic Malware
- Metamorphic Malware: Similar to Polymorphic but can change its appearance with each iteration but takes this concept further by completely rewriting its own code to appear entirely different while retaining its original functionality.
  - Metamorphic malware is a type of malicious software (malware) that continually changes its code and appearance while preserving its functionality and malicious intent. Unlike traditional malware, which relies on static signatures or patterns to detect and mitigate, metamorphic malware dynamically alters its code structure and behavior with each iteration, making it difficult to detect and analyze using conventional security tools and techniques.
  - Analogy: Metamorphic Virus is like a Lepord that can change into a Lion, then a Tiger, and so on.
  - Analogy: Metamorphic malware is like a constantly changing maze. Every time you enter, the paths shift, making it hard to navigate and find your way out.
  - IOA:
    - Code Transformation: Metamorphic malware employs advanced code transformation techniques to modify its code structure, logic, and appearance while preserving its functionality, making each instance unique and difficult to detect.
    - Polymorphic Behavior: Metamorphic malware exhibits polymorphic behavior by generating multiple variants of itself with different code structures and cryptographic signatures to evade signature-based detection methods.
    - Self-Modifying Code: Metamorphic malware dynamically modifies its code at runtime, altering its execution flow, instruction sequences, or function calls to create variations that are challenging to detect using static analysis techniques.
    - Anti-Emulation Techniques: Techniques used by metamorphic malware to detect virtual environments, sandboxes, or analysis tools and alter their behavior to avoid detection or analysis.
    - Evasion of Behavioral Analysis: Metamorphic malware mimics legitimate system behavior, delays execution, or evades detection by behavioral analysis tools by dynamically changing its execution patterns or system interactions.
    - Stealthy Persistence: Metamorphic malware maintains persistence on infected systems by disguising itself as legitimate processes, services, or system components, making it harder to detect and remove.
    - Encrypted Payloads: Metamorphic malware encrypts its payload or key components using cryptographic algorithms, making it challenging to identify and analyze malicious code patterns or signatures.
    - Command-and-Control (C2) Communication: Communication between metamorphic malware and external C2 servers controlled by attackers for command execution, data exfiltration, or further instructions.
  - IOC:
    - Behavioral Anomalies: Anomalies in system behavior indicative of metamorphic malware activity, such as unusual process execution, network connections, or system resource consumption.
    - Code Patterns: Patterns or signatures associated with metamorphic malware variants, including code snippets, assembly instructions, or cryptographic algorithms used for code transformation or obfuscation.
    - Runtime Artifacts: Runtime artifacts or traces left by metamorphic malware during execution, such as registry modifications, file system changes, or memory allocations.
    - Network Traffic: IP addresses, domains, or URLs associated with metamorphic malware C2 servers, malware distribution, or data exfiltration.
    - Malicious URLs: URLs hosting metamorphic malware downloads or serving malware payloads disguised as legitimate content.
    - Payload Signatures: Signatures or characteristics of metamorphic malware payloads, including file hashes, file sizes, or file headers used for identification and classification.
    - Cryptographic Keys: Encryption keys, certificates, or digital signatures used by metamorphic malware for payload encryption or communication encryption.
    - Command-and-Control Channels: Unique identifiers, encryption keys, or communication channels used by metamorphic malware to authenticate and communicate with C2 servers.
    
References:  
[ZMist](https://crypto.stanford.edu/cs155old/cs155-spring09/papers/viruses.pdf)


---
#### 10.5.3.11 Ransomware
- Ransomware: Blocks access to a system or part of a system until money is paid.
  - Ransomware is a type of malicious software (malware) designed to encrypt files or lock users out of their systems, typically with the intention of extorting money from the victim in exchange for restoring access or decrypting the files. Ransomware attacks have become increasingly prevalent and sophisticated, posing a significant threat to individuals, businesses, and organizations worldwide.
  - Analogy: Ransomware malware is like a digital hostage-taker. It encrypts your files and demands a ransom for their release, holding your data hostage until you pay up.
  - IOA:
    - File Encryption: Suspicious activities indicating the encryption of files on the infected system by ransomware, often characterized by changes in file extensions, file contents, or access permissions.
    - Mass File Modification: Rapid and simultaneous modification of a large number of files on the system, resulting in files becoming inaccessible or displaying ransom notes.
    - File Renaming: Renaming of encrypted files with unique identifiers or extensions appended to their original filenames, typically used by ransomware to differentiate encrypted files from their unencrypted counterparts.
    - Ransom Note Creation: Creation of ransom notes or messages by ransomware, typically stored as text files or displayed as pop-up windows, providing instructions on how to pay the ransom and obtain decryption keys.
    - Network Share Encryption: Encryption of network shares or mapped drives accessible from the infected system, potentially affecting shared files and resources across the network.
    - System Lockdown: Locking of the infected system or user’s desktop by ransomware, preventing access to files, applications, or system utilities until the ransom is paid or decryption keys are obtained.
    - Communication with Command-and-Control (C2) Servers: Communication between ransomware-infected systems and external C2 servers controlled by attackers, typically used for ransomware deployment, command execution, or ransom payment instructions.
    - Persistence Mechanisms: Methods used by ransomware to maintain persistence on infected systems, such as registry modifications, startup entries, or scheduled tasks, ensuring that the ransomware persists across system reboots or shutdowns.
  - IOC:
    - Ransom Note Artifacts: Text files, HTML pages, or pop-up windows containing ransom notes left by ransomware on infected systems, providing contact information, payment instructions, or decryption deadlines.
    - Encrypted File Extensions: Unique file extensions or identifiers appended to encrypted files by ransomware, often used to identify encrypted files and differentiate them from unencrypted files.
    - File Hashes: MD5, SHA1, or SHA256 hashes of known ransomware executables, payloads, or malicious files associated with ransomware infections.
    - Network Traffic: IP addresses, domains, or URLs associated with ransomware C2 servers, malware distribution, or payment portals used for ransom payments and decryption key delivery.
    - Bitcoin Wallet Addresses: Bitcoin wallet addresses provided by ransomware operators for receiving ransom payments, often included in ransom notes or payment instructions.
    - Encryption Keys: Encryption keys or cryptographic artifacts used by ransomware to encrypt files, stored locally or transmitted to C2 servers for decryption key retrieval.
    - Command-and-Control Channels: Unique identifiers, encryption keys, or communication channels used by ransomware to authenticate and communicate with C2 servers, facilitating ransomware deployment and data exfiltration.
    - System Artifacts: Registry entries, file system changes, or system logs indicating ransomware activity, such as changes to registry keys, creation of encrypted files, or modifications to system settings.

References:  
[RobbinHood](https://krebsonsecurity.com/2019/06/report-no-eternal-blue-exploit-found-in-baltimore-city-ransomware/)


---
#### 10.5.3.11 Mobile Code
- Mobile Code: Includes macro viruses; class of benign programs meant to be mobile and executed by large numbers of systems without being installed by users; distributed in many formats; can contain malicious code
  - Mobile code refers to software programs or scripts that are designed to execute on mobile devices, such as smartphones, tablets, or other portable devices. These programs are often distributed over networks and can execute on a remote system without the need for installation. Mobile code is commonly used to enhance the functionality of mobile applications, enable dynamic content delivery, or facilitate remote management and administration.
  - Analogy: Mobile code malware is like a hitchhiker on the internet highway. It travels freely from one device to another, spreading through websites, email attachments, or downloads.
  - IOA:
    - App Installation: Suspicious activities indicating the installation of unauthorized or malicious apps on mobile devices, such as apps from untrusted sources or third-party app stores.
    - App Permissions Abuse: Malicious apps requesting excessive permissions or permissions unrelated to their functionality, such as accessing sensitive data, device features, or network resources without legitimate reasons.
    - Side-Loading: Installation of apps or executables from sources other than official app stores, such as sideloading apps via USB connections, email attachments, or direct downloads from websites.
    - Jailbreaking or Rooting: Modification of device settings or firmware to remove restrictions imposed by manufacturers or operating system vendors, allowing users to install unauthorized apps or access privileged functions.
    - Exploitation of Vulnerabilities: Exploitation of known vulnerabilities or security weaknesses in mobile operating systems, apps, or firmware to gain unauthorized access, escalate privileges, or compromise device integrity.
    - Untrusted Content Execution: Execution of untrusted or malicious code embedded in web pages, email attachments, or SMS messages, potentially leading to the installation of malware or compromise of sensitive data.
    - Man-in-the-Middle (MitM) Attacks: Intercepting and modifying mobile traffic between devices and remote servers to inject malicious code, manipulate data, or steal credentials.
    - Phishing and Social Engineering: Deceptive techniques used to trick mobile users into installing malicious apps, disclosing sensitive information, or performing unauthorized actions, such as clicking on malicious links or downloading fake updates.
  - IOC:
    - Malicious App Signatures: SHA256 hashes or digital signatures of known malicious apps, payloads, or APK files associated with mobile code threats, including malware, adware, spyware, or ransomware.
    - App Permissions Analysis: Analysis of app permissions requested by installed apps to identify suspicious or excessive permissions that may indicate malicious behavior or privacy violations.
    - Network Traffic Patterns: Anomalies or patterns in network traffic generated by mobile devices, such as communication with known malicious domains, C2 servers, or suspicious IP addresses.
    - Behavioral Anomalies: Unusual behavior or activities observed on mobile devices, such as sudden battery drain, performance degradation, or unauthorized access to sensitive data or resources.
    - System Logs and Artifacts: System logs, crash reports, or forensic artifacts left by mobile code threats during execution, installation, or exploitation attempts, providing insights into malicious activities or attack vectors.
    - Command-and-Control (C2) Communication: Communication between compromised mobile devices and external C2 servers controlled by attackers for command execution, data exfiltration, or further instructions.
    - Malicious URLs and Domains: URLs, domains, or IP addresses associated with mobile code threats, including phishing websites, exploit kits, or malicious app download links used for malware distribution or infection.
    - Compromised Accounts: Evidence of compromised user accounts, credentials, or personal information associated with mobile code threats, such as login credentials stolen through phishing attacks or leaked from compromised apps.
    
References:  
[Triada](https://security.googleblog.com/2019/06/pha-family-highlights-triada.html)


---
#### 10.5.3.12 BIOS/Firmware Malware
- BIOS/Firmware Malware: BIOS/firmware malware refers to malicious software that targets the basic input/output system (BIOS) or firmware of a computer’s hardware components. The BIOS is a firmware interface that initializes and controls hardware during the boot process, while firmware is software embedded into hardware devices to control their operation.
  - BIOS/firmware malware is extremely difficult to detect and remove because it resides in the firmware of the computer’s hardware components. Unlike traditional malware that operates at the operating system level and can be removed by reinstalling the OS, BIOS/firmware malware persists even after reboots and operating system reinstalls.
  - BIOS/firmware malware operates at a low level, controlling the hardware components of the computer, including the motherboard, hard drive, and peripherals. This level of access gives the malware significant control over the system, allowing it to manipulate hardware operations, intercept data, and evade detection by security software that operates at higher levels of the system.
  - Recovering from a BIOS/firmware malware infection is challenging and often requires specialized tools and expertise. Remediation efforts may involve manually reflashing the firmware, replacing hardware components, or restoring the system to a known good state using firmware recovery mechanisms. These processes can be complex, time-consuming, and may not always guarantee complete removal of the malware.
  - Analogy: BIOS/firmware malware is like a mole in the foundation of your house. It burrows deep into the core system of your computer, hiding in the firmware that controls hardware operations.
  - IOA:
    - Anomalous system behavior during the boot process, such as:
      - Unauthorized changes to the Master Boot Record (MBR) or Unified Extensible Firmware Interface (UEFI) boot sequence.
      - Execution of suspicious code during firmware initialization or system startup.
    - Abnormal runtime activities, including:
      - Attempts to access memory locations or system resources outside the expected range for legitimate firmware operations.
      - Unusual system calls or API invocations indicative of firmware manipulation.
    - Behavioral patterns consistent with firmware tampering, like:
      - Execution of firmware flashing or update commands without user authorization.
      - Unauthorized modifications to firmware variables or configuration parameters during runtime.
    - Anomalies in firmware integrity checks, such as:
      - Failure of Secure Boot mechanisms to validate the integrity of firmware components during the boot process.
      - Detection of unsigned or modified firmware images during system integrity checks.
  - IOC:
    - Unusual modifications to BIOS/firmware configuration settings, such as:
      - Changes to boot order or boot options.
      - Unauthorized updates or modifications to firmware versions.
      - Presence of unfamiliar or unexpected firmware modules.
    - Anomalies in system behavior, including:
      - Unexpected system crashes or reboots during the boot process.
      - Unexplained changes in system performance or stability.
      - Failure to boot from trusted media or devices.
    - Persistence mechanisms, such as:
      - Changes to BIOS/firmware boot code that ensure the malware remains active even after system reboots.
      - Modifications to firmware update mechanisms to prevent legitimate firmware updates.
    - Network communication anomalies, like:
      - Unusual network traffic patterns originating from the compromised system, indicating communication with command-and-control (C2) ** servers or other malicious entities.
      - Network connections to suspicious domains or IP addresses associated with firmware malware campaigns.


---
## 10.6 Determine network anomalies through traffic analysis
Detecting network anomalies through traffic analysis involves monitoring and analyzing network traffic patterns to identify deviations from expected behavior.
1. Establish Baseline: Begin by establishing a baseline of normal network traffic behavior during typical operations. This baseline includes metrics such as network bandwidth utilization, packet rates, protocols used, and communication patterns between devices.
2. Monitor Traffic: Continuously monitor network traffic using network monitoring tools such as packet sniffers, flow collectors, or intrusion detection systems (IDS). Capture and analyze network packets or flow data to gain insights into traffic patterns, communication protocols, and traffic volumes.
3. Analyze Traffic Patterns: Analyze network traffic patterns to identify deviations or anomalies from the established baseline. Look for unusual spikes or drops in traffic volume, unexpected protocol usage, abnormal communication patterns, or suspicious traffic flows.
4. Identify Anomalies: Identify potential network anomalies based on observed deviations from normal traffic behavior. Common anomalies include sudden increases in network traffic, unusual port scanning activities, unauthorized access attempts, or communication with known malicious IP addresses.
5. Correlate Events: Correlate network events and anomalies with other security data sources such as system logs, intrusion detection alerts, or threat intelligence feeds. Look for patterns or indicators of compromise (IOCs) that may indicate malicious activities or security incidents.
6. Investigate Anomalies: Investigate detected network anomalies to determine their cause and potential impact on the network. Analyze packet captures, examine network logs, and conduct forensic analysis to identify the root cause of anomalies and assess the severity of the situation.
7. Respond and Mitigate: Take appropriate action to respond to identified network anomalies and mitigate potential risks. This may involve blocking malicious traffic, isolating affected systems, applying security patches or updates, or implementing additional security controls to prevent future incidents.
8. Continuously Monitor: Continuously monitor network traffic and reassess the baseline to adapt to evolving threats and changing network conditions. Regularly update detection mechanisms, refine anomaly detection algorithms, and stay informed about emerging security threats to improve network defense capabilities.


---
### 10.6.1 ICMP Tunneling

![image](https://github.com/ruppertaj/WOBC/assets/93789685/e95d06bf-84f6-4f88-9336-e020d561b0de)

ICMP tunneling is a command-and-control (C2) attack technique that secretly passes malicious traffic through perimeter defenses. Malicious data passing through the tunnel is hidden within normal-looking ICMP echo requests and echo responses.

Let’s say a user downloaded malware or an attacker exploited a vulnerability to install malware on a victim device. The malware must establish a C2 tunnel from inside the network to communicate with the external attacker. ICMP is a trusted protocol that helps administrators, so ICMP messages are often allowed to travel across firewalls and network segments that typically block inbound and outbound malicious traffic.

Different types of malicious data can be inserted into an ICMP datagram, from small amounts of code to a large encapsulated HTTP, TCP, or SSH packet. A datagram is similar to a packet, but datagrams do not require an established connection or confirmation that the transmission was received (unlike connection-based protocols like TCP). ICMP datagrams include a data section that can carry a payload of any size (see RFC 792). For example, if the attacker wants to create an SSH reverse shell (which enables the remote attacker to interact with the victim), the attacker can insert an SSH packet into the data section of the ICMP datagram that will establish the reverse shell. Or a compromised device can insert small pieces of exfiltrated data into the datagram of an echo request.

Over time, several ICMP echo request and response messages are sent between the compromised device and the attacker-controlled C2 server to exchange unique payloads of commands or exfiltrated data within each ICMP echo message.

- Detecting ICMP Tunneling relies on knowing how ICMP echo requests (type 8) and echo replies (type 0) are supposed to opperate.
  - ICMP PING uses Type 8 and Type 0
    - Both should be 1 echo request sent would get 1 echo reply in return.
    - Both will have the same size and payload.
      - Linux:
        - Default size: 64 bytes (16 byte ICMP header + 48 byte payload)
        - Payload message: !\”#\$%&\‘()*+,-./01234567
      - Windows:
        - Default size: 48 bytes (16 byte ICMP header + 32 byte payload)
        - Payload message: abcdefghijklmnopqrstuvwabcdefghi
    - Look out for Request/Reply imbalances
    - Abnormal/different payloads

References:  
[Infosec Writeups: ICMP Tunneling](https://infosecwriteups.com/ping-power-icmp-tunnel-31e2abb2aaea)


---
### 10.6.2 DNS Tunneling

![image](https://github.com/ruppertaj/WOBC/assets/93789685/4efe2fb7-06f8-452d-911d-19ea901c3c16)

DNS tunneling is a difficult-to-detect attack that routes DNS requests to the attacker’s server, providing them with a covert command and control channel, and data exfiltration path.

Let’s start with a compromised device: a user downloaded malware or an attacker exploited a vulnerability to deliver a malicious payload. If the attacker wants to maintain contact with the compromised device (to run commands on the victim device or exfiltrate data), they can establish a command-and-control (C2) connection. C2 traffic must be able pass through network perimeter defenses and evade detection while crossing the network.

DNS is a good candidate for establishing a tunnel, which is a cybersecurity term for a protocol connection that encapsulates a payload that contains data or commands and passes through perimeter defenses. Essentially, DNS tunneling hides data within DNS queries that are sent to an attacker-controlled server. DNS traffic is generally allowed to pass through perimeter defenses, such as firewalls, that typically block inbound and outbound malicious traffic.

To establish a DNS tunnel, the attacker registers a domain (baddomain.com) and sets up a C2 server as the authoritative name server for baddomain.com. The malware or payload on the compromised device sends a DNS query for a subdomain that represents an encoded communication (base64encodedcommunication.baddomain.com). The query is eventually routed by a DNS resolver (through root and top-level domain servers) to the C2 server. The C2 server then sends a malicious DNS response that includes data (such as a command) to the compromised device, passing undetected through the perimeter. Over time, the attacker can continue C2 activity or exfiltrate data through the DNS tunnel.

![image](https://github.com/ruppertaj/WOBC/assets/93789685/9f0065a3-28f6-4b5b-85a2-377f493f0c84)

- Detecting DNS Tunneling relies on knowing how DNS queries and responses are supposed to opperate.
  - DNS typically issues 1 Query and gets 1 Response.
  - Look out for:
    - Query/Response imbalances
    - Abnormal/different payloads
    - Continuous Queries over a short timeframe

References:  
[Unit42: DNS Tunneling Explained](https://unit42.paloaltonetworks.com/dns-tunneling-how-dns-can-be-abused-by-malicious-actors/)


---
### 10.6.3 HTTP(s) Tunneling
HTTP or HTTPS is not only a ubiquitous protocol for web communication but also a favored choice for creating covert channels due to its widespread acceptance and encrypted nature. While HTTPS encrypts data in transit, many defenders may overlook HTTPS streams, assuming they are secure. Similar to DNS traffic over TCP/UDP port 53, HTTP(S) traffic over TCP/UDP port 443 often bypasses enterprise firewalls due to its common allowance. Given the immense number of IP addresses associated with websites, creating granular firewall rules for each one becomes impractical, leading to the adoption of broad and generalized rules. Consequently, adversaries leverage this laxity to establish covert communication channels over HTTP(S), exploiting the protocol’s prevalence and encrypted nature to evade detection and exfiltrate sensitive information clandestinely. Thus, organizations must implement comprehensive monitoring and detection mechanisms, including deep packet inspection and behavior analysis, to effectively identify and mitigate the risks associated with covert HTTP(S) channels.

- Detecting HTTPs Tunneling relies on knowing how HTTPs traffic usually opperate.
  - HTTP is generally "bursty" in nature.
    - Client issues request and the server responds
    - One request can spawn several megabytes of data in response.
    - After the download the traffic generally stops.
  - Capture the start of the connection.
    - All connections including encrypted connections start in clear text.
    - Capturing the negotiations in the clear can indicate if its a tunnel or not.
  - Look out for:
    - Steady connections
      - HTTPs you will need to check session establishment for abnormalities


---
### 10.6.4 Beaconing

![image](https://github.com/ruppertaj/WOBC/assets/93789685/98474ecb-6a8e-4ea2-ad4e-404f69dc7f45)

When a system becomes infected, it generates an outbound connection across the internet to the attacker’s C&C server. Typically this connection will try and mimic normal traffic patterns by using HTTP, HTTPS or DNS. From a cursory view, the traffic will look like normal network activity. The intent of the connection is to inform the C&C server that a new compromised system has been activated and that the system is ready and waiting for marching orders. The process will then sleep for some period of time before repeating the check in process.

When the attacker wishes to activate the compromised system, they simply cue up a command on the C&C server. The next time the compromised system checks in, they have relayed the commands and execute on whatever marching orders have been given to them. These marching orders can be anything from stealing information off of the local system (data exfiltration) to attacking some identified host out on the Internet (DDoS attack).
---
**Beacon Characteristics** Within the security industry, this behavior of calling home at regular intervals is referred to as “beaconing”. While on the surface beaconing can appear similar to normal network traffic, there are some unique traits we can look for as part of a network threat hunt. These traits revolve around the timing of the communications and the packet size being used.

- **Beacon Timing** As shown in the above example, a beaconing system calls home at regular intervals. This could be as quick as every 8-10 seconds or as long as a few times a day. It really depends on how patient the attacker is and how long they feel they can avoid detection. If the attack is concerned that their malware may be detected quickly, they may beacon more frequently in order to maximize system use prior to detection. There really is no specific time interval that all attackers use, which again contributes to the difficulty in detecting beacons.
 - Most network activity is random in its timing. For example, you may frequently use Google to perform searches, but it is unlikely that you use it exactly at the top of the hour, every hour. You leverage Google when you need it, not at some fixed time interval. So the predictable nature of beacon timing is one of the unique characteristics we can clue in on.
- **Beacon Packet Size** As noted in the first figure, the compromised system will spend a lot of time checking in only to find there are no marching orders for it to execute. This communication exchange of checking in and being told there is nothing to do uses a fixed set of commands. The result is that all of these sessions where the malware has nothing to do will result in identical amounts of data being exchanged. Even if the attacker takes steps to obfuscate the data, the size will remain consistent.
  - Most network activity is random in the amount of data exchanged in each session. For example, visiting multiple web pages on the same site will return images, text and code of various lengths. This will cause each session generated to transfer different amounts of data. So another predictable characteristic of beaconing behavior is consistency if the amount of data transferred per session.
---
**Beacon False Positives** Beaconing is a communication characteristic. It’is not good or evil, but just a way of describing the communication flow. While beaconing is heavily relied on by call home software, there are in fact times that legitimate software can exhibit beaconing behavior as well. The most common false positive you will see is Network Time Protocol (NTP). NTP is used to ensure that the time on the local system remains accurate. NTP will beacon at a consistent interval in order to check the current time and ensure that the local system clock has not drifted. The beacon interval varies with different operating systems, but it is usually once every 15 to 60 minutes. Further, because NTP asks the same question each time (What’s the current time?), and gets back a fixed length answer, the amount of data transferred in each session is the same. So while NTP is the perfect example of beaconing behavior, it’s a vital tool that’s needed by every system and hardware device.

![image](https://github.com/ruppertaj/WOBC/assets/93789685/2e68781b-1c2d-4564-9edf-9defc95ee93b)

- Knowing and understanding beacons is the first step in discovering them.
  - Beacons are Call back to the C&C server
  - Gets/sends commands from/to C&C
  - Look out for:
    - Beacon Timing are commonly in regular intervals
    - Beacons to C&C generally have no payload size
    - Orders will have payloads

References:  
[Extrahop: Beaconing](https://www.extrahop.com/resources/attacks/c-c-beaconing/)  
[Critical Insight: Beacons](https://www.criticalinsight.com/resources/news/article/purple-team-about-beacons)


---
## 10.7 DEMO
**file: analysis-demo.pcap**

When a system becomes infected, it generates an outbound connection across the internet to the attacker’s C&C server. Typically this connection will try and mimic normal traffic patterns by using HTTP, HTTPS or DNS. From a cursory view, the traffic will look like normal network activity. The intent of the connection is to inform the C&C server that a new compromised system has been activated and that the system is ready and waiting for marching orders. The process will then sleep for some period of time before repeating the check in process.

When the attacker wishes to activate the compromised system, they simply cue up a command on the C&C server. The next time the compromised system checks in, they have relayed the commands and execute on whatever marching orders have been given to them. These marching orders can be anything from stealing information off of the local system (data exfiltration) to attacking some identified host out on the Internet (DDoS attack).

First thing we do is check to see what kind of traffic we have in the pcap. We can check that by looking at protocol statistics in Wireshark.

![image](https://github.com/ruppertaj/WOBC/assets/93789685/2bca342e-79c2-4dc6-af3b-ee32625ece92)

We can see several protocols that provide us useful information.

- SMB for Host Names and Domain Names.
- LDAP / Kerberos for what user is logged on to what system, and requested resources or access.
---
Next look at what hosts are in the pcap by looking at the endpoints.

![image](https://github.com/ruppertaj/WOBC/assets/93789685/750b9b0a-71ad-46cc-ad46-20592140347d)

Seeing as 192.168.2.x is a non routable IP address, we can deduce that the traffic was captured inside this network. The 192.168.2.255 address is a good indicator that this is a /24 network, as that address is normally a broadcast address for a /24.
---
We can try and determine the clients using TCP. For clients we can do this by using the filter `tcp.flags == 0x02`

![image](https://github.com/ruppertaj/WOBC/assets/93789685/c2e6db97-c01f-4bc2-bbb8-945323faf4b5)

- 192.168.2.147 is the only device making outbound connections, so this is can be labeled as a client in this case.

QUESTION 1: What is the Host Name of this device?

QUESTION 2: What is the Domain Name that this device is attached to?

QUESTION 3: Which user is logged in to this device?
---
**ANSWERS**
Apply the `nbns` filter. The device identifies itself and its domain in packets sent to the broadcast address.

![image](https://github.com/ruppertaj/WOBC/assets/93789685/c9f6aab8-7447-4af8-b3ce-1757e1c947ff)

**Answer 1**: LYAKH-WIN7-When a system becomes infected, it generates an outbound connection across the internet to the attacker’s C&C server. Typically this connection will try and mimic normal traffic patterns by using HTTP, HTTPS or DNS. From a cursory view, the traffic will look like normal network activity. The intent of the connection is to inform the C&C server that a new compromised system has been activated and that the system is ready and waiting for marching orders. The process will then sleep for some period of time before repeating the check in process.

When the attacker wishes to activate the compromised system, they simply cue up a command on the C&C server. The next time the compromised system checks in, they have relayed the commands and execute on whatever marching orders have been given to them. These marching orders can be anything from stealing information off of the local system (data exfiltration) to attacking some identified host out on the Internet (DDoS attack).S

Apply the `kerberos.as_req_element` filter. While not all AS-REQ packets have the username, there is a good chance at least 1 will have it.

![image](https://github.com/ruppertaj/WOBC/assets/93789685/f3ae64a2-d7b0-4b0d-a681-59caa782b745)

Answer 3: jermija.lyakh
---
We can also try an determine the servers using TCP. For servers we can use the filter `tcp.flags == 12`

![image](https://github.com/ruppertaj/WOBC/assets/93789685/9694e7d3-8d8a-4676-9713-433283ebaa66)

We see three IP’s that respond to the SYN:
- 192.168.2.4
- 198.54.126.123
- 23.211.124.169

We will isolate each server with a filter to see what ports it has been observed responding on.
- For 192.168.2.4: `ip.addr == 192.168.2.4 && tcp.flags == 0x12`
- For 198.54.126.123: `ip.addr == 198.54.126.123 && tcp.flags == 0x12`
- For 23.211.124.169: `ip.addr == 23.211.124.169 && tcp.flags == 0x12`
- Or use the endpoints tab in statistics

![image](https://github.com/ruppertaj/WOBC/assets/93789685/4d50beff-f415-4872-8b76-2c9dc0c58301)

QUESTION 4: What is the URL that returned a Windows executable file?
---
Apply the `http.request.method == GET` filter.

![image](https://github.com/ruppertaj/WOBC/assets/93789685/49327f40-29e9-46fd-8831-748dd4864467)

ANSWER 4: microsystem.com/hojuks/vez.exe
---
QUESTION 5: When did the URL request happen? (date and time in UTC)

Using the same filter and packet highlighted as before; you have to change the time display in Wireshark. This can be changed in the [View→Time Display Format→UTC Date and Time of Day]

![image](https://github.com/ruppertaj/WOBC/assets/93789685/070e4aad-7748-4fda-8466-b68bf3a21da5)

Then look at the time field of the packet with the GET request.

![image](https://github.com/ruppertaj/WOBC/assets/93789685/e4495a13-3711-43a3-9511-3b855a5e0311)

ANSWER 5: 2018-11-13 at 0202 UTC
---
QUESTION 6: How many bytes is the Windows executable file returned from that URL?

Right click the packet with the GET request and select [Follow Stream] The content length field is the size of the file.

![image](https://github.com/ruppertaj/WOBC/assets/93789685/09f6c161-9c00-49cf-a7dc-84cf72b13665)

ANSWER 7: 699,392 bytes
---
QUESTION 7: What is the MD5 file hash of the Windows executable file returned from that URL?

To get do any analysis on the file you have to first export it: [File→Export Object→HTTP]

demo exportsave

This gets us the file to now get the hash from. Drop into the terminal and rung the command `md5sum vez.exe`

![image](https://github.com/ruppertaj/WOBC/assets/93789685/2eb5702f-b15d-4815-8714-28e2a6cc7914)

ANSWER 7: 78e6812a0aaad85183df768b1a14dcc0
---
QUESTION 8: After receiving the Windows executable file, what IP address did the infected Windows host try to establish a TCP connection with?

When a malicious file is downloaded, it is often normal to see it attempt an outbound connection within a fraction of a second of the download completing. Simply look for the next SYN packet after the download. To make it easier you can use a filter such as:

`ip.addr == 192.168.2.147 && tcp.flags == 0x02`

![image](https://github.com/ruppertaj/WOBC/assets/93789685/139f1586-08e8-4819-aee1-d556c47dcf9c)

ANSWER 8: 93.87.38.24

Follow Up Discussion:

If you search https://virustotal.com/ for the MD5 of the file what are the results? Does the information there match what you discovered?
