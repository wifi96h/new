## 11.1 Describe differences among traffic filtering methods and technologies
Before we discuss the methods that firewalls can employ to filter traffic lets first identify the reasons why network traffic should be filtered. Some of these reasons are as follows:

Block malicious traffic

This is the most common reason to filter traffic. Any known malicious intent should be blocked.

Decrease load on network infrastructure

On busy networks, the network infrastructure can be heavily taxed with user traffic. Much of this traffic might not be organizational business traffic, but rather users browsing Video/Audio streaming sites or Social Media. These sites can potentially cause severe network congestion. Some organizations might choose to block this unnecessary traffic or choose to employ technologies like Quality of Service (QoS) to limit its bandwidth utilization.

Ensure data flows in an efficient manner

VPN and multicast traffic might need to be pruned to ensure they get to the proper destinations but not over networks they do not need to traverse.

Ensure data gets to intended recipients and only intended recipients

Just because some traffic might not be malicious it does not mean that it needs to consume bandwidth over network segments it has no need to communicate with.

Obfuscate network internals

Using technologies like NAT/PAT to translate source/destination IP addresses.



Practical applications of filtering

Network Traffic - allow or block traffic to/from remote locations.

Email addresses - to block unwanted email to reduce risk or increase productivity

Computer applications in an organization environment - for security from vulnerable software

MAC filtering - also for security to allow only specific computers access to a network



References:



Instructor Note
Instructor Notes



11.1.1 Network Traffic Filtering Concepts
Network traffic filtering serves as a cornerstone in cybersecurity, indispensable for governing data flow within a network, safeguarding against unauthorized access, mitigating security threats, and upholding security policies. However, grasping effective traffic filtering requires a comprehensive understanding of several key aspects:

Protocols Operation: Insight into network protocols from Network Fundamentals is paramount. Understanding how protocols function enables the creation of efficient filtering rules tailored to specific protocols, enhancing network security.

Header Analysis: Proficiency in discerning legitimate protocol headers from abnormal ones, possibly crafted through packet manipulation, is essential. This skill aids in identifying suspicious traffic patterns and potential security breaches.

Network Reconnaissance: Proficiency in network reconnaissance methodologies is crucial. This knowledge facilitates the identification of vulnerabilities and potential attack vectors, informing proactive filtering strategies to mitigate risks.

Tunnel Analysis: Understanding the structure and operation of tunnels is vital for effective traffic filtering. By recognizing tunneling protocols and their characteristics, security professionals can detect and mitigate covert communication channels and unauthorized access points.

Malware Analysis: Comprehensive knowledge of malware types and their behavior is indispensable. Recognizing indicators of compromise and malicious activities empowers security teams to implement targeted traffic filtering measures to thwart malware propagation and mitigate the impact of cyber attacks.



References:



Instructor Note
Instructor Notes



11.1.1.1 Defense in Depth
Defense in depth is a cybersecurity strategy that involves deploying multiple layers of security controls and measures to protect against various types of threats. These layers are designed to provide redundancy and resilience, ensuring that if one layer is breached, there are additional layers to mitigate the impact and prevent unauthorized access.



300



Perimeter Security: Comparable to the protective perimeter of a house, this layer serves as the first line of defense against cyber threats. Internal attacks, whether intentional or unintentional, pose significant risks, making perimeter defense crucial. Security measures at this layer include routers, proxy servers, and firewalls, which act as barriers to unauthorized access from external networks.

Network Security: Focused on safeguarding workstations within the business network, this layer aims to mitigate potential threats originating from internal sources. Host protection mechanisms fortify workstations against attacks initiated from within the network, shielding sensitive data from breaches even if the firewall is compromised.

Endpoint Security: Targeting the entry points of end-user devices, endpoint security is vital for protecting laptops, mobile phones, and desktops connected to the network. As these devices are susceptible to cyber attacks, robust protection mechanisms are essential to thwart malware, ransomware, and zero-day threats.

Application and OS Security: While perimeter defenses regulate traffic flow, applications and web servers running on different operating systems introduce additional security considerations. Access to operating systems poses risks to network integrity, making patching vulnerabilities and implementing security features crucial. Strengthening this layer is pivotal to fortifying overall network security against internal and external threats.

Data and Information Protection: While on-premise security measures are vital, ensuring the protection of valuable data beyond the premises is equally critical. Various aspects of data protection, including securing operating systems, storing sensitive data securely, and encrypting data to prevent unauthorized access, play pivotal roles in safeguarding critical information assets. By addressing these categories comprehensively, organizations can bolster their defense against data breaches and unauthorized access attempts, ensuring the integrity and confidentiality of their data assets.

In this section, our primary focus will be on exploring key components of perimeter, network, and endpoint security. While each layer of the security stack is essential, we’ll delve into these specific areas to provide a comprehensive understanding of foundational security principles and practical implementation strategies.



References:

https://colohouse.com/infographic-defense-in-depth/

https://ussignal.com/blog/moving-beyond-blinky-box-security-to-defense-in-depth-security



Instructor Note
Instructor Notes



11.1.1.2 Default policies
A default policy is simply the last condition tested for filtering. They may be listed or implied.

Explicit - precisely and clearly expressed, leaving nothing to implication; fully stated.
In the world of traffic filtering, an explicit rule would be one that is entered into ACLs, signatures, Firewall rules or other filtering and routing mechanism.

Implicit - Implied or understood though not directly expressed or stated.
In traffic filtering an implicit rule or policy is the last condition that is compared to route or filter a packet. If a packet does not match any of the rules, filters or signatures, the packet is acted on by the implicit rule or policy. Implicit rules can be either accept or deny.

This ties to Allow-Listing (formerly whitelisting) and Block-Listing (formerly blacklisting). Whether a device is implicit permit or implicit deny is up to the manufacturer or programmer but can often be reconfigured by the user. Implicit and explicit rules and policies will be seen later when creating and modifying host based firewall rules and router ACLs.



References:



Instructor Note
Instructor Notes



11.1.1.3 Block-Listing vs Allow-Listing
Block-Listing is one of the oldest algorithms in computer security, and it’s used by most antivirus software to block unwanted entities. The process of Block-Listing applications involves the creation of a list containing all the applications or executables that might pose a threat to the network, either in the form of malware attacks or simply by hampering its state of productivity. Block-Listing can be considered a threat-centric method.

Filtering Nature

Implicit ACCEPT

Traffic is allowed by default unless specifically blocked by a rule.

Explicit DENY

Traffic is explicitly blocked or denied based on predefined rules.

Pros

Simplicity

Admins can easily block only known malicious software and allow everything else.

Good approach for enterprises that are keen on taking a more relaxed approach to application control.

Cons

Because malware is being produced every day, it can be impossible for an admin to keep an updated and list of malicious applications.

Vulnerabilities in cases of zero-day attacks regardless of the security system they have in place.

Predicting and preventing zero-day attacks would be ineffective.

Applications that default to Block-Listing

Many Host-Based Firewalls

Linux IPTABLES/NFTables

Antivirus software



Allow-Listing - is where a list of trusted entities such as applications and websites are created and exclusively allowed to function in the network. Allow-Listing takes more of a trust-centric approach and is considered to be more secure. This method of application control can either be based on policies like file name, product, and vendor, or it can be applied on an executable level, where the digital certificate or cryptographic hash of an executable is verified.

Filtering Nature

Implicit DENY

Traffic is denied by default unless specifically allowed by an explicit rule.

Explicit ACCEPT

Traffic is explicitly allowed or permitted based on predefined rules.

Pros

Allows a limited number of applications to run, effectively minimizing the attack surface.

Is much easier, as the number of trusted applications would be lower when comparing it to the number of distrusted ones.

Enterprises that conform to strict regulatory compliance practices can benefit.

Cons

Inability to access essential applications would put various critical tasks on halt.

Determining which applications should be allowed to execute is an intensive process in itself.

Cannot function seamlessly without human intervention.

Applications that default to Allow-Listing

Default for most Network-Based Firewalls

Access Control Lists (ACLs)



References:

https://www.manageengine.com/application-control/whitelisting-vs-blacklisting.html

https://consoltech.com/blog/blacklisting-vs-whitelisting/



Instructor Note
Instructor Notes



11.1.1.4 Hardening a network
Hardening a network involves implementing various security measures and best practices to strengthen its defenses against potential cyber threats and attacks. One official definition of system hardening, according to the National Institute of Standards and Technology (NIST), is that it’s "a process intended to eliminate a means of attack by patching vulnerabilities and turning off non-essential services".

Purpose

To simply minimize the number of potential entryways an attacker could use to access your system and to do so from inception.

Steps of network hardening:

Inventory and Assessment:

Asset Discovery: Get a comprehensive overview of everything connected to your network. This includes devices, servers, applications, and services. You can’t secure what you don’t know exists.

Vulnerability Scanning: Use vulnerability scanning tools to identify weaknesses in your network devices, operating systems, and applications. This helps prioritize your patching efforts.

Securing Access:

Firewall Configuration: Ensure your firewall is properly configured with strong rules that only allow authorized traffic. Regularly audit and update these rules to reflect changes in your network.

Access Control Lists (ACLs): Implement ACLs to define which devices and users can access specific network resources. This restricts unauthorized access and minimizes potential damage from breaches.

Multi-Factor Authentication (MFA): Enforce MFA for all user accounts, especially those with access to sensitive data or systems. MFA adds an extra layer of security beyond just usernames and passwords.

Audit and monitor all network access: Familiarize yourself with your network by actively monitoring access requests and identifying any unusual or suspicious behavior. Utilize intelligent filters and machine learning algorithms to streamline the detection of abnormal activity and reduce the volume of logs generated. Additionally, ensure access logs are archived to facilitate thorough investigation in the event of a security incident.

Manage and restrict admin access: Attackers continuously seek admin access, particularly credentials granting full network control to escalate privileges. Regularly revoke excessive admin privileges and adhere to the principle of least privilege. Consider adopting just-in-time (JIT) privilege elevation practices.

Reducing the Attack Surface:

Unused Ports and Services: Identify and disable any unused network ports and services. This eliminates potential vulnerabilities that attackers could exploit.

Unnecessary Accounts and Privileges: Remove or disable any unused user accounts and restrict access privileges to the minimum level required for each user’s role. This reduces the potential damage if an account is compromised.

Secure Remote Access: When enabling remote access (e.g., for employees working from home), use strong protocols like SSH or VPN (preferably OpenVPN for its security features) instead of weaker ones like Telnet or FTP.

Remove unused devices: During audits, identify unused devices and promptly initiate their deprovisioning to mitigate potential vulnerabilities. Unused devices are often overlooked, leading to weak credentials and making them appealing targets for attackers.

Remove unused software and services: Regularly assess your service lifecycle and software inventory to identify candidates for removal. Unused services and software pose significant risks to the business, particularly if they remain unpatched or outdated. Such neglect can result in weak configurations, default credentials, or vulnerabilities that may facilitate unauthorized access to critical systems and data.

Patch Management and Updates:

Regular Updates: Develop a system for regularly applying security patches and updates to your network devices (firewalls, routers, switches) and operating systems on connected devices. These updates often contain fixes for newly discovered vulnerabilities.

Patch Testing: If possible, implement a patch testing process to minimize disruption caused by unexpected bugs in updates.

Network Segmentation:

Segmenting your network: Divide your network into smaller segments based on security needs. This prevents attackers from easily accessing critical resources if they breach one segment. For instance, isolate your guest network from your internal network.

Encryption:

Data Encryption: Implement data encryption protocols like SSL/TLS to secure communication between devices and servers on your network. This scrambles data in transit, making it unreadable for anyone who intercepts it.

Monitoring and Logging:

Network Activity Monitoring: Continuously monitor your network activity for suspicious behavior. Look for anomalies that might indicate intrusions or attempted attacks.

Security Logging: Maintain detailed logs of security events for analysis. These logs can help identify attack patterns and investigate security incidents.

User Education:

Security Awareness Training: Educate users about cyber threats and best practices like identifying phishing attempts and avoiding suspicious links. Empowering your users can be a strong defense against social engineering attacks



References:

https://www.nist.gov/



Instructor Note
Instructor Notes



11.1.2 Discuss filtering device types

![image](https://github.com/ruppertaj/WOBC/assets/93789685/1513fdcd-298e-414b-a72c-b223c00268ca)

Switch

Port Based ACL (PACL) or VLAN ACL (VACL).

VLANs can offer network segmentation.

Port security and MAC filtering.

Commonly used Switch vendors

Cisco (https://www.cisco.com/)

Juniper (https://www.juniper.net/us/en/)

Dell (https://www.dell.com/en-us/work/shop/networking/sc/switches)

Brocade (https://www.broadcom.com/products/fibre-channel-networking/switches)

Routers

Access Control Lists (ACL) to filter on source IP, destination IP, port number, and protocol type.

Inter VLAN routing.

Network segmentation.

Route filtering techniques such as route maps and prefix lists can be used to control the propagation of routing information between routers, reducing the risk of routing table manipulation attacks.

Commonly used Router vendors

Cisco (https://www.cisco.com/)

Juniper (https://www.juniper.net/us/en/)

Proxy

Rules configured by system administrators to create a white/black list of websites.

Act as intermediaries between clients and servers, filtering and caching web traffic to improve performance and security.

Content filtering policies can be applied to proxy servers to block or allow specific websites, applications, or content types, helping organizations enforce acceptable use policies and protect against web-based threats.

Commom proxy appliance used

Bluecoat (https://www.edgeblue.com/)

IDS/IPS

Use signatures to filter traffic.

Monitor network traffic for signs of suspicious activity or known attack patterns, providing real-time threat detection and prevention capabilities.

Common IDS application used

snort (https://www.snort.org/)

FireEye (https://www.fireeye.com/)

Zeek (Formerly Bro) (https://zeek.org/)

Fidelis (https://fidelissecurity.com/)



References:

https://www.businessinsider.com/what-is-a-proxy-server



Instructor Note
Instructor Notes



11.1.3 Explain how filters work at various layers of the OSI model
Physical Layer (Layer 1):

At the physical layer, filters are not typically applied, as this layer deals with the physical transmission of data over the network medium, such as cables and connectors.

Data Link Layer (Layer 2):

At the data link layer, filters can be implemented using MAC address filtering.

MAC address filters allow or deny network traffic based on the hardware addresses (MAC addresses) of devices connected to the network.

Switches and bridges often employ MAC address filtering to control access to network resources within the same broadcast domain.

Network Layer (Layer 3):

At the network layer, filters are commonly implemented using access control lists (ACLs) in routers and firewalls.

ACLs can permit or deny traffic based on criteria such as source and destination IP addresses, protocols, port numbers, and IP address ranges.

Routers use ACLs to filter traffic between different network segments or subnets, enforcing routing policies and controlling the flow of packets.

Transport Layer (Layer 4):

At the transport layer, filters can be applied based on transport layer protocols such as TCP (Transmission Control Protocol) and UDP (User Datagram Protocol).

Firewall rules can be configured to allow or deny traffic based on TCP/UDP port numbers, which identify specific applications or services running on network hosts.

Stateful inspection firewalls examine the state of TCP connections to allow only legitimate traffic that belongs to established sessions.

Session, Presentation, and Application Layers (Layers 5-7):

Filters at these layers often involve deep packet inspection (DPI) and application-layer filtering to inspect and control traffic based on the contents of the data payload.

DPI allows firewalls and intrusion detection/prevention systems (IDS/IPS) to analyze the application-layer protocols and detect specific application signatures or behavior patterns.

Application-layer filters can enforce security policies based on application types, URLs, keywords, and other application-specific attributes.



References:



Instructor Note
Instructor Notes



11.1.3.1 Devices operate at various OSI layers
Filtering devices, mechanisms and filter operation layers

Devices	Filtering mechanisms	Operates at OSI Layer
Switch

PACL & VACL (ACL)

Layer 2 (Layer 3)

Router

ACL

Layers 3 & 4

Proxies

Content based such as:
URL & DNS blocklist
MIME filtering
Content keyword filtering

Layers 3-7

Intrusion Detection &
Prevention Systems

Signatures

Layers 3-7

Host Based Firewall

Rules

Layers 3-7

Network Firewall

Rules
Packet Filtering (stateless)
Stateful (Connection based)
Application Layer & Next Gen FW

.
Layers 3 & 4
Layers 3 & 4
Layers 3-7

Layer 2 switches use PACLs and VACLs

A Vlan Access Control List (VACL), provides access control for all packets that are bridged within a VLAN or that are routed into or out of a VLAN. This is based on the VLAN Tag and VLAN ID number. VACLs apply to all packets, not just routed packets.

A Port Access Control Lists (PACL), provide access control on specific layer 2 (physical) ports on a switch. They apply only to incoming traffic on a layer 2 device. PACLs override VACLs and ACLs and provide another layer of access control and filter based on MAC addresses and physical port number.

ACLs and PACLs work at the Data Link Layer (layer 2) of the OSI model at they filter based on the MAC address of the frame or the VLAN tag in the Ethernet frame.

However, a layer 3 switch with ACLs will not filter on ports and will only filter at the networking layer.



References:



Instructor Note
Instructor Notes



11.1.3.2 Operation Modes
Firewalls can be placed using two operational modes. Although Transparent Mode is possible for many firewalls the default (and most common) mode is Routed Mode.

r t mode



Routed Mode

The firewall is a "routed hop" in the network.

It has 2 or more addressable interfaces (each on different networks).

Performs functions a router would perform just with additional filtering roles.

Routes traffic between different IP subnets.

It can perform NAT between connected networks.

Can use routing protocols to relay information between security zones.

Advantages of routed mode include ease of implementation, flexibility in network design, and support for advanced routing features.

Disadvantages are that they are more expensive and are easily targeted.



Transparent Mode.

Is placed on the network as a Layer 2 device that acts like a "bump in the wire".

It is not seen as a hop to connected devices is also called a "stealth firewall".

Bridges traffic between network segments without requiring any IP address changes.

Must be placed "in-line" of network traffic. Between a Router and a switch for example.

Performs functions of a Firewall but not of a router.

Advantages to this type of setup include it makes it much more difficult for an attacker to find the firewall and perform reconnaissance such as "Firewalking".

Disadvantages are that they are not scalable and another transparent mode firewall must be installed for each network segement.



Firewalking is a technique developed by Mike Schiffman and David Goldsmith that utilizes traceroute techniques and TTL values to analyze IP packet responses in order to determine gateway ACL (Access Control List) filters and map networks. It is an active reconnaissance network security analysis technique that attempts to determine which layer 4 protocols a specific firewall will allow.



References:

https://en.wikipedia.org/wiki/Firewalk_(computing)

https://www.sciencedirect.com/topics/computer-science/transparent-mode

https://www.cisco.com/c/en/us/td/docs/security/asa/asa96/configuration/general/asa-96-general-config/intro-fw.html



Instructor Note
Instructor Notes



11.1.3.3 Firewall Filtering Methods
Filtering methods refers to how the filewall can filter traffic. The methods are:

Stateless (Packet) Filtering (L3+4)

Referred to as 1st generation firewalls.

Filters on only the information in the Layer 3 and 4 headers.

Source and Destination IP address

Layer 3 or Layer 4 Protocol. This is identified by examining the Protocol (IPv4) or Next Header (IPv6) fields. This looks for protocols such as ICMP, TCP, or UDP.

TCP or UDP ports

ICMP types/codes

Stateful Inspection (L4)

Referred to as 2nd generation firewalls.

Filters using the same methods as Stateless Firewalls.

Adds "State" tracking. This is done by creating tables of all outgoing connection requests and will allow only the responses to these requests.

This can easily be done with TCP due to its connection nature but can be done with UDP but can be more challenging.

This method offers enhanced security by preventing unauthorized connections and protecting against certain types of network attacks, such as TCP SYN flood attacks.

Circuit-Level (L5)

Filters using the same methods as Stateless Firewalls.

Monitors TCP Handshakes and other session initiated communications.

Application Layer (L7)

Referred to as 3rd generation

Filters using the same methods as Statefull Firewalls.

Adds ability to perform "Deep Packet Inspection". This means that it will recieve all packets in a communication stream and put them together much like the destination host would.

Able to examine data payload to determine if it matches any known signatures or malware types.

Application layer firewalls can filter traffic based on application behavior, content types, URLs, keywords, and other application-specific attributes, providing more comprehensive protection against advanced threats.

Next Generation (NGFW) (L7)

Filters using the same methods as Application Firewalls.

Adds additional "Features".

Built in Anti-Virus scanning.

Web (URL) Filtering.

Deeper packet inspection and Malware detection.

User access control by interacting with Active Directory, LDAP, RADIUS, TACACS+, and others.

Application access control. Based of the source/destination application (not just the port).

Integrated IPS.

TLS/SSL inspection.

QoS management.

Integration and correlation with Security Information and Event Management (SIEM) systems, threat intelligence platforms, endpoint security solutions, and security orchestration, automation, and response (SOAR) tools.



References:

https://searchsecurity.techtarget.com/feature/The-five-different-types-of-firewalls

https://phoenixnap.com/blog/types-of-firewalls



Instructor Note
Instructor Notes



11.1.3.4 Software vs Hardware vs Cloud Firewalls
Software

Host-based firewalls are usually software-based. This means that the Firewall is installed as an application onto the host. The resources needed for its functions must be provisioned from the Operating system. Must share resources with other applications that are hosted on the system. The firewall service is loaded after the operating system boot.

Windows:

[Norton](https://us.norton.com/)

[Mcafee](https://www.mcafee.com/)

[ZoneAlarm](https://www.zonealarm.com/)

[BitDefender](https://www.bitdefender.com/)

[Avast](https://www.avast.com/)

[GlassWire](https://www.glasswire.com/)

[Comodo](https://personalfirewall.comodo.com/)

[TinyWall](https://tinywall.pados.hu/)

Linux:

[iptables](https://www.netfilter.org/projects/iptables/index.html)

[nftables](https://www.netfilter.org/projects/nftables/index.html)

[UncomplicatedFirewall (UFW)](https://wiki.ubuntu.com/UncomplicatedFirewall)

[FirewallD](https://firewalld.org/)

MAC:

[Little Snitch](https://www.obdev.at/index.html)

[LuLu](https://objective-see.com/)

[Vallum](https://vallumfirewall.com/)

[Murus Pro](https://murusfirewall.com/)

Hardware

Network Firewalls typically fall into this category. These are purpose-built appliances with minimal operating systems. They do not contain user applications so all the system resources are dedicated to its function.

[Cisco](https://www.cisco.com/c/en/us/products/security/firewalls/index.html#~products)

[Fortinet](https://www.fortinet.com/products/next-generation-firewall)

[PaloAlto](https://www.paloaltonetworks.com/products/product-selection.html)

[SonicWall](https://www.sonicwall.com/products/firewalls/)

[CheckPoint](https://www.checkpoint.com/quantum/next-generation-firewall/)

[Immunet](https://www.immunet.com/index)

[Barracuda](https://www.barracuda.com/products/cloudgenfirewall)

[F5](https://www.f5.com/products/security/advanced-firewall-manager)

[ForcePoint](https://www.forcepoint.com/product/ngfw-next-generation-firewall)

[Juniper](https://www.juniper.net/us/en/products/security/srx-series.html)

Cloud

Managed by Service Providers and is offered as a "firewall as a service". This is a popular option for smaller organizations that cannot afford to purchase and manage their own appliance firewall.



References:

https://searchsecurity.techtarget.com/feature/The-five-different-types-of-firewalls



Instructor Note
Instructor Notes



11.1.4 Describe the limitations of packet filters in terms of directionality
In both networking and in life What you want is not necessarily what you get. As we have demonstrated the varying results from different types of firewalls let us discuss a possible unintended result from packet filtering firewalls. It is important to be mindful of the direction that your rules are applied. Typically any inbound rules will not have an impact on outbound traffic on that same interface. To effectively control traffic you will need to visualize the traffic in 4 ways.

Traffic originating from the Client (A) localhost to the Server (B) remote-host.

Return traffic from Server (B) remote-host to Client (A) localhost.

--OR--

Traffic originating from the Client (B) remote-host to the Server (A) localhost.

Return traffic from Server (A) localhost to Client (B) remote-host.

Each one of these methods will have different traffic flows and patterns that need to be addressed to ensure you meet your filtering intent.

The goal when placing any rules is to first determine the direction of the intended traffic as it "flows" through each network device. Placement is important as to not affect other traffic. Bi-directional communication must also be taken into account. This means that not only the traffic from a A to B but also the response from B back to A.



References:



Instructor Note
Instructor Notes



11.1.4.1 Tracking traffic from Client A to Server B
In this scenario we are the Client (A) communicating to the Server (B) to it’s SSH port 22.



atob



Tracking traffic from Client (A) to Server (B):

Client: Track outbound traffic by:

The source IP will be ourselves which will not be evaluated.

The client’s random high source port cannot be used for filtering conditions.

Destination IP (192.168.2.10).

Destination service port (22).

Router interface G0/0 Track inbound traffic by:

Source IP (192.168.1.10).

The client’s random high source port cannot be used for filtering conditions.

Destination IP (192.168.2.10).

Destination service port (22).

Router interface G0/1 Track outbound traffic the same as the inbound rules.

Server: Track inbound traffic by:

Source IP (192.168.1.10).

The client’s random high source port cannot be used for filtering conditions.

The destination IP is itself so its not evaluated.

Destination service port (22).

Tracking traffic from Server (B) back to Client (A):

Server: Track outbound traffic by:

The source IP will be itself which will not be evaluated.

Source service port (22).

Destination IP (192.168.1.10)

The client’s random high destination port cannot be used for filtering conditions.

Router interface G0/1 Track inbound traffic by:

Source IP (192.168.2.10).

Source service port (22).

Destination IP (192.168.1.10).

The client’s random high destination port cannot be used for filtering conditions.

Router interface G0/0 Track outbound traffic the same as the inbound rules.

Client: Track inbound traffic by:

Source IP (192.168.2.10).

Source service port (22).

The destination IP is itself so its not evaluated.

The client’s random high destination port cannot be used for filtering conditions.



References:



Instructor Note
Instructor Notes



11.1.4.2 Tracking traffic from Client B to Server A
In this scenario we are the Server (A) with client (B) communicating to our SSH port 22.



btoa



Tracking traffic from Client (B) to Server (A):

Client: Track outbound traffic by:

The source IP will be ourselves which will not be evaluated.

The client’s random high source port cannot be used for filtering conditions.

Destination IP (192.168.1.10).

Destination service port (22).

Router interface G0/1 Track inbound traffic by:

Source IP (192.168.2.10).

The client’s random high source port cannot be used for filtering conditions.

Destination IP (192.168.1.10).

Destination service port (22).

Router interface G0/0 Track outbound traffic the same as the inbound rules.

Server: Track inbound traffic by:

Source IP (192.168.2.10).

The client’s random high source port cannot be used for filtering conditions.

The destination IP is itself so its not evaluated.

Destination service port (22).

Tracking traffic from Server (A) back to Client (B):

Server: Track outbound traffic by:

The source IP will be itself which will not be evaluated.

Source service port (22).

Destination IP (192.168.2.10)

The client’s random high destination port cannot be used for filtering conditions.

Router interface G0/0 Track inbound traffic by:

Source IP (192.168.1.10).

Source service port (22).

Destination IP (192.168.2.10).

The client’s random high destination port cannot be used for filtering conditions.

Router interface G0/1 Track outbound traffic the same as the inbound rules.

Client: Track inbound traffic by:

Source IP (192.168.1.10).

Source service port (22).

The destination IP is itself so its not evaluated.

The client’s random high destination port cannot be used for filtering conditions.



References:



Instructor Note
Instructor Notes



11.1.5 Filter packets utilizing network devices
Filter intentv4



The packet-filtering firewall has a rule (shown in top right) placed on its inbound interface from the internet denying any source IP traffic to 192.168.4.26 which belongs to the DFAS supervisor. When the outside attacker from 178.28.5.24 tries to communicate with that specified ip address, the firewall drops the traffic, as it is supposed to do and shown by the action (deny).



References:



Instructor Note
Instructor Notes



11.1.5.1 Basic filtering intent
Filter intent example



The firewall has the same rule (still in top right). Now user 192.168.4.26 is attempting to communicate with the Ft Bragg regional server. The FT Bragg server is hosting a web site or database server. The internal host 192.168.4.26 begins the TCP three-way handshake to establish a connection before data is transferred. Initially, the internal hosts sends a SYN to establish a connection from a random high port (2525) to the server’s port 80.

The firewall receives the traffic from its internal LAN interface. The firewall checks to see if traffic for the FT Bragg server is allowed to leave the network. In this case, filtering allows this, so traffic from the DFAS supervisors host is sent to 192.168.6.27.

The server now responds back to the TCP SYN message with a SYN/ACK (the second step in the handshake). However, when the firewall examines the packet, it determines the packet matches an access control entry and should be dropped. The result is the connection is never fully established, denying the DFAS supervisor requested resources.



References:



Instructor Note
Instructor Notes



11.1.5.2 Ways to help allow communications between a client and server web sites.
Using a proxy server is one way to correct the communications break and allow 200.1.1.10 to get to the website(s) hosted by 170.1.1.1.

Replacing the packet filtering firewall with a more modern stateful firewall (or application layer) is another way to allow hosts in the internal network to access web services outside the organization network.



11.2 Understand Host Based Filtering
Host-based firewalls are generally software installed on top of a user operating system like Windows, Linux, or MAC. For Windows, there is Windows Firewall (legacy) and the current Windows Defender Firewall. Other 3rd party applications can be installed as well. Linux Host-Based Firewalls include IPTables or NFTables. MAC also has a built-in application firewall.

Host-based firewalls focus on filtering traffic to or from the host it is installed on only. For host-based filtering, we will focus on implementing IPTables and NFTables but the concepts learned from implementing these rules applies to any host-based firewalls.

Windows - Norton, Mcafee, ZoneAlarm, Avast, etc.

Linux - iptables, nftables, UFW, FirewallD, etc.

MAC - Little Snitch, LuLu, Vallum, etc.



References:



Instructor Note
Instructor Notes



11.2.1 Interpret and generate iptables/nftables rules


References:



Instructor Note
Instructor Notes



11.2.1.1 Describe the purpose of netfilter framework in the Linux kernel
Netfilter.org is a community-driven organization dedicated to the development and maintenance of the Netfilter framework, which is a core component of the Linux kernel responsible for packet filtering, network address translation (NAT), packet mangling, and connection tracking.

ipfwadm (IP Firewall Administration) utility was introduced in Linux kernel version 1.2. It served as one of the early packet filtering tools for Linux systems, allowing administrators to configure basic firewall rules to control the flow of network traffic.

ipchains packet filtering framework was introduced in Linux kernel version 2.2. It served as the primary firewall solution for Linux systems until it was superseded by iptables in Linux kernel version 2.4.

iptables was introduced in Linux kernel version 2.4. It replaced the previous packet filtering mechanism, ipchains, which was available in Linux kernel versions prior to 2.4. iptables provided a more flexible and powerful framework for packet filtering, network address translation (NAT), and packet mangling, and it became the standard firewall solution for Linux systems.

nftables was introduced in Linux kernel version 3.13. It was developed as a replacement for the previous packet filtering framework, iptables. nftables provides a more modern, efficient, and flexible infrastructure for packet filtering, network address translation (NAT), and packet mangling. It offers enhanced performance, scalability, and ease of use compared to iptables, and it supports a more expressive and intuitive syntax for defining firewall rules and configurations. Since its introduction, nftables has gained popularity and has gradually replaced iptables as the preferred firewall solution on Linux systems.



References:

https://www.netfilter.org/



Instructor Note
Instructor Notes



11.2.1.2 Netfilter framework
Made to provide:

packet filtering - just using the -(s or d), -p w/ --(dport or sport)

stateless Firewalls - (same as packet filtering)

stateful firewalls (example: -m state --state ESTABLISHED)

network address and port translation (NAT and PAT) (-t nat -A PREROUTING/POSTROUTING ) - NAT and PAT configurations for additional addressing, masquerading and transparent proxies

other packet manipulation ( -t mangle ) - policies for packet modification (mangling) for routing and QoS (Quality of Service) manipulation. The framework can also collect statistics on byte/packet counts for each rule, known as IP Accounting)



References:

https://www.netfilter.org/

[Nftables as a Second Language](https://www.sans.org/reading-room/whitepapers/firewalls/nftables-second-language-35937) by SANS Institute, Kenton Groombridge



Instructor Note
Instructor Notes



11.2.2 Configure iptables filtering rules


References:



Instructor Note
Instructor Notes



11.2.2.1 Netfilter hooks
In Linux, hooks refer to specific points within the kernel code where external modules or subsystems can register callback functions to intercept and modify the behavior of the kernel’s processing flow. These hooks serve as entry or exit points for extending or customizing kernel functionality without directly modifying the kernel source code.

Linux hooks are typically implemented using function pointers or callback mechanisms, allowing external modules to register their own functions to be called at specific points during kernel execution.

Some examples of Linux hooks:

System Startup and Shutdown Hooks:

init scripts and systemd units for custom actions at boot and shutdown.

/etc/rc.local for custom commands at startup.

/etc/rc.d/* directories for custom init scripts.

Kernel Module Hooks:

Module loading/unloading: insmod, rmmod, modprobe.

/etc/modprobe.d/ directory for module configuration.

Shell Startup Hooks:

.bashrc, .bash_profile, .profile for shell initialization.

.zshrc, .zprofile for Zsh shell initialization.

Desktop Environment Hooks:

GNOME/KDE/Xfce startup and logout scripts.

~/.config/autostart for user-level startup applications.

Package Management Hooks:

apt, yum, dnf hooks for package installation/removal.

/etc/apt/apt.conf.d/, /etc/yum/pluginconf.d/ for package manager configuration.

Udev Rules:

/etc/udev/rules.d/ for defining rules for device events.

/lib/udev/rules.d/ for system-wide device rules.

Cron Jobs:

/etc/cron.d/, /etc/cron.daily/, etc. for scheduled tasks.

crontab -e for user-specific cron jobs.

Git Hooks:

Git hooks (e.g., pre-commit, post-merge) for version control actions.

Located in the .git/hooks/ directory of a Git repository.

SSH Hooks:

~/.ssh/rc for SSH client-side scripts.

/etc/ssh/sshd_config for SSH server-side configuration.

Application Configuration Hooks:

Configuration files (e.g., /etc/ssh/sshd_config, /etc/nginx/nginx.conf) for application-specific settings.

Netfilter calls on the five Network Packet Processing Hooks inside the Linux kernel that allows kernel modules to register callback functions with the network stack. A registered callback function is called for every packet that traverses the hooks in the network stack. IPTables uses the same hooks as NFTables.



IPtables



Network Packet Processing Hooks called on by Netfilter:

NF_IP_PRE_ROUTING: Triggers on any incoming traffic after entering the network stack. This hook is tied the the chain PREROUTING and is processed before any routing decisions have been made regarding where to send the packet.

NF_IP_LOCAL_IN: Triggers on incoming packets that have been determined through the internal routing decision that the packet is destined to the local system. This hook is is tied the the chain INPUT.

NF_IP_FORWARD: Triggers on packets that have been determined through the internal routing decision that the packet is to be forwarded to another host through another outbound interface than what it came in on. This hook is is tied the the chain FORWARD.

NF_IP_LOCAL_OUT: Triggers on outbound traffic created by any local process as soon it hits the network stack. This hook is is tied the the chain OUTPUT.

NF_IP_POST_ROUTING: Triggers on any outgoing or forwarded traffic after routing has taken place and just before being transmitted on the wire. This hook is is tied the the chain POSTROUTING.

To use netfilter hooks inside the kernel, you’ll need to create a hook function. A pointer to a function that is called as soon as the hook is triggered.



References:

https://www.netfilter.org/documentation/HOWTO/netfilter-hacking-HOWTO-3.html

https://wiki.nftables.org/wiki-nftables/index.php/Netfilter_hooks

https://www.digitalocean.com/community/tutorials/a-deep-dive-into-iptables-and-netfilter-architecture#netfilter-hooks



Instructor Note
Instructor Notes



11.2.2.2 Netfilter paradigm
T30 NetfilerFrameHieracrchy



Many components are common to both iptables and nftables as they use the same back end processes and hooks to execute host based filtering in *Nix. One characteristic both tables have is a common hierarchy which consists of:

Tables - contain chains

Chains - contain rules

Rules - dictate what to match and what actions to perform on packets when packets match a rule

In iptables the tables and chains are already created so only the rules need to be made. nftables generally come with nothing configured so the tables and chains must be created along with the rules.



References:



Instructor Note
Instructor Notes



11.2.2.3 What are iptables?
Iptables is the mechanism that Linux operating systems use to filter traffic to, from, or through a host. Rules are configured on the host based on IP’s, ports, protocols, policies, etc. It all depends on what your requirements are. Rules are read from the top of the rules list to the bottom. So, order matters.

Iptables are the default firewall for most Linux distributions such as (Debian and Ubuntu). Ubuntu does however come with ufw (Uncomplicated Firewall) that will assist users in configuring iptable rules but it is disabled by default. CentOS and Red Hat Enterprise Linux (RHEL) distributions use firewalld by default to manage the firewall and configure iptables.

There are several different iptables tables that you can use depending on your requirements.

Netfilter project created several (separate) applications to filter on different layer 2 or layer 3+ protocols.

iptables - IPv4 packet administration [(Manual)](http://ipset.netfilter.org/iptables.man.html), [(Manual Extensions)](http://ipset.netfilter.org/iptables-extensions.man.html)

ip6tables - IPv6 packet administration [(Manual)](http://ipset.netfilter.org/ip6tables.man.html)

ebtables - Ethernet Bridge frame table administration [(Manual)](https://linux.die.net/man/8/ebtables)

arptables - arp packet administration [(Manual)](https://linux.die.net/man/8/arptables)

Each of these applications contains:

Packet matching Tables.

Process on how the Kernal is to process any matched packets.

Process on specific Chains/Hooks.



References:

http://ipset.netfilter.org/iptables.man.html

http://ipset.netfilter.org/iptables-extensions.man.html

http://ipset.netfilter.org/ip6tables.man.html

https://linux.die.net/man/8/ebtables

https://linux.die.net/man/8/arptables

https://ubuntu.com/server/docs/security-firewall



Instructor Note
Instructor Notes



11.2.2.3 Tables of iptables
filter - default table. Used to ACCEPT, DROP or REJECT packets that match. Provides packet filtering.

INPUT: packets going to the local machine

FORWARD: packets routed through the server

OUTPUT: locally generated packets

nat - used to translate private ←→ public address and ports.

PREROUTING: designating packets when they come in

POSTROUTING: locally generated packets before routing takes place

OUTPUT: altering packets on the way out

mangle - provides special packet alteration. Can modify various fields header fields.

PREROUTING: incoming packets

POSTROUTING: outgoing packets

INPUT: packets coming directly into the server

FORWARD: packets being routed through the server

OUTPUT: locally generated packets that are being altered

raw - used to configure exemptions from connection tracking.

PREROUTING: packets that arrive by the network interface

OUTPUT: processes that are locally generated

security - used for Mantator Access Control (MAC) networkign rules.

INPUT: packets entering the server

FORWARD: packets passing through the server

OUTPUT: locally generated packets



References:

[Netfilter Tables](https://www.digitalocean.com/community/tutorials/a-deep-dive-into-iptables-and-netfilter-architecture#which-tables-are-available)

[Netfilter Chains](https://www.digitalocean.com/community/tutorials/a-deep-dive-into-iptables-and-netfilter-architecture#iptables-tables-and-chains)



Instructor Note
Instructor Notes



11.2.2.4 iptables syntax
iptables -t [table] [options] [chain] [rules] -j [action]

-t [table] can be filter(default), nat, mangle, raw or security
Common iptable [options]:

-A, --append - Append a rule. Rule will be created at the end of the list or below the rule number you specify.
-I, --insert - Insert a rule. Rule will be created at the top of the list or above the rule number you specify.
-R, --replace - Replace a rule. The rule number your specify will be replaced with this rule.
-D, --delete - Delete a rule. The rule number you specify will be deleted.
-F, --flush - Flush the table of all rules.
-L, --list - List all rules in the specified table.
-S, --list-rules - Prints the rules in the specified table.
-P, --policy - Set the policy for the chain.
-n, --numeric - IP addresses and port numbers will be printed in numeric format.
-L --line-numbers - When listing rules, add line numbers to the beginning of each rule, corresponding to that rule's position in the chain.
[chain] - Can be PREROUTING, INPUT, FORWARD, OUTPUT, or POSTROUTING
[rules]

-i [iface] - Specifies the input interface
-o [iface] - Specifies the output interface
-s [ip.add | network/mask] - Specifies the source IP
-d [ip.add | network/mask] - Specifies the destination IP
-p [tcp | udp | icmp] - Specifies the protocol.
-p [tcp | udp] --sport [port | port1:port2] - Specifies the source port(s). Can be one port or one range.
-p [tcp | udp] --dport [port | port1:port2] - Specifies the destination port(s). Can be one port or one range.
-p icmp --icmp-type type# { /code# }  - Specifies specific icmp types and codes
-p tcp --tcp-flags SYN,ACK,PSH,RST,FIN,URG,ALL,NONE  - Specifies specific one or more TCP flags to filter on.

-m is used to call functions from iptables extensions:
-m state --state [state] - Enables stateful packet tracking. States can be NEW,ESTABLISHED,RELATED,UNTRACKED,INVALID
-m conntrack --ctstate [state] - Enables stateful packet tracking. States can be NEW,ESTABLISHED,RELATED,UNTRACKED,INVALID
-m mac --mac-source [mac]
       --mac-destination [mac]
-m multiport -p [tcp | udp] --sports [port1,port2,..port15] - Specifies the source port(s). Can be one port, one range, or
                                                             comma delimited.
                            --dports [port1,port2,..port15] - Specifies the destination port(s). Can be one port, one range, or
                                                             comma delimited.
                            --ports [port1,port2,..port15]  - Specifies the port(s). Can be one port, one range, or comma delimited.
                                                             Ports imply source or destination.
-m bpf --bytecode "bytecode" - Specify a Berkeley Packet Filter (BPF) bytecode filter as a matching criteria for filtering
                               network packets.
-m iprange --src-range { ip1-ip2 } - Specifies a range of source IPs.
           --dst-range { ip1-ip2 } - Specifies a range of destination IPs.
-j [action] - ACCEPT, REJECT, or DROP


References:

http://ipset.netfilter.org/iptables.man.html

http://ipset.netfilter.org/iptables-extensions.man.html



Instructor Note
Instructor Notes



11.2.2.5 iptables rule examples
Specify an interface

iptables -A INPUT -i eth0 -j ACCEPT
iptables -A OUTPUT -o eth1 -j ACCEPT
iptables -A FORWARD -i eth0 -o eth1 -j ACCEPT
Specify an IP address

iptables -A INPUT -s 10.10.0.40 -j ACCEPT
iptables -A OUTPUT -d 10.10.0.40 -j ACCEPT
iptables -A FORWARD -s 192.168.1.10 -d 10.10.0.40 -j ACCEPT
Specify a network

iptables -A INPUT -s 10.10.0.32/27 -j ACCEPT
iptables -A OUTPUT -d 10.10.0.32/27 -j ACCEPT
iptables -A FORWARD -s 192.168.1.0/24 -d 10.10.0.32/27 -j ACCEPT
Specify a TCP port as a server

iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -A OUTPUT -p tcp --sport 22 -j ACCEPT
Specify a TCP port as a client

iptables -A OUTPUT -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -p tcp --sport 22 -j ACCEPT
Specify a UDP port as a server

iptables -A INPUT -p udp --dport 53 -j ACCEPT
iptables -A OUTPUT -p udp --sport 53 -j ACCEPT
Specify a UDP port as a client

iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
iptables -A INPUT -p udp --sport 53 -j ACCEPT
Specify inbound ICMP

iptables -A INPUT -p icmp --icmp-type 8 -j ACCEPT
iptables -A OUTPUT -p icmp --icmp-type 0 -j ACCEPT
Specify outboud ICMP

iptables -A OUTPUT -p icmp --icmp-type 8 -j ACCEPT
iptables -A INPUT -p icmp --icmp-type 0 -j ACCEPT
Specify TCP ports using multiport

iptables -A INPUT -p tcp -m multiport --ports 21-23,80,3389 -j ACCEPT
iptables -A OUTPUT -p tcp -m multiport --ports 21-23,80,3389 -j ACCEPT
Specify UDP ports using multiport

iptables -A INPUT -p udp -m multiport --ports 53,67-69 -j ACCEPT
iptables -A OUTPUT -p udp -m multiport --ports 53,67-69 -j ACCEPT
Specify TCP states using multiport

iptables -A INPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT


References:

http://ipset.netfilter.org/iptables.man.html

http://ipset.netfilter.org/iptables-extensions.man.html



Instructor Note
Instructor Notes



11.2.2.6 Modify iptables
Flush table. This will delete all the rules in the table specified. It will not however change the policies.

iptables -t [table] -F
Change default policy. ACCEPT is the default policy (Block-List). This is used to change it to REJECT or DROP.

iptables -t [table] -P [chain] [action]
iptables -t filer -P INPUT DROP
iptables -t filer -P OUTPUT REJECT
iptables -t filer -P FORWARD ACCEPT
Lists the rules in the specified table.

iptables -t [table] -L
Lists rules with rule numbers.

iptables -t [table] -L --line-numbers
Lists rules as commands interpreted by the system.

iptables -t [table] -S
Inserts rule at the top of the list.

iptables -t [table] -I [chain] [rule] -j [action]
iptables -t filter -I INPUT -p tcp -m multiport --ports 21-23,80,3389 -j ACCEPT
Inserts rule before Rule number.

iptables -t [table] -I [chain] [rule #] [rule] -j [action]
iptables -t filter -I INPUT 5 -p tcp -m multiport --ports 21-23,80,3389 -j ACCEPT
Replaces rule at number.

iptables -t [table] -R [chain] [rule #] [rule] -j [action]
iptables -t filter -R INPUT 5 -p tcp -m multiport --ports 21-23,80,3389 -j ACCEPT
Deletes rule at number.

iptables -t [table] -D [chain] [rule #]
iptables -t filter --D INPUT 5


References:

https://ipset.netfilter.org/iptables.man.html

http://ipset.netfilter.org/iptables-extensions.man.html



Instructor Note
Instructor Notes



11.2.2.7 iptables demonstration
For the demonstration you will need to access your INTERNET_HOST, BLUE_HOST-1, BLUE_HOST-3, and BLUE_INT_DMZ_HOST-1 hosts via multiple terminals or terminator.

You will be constructing and placing iptables rules to meet the intent for filtering on the Linux hosts.



List iptables rules on your BLUE_HOST-1.

student@blue_host-1:~$ sudo iptables -L
[sudo] password for student:
Chain INPUT (policy ACCEPT)
target     prot opt source               destination

Chain FORWARD (policy ACCEPT)
target     prot opt source               destination

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination
This shows the rules for the filter table (the default table since no table was listed). In this case, there are no rules. You can run the command using -S list the rules by chain and its default policies. The dedault policies are listed as ACCEPT.

To view the rules on the nat, mangle, raw or security tables, insert -t [table_name] after the iptables command.



Create IPTables rules

I want to explicitly open tcp port 22 as both source and destination port and as both INPUT and OUTPUT. If you are creating these rules on your Internet_Host then you will also need to ensure your allow your X11 forwarding ports (6010, 6011, and 6012).

These rules will allow your system to be the SSH server. It will allow incoming SSH traffic destined to your localhost port 22 and allow SSH traffic from your localhost port 22.

$ sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT
$ sudo iptables -A OUTPUT -p tcp --sport 22 -j ACCEPT
These rules will allow your system to be an SSH client. It will allow outbound traffic destined to the remote SSH port 22 and allow the return traffic from the remote SSH port 22.

$ sudo iptables -A OUTPUT -p tcp --dport 22 -j ACCEPT
$ sudo iptables -A INPUT -p tcp --sport 22 -j ACCEPT
Optional - If you need to enable X11 forwarding on your system. These rules will allow inbound tcp traffic to/from ports 6010, 6011 and 6012 using the multiport --ports option. It will also allow the traffic to/from those ports for outbound traffic.

$ sudo iptables -A INPUT -p tcp -m multiport --ports 6010,6011,6012 -j ACCEPT
$ sudo iptables -A OUTPUT -p tcp -m multiport --ports 6010,6011,6012 -j ACCEPT
When packets match rules criteria, the table executes the target command associated with the matching rule. Commonly used targets in iptables include: ACCEPT, DROP, and REJECT. If the criteria is not matched, it moves on to the next rule sequentially from top to bottom. Default policies (iptables-outcomes) are read last and provide the explicit default action.



Close all other ports via Policy (-P switch) and list the iptables rules

$ sudo iptables -P INPUT DROP
$ sudo iptables -P OUTPUT DROP
$ sudo iptables -P FORWARD DROP

$ sudo iptables -L -n --line-numbers
Chain INPUT (policy DROP)
num  target     prot opt source               destination
1    ACCEPT     tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:22
2    ACCEPT     tcp  --  0.0.0.0/0            0.0.0.0/0            tcp spt:22
3    ACCEPT     tcp  --  0.0.0.0/0            0.0.0.0/0            multiport ports 6010,6011,6012

Chain FORWARD (policy DROP)
num  target     prot opt source               destination

Chain OUTPUT (policy DROP)
num  target     prot opt source               destination
1    ACCEPT     tcp  --  0.0.0.0/0            0.0.0.0/0            tcp spt:22
2    ACCEPT     tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:22
3    ACCEPT     tcp  --  0.0.0.0/0            0.0.0.0/0            multiport ports 6010,6011,6012
Always test the effectiveness of the iptables rules and connectivity. This can be done with any host as long as it matches the criteria of the rules created.



Block / Allow specific IP addresses (Block-Listing and Allow-Listing)

These rules will block all inbound and outbound traffic to/from 172.16.82.112 (BLUE_HOST-3) but accept all inbound and outbound traffic to/from 172.16.40.10 (BLUE_INT_DMZ_HOST-1)

Since processing order has been covered, ensure that their rules would block all 172.16.82.112 traffic (must be placed before the ssh rule).

$ sudo iptables -I INPUT -s 172.16.82.112 -j DROP
$ sudo iptables -I OUTPUT -d 172.16.82.112 -j DROP
$ sudo iptables -A INPUT -s 172.16.40.10 -j ACCEPT
$ sudo iptables -A OUTPUT -d 172.16.40.10 -j ACCEPT
List the rules and insure the rules are in the correct order.

$ sudo iptables -L --line-numbers
Chain INPUT (policy DROP)
num  target     prot opt source               destination
1    DROP       all  --  172.16.82.112        anywhere
2    ACCEPT     tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:22
3    ACCEPT     tcp  --  0.0.0.0/0            0.0.0.0/0            tcp spt:22
4    ACCEPT     tcp  --  0.0.0.0/0            0.0.0.0/0            multiport ports 6010,6011,6012
5    ACCEPT     all  --  172.16.40.10         anywhere

Chain FORWARD (policy DROP)
num  target     prot opt source               destination

Chain OUTPUT (policy DROP)
num  target     prot opt source               destination
1    DROP       all  --  anywhere             172.16.82.112
2    ACCEPT     tcp  --  0.0.0.0/0            0.0.0.0/0            tcp spt:22
3    ACCEPT     tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:22
4    ACCEPT     tcp  --  0.0.0.0/0            0.0.0.0/0            multiport ports 6010,6011,6012
5    ACCEPT     all  --  anywhere             172.16.40.10
Always test rules to make sure everything matches criteria required.



Tracking connections

Viewing the number of packets and the size of data matching the iptalbes rules, as well as number of dropped packets is possible via the verbose switch (-v):

$ sudo iptables -L -v
(pkts and bytes will vary)

Chain INPUT (policy DROP 173 packets, 11996 bytes)
 pkts bytes target     prot opt in     out     source               destination
    0     0 DROP       all  --  any    any     172.16.82.112        anywhere
13472 1940K ACCEPT     tcp  --  any    any     anywhere             anywhere             tcp dpt:ssh
    0     0 ACCEPT     tcp  --  any    any     anywhere             anywhere             tcp spt:ssh
33017 6762K ACCEPT     tcp  --  any    any     anywhere             anywhere             multiport ports 6010,6011,6012
    6   504 ACCEPT     all  --  any    any     172.16.40.10         anywhere

Chain FORWARD (policy DROP 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination

Chain OUTPUT (policy DROP 211 packets, 15224 bytes)
 pkts bytes target     prot opt in     out     source               destination
    2   168 DROP       all  --  any    any     anywhere             172.16.82.112
    0     0 ACCEPT     tcp  --  any    any     anywhere             anywhere             tcp dpt:ssh
13571 3785K ACCEPT     tcp  --  any    any     anywhere             anywhere             tcp spt:ssh
32427 6669K ACCEPT     tcp  --  any    any     anywhere             anywhere             multiport ports 6010,6011,6012
    6   504 ACCEPT     all  --  any    any     anywhere             172.16.40.10


Packet and byte counts can be reset via:

$ sudo iptables -Z
The previous command (-Z) results in a table with the count reset.



Use iptables-save to Save your configuration

Use the iptables-save command and direct it to a file name.

$ sudo iptables-save > cctcipt.conf
$ ls -l
total 8
-rw-r--r-- 1 student student  800 Aug  3 20:37 cctcipt.conf
Other switch options that can be used are as follows: -c keeps the current packet and byte counters
-t is used to save a specific table, by default all tables are saved.

Preparing to Flush (-F) the rules

Change all policies back to ACCEPT:

$ sudo iptables -P INPUT ACCEPT
$ sudo iptables -P OUTPUT ACCEPT
$ sudo iptables -P FORWARD ACCEPT
Flush the rules:

$ sudo iptables -F
Use the iptables-restore to, well, restore the configuration.

$ sudo iptables-restore < cctcipt.conf -v
[sudo] password for student:
# Generated by iptables-save v1.6.0 on Mon Aug  3 20:37:16 2020
Flushing chain `INPUT'
Flushing chain `FORWARD'
Flushing chain `OUTPUT'
# Completed on Mon Aug  3 20:37:16 2020


References:

http://ipset.netfilter.org/iptables.man.html

http://ipset.netfilter.org/iptables-extensions.man.html#lbDO



Instructor Note
Instructor Notes



11.2.3 Configure NFTables filtering rules
What are nftables?

Nftables is a new packet classification framework that aims to replace the existing iptables. However, in contrast to Iptables, no pre-defined tables or chains exist. All tables and chains have to be explicitly created by the user. The user can give arbitrary names to the tables and chains when creating them.

Nftables has been available since Linux kernel 3.13 released on 19 January 2014. Starting with Debian 10 Buster (released July 6th, 2019), nftables is now the default firewall framework.

Nftables family entries are linked to all tables and chains are:

ip - IPv4 packets (at layer 3)

ip6 - IPv6 packets (layer 3)

inet - IPv4 and IPv6 packets

arp - layer 2 (Data Link layer information) before processing at the Network layer

bridge - processing traffic/packets traversing bridges (switching).

netdev - allows for user classification of packets nftables passes up to the networking stack, allowing for visibility of network traffic traversing the NIC. Netdev has been used to prevent DDoS attacks and load balancing. This is new to nftables as there was no counterpart in iptables.



References:

https://www.netfilter.org/projects/nftables/manpage.html

https://www.debian.org/releases/buster/



Instructor Note
Instructor Notes



11.2.3.1 NFTables Enhancements
There are several enhancements with NFTables which include:

one framework that combines:

iptables

ip6tables

arptables

ebtables

much greater flexibility

faster rule processing using BPFs

simpler and cleaner syntax

easier to write and to maintain

less code duplication

easier extension to new protocols

simultaneous configuration of IPv4 and IPv6

each rule can take multiple actions

That said, IPTables and NFTables are both used in production environments (the reason you are learning both). IPTables is robust enough for many legacy uses while NFTables, created by the same organization, is the newer *Nix host based firewall.



References:

https://wiki.nftables.org/wiki-nftables/index.php/Main_differences_with_iptables



Instructor Note
Instructor Notes



11.2.3.2 NFTables hooks
T31 NftablesFlow



With IPTables, the standard tables and chains are all pre-created and the chains are already tied to their respective hooks. * Tables for IPv4 traffic only: filter nat mangle security ** raw

Chains already assigned to the tables and mapped to their hooks:

PREROUTING chain was pre-created and mapped to the NF_IP_PRE_ROUTING hook.

INPUT chain mapped to NF_IP_LOCAL_IN hook

FORWARD chain mapped to NF_IP_FORWARD hook

OUTPUT chain mapped to NF_IP_LOCAL_OUT hook

POSTROUTING chain mapped to NF_IP_POST_ROUTING hook

With NFTables, no tables or chains are pre-made nor are the chains mapped to their hooks. These all will need to be created.

The hooks are:

ingress - This hook, available only in the netdev family, processes packets entering the system. It is invoked at Layer 2 and used for early filtering, policing and Network and Port Address Translation.

prerouting - hook is triggered by any incoming traffic very soon after entering the network stack. This hook is processed before any routing decisions have been made.

input - is triggered after an incoming packet has been routed if the packet is destined for the local system.

forward - This hook is triggered after an incoming packet has been routed if the packet is to be forwarded to another host.

output - hook is triggered after an incoming packet has been routed if the packet is to be forwarded to another host.

Postrouting - triggered by any outgoing or forwarded traffic after routing has taken place and just before being put out on the wire.



References:



Instructor Note
Instructor Notes



11.2.3.3 Nftables chain types
The possible chain types are:

filter - Filter chains are the most common and widely used chain type in nftables. They are responsible for filtering network packets based on predefined rules. Filter chains are typically used for implementing firewall policies to allow, block, or modify traffic based on criteria such as source/destination IP addresses, port numbers, and protocols. This is supported by the arp, bridge, ip, ip6 and inet table families.

route - used to reroute packets if any relevant IP header field or the packet mark is modified. If you are familiar with iptables, this chain type provides equivalent semantics to the mangle table but only for the output hook (for other hooks use type filter instead). Route chains allow administrators to define rules for forwarding packets to different network interfaces or routing tables based on specific criteria such as source/destination IP addresses, packet attributes, or firewall marks. This is supported by the ip, ip6 and inet table families.

nat - used to perform Networking Address Translation (NAT). Only the first packet of a given flow hits this chain; subsequent packets bypass it. Therefore, never use this chain for filtering. NAT chains are responsible for modifying source and destination IP addresses and port numbers to enable communication between different network segments, facilitate internet access for internal hosts, and hide internal network topologies. The nat chain type is supported by the ip, ip6 and inet table families.



References:

https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains#Base_chain_types

https://www.netfilter.org/projects/nftables/manpage.html



Instructor Note
Instructor Notes



11.2.3.4 NFTables syntax
In order to create nftables, you have to configure them in this order



1. Create the Table using the nft add table command.

Tables are a container of chains. There are no tables pre-created in NFTables whereas iptables had tables like filter, nat, mangle, raw, and security already pre-made.

To create a new table:

nft add table [family] [table]

[family] = ip(default), ip6, inet, arp, bridge and netdev.

[table] = user provided name for the table.


2. Create the Base Chain using the nft add chain command.

Chains are a container of rules. There are no chains pre-created in NFTables whereas iptables has chains like PREROUTING, INPUT, FORWARD, OUTPUT, and POSTROUTING. In iptables, these chains are aleady mapped to their respective netfilter hooks. In NFTables we must create these chains and map them to their respective netfilter hooks.

When creating the chains we must specify which table to place them in.

To create a new chain:

nft add chain [family] [table] [chain] { type [type] hook [hook] priority [priority] \; policy [policy] \;}

[chain] = User defined name for the chain.

[type] =  can be filter, route or nat.

[hook] = prerouting, ingress, input, forward, output or postrouting.

[priority] = user provided integer. Lower number = higher priority. default = 0. Use "--" before negative numbers. (`-- -100`)

[policy]  = set policy for the chain. Can be accept (default) or drop.

Use "\" to escape the ";" in bash. The `;`(semi colon ) is used to separate commands on same line


3. Create a rule in the Chain using the nft add rule command.

Rules must be created to specify what traffic we wish to filter by specifying specify match statements.

When creating the rules we need to speicify which table and chain to place them in.

To create a new rule:

nft add rule [family] [table] [chain] [matches (matches)] [statement]

[matches] = typically protocol headers(i.e. ip, ip6, tcp, udp, icmp, ether, etc)

(matches) = these are specific to the [matches] field.

[statement] = action performed when packet is matched. Some examples are: log, accept, drop, reject, counter, nat (dnat, snat, masquerade)
[matches]

ip saddr { ip | ip1-ip2 | ip/CIDR | ip1, ip2, ip3 }
ip daddr { ip | ip1-ip2 | ip/CIDR | ip1, ip2, ip3 }
tcp flags { syn, ack, psh, rst, fin }
tcp sport { port1 | port1-port2 | port1, port2, port3 }
tcp dport { port1 | port1-port2 | port1, port2, port3 }
udp sport { port1 | port1-port2 | port1, port2, port3 }
udp dport { port1 | port1-port2 | port1, port2, port3 }
icmp type type#
icmp code code#
ct state { new, established, related, invalid, untracked }
iif [iface]
oif [iface]
[statement] - can be accept, reject, or drop


References:

https://www.netfilter.org/projects/nftables/manpage.html

https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes

https://javarevisited.blogspot.com/2011/06/special-bash-parameters-in-script-linux.html



Instructor Note
Instructor Notes



11.2.3.5 NFTables rule examples
Creating a table

nft add table ip CCTC
Creating chains

nft add chain ip CCTC INPUT { type filterhook input priority 0 \; policy accept \;}
nft add chain ip CCTC OUTPUT { type filter hook output priority 0 \; policy accept \;}
Specify an interface

nft add rule ip CCTC INPUT iif eth0 accept
nft add rule ip CCTC OUTPUT oif eth1 accept
Specify an IP address

nft add rule ip CCTC INPUT ip saddr 10.10.0.40 accept
nft add rule ip CCTC OUTPUT ip daddr 10.10.0.40 accept
Specify a network

nft add rule ip CCTC INPUT ip saddr 10.10.0.32/27 accept
nft add rule ip CCTC OUTPUT ip daddr 10.10.0.32/27 accept
Specify a TCP ports as a server

nft add rule ip CCTC INPUT tcp dport { 21-23, 80, 3389 } accept
nft add rule ip CCTC OUTPUT tcp sport { 21-23, 80, 3389 } accept
Specify a TCP ports as a client

nft add rule ip CCTC OUTPUT tcp dport { 21-23, 80, 3389 } accept
nft add rule ip CCTC INPUT tcp sport { 21-23, 80, 3389 } accept
Specify a UDP ports as a server

nft add rule ip CCTC INPUT udp dport { 53, 67-69 } accept
nft add rule ip CCTC OUTPUT udp sport { 53, 67-69 } accept
Specify a UDP ports as a client

nft add rule ip CCTC OUTPUT udp dport { 53, 67-69 } accept
nft add rule ip CCTC INPUT udp sport { 53, 67-69 } accept
Specify inbound ICMP

nft add rule ip CCTC INPUT icmp type 8 accept
nft add rule ip CCTC OUTPUT icmp type 0 accept
Specify outboud ICMP

nft add rule ip CCTC OUTPUT icmp type 8 accept
nft add rule ip CCTC INPUT icmp type 0 accept
Specify TCP states

nft add rule ip CCTC INPUT tcp dport { 21-23, 80, 3389 } ct state { new, established } accept
nft add rule ip CCTC OUTPUT tcp sport { 21-23, 80, 3389 } ct state { new, established }  accept


References:

https://www.netfilter.org/projects/nftables/manpage.html

https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes

https://javarevisited.blogspot.com/2011/06/special-bash-parameters-in-script-linux.html



Instructor Note
Instructor Notes



11.2.3.6 Modify NFTables


The ruleset keyword is used to identify the whole set of tables, chains, etc. currently in place in kernel.

nft {list | flush} ruleset [-a]
The ruleset keyword is used to identify the whole set of tables, chains, etc. currently in place in kernel. This will with list or flush the ruleset.



nft {add | delete | list | flush } table [family] [table]
Delete will delete the specified table and its rules.

Flush will delete the chains and rules in the table but not the table itself.

List will display the chains and rules in the specified table.



nft {add | delete | list | flush } chain [family] [table] [chain]
Delete will delete the specified chain in the specified table.

Flush will delete the rules in the specified chain in the specified table.

List will display the rules in the specified chain in the specified table.



List the table with the handle numbers

nft list table [family] [table] [-a]


Adds after the rule with the specified handle number

nft add rule [family] [table] [chain] [position <position>] [matches (matches)] [statement]


Inserts before the rule with the specified handle number

nft insert rule [family] [table] [chain] [position <position>] [matches (matches)] [statement]


Replaces the rule with the specified handle number

nft replace rule [family] [table] [chain] [handle <handle>] [matches (matches)] [statement]


Deletes the rule with the specified handle number

nft delete rule [family] [table] [chain] [handle <handle>]


To change the current policy

nft add chain [family] [table] [chain] { \; policy [policy] \;}


References:

https://www.netfilter.org/projects/nftables/manpage.html

https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes

https://javarevisited.blogspot.com/2011/06/special-bash-parameters-in-script-linux.html



Instructor Note
Instructor Notes



11.2.3.7 NFTables demonstration


There are no pre-created tables in NFTables like there are in IPTables (filter, nat, mangle, etc.). Tables must be created and mapped to a specific family (ip, ip6, or inet).



Create the table

$ sudo nft add table ip HEADER
$ sudo nft list ruleset
table ip HEADER
If you do not explicitly express the [family], [ip] is the default.



Create a base chain

Since there are no predefined chains in nftables, they have to be created. The two types of chains are:

Non-base (occasionally referred to as Regular) - which is used as a jump target (the action to be performed). Non-base chains are not mapped to a hook so it does not not see the traffic unless passed it by a base chain.

Creating a regular (non-base) chain syntax is:

nft add chain [family] [table_name] [chain_name]
Base - used for rules that filters packets. Base chains are mapped to a hook. (where packets are compared and which uses the kernel hooks to assess the network packets)

Creating a base chain the syntax is:

nft add chain [family] [table] [chain] { type [type] hook [hook] priority [priority] \; policy [policy] \;}
[Family] = this must be the same you provided when you created the table.

[Table] = this must be the same name you provided when you created the table.

[Chain] = User defined name for the chain.

[Type] = can be filter, route or nat. This will correlate to the Family.

[Hook] = for IPv4, IPv6 and inet (IPv4/6) addresses are: prerouting, input, forward, output or postrouting. This will correlate depending on the Family and Type.

[priority] = This is a user provided integer. The lower the number, the higher the priority. Priorities can be negative numbers. The filter table has a default priority of 0. Default priorities are published at: https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains. For the purposes of this class, default priorities will be used and will not be explicitly expressed in the rules.

[policy] = this will set the default policy for the chain. Can be accept (default), reject, drop.



$ sudo nft add chain ip HEADER INPUT { type filter hook input priority 0 \; policy accept \; }
$ sudo nft add chain ip HEADER OUTPUT { type filter hook output priority 0 \; policy accept \; }


Now list the chain rules, which will result in:

$ sudo nft list ruleset
table ip HEADER {
	chain INPUT {
		type filter hook input priority 0; policy accept;
	}

	chain OUTPUT {
		type filter hook output priority 0; policy accept;
	}
}


Creating NFTables rules

Similar to iptables, rules are added via add (append to end of the chain) and insert (prepend to the top of the chain).

Creating rule syntax is:

nft [add/insert] rule [family] [table] [chain] [matches (matches)] [statement]
[Family] = this must be the same you provided when you created the table.

[Table] = this must be the same name you provided when you created the table.

[Chain] = this must be the same name you provided when you created the chain.

[matches] = these are typically the protocol header specification (i.e. ip, ip6, tcp, udp, icmp, ether, etc)

(matches) = these are specific to the [matches] field. Use this link for a comprehensive list. https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes

[statement] = action performed when packet is matched. Some examples are: log, accept, drop, reject, counter, dnat, snat, masquerade.

accept

drop

queue (send to userspace and stop further rule evaluation)

log (the packets)

reject (and provide a reason in a return message)

limit (traffic flow rate)

nat - for network address translation

and a few others not covered in this course



To explicitly open tcp port 22 as both source and destination port for the input hook and list the rule by listing the chain. This requires more granular detail than the chain listing.



$ sudo nft insert rule ip HEADER input tcp dport 22 accept
$ sudo nft insert rule ip HEADER input tcp sport 22 accept
$ sudo nft list chain ip HEADER input -ann
table ip HEADER {
	chain input {
		type filter hook input priority 0; policy accept;
		tcp sport 22 accept # handle 4
		tcp dport 22 accept # handle 3
	}
}
The -ann option at the end of the command causes display of the handle (rule) number; nn disables address and port resolution; n alone disables address resolution.

-a, --handle - Show object handles in output.

-n, --numeric - Print fully numerical output.



Knowing what you have seen thus far, add a base chain hooked to output, add rules to explicitly allow ssh and list the chain and rules.

$ sudo nft insert rule ip HEADER output tcp dport 22 accept
$ sudo nft insert rule ip HEADER output tcp sport 22 accept
$ sudo nft list chain ip HEADER output -ann
table ip HEADER {
	chain output {
		type filter hook output priority 0; policy accept;
		tcp sport 22 accept # handle 6
		tcp dport 22 accept # handle 5
	}
}


Edit the Chains to drop all other traffic by editing the policy for the chains and list the rules by chain.

$ sudo nft add chain ip HEADER input { \; policy drop \; }
$ sudo nft add chain ip HEADER output { \; policy drop \; }
$ sudo nft list ruleset -a
table ip HEADER {
	chain input {
		type filter hook input priority 0; policy drop;
		tcp sport ssh accept # handle 4
		tcp dport ssh accept # handle 3
	}

	chain output {
		type filter hook output priority 0; policy drop;
		tcp sport ssh accept # handle 6
		tcp dport ssh accept # handle 5
	}
}


Block / Allow specific IP addresses (Block-Listing and Allow-Listing)

To block and allow specific IP addresses, use the saddr and daddr (souce and destination address) matches and statements to allow or drop as desired. As in the iptables demonstration, this demonstration will block (drop) all traffic from BLUE_HOST-1 (172.16.82.106) and allow (accept) all traffic from BLUE_INT_DMZ_HOST-1 (172.16.40.10)

$ sudo nft insert rule ip HEADER input ip saddr 172.16.82.106 drop
$ sudo nft insert rule ip HEADER output ip daddr 172.16.82.106 drop
$ sudo nft add rule ip HEADER output ip daddr 172.16.40.10 accept
$ sudo nft add rule ip HEADER input ip saddr 172.16.40.10 accept
$ sudo nft list ruleset -a

 table ip HEADER {
     chain input {
		type filter hook input priority 0; policy drop;
		ip saddr 172.16.82.106 drop # handle 7
		tcp sport ssh accept # handle 4
		tcp dport ssh accept # handle 3
		ip saddr 172.16.40.10 accept # handle 10
	}

	chain output {
		type filter hook output priority 0; policy drop;
		ip daddr 172.16.82.106 drop # handle 8
		tcp sport ssh accept # handle 6
		tcp dport ssh accept # handle 5
		ip daddr 172.16.40.10 drop # handle 9
	}

}


To allow X11 forwarding ports (inbound and outbound) both to (and from) system.

$ sudo nft insert rule ip HEADER input tcp dport { 6010, 6012, 6011 } ct state { new, established } accept
$ sudo nft insert rule ip HEADER input tcp sport { 6010, 6012, 6011 } ct state { new, established } accept
$ sudo nft insert rule ip HEADER output tcp dport { 6010, 6012, 6011 } ct state { new, established } accept
$ sudo nft insert rule ip HEADER output tcp sport { 6010, 6012, 6011 } ct state { new, established } accept
$ sudo nft list ruleset -a
table ip HEADER {
	chain input {
		type filter hook input priority 0; policy drop;
		ip saddr 172.16.82.106 drop # handle 7
		tcp sport ssh accept # handle 4
		tcp dport ssh accept # handle 3
		ip saddr 172.16.40.10 accept # handle 10
		tcp dport { 6010, 6012, 6011 } ct state { new, established } accept # handle 11
		tcp sport { 6012, 6010, 6011 } ct state { new, established } accept # handle 12
	}

	chain output {
		type filter hook output priority 0; policy drop;
		ip daddr 172.16.82.106 drop # handle 8
		tcp sport ssh accept # handle 6
		tcp dport ssh accept # handle 5
		ip daddr 172.16.40.10 drop # handle 9
		tcp dport { 6011, 6010, 6012 } ct state { new, established } accept # handle 13
		tcp sport { 6012, 6011, 6010 } ct state { new, established } accept # handle 14
	}

}
Handle numbers will vary by user. Handle numbering is not like iptable rule numbering. In iptables the rule numbers are always numbered starting at rule number 1 at the top.

Handles in NFTables are more like system identification numbers (sid) in that they are unique to the rule itself. Each rule will generate its own sid in the order that the rules are created and not necessarily in the order, they will be when you list the rules.



Save nft configuration and reload

$ sudo nft list ruleset > /etc/nftables.rules

$ sudo nft -f /etc/nftables.rules
The first command redirects the list to a file in /etc.

The second command reloads the rules.

Some of the syntax to save a configuration may or may not work on certain flavors of linux.



References:

https://wiki.archlinux.org/index.php/Iptables

https://wiki.archlinux.org/index.php/nftables

http://raynux.com/blog/2009/04/15/iptables-quick-command-list/line

https://likegeeks.com/linux-iptables-firewall-examples/

https://wiki.nftables.org/wiki-nftables/index.php/Main_Page

https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains

https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes



Instructor Note
Instructor Notes



11.2.4 Configure iptables nat rules


References:



Instructor Note
Instructor Notes



11.2.4.1 What is nat
Provides a way to conserve publicly routable IP addresses.

It is the subject of RFC 1631 "The IP Network Address Translator (NAT)"

Maps one RFC 1918 private IP address to one public IP address. With NAT it is considered a one-to-one mapping. This means that one internal IP address is translated to/from one public IP address.

Provides a method to obfuscate the identities of devices a private network while proving connectivity to the Internet.

PAT uses ports to track communications and not just the IP address. This allows several hosts to share one public IP address.

PAT maps many private IP addresses to one public IP address which provides greater conservation of IP addresses

It provides greater obfuscation the entities in a private network while also proving connectivity to the Internet.

PAT is an extension of NAT.



References:

https://datatracker.ietf.org/doc/html/rfc1631

https://datatracker.ietf.org/doc/html/rfc1918



Instructor Note
Instructor Notes



11.2.4.2 NAT & PAT operators & Chains
Statement Operator

Applicable Chains

SNAT

POSTROUTING
INPUT

MASQUERADE

POSTROUTING

DNAT

PREROUTING
OUTPUT

REDIRECT

PREROUTING
OUTPUT

The SNAT and MASQUERADE statements specify that the source address of the packet should be modified.

SNAT is only valid in the postrouting and input chains

MASQUERADE is used only in postrouting. The MASQUERADE statement is a special form of snat which always uses the outgoing interface’s IP address to translate to. It is particularly useful on gateways with dynamic (public) IP addresses.

The DNAT and REDIRECT statements are only valid in the prerouting and output chains, they specify that the destination address of the packet should be modified.

The REDIRECT statement is a special form of dnat which always translates the destination address to the localhost’s address. It comes in handy if one only wants to alter the destination port of incoming traffic on different interfaces.



References:

[SNAT](https://ipset.netfilter.org/iptables-extensions.man.html#lbDP)

[DNAT](https://ipset.netfilter.org/iptables-extensions.man.html#lbCU)

[MASQUERADE](https://ipset.netfilter.org/iptables-extensions.man.html#lbDE)

[REDIRECT](https://ipset.netfilter.org/iptables-extensions.man.html#lbDK)



Instructor Note
Instructor Notes



11.2.4.3 Source NAT


Source NAT image



Change the Source IP of all packets leaving eth0 to 1.1.1.1.

Specifying the DNAT for return traffic is not needed. A table of all translated address is created to reverse the translation.

iptables -t nat -A POSTROUTING -o eth0 -j SNAT --to 1.1.1.1


T16 Source NAT Graphic



Change the Source IP and port of all TCP packets leaving eth0 to 1.1.1.1 port 9001.

iptables -t nat -A POSTROUTING -p tcp -o eth0 -j SNAT --to 1.1.1.1:9001


Change the Source IP of all packets leaving eth0 to the IP address of the outbound interface.

iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE


References:

[SNAT](https://ipset.netfilter.org/iptables-extensions.man.html#lbDP)

[MASQUERADE](https://ipset.netfilter.org/iptables-extensions.man.html#lbDE)



Instructor Note
Instructor Notes



11.2.4.4 Destination NAT


Dest NAT image



iptables -t nat -A PREROUTING -i eth0 -j DNAT --to 10.0.0.1
Change the destination IP of all packets entering eth0 to 10.0.0.1.



Perform this with caution. This will cause all packets to the nat system to be forwarded to the internal system. Remote access to the nat system will not be possible. Specifying specific traffic to match for can mitigate this.



Change the destination IP and port of different traffic incoming to eth0 to specific internal IP address and ports.

iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 22 -j DNAT --to 10.0.0.1:22
iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 -j DNAT --to 10.0.0.2:80
iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 443 -j DNAT --to 10.0.0.3:443


Redirect all traffic incoming to eth0 tcp port 80 to port 8080 on the local system.

iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 -j REDIRECT --to-port 8080


References:

[DNAT](https://ipset.netfilter.org/iptables-extensions.man.html#lbCU)

[REDIRECT](https://ipset.netfilter.org/iptables-extensions.man.html#lbDK)



Instructor Note
Instructor Notes



11.2.5 Configure NFTables nat rules


References:



Instructor Note
Instructor Notes



11.2.5.1 Creating nat tables and chains


Create the NAT table using the nft add table command.

nft add table ip NAT


Create the NAT chains using the nft add chain command.

nft add chain ip NAT PREROUTING {type nat hook prerouting priority 0 \; }
nft add chain ip NAT POSTROUTING {type nat hook postrouting priority 0 \; }


You are required to register both the prerouting and postrouting chains (the origination and reply directions) in order for the NAT engine to work.



References:



Instructor Note
Instructor Notes



11.2.5.2 Source NAT


Changes the internal source IP address 10.1.0.2 going out eth0 to the public address of 144.15.60.11.

nft add rule ip NAT POSTROUTING ip saddr 10.1.0.2 oif eth0 snat 144.15.60.11


Changes all internal hosts on the 10.1.0.0/24 network going out eth0 to the IP address of the outbound interface.

nft add rule ip NAT POSTROUTING ip saddr 10.1.0.0/24 oif eth0 masquerade


References:

https://www.netfilter.org/projects/nftables/manpage.html



Instructor Note
Instructor Notes



11.2.5.3 Destination NAT


Change the destination IP and port of different traffic incoming to eth0 to specific internal IP address.

nft add rule ip NAT PREROUTING iif eth0 tcp dport { 80, 443 } dnat 10.1.0.3


Redirect all traffic incoming to eth0 tcp port 80 to port 8080 on the local system.

nft add rule ip NAT PREROUTING tcp dport 80 redirect to 8080


References:

https://www.netfilter.org/projects/nftables/manpage.html



Instructor Note
Instructor Notes



11.2.6 Configure iptables mangle rules
The mangle table is a table in iptables to perform specialized packet alteration. It is unique compared to other tables in that it can apply rules in all five chains.

References:

https://ipset.netfilter.org/iptables.man.html



Instructor Note
Instructor Notes



11.2.6.1 Mangle examples with iptables


Set the TTL for all traffic leaving eth0 to 128.

iptables -t mangle -A POSTROUTING -o eth0 -j TTL --ttl-set 128


Set the DSCP for all traffic leaving eth0 to 26.

iptables -t mangle -A POSTROUTING -o eth0 -j DSCP --set-dscp 26


References:

[TTL modification](https://ipset.netfilter.org/iptables-extensions.man.html#lbDY)

[DSCP modification](https://ipset.netfilter.org/iptables-extensions.man.html#lbCW)



Instructor Note
Instructor Notes



11.2.6.2 Mangle examples with nftables


Create the MANGLE table using the nft add table command.

nft add table ip MANGLE


Create the MANGLE chains using the nft add chain command.

nft add chain ip MANGLE INPUT {type filter hook input priority 0 \; policy accept \;}
nft add chain ip MANGLE OUTPUT {type filter hook output priority 0 \; policy accept \;}
Set the TTL for all traffic leaving eth0 to 128.

nft add rule ip MANGLE OUTPUT oif eth0 ip ttl set 128
Set the DSCP for all traffic leaving eth0 to 26.

nft add rule ip MANGLE OUTPUT oif eth0 ip dscp set 26


11.3 Understand Network Based Filtering
Network-based firewalls are typically appliance-based devices for maximum performance. A computer system with at least two or more NIC’s with a software firewall installed can also be used. This method may be suitable for small networks but medium to large networks may not be able to process all the packets which will result in network bottlenecks and dropped packets.

Network filtering is the process of controlling access to or from a network segment. It does this by analyzing incoming and outgoing packets and letting them pass through your network devices or dropping them based on the IP address of the source or destination. These firewalls however can not control traffic to or from systems on the same network segment.



References:



Instructor Note
Instructor Notes



11.3.1 Describe firewall type
What are the differences and similarities between types of firewalls?

A packet filtering firewall operates primarily at layer 3, and filters based on ports at layer 4, looking at the network address and TCP or UDP ports to judge if packets should be allowed, dropped or rejected. These types of firewalls are obsolete but still in use.

A stateful firewall tracks TCP connection states and thus works at layers 4 and 3. It retains packets until enough information is available to make a judgment about the connection status (new, established, related, or invalid) before allowing, dropping or rejecting packets.

The application layer Next Generation firewalls track the state of connections and provides packet inspection and filtering based on application information in the payload. It operates at OSI layers 3-7. It is also known by some as CBAC (Content Based Access Control).



zone

Zone-Based Policy Firewall (Zone-Policy Firewall, ZBF or ZFW)

Is a method of configuration for application layer firewalls based on zones instead of interfaces. Interfaces are assigned to zones, and inspection policy is applied to traffic moving between the zones. Inter-zone policies offer flexibility and granularity, so different inspection policies can be applied to multiple host groups connected to the same router interface. Each interface set up in a zone is denied access to any other interface by default, isolating sensitive subnetworks from the rest of the network and Internet.



hostbased

Host Based Firewalls - These perform similar function as Network firewalls but work in a software installed on a host machine. Protects only that host and is not as efficient to block traffic compared to Network based firewall.

Host based Firewalls include but not limited to:

netfilter - iptables/nftables

windows defender

Symantec or McAfee host based applications



netbased

Network Based Firewalls - These are mostly proprietary appliances with the primary intent to filter network traffic. Firewalls use rules as the mechanism to filter traffic.

Network based Firewalls include but not limited to:

Cisco ASA

Palo Alto

Dell Sonic Wall

Juniper

References:



Instructor Note
Instructor Notes



11.3.2 Interpret a data flow diagram given a set of firewall rules


Using a Cisco ASA Flow Diagram

On an inbound packet and functioning as a router the ASA (Adaptive Security Appliance) and other routers:

Checks for an existing connection

Creates a connection if one does not exist

Checks for ACLs on the interface

Checks for a packet-ACL match until a match is found or uses the default ACE (Access Control Entry)

Acts on the packet according to the matching access control entry

Cisco ASA

from www.ciscopress.com



Step 1. A packet is received on a given interface of the Cisco ASA. If a VPN is configured, the packet is decrypted at this point. If ACL bypass is configured for VPN traffic, the Cisco ASA proceeds to step 5.

Step 2. The Cisco ASA checks to see if there is an existing connection for the source and destination hosts for that specific traffic. If there is an existing connection, the Cisco ASA bypasses the ACL checks and performs application inspection checks and proceeds to step 5.

Step 3. If there is no existing connection for that traffic, the Cisco ASA performs the NAT checks (or untranslate process).

Step 4. The Cisco ASA allows or denies traffic based on the rules in the configured ACLs.

Step 5. If traffic is allowed, the Cisco ASA performs application inspection.

Step 6. The Cisco ASA forwards the packet to the Cisco ASA FirePOWER module. If promiscuous monitor-only mode is configured, only a copy of the packet is sent to the Cisco ASA FirePOWER module. If the Cisco ASA FirePOWER module is configured in inline mode, the packet is inspected and dropped if it does not conform to security policies. If the packet is compliant with security policies and Cisco ASA FirePOWER module protection capabilities, it is sent back to the ASA for processing.

Step 7. The Cisco ASA determines the egress interface based on NAT or Layer 3 routing.

Step 8. Layer 3 routing is performed.

Step 9. Layer 2 address lookup occurs.

Step 10. The packet is sent to the network.

References:

https://www.ciscopress.com/articles/article.asp?p=2730336&seqNum=7



Instructor Note
Instructor Notes



11.3.3 Determine positioning of filtering devices on a network


References:



Instructor Note
Instructor Notes



11.3.3.1 Filtering Device placement challenges
Placing filtering devices on a network can be a challenge that requires extensive planning. You might think to apply filtering rules on every networking device but performance and maintenance are cause for concern. Effective filtering of traffic is done as the situation dictates. Placement of filtering devices and rules will affect what traffic is seen and filtered.

Before creating your filtering rules we should define a series of steps.



References:

https://securityskeptic.typepad.com/the-security-skeptic/firewall-best-practices-egress-traffic-filtering.html

https://www.ncsc.gov.ie/emailsfrom/DDoS/Ingress-Egress/index.html

https://insights.sei.cmu.edu/blog/best-practices-and-considerations-in-egress-filtering/

https://www.netwrix.com/network_security_best_practices.html

https://www.coxblue.com/how-to-secure-your-business-network-a-12-step-guide-to-network-security/

https://www.apnic.net/manage-ip/apnic-services/registration-services/resource-quality-assurance/what-is-a-bogon-address/

https://en.wikipedia.org/wiki/Bogon_filtering

https://freenetworktutorials.com/ipv4-and-ipv6-bogon-address-list/



Instructor Note
Instructor Notes



11.3.3.1.1 Determine our network segments
1. First we need to determine our network segments.

Public (Internet) - Boundry connected to/from the Internet.

What address do we allow in or out?

What protocols are allowed in and out?

Semi-private (Extranet) - Networks that we allow access to trusted third-party partners.

Allow traffic to/from for specific protocols.

Private (Intranet) - Networks that only allow access to internal users.

What traffic is allowed in/out?

Will it be using NAT?

What traffic is allowed to/from the internet/DMZ?

Demilitarized Zone (DMZ) - Network that should allow internet and intranet users.

Filter traffic from internet/intranet to/from servers by exception to/from service ports.

Virtual Private Network (VPN) - Boundry where internal users can access the intranet from anywhere using the internet.

Will there be VPN usage? If so how can we allow this traffic in/out to authorized endpoints?

Network Address Translation (NAT) - Determine the private/public address boundary.

Is nat used?

Where are the boundries at?

Within boundries firewall rules use internal addresses.

Outside boundries firewall rules use the public address.



References:



Instructor Note
Instructor Notes



11.3.3.1.2 Conduct audit
2. Second we conduct an audit of:

Authorized applications, protocols, and ports - What is critical for your organization to operate, and what is authorized.

remote access (ssh or telnet)

Web - http(s)

routing protocols (OSPF, EIGRP, RIP, or BGP) - allow by exception from known networking devices

SMB/NetBios - should it be allowed?

DNS (53) - traffic to/from known authorized DNS servers

IPv4(v6) - Identify all valid endpoints. Classify by clients and servers. Clients should only be allowed to communicate to/from servers.

ICMPv4(v6) - If all icmp is not permitted then identification of specific type/codes.

IPsec/VPN or other tunneling protocols - If used, then they should be explicitly allowed to/from VPN endpoints.

Other organizational applications

Known unused or unauthorized applications, protocols, and ports - What is not authorized or known malicious.

Not using/allowing FTP, telnet, icmp, others? - Block them explicitly.

Block Bogon’s

RFC 1918 addresses (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)

Internal loopback (127.0.0.1)

APIPA (169.254.0.0/16)

Documentation Addresses (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)

IPv6 Unassigned Addresses

Reserved IPv4 Address Space. IPv4 address ranges reserved by the Internet Assigned Numbers Authority (IANA) for specific purposes, such as future use, multicast, or experimental use.

Other reserved addresses

Block your organizational IPs from entering network as source IP. Your addresses should only be the source IP exiting network and the destination IP when entering.

Tunneling IP’s like Toredo, 6to4

Authorized internal:

Servers - All servers on your network and what users are allowed/required to access them.

Client systems - All client hosts on the network. What operating systems are they running? Who are allowed to login to them? Should client systems be allowed to access each other?

Users - Users allowed to access your network and what level of access do they require? What servers are they allowed to access?

Admins - Who as the access? What levels of permissions do they have on each system/domain? Should they be allowed to have internet/email access?

Networking Devices - All firewalls, routers, and switches on your network.



References:



Instructor Note
Instructor Notes



11.3.3.1.3 Determine filtering devices needed
3. Third we determine the filtering devices that will achieve our intent.

Switches - layer 2 MAC address filtering and port security.

Routers and Layer 3 Switch - IP address, protocol, and port filtering using Access Control Lists (ACLs).

Routers with TCP state filtering. UDP state filtering is also possible in some cases but can be more resource-intensive.

Layer 7 Application or Next-Generation Firewall (NGF) filtering of specific used enterprise applications using signatures and rules. Provides deep inspection of entire traffic flows.

Layer 7 Intrusion Prevention System (IPS) filtering of known malware and traffic patterns using signatures. Provides deep inspection packet-by-packet.



References:



Instructor Note
Instructor Notes



11.3.3.1.4 Determine filtering device placement
4. Fourth (and last) we need to determine the placement of each filtering device to achieve our intent.

As mentioned earlier it might seem best to place rules to filter this traffic everywhere but we need to remember that each networking device that traffic has to traverse adds latency. Any additional rules will only add unnecessary delay. Efficient filtering is achieved by creating and applying enough rules to meet our intent most effectively.

Determine whether to white-list or black-list. Which would be a shorter list?

Is there more traffic to block than allow? Create a white list of authorized traffic then block the rest.

Is there more traffic to allow than block? Create a black list of the unauthorized traffic then allow the rest.

In general it is best to place a filter closest to the origin of traffic being filtered to avoid unnecessary processing and bandwidth overhead that would result if the packet was allowed to traverse the network before being dropped at a later point.

For outbound traffic coming from our internal clients it might be best to apply a rule on the interface closest to the source of this traffic. Sometimes it’s more appropriate to apply the rule at the destination where the client may (or may not) be permitted to communicate with.

For inbound traffic coming from the internet it might be best to apply the rule on the external internet-facing interface.

Although its acceptable to use implicit deny rules to block unauthorized traffic, it may be benificial to create explicit rules will allow logging when these unauthorized protocols are used.



References:



Instructor Note
Instructor Notes



11.3.3.2 Typical locations for filtering devices
IPS - must be placed inline so it can block all prohibited traffic. IDS are generally able to receive monitored traffic from a SPAN or mirrored port but can be placed inline as well.

Firewalls - should be placed a the gateway just inside and outside of the network and between networks with different levels of trust such as between a DMZ and the rest of the network.

Routers - At least one router will be placed at the edge of the internal and external (Internet) connection to provide external networking services to the internal networks. Additional routers and/or switches may be placed at the edge of subnets to route internal network traffic. Routers use ACLs to filter.

Switches are usually used to connect hosts, printers, servers and other devices to a network. They can filter using VACLs, PACLs and ACLs (layer 3 switch only).

Proxy - Rules configured by system administrators to create a white/black list of websites.The act as intermediaries between clients and servers, filtering and caching web traffic to improve performance and security. Content filtering policies can be applied to proxy servers to block or allow specific websites, applications, or content types, helping organizations enforce acceptable use policies and protect against web-based threats. Commonly these may be placed in the DMZ to allow equal access from the clients to communicate to the internet.



References:



Instructor Note
Instructor Notes



11.3.3.3 Filtering Device Placement example


placement4



References:



Instructor Note
Instructor Notes



11.3.3.3.1 The placement of filtering devices can be viewed on a network diagram (see image)
Location A - A Firewall could be placed here. It is the most logical selection for a filtering device at that location.

Location B - A ACL can be placed at this location. The direction that is applied depends on whether you are filtering packets inbound or outbound.

Location C - A firewall could be place at this location.

Location D - A proxy is most likely to be placed at this location. Proxies are often placed in DMZs. However, an IDS/IPS is not outside the realm of reason. Your customers intent will dictate which device would be used.

Location E - Since this is a router, Access Control Lists would be on the device.

Locations F, G, H - Switches use ACL’s in the form of PACL’s and VACLs.

Location I - An iptable or nftable can be used here. Windows firewall or defender can be used for windows boxes. There is no reason to place a proxy, or another physical firewall between the switch and host.



References:



Instructor Note
Instructor Notes



11.4 Interpret Cisco access control list (ACL)
An ACL is the mechanism filtering traffic on a router or layer 3 switch. Based on the conditions supplied by the ACL, a packet is allowed or blocked from further movement. Standard ACLs filter only on the traffic source and traffic type (TCP, UDP, etc) while Extended ACLs can filter on traffic source, destination and protocol (via port numbers).

ACLs work at the Network and Transport OSI layers (layers 3 & 4) because the filter on IP addresses and TCP or UDP ports in the packets, segments and datagrams.

Routers use Access Control Lists (ACLs) to filter, permit or deny, traffic. All ACLs, whether standard or extended can be numbered or named. Extended ACLs are more versatile and can filter with increased granularity.



Cisco ACL numbering & naming conventions

ACL Type	Range/Identifier	Filters on
IP Numbered Standard

1-99
1300-1999 (expanded range)

* Source Address
* Protocol type (TCP, ICMP, iPv6, IP, etc.)

IP Numbered Extended

100-199
2000-2699 (expanded range)

* Source Address
* Destination Address
* protocol type (IP, UDP, etc.)
Optional:
* Protocol or port (DNS, SMTP, NTP, SMB, 22, 67, etc.)
* Other optional fields including:
--- connection status
--- fragmentation state

Named:
Standard
Extended

.
ip access-list standard {Name}
ip access-list extended {Name}

see above

200-299

Ethernet Type Code

{mostly obsolete but range still reserved}

300-399

DECnet

{mostly obsolete but range still reserved}

400-499

XNS

{mostly obsolete but range still reserved}

500-599

Extended XNS

{mostly obsolete but range still reserved}

600-699

Appletalk

{mostly obsolete but range still reserved}

700-799

Ethernet MAC

{mostly obsolete but range still reserved}

800-899

IPX Standard

{mostly obsolete but range still reserved}

900-999

IPX Extended

{mostly obsolete but range still reserved}

1000-1999

IPX SAP

{mostly obsolete but range still reserved}

1100-1199

MAC Extended

{mostly obsolete but range still reserved}

1200-1299

IPX Summary

{mostly obsolete but range still reserved}

Protocols other than the IP ranges are mostly obsolete. For IPv6 ACLs, named ACLs must be used.



References:



Instructor Note
Instructor Notes



11.4.1 Syntax to create Access Lists
From the configuration mode create a new access list:
The command is enable, followed by the the ACL number, or, if named, the terms 'standard' or 'extended' and the name of the access list.

Demo> enable #enter privileged exec mode
Demo# configure terminal #enter global config mode
Demo(config)# access-list 37
Demo(config)# ip access-list standard block_echo_request
Demo(config)# access-list 123
Demo(config)# ip access-list extended zone_transfers


(From the illustration above) Types of ACL’s produced are as follows:

The first ACL created is a standard numbered ACL.

The second ACL created is a standard named ACL.

The third ACL created is an extended numbered ACL.

The fourth ACL created is an extended named ACL.



References:



Instructor Note
Instructor Notes



11.4.2 Create access control entries for standard ACLs
prompt for standard acl configuration mode

action

source IP address

source wildcard

router(config)#

permit or deny

IP address or "any"

range from 0.0.0.0 to 255.255.255.255
0.0.0.0 = host = exact match
0.255.255.255 = IP address/8
omit if source IP address is "any"

Standard ACLs are ideal when rules need to be created to either allow or deny all traffic from a particular source IP. It is not possible to specify a destination IP, protocols, or ports with a standard ACL. This means that placement of these ACLs are critical. Typically the rule for standard ACLs is to place them as close to the destination as possible.



References:



Instructor Note
Instructor Notes



11.4.2.1 Standard Numbered ACL Syntax
router(config)# access-list {1-99 | 1300-1999}  {permit|deny}  {source IP add}
               {source wildcard mask}
router(config)# access-list 10 permit host 10.0.0.1
router(config)# access-list 10 deny 10.0.0.0 0.255.255.255
router(config)# access-list 10 permit any


References:



Instructor Note
Instructor Notes



11.4.2.2 Standard Named ACL Syntax
router(config)# ip access-list standard [name]
router(config-std-nacl)# {permit | deny}  {source ip add}  {source wildcard mask}
router(config)# ip access-list standard CCTC-STD
router(config-std-nacl)# permit host 10.0.0.1
router(config-std-nacl)# deny 10.0.0.0 0.255.255.255
router(config-std-nacl)# permit any


References:

https://www.cisco.com/c/en/us/td/docs/routers/asr9000/software/asr9k_r4-0/addr_serv/command/reference/ir40asrbook_chapter1.html

https://www.cisco.com/c/en/us/td/docs/security/asa/asa92/configuration/general/asa-general-cli/acl-overview.pdf

https://www.cisco.com/c/en/us/support/docs/security/ios-firewall/23602-confaccesslists.html

https://www.cbtnuggets.com/blog/certifications/cisco/networking-basics-configuring-extended-access-lists-on-cisco-routers

https://www.dummies.com/programming/networking/cisco/extended-access-control-lists-acls/



Instructor Note
Instructor Notes



11.4.3 Create access control entries for extended ACLs
action

Layer 3/4 protocol

Source IP Address

Source wildcard

[operator] [port]

permit or deny

tcp/udp/icmp

IP address or "any"

range from 0.0.0.0 to 255.255.255.255
0.0.0.0 = host = exact match
0.255.255.255 = IP address/8
omit if source IP address is "any"

lt - less than
gt - greater than
(n)eq - (not) equal
range - of ports
icmp-type (and code)

Destination IP Address

Destination wildcard

[operator] [port]

[Options]

IP address or "any"

range from 0.0.0.0 to 255.255.255.255
0.0.0.0 = host = exact match
0.255.255.255 = IP address/8
omit if source IP address is "any"

lt - less than
gt - greater than
(n)eq - (not) equal
range - of ports
icmp-type (and code)

including:
established
fragments
log(-input)
time-range
ttl
match-any
match-all



Syntax Explained:

Syntax in braces [ ] is optional. Ports can be referenced by port number. Some ports can be referred to by a port name such as tftp or 69 (on UDP).

Established works by matching TCP packets with acknowledgment or reset bits turned on. It is only usable on a stateful (and higher) firewall and only with TCP.

Fragments is optional and apply only to fragmented packets after the initial fragment.

Log will log any matching packets while log-input includes the interface information.

time-range defines specific times of day and week to implement time-based ACLs. It uses the router system clock, best used with NTP (Network Time Protocol)

ttl will match against packet time to live.

icmp-type and icmp-code match against packet type or code.

match-any and match-all are used to filter segments by TCP flag(s).

As ACLs are read top-down. The first rule that matches the traffic the action is taken. Further matching rules are not checked. It is important to arrange the rules in the proper order to meet your intent. In general, it is best to place the more specific rules at the top and the more general rules towards the bottom.

The term "any" takes the place of the source or destination IP addresses and the source or destination wildcard. It is the equivalent to any IP address, with a wildcard of 255.255.255.255

Extended ACLs are more specific of where the traffic is coming from and going to as well as the specific protocol and ports used. For this reason its recommended to place these rules as close to the course of the traffic as possible. This is to stop unauthorized traffic as soon as possible.



References:



Instructor Note
Instructor Notes



11.4.3.1 Extended Numbered ACL Syntax
router(config)# access-list {100-199 | 2000-2699} {permit | deny} {protocol}
               {source IP add & wildcard} {operand: eq|lt|gt|neq}
               {port# |protocol} {dest IP add & wildcard} {operand: eq|lt|gt|neq}
               {port# |protocol}
router(config)# access-list 144 permit tcp host 10.0.0.0.1 any eq 22
router(config)# access-list 144 deny tcp 10.0.0.0 0.255.255.255 any eq 23
router(config)# access-list 144 permit icmp 10.0.0.0 0.255.255.255 192.168.0.0
               0.0.255.255 echo
router(config)# access-list 144 deny icmp 10.0.0.0 0.255.255.255 192.168.0.0
               0.0.255.255 echo echo-reply
router(config)# access-list 144 permit ip any any


References:



Instructor Note
Instructor Notes



11.4.3.2 Extended Named ACL Syntax
router(config)# ip access-list extended  [name]
router(config-ext-nacl)# [sequence number] {permit | deny} {protocol}
                        {source IP add & wildcard} {operand: eq|lt|gt|neq}
                        {port# |protocol} {dest IP add & wildcard} {operand:
                        eq|lt|gt|neq} {port# |protocol}
router(config)# ip access-list extended CCTC-EXT
router(config-ext-nacl)# permit tcp host 10.0.0.0.1 any eq 22
router(config-ext-nacl)# deny tcp 10.0.0.0 0.255.255.255 any eq 23
router(config-ext-nacl)# permit icmp 10.0.0.0 0.255.255.255 192.168.0.0
                        0.0.255.255 echo
router(config-ext-nacl)# deny icmp 10.0.0.0 0.255.255.255 192.168.0.0
                        0.0.255.255 echo echo-reply
router(config-ext-nacl)# permit ip any any


Examples:

Demo# deny tcp any any eq telnet
Demo# permit tcp any any eq 22
Demo# deny tcp 10.0.0.2 host gt 1023 any
Demo# deny udp 172.169.1.1 host range 52-59 10.5.0.1 0.0.255.255 log
Demo# deny tcp 172.169.0.1 0.0.255.255 gt 1023 10.5.0.1 0.0.255.255 ttl lt 32
The first access control entry denies telnet from any device to any device on the network.

The second ace allows any host to connect to any other host thru SSH.

The third access control entry denies traffic from 10.0.0.2 with a port number greater than 1023 (well known ports) to connect to any host on the network.

The fourth ace denies udp ports 52-59 from 172.169.1.1 to the 10.5.0.0 network and log all such packets to include the interface information.

The last ace denies tcp ports above the well-known ports from the 172.169.0.0 network destined for the 10.5.0.0 network that has a ttl less than 32



References:



Instructor Note
Instructor Notes



11.4.4 ACL Rule Guidelnes
ACL are just lists of IPs, protocols, ports, and action statement. This mean that this can be used for may purposes.

Filtering traffic in/out of a network interface.

Permit or deny traffic to/from a router VTY line.

Identify authorized users and traffic to perform NAT.

Classify traffic for Quality of Service (QoS).

Trigger dial-on-demand (DDR) calls.

Control Bandwidth.

Limit debug command output.

Restrict the content of routing updates.



When applying and ACL we need to keep these in mind:

Only one ACL can be applied per:

Interface

Protocol (ipv4 or ipv6)

Direction (inbound or outbound)

Standard ACLs should be applied closest to the destination of the traffic.

Entries only contain the source address.

Placing too soon will cause traffic from that source to be blocked/allowed from that point on.

Best placement is at the destination where the traffic should be filtered.

Extended ACLs should be applied closest to the source of the traffic.

Entries contain the source and intended destination.

Best to place as soon as possible to avoid wasted processing of the packet on upstream routers and also avoid wasted network bandwidth.

Each ACL must contain at least one permit statement.

Due to the implicit nature of an ACL an ACL with all denies will essentially deny all traffic.

ACLs are read top-down.

The first rule that matches the traffic the action is taken.

Further matching rules are not checked.

It is important to arrange the rules in the proper order to meet your intent.

In general, it is best to place the more specific rules at the top and the more general rules towards the bottom.

Inbound access lists process packets before the packets are routed to an outbound interface.

Before the router makes a decision on where to forward the packet.

Generally considered more efficent.

Does not apply to traffic going to its VTY lines. (telnet or ssh)

Outbound access lists process packets before they leave the device.

Traffic is filtered after the router process the packet and makes a route determination.

Generally considered less efficent.

ACLs do not filter traffic from the device itself.

Inbound access list do not filter SSH or telnet traffic to the device itself.

This traffic targets its VTY lines and not the interface where the ACL is applied.

ACLs are applied to traffic that traverses "through" the router.

An access list can control traffic arriving at a device or leaving a device, but not traffic originating at a device.

This may lead to attackers using the device as a pivot.

Only Standard ACLs may be applied to the VTY lines.

This is because the VTY line cannot filter protocols or ports.

The vty is already accepting TCP ports 22 and/or 23.

If you want to restrict this then you must use the transport input [ telnet | ssh ] command on the vty line.



References:



Instructor Note
Instructor Notes



11.4.5 Apply an ACL to an interface or line
ACLs are only lists of traffic to match and by itself does nothing unless applied in some form.



To apply an ACL to a router interface:

router(config)#  interface {type} {mod/slot/port}
router(config)#  ip access-group {ACL# | name} {in | out}
router(config)#  interface s0/0/0
router(config-if)#  ip access-group 10 out
router(config)#  interface g0/1/1
router(config-if)#  ip access-group CCTC-EXT in
To apply an ACL to a router vty line:

router(config)#  line vty 0 15
router(config)#  access-class CCTC-STD in


References:



Instructor Note
Instructor Notes



11.4.6 ACL creation from user prompt:
This example show the commands required to create an ACL, populate it with filtering criteria and apply it to an interface.

Router1> enable
Router1# configure terminal
Router1(config)# ip access-list standard Another_Land
Router1(config-std-nacl)# remark deny IP impersonation and log
Router1(config-std-nacl)# deny 10.1.0.0 0.0.255.255 log
Router1(config-std-nacl)# permit 10.0.0.0 0.255.255.255
Router1(config-std-nacl)# end
Router1(config)# interface gigabit 0/0/0
Router1(config-if)# ip access-group Another_Land in
Router1(config)# end
Router1# show ip access-list


Explanation, line by line:

Escalate from user exec mode to privilege exec mode

Go to global configuration mode

create a standard ACL named Another_Land

remark that the purpose is to prevention IP address impersonation and to log

Deny all IP addresses that match the 10.1.0.0/16 network (your network) and log any packets that match.

Permit all traffic from 10.0.0.0/8 network

end adding rules to Another_Land ACL

Enter configure interface mode to configure the FE interface 0/0/0

Apply the ACL Another_Land inbound on the Ge 0/0/0 (gateway) interface inbound to the router

Exit configuration mode

show the ip access-list

The standard ACL is a blunter, less flexible tool compared to an extended ACL, but it is still useful and can protect the network.



References:

https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_data_acl/configuration/xe-3s/sec-data-acl-xe-3s-book/sec-acl-named.html



Instructor Note
Instructor Notes



11.4.7 ACL Placement
In general it is best to place a filter closest to the traffic source to prevent unnecessary network traffic. However…​

Standard access lists are placed closest to the destination because the destination is not specified in a standard ACL. If a standard ACL is placed near the source, all traffic originating from the source to ANY destination would be dropped, blocking communication with legitimate destinations. For standard ACLs, connectivity trumps efficiency.

Extended access lists are applied closest to the source as both source and destination address are defined in an extended ACL. This prevents unnecessary transit of the traffic in the network that but allows all destinations to receive the packets.



References:



Instructor Note
Instructor Notes



11.4.6.1 Practical example of an ACL placement
aclplacement


Placing a Standard ACL (Router and Interface) to block traffic from host 10.3.0.4 to host 10.5.0.7.

The standard ACL will be placed on Router A, G0/2 interface on the outbound interface. You want to apply a standard ACL closets to the destination.

Note: If placed on rtr A, G0/0, it would also block traffic to 10.1.0.0/24 network.



aclplacement



Placing an extended ACL (Router and Interface) to block traffic from host 10.1.0.1 to host 10.5.0.17.

The extended ACL will be placed on Router A, G0/1 interface inbound. You want to apply extended ACL closets to the source



Interpret this ACL:

ip access-list 101 deny udp host 19.3.0.29 10.5.0.0 0.0.0.255 eq 69
ip access-list 101 deny tcp any 10.3.0.0 0.0.0.255 eq 22
ip access-list 101 deny tcp any 10.1.0.0 0.0.0.255 eq 23
ip access-list 101 deny icmp any 10.5.0.0 0.0.0.255 echo
ip access-list 101 deny icmp any 10.5.0.0 0.0.0.255 echo-reply
If you notice that every access control entry has a deny statement. ACLs have a default implicit deny at the end. Therefore, this ACL would deny every packet that attempts to enter. You have to expiicity allow the networks you want to enter.



References:



Instructor Note
Instructor Notes



11.4.8 Turbo ACLs
ACLs are read top down unless the router is using Turbo ACLs on a Cisco device. Turbo ACLs use the normal ACLs but then creates a lookup table (database) of all access control entries.



The Fields created by in the "Turbo Table" are:

Source IP (the first 16 (most significant) bits thereof)

Source IP - 16 least significant bits

Destination IP - with 16 most significant bits

Destination IP - with 16 least significant bits

IP (layer 3) flags (IP, ICMP, NAT, etc)

Layer 3 protocol fields and Layer 4 flags field (TCP, UDP, NetBIOS, etc).

Layer 4 Source port

Layer 4 Destination port



These eight fields are bitmapped to equivalence tables which are bitwise AND compared to each other and the packet to look for a ACE match on the packet.

Turbo ACLs reduce processing time if the router has a large enough number of ACEs to be efficient. The rule of thumb Tubro ACLs makes sense for a list of 10+ ACEs. The disadvantage of Turbo ACLs is the additional memory required on the router for the tables it creates.

Use of Turbo ACLs can be done on any supporting device by using the access-list compiled global configuration command.



References:

https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_data_acl/configuration/15-mt/sec-data-acl-15-mt-book/sec-acl-turbo-enhanc.html

https://community.cisco.com/legacyfs/online/legacy/3/4/9/69943-TURBO%20ACL.pdf

https://www.cisco.com/c/en/us/td/docs/routers/asr9000/software/asr9k_r4-0/addr_serv/command/reference/ir40asrbook_chapter1.html#wp2050610028

https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_data_acl/configuration/xe-3s/sec-data-acl-xe-3s-book/sec-create-ip-apply.html#GUID-9B178E56-F2AE-4910-9774-BBA30C85B179

https://www.cisco.com/c/en/us/support/docs/security/ios-firewall/23602-confaccesslists.html#extacls

https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_data_acl/configuration/xe-3s/sec-data-acl-xe-3s-book/sec-create-ip-al-filter.html#GUID-405615ED-EA35-4387-B3C3-6F0FA7DEDDCE



Instructor Note
Instructor Notes



11.5 Understand Intrusion Detection or Prevention Systems
Intrusion Detection Systems (IDS) and Intrusion Prevention Systems (IPS) are security mechanisms designed to monitor network traffic or system activities for malicious or unauthorized behavior and take appropriate action to mitigate threats.



References:



Instructor Note
Instructor Notes



11.5.1 Contrast Intrusion Detection Systems and Intrusion Prevention Systems
Intrusion Detection and Intrusion Prevention systems are very similar. In fact, they may be the same device with different actions configured in response to potentially malicious traffic.

The primary operational difference is IPS will act on suspected malicious traffic. It can stop the traffic, hence preventing an incident. In contrast, an IDS only monitors. It will send alerts/log messages for traffic, but it will not intervene to block traffic on the network.

Intrusion Detection Systems (IDS):

IDS are passive security tools that analyze network traffic or system logs to detect suspicious or malicious activity.

IDS typically operate in one of two modes: network-based (NIDS) or host-based (HIDS).

Network-based IDS (NIDS) monitor network traffic and analyze packet headers or payloads for signs of intrusion or abnormal behavior.

Host-based IDS (HIDS) run on individual hosts or servers and monitor system logs, file integrity, and other host-specific data for signs of compromise or intrusion.

When an IDS detects suspicious activity, it generates alerts or notifications to security administrators, who can investigate and respond to potential threats.

Intrusion Prevention Systems (IPS):

IPS are active security tools that not only detect malicious or unauthorized activity but also take automated action to prevent or block threats in real-time.

IPS are often deployed inline on network devices or security appliances and can actively inspect and block network traffic based on predefined rules or signatures.

IPS use similar detection techniques as IDS, such as signature-based detection, anomaly detection, and heuristic analysis, but they have the capability to take immediate action to block or mitigate threats.

IPS can block suspicious IP addresses, drop malicious packets, or modify firewall rules dynamically to prevent further intrusion attempts.

Placement - Because of these different operations, IDS and IPS have different network placement requirements. IPS must be placed in line with all network traffic (usually connected to the gateway router or firewall), while IDSs are usually connected to a mirrored port or SPAN (Switched Port Analyzer) port.

In line - IPS - device must be in the path of the traffic in order to stop unauthorized traffic.

or not - IDS - get passed copies of all traffic for inpection. Can log or alert of malicious traffic but cannot stop or prevent it.



References:

https://www.varonis.com/blog/ids-vs-ips/

https://www.dnsstuff.com/ids-vs-ips

https://www.checkpoint.com/cyber-hub/network-security/what-is-an-intrusion-detection-system-ids/ids-vs-ips/



Instructor Note
Instructor Notes



11.5.1.1 Common IDSs and IPSs
Snort is not the only IDS/IPS used but it is the one we will go over in this course. Understanding the operation of one will help you understand the operation of them all. The only difference would be how they are configured.



ID/IPS	platforms	website
OSSEC

Windows, MAC, *nix, Virtual

https://www.ossec.net/

Snort

various *nix

https://www.snort.org/

Suricata

Windows, MAC, *nix

https://suricata-ids.org/

Bro Network Security Monitor

MAC, Linux, FreeBSD

https://www.bro.org/

Open WIPS NG

*nix

http://openwips-ng.org/index.html

Samhain

*nix

https://www.la-samhna.de/samhain/

Security Onion

Linux

https://securityonion.net/



References:

https://www.clearnetwork.com/top-intrusion-detection-and-prevention-systems/

https://www.softwaretestinghelp.com/intrusion-detection-systems/

https://www.csoonline.com/article/3532249/12-top-idsips-tools.html



Instructor Note
Instructor Notes



11.5.2 Comparing IPS and Firewalls
Intrusion Prevention Systems (IPS) and Application Firewalls are both security solutions designed to protect networks and applications from various threats, but they differ in their focus, capabilities, and deployment scenarios.

Focus:

IPS (Intrusion Prevention System):

IPS primarily focuses on identifying and mitigating network-based attacks, such as exploits targeting vulnerabilities in network protocols, applications, or operating systems. It monitors network traffic for known attack signatures or suspicious behavior and takes action to block or prevent malicious activity in real-time.

Works more at the Network layer by inspecting on a packet-by-packet basis for attacks.

Application Firewall:

Application Firewalls are specifically designed to protect web applications by inspecting and filtering HTTP/HTTPS traffic at the application layer. They focus on preventing common web application attacks such as SQL injection, cross-site scripting (XSS), and command injection by analyzing HTTP request and response payloads and enforcing security policies.

Works at the Application layer by performing deep packet inspections on traffic "flows".



References:



Instructor Note
Instructor Notes



11.5.3 Discuss Signature vs Behavior based detection
Signature-based detection and behavior-based detection are two common approaches used in cybersecurity tools, particularly in intrusion detection and prevention systems (IDS/IPS), to identify and mitigate threats.

Recognition Methods

Signature - Rule based detection and preventions systems that can prevent known attacks but rarely, if ever, have success against unknown attacks.

Heuristic aka Behavioral - Reference a known baseline for activity on the network activity and look for behaviors that do not conform (an anomaly) to the baseline pattern.



References:

http://www.omnisecu.com/security/infrastructure-and-email-security/types-of-intrusion-detection-systems.php

https://www.dummies.com/computers/operating-systems/windows-xp-vista/examining-different-types-of-intrusion-detection-systems/

https://accedian.com/blog/what-is-the-difference-between-signature-based-and-behavior-based-ids/

https://www.infosecurity-magazine.com/opinions/malware-detection-signatures/

https://labsblog.f-secure.com/2016/10/17/whats-the-deal-with-non-signature-based-anti-malware-solutions/



Instructor Note
Instructor Notes



11.5.3.1 A closer look at Signature and Behavior Based IDS/IPSs:
Knowledge-based IPS/IDS use signatures (rules) to identify potentially malicious traffic. There are two methods of comparing signatures against traffic. They are:

Atomic signatures that look at a single packet, activity, or event. Because these signatures trigger on a single packet/event, they do not require the device to maintain state information about other related traffic.

A stateful signature uses a sequence of specific events, requiring a device to maintain state, to alert on. This "state" is not necessarily confined to layer 4 but numerous layers during a conversation.



References:



Instructor Note
Instructor Notes



11.5.3.2 Advantages and Disadvantages of Signature based IDSs/IPSs
Low false alert rate with proper "tunning" (uses signatures of known malicious packets).

Signature database must be constantly updated. Must keep up-to-date with all new attack patterns.

Cannot detect previously unknown attacks. Attacks with no known patterns to look for.

Previously known attacks can easily be obfuscated to work again by changing the signature via encryption, chunking, or other methods.



References:



Instructor Note
Instructor Notes



11.5.3.3 Advantages and Disadvantages of Behavior based IDSs/IPSs
Relies on looking for variances from network baselines.

Behavior-based IDSs are more likely to detect new or obfuscated attacks.

Not as dependent on knowing the vulnerabilities of the underlying systems (applications and operating systems).

Are untrustworthy if the baseline is corrupted or if the network was already compromised at the time of baselining.

Higher false alarm (false positive) rate than knowledge-based systems.

Lots of false advertising on the capabilities of "behavior-based" systems.

higher cost in speed and resource use.



Companies may label their IDS/IPS applications as Behavior (Anomaly) based, but a closer look reveals some tactics used by a behavioral-based IDS includes application hardening and URL categorization, which certainly require signatures. There are no common definitions or standards when it comes to behavioral-based intrusion detection and prevention systems. What that means to one customer, or vendor, can vary greatly.

All the filtering devices we have or will covered use some sort of signature and can thus be evaded.



References:

http://www.omnisecu.com/security/infrastructure-and-email-security/types-of-intrusion-detection-systems.php

https://www.dummies.com/computers/operating-systems/windows-xp-vista/examining-different-types-of-intrusion-detection-systems/

https://www.infosecurity-magazine.com/opinions/malware-detection-signatures/

https://labsblog.f-secure.com/2016/10/17/whats-the-deal-with-non-signature-based-anti-malware-solutions/



Instructor Note
Instructor Notes



11.5.4 Construct advanced IDS (snort) rules
Before we get into creating Snort rules lets first discuss some Snort basics. Similar to tcpdump or Wireshark, Snort is a packet sniffer and it sniffs packets much the same way by accessing the libpcap capture library. How Snort differs is how it uses the packets it sniffs. TCPdump and Wireshark captures all packets (or if capture filters are used then only some) and displaying them to the screen or saving them to a pcap. Snort however captures all packets and attempts to match the traffic to defined rules.



Snort Basics

Snort Installation directory

/etc/snort

Snort Configuration file. Configuration files are used to define one or more rule files for packet matching. It uses the command include /path/name.rules to add rules to the configuration file. Several configuration files can be created for different Snort instances. Use the -c config-file to specify the configuration file or rule.

/etc/snort/snort.conf

Snort rules directory. Rule files can be created anywhere but this is the default location.

/etc/snort/rules

Snort rule files. The functionality of Snort relies on its rules. They can be download from Snort or can be user-defined. Generally, they are given the .rules extension to identify them as rule files but are not required.

[name].rules

Snort Log directory. If not otherwise specified, all alerts and logs are created here. Other locations can be specified using the -l log-file.

/var/log/snort

Common Snort command line switches

-D - Runs snort in Daemon mode

-l log-dir - to specify the location where Snort should create its logs. If not specified then the default is /var/log/snort

-c config-file - to specify a configuration or rule file that Snort should use for packet matching.

-r pcap-file - to specify a pcap file for Snort to read.

-p - Turn off promiscuous mode sniffing.

-e - Display/log the link-layer packet headers.

-i interface - Specify the interface for the Snort Daemon to sniff on.

-V - Show the version number and exit.

To run snort as a Daemon

sudo snort -D -c /etc/snort/snort.conf -l /var/log/snort

To run snort against a PCAP

sudo snort -c /etc/snort/rules/file.rules -r file.pcap



References:

[Introduction to Writing Snort 3 Rules](https://snort-org-site.s3.amazonaws.com/production/document_files/files/000/000/596/original/Rules_Writers_Guide_to_Snort_3_Rules.pdf?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIXACIED2SPMSC7GA%2F20210823%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20210823T165213Z&X-Amz-Expires=172800&X-Amz-SignedHeaders=host&X-Amz-Signature=8148b466d99fd829da748ba2f24954153a90a7768c55be6b9206cbf6a8bd69d0)

[Snort User Manual](http://manual-snort-org.s3-website-us-east-1.amazonaws.com/)

https://www.snort.org/downloads/#rule-downloads



Instructor Note
Instructor Notes



11.5.4.1 Snort IDS/IPS rule - header
Snort rules consist of a header which sets the conditions for the rule to work and rule options (a rule body) which provides the actual rule (matching criteria and action).

[action] [protocol] [source ip] [source port] [direction] [destination ip] [destination port] ( match conditions ;)
A Snort header is composed of:

Action - such as alert, log, pass, drop, reject

alert - generate alert and log packet

log - log packet only

pass - ignore the packet

drop - block and log packet

reject - block and log packet and send TCP message (for TCP traffic) or ICMP message (for UDP traffic)

sdrop - silent drop - block packet only (no logging)

Protocol

tcp

udp

icmp

ip

Source IP address

a specific address (i.e. 192.168.1.1 )

a CIDR notation (i.e. 192.168.1.0/24 )

a range of addresses (i.e. [192.168.1.1-192.168.1.10] )

multiple addresses (i.e. [192.138.1.1,192.168.1.10] )

variable addresses (i.e. $EXTERNALNET ) (must be defined to be used)

"any" IP address

Source Port

one port (i.e. 22 )

multiple ports (i.e. [22,23,80] )

a range of ports (i.e. 1:1024 = 1 to 1024, :1024 = less than or equal to 1024, 1024: = greater than or equal to 1024)

variable ports (i.e. $EXTERNALPORTS) (must be defined to be used)

any - When icmp protocol is used then "any" must still be used as a place holder.

Direction

source to destination ( - > )

either direction ( <> )

Destination IP address

a specific address (i.e. 192.168.1.1 )

a CIDR notation (i.e. 192.168.1.0/24 )

a range of addresses (i.e. [192.168.1.1-192.168.1.10] )

multiple addresses (i.e. [192.138.1.1,192.168.1.10] )

variable addresses (i.e. $EXTERNALNET ) (must be defined to be used)

"any" IP address

Destination port

one port (i.e. 22 )

multiple ports (i.e. [22,23,80] )

a range of ports (i.e. 1:1024 = 1 to 1024, :1024 = less than or equal to 1024, 1024: = greater than or equal to 1024)

variable ports (i.e. $INTERNALPORTS) (must be defined to be used)

any - When icmp protocol is used then "any" must still be used as a place holder.



You can use the ! symbol in front of any variable to provide negation. (i.e. !22 or !192.168.1.1)


References:

[Snort Rules Headers](http://manual-snort-org.s3-website-us-east-1.amazonaws.com/node29.html)



Instructor Note
Instructor Notes



11.5.4.2 Snort Rule Options:
All options are optional but without using options it will only function similar to an ACL. Adding certain options allow for more specific header and payload matching over what ACLs can provide.

All Snort rule options are separated via a semicolon (;).

Rule option keywords are separated from their arguments (values) with a colon (:).



References:

[Snort Rule Options](http://manual-snort-org.s3-website-us-east-1.amazonaws.com/node30.html)



Instructor Note
Instructor Notes



11.5.4.2.1 Snort IDS/IPS General rule options:
msg - specifies the human-readable alert message. This only adds the message to the alert file.

msg:"Put this message in the log";

reference - links to external source of the rule. This just adds references to the attack the rule is filtering for.

reference:cve,CAN-2000-1574;

sid - used to uniquely identify Snort rules. This is required and all rules must have a unique sid.

sid:123456;

rev - uniquely identify revisions of Snort rules. This is purely for the administrator.

rev: 1.1;

Classtype - used to categorize a rule as detecting an attack that is part of a more general type of attack class. Classtypes must be defined before they can be used.

classtype:attempted-recon;

priority - assigns a severity level to rules (1 - really bad, 2 - badish, 3 - informational).

priority:10;

metadata - allows a rule writer to embed additional information about the rule.

metadata:engine shared,service http;



References:

[Snort General Rule Options](http://manual-snort-org.s3-website-us-east-1.amazonaws.com/node31.html)



Instructor Note
Instructor Notes



11.5.4.2.2 Snort IDS/IPS Payload detection options:
content - looks for a string of text within the packet payload.

content:"anonymous";

|binary data| - to look for a binary HEX within the packet payload.

content:"|9090 9090 9090|";

nocase - modified content, makes it case insensitive.

nocase;

offset - specify how many bytes Snort should ignore before starting to search for a pattern within a packet. (i.e. an offset of 10 specifies to ignore the first 10 bytes and start searching from byte 11 until the end)

offset:10;

depth - specify how far into a packet Snort should search for the specified pattern. (i.e. a depth of 10 specifies the match must be found within the first 10 bytes)

depth:10;

distance - similar to offset, it specifies how far into a packet Snort should ignore before starting to search for the specified pattern relative to the end of the previous pattern match. (i.e. a distance of 10 specifies the match must be found after ignoring 10 bytes after the first match and start searching from byte 11 until the end)

distance:10;

within - similar to depth, it specifies how far Snort should search for the specified pattern relative to the end of the previous pattern match. Designed to be used in conjunction with the distance. (i.e. a within of 10 specifies the match must be found within 10 bytes after the first match.)

within:10;



References:

[Snort Payload Detection Options](http://manual-snort-org.s3-website-us-east-1.amazonaws.com/node32.html)



Instructor Note
Instructor Notes



11.5.4.2.3 Snort IDS/IPS Non-Payload detection options:
flow - direction (to/from client and server) and state of connection (established, stateless, stream/no stream)

flow:established, from_server;

ttl - The ttl keyword is used to check the IP time-to-live value.

ttl:128;

tos - The tos keyword is used to check the IP TOS field for a specific value.

tos:26;

ipopts - The ipopts keyword is used to check if a specific IP option is present

ipopts:lsrr;

seq - check for a specific TCP sequence number

seq:0;

ack - check for a specific TCP acknowledge number.

ack:0;

window - used to check for a specific TCP window size.

window:55808;

flags - The flags keyword is used to check if specific TCP flag bits are present.

flags:SA;

itype - The itype keyword is used to check for a specific ICMP type value.

itype:3;

icode - The icode keyword is used to check for a specific ICMP code value.

icode:3;

fragbits - used to check if fragmentation and reserved bits are set in the IP header.

fragbits:R;



References:

[Snort Non-Payload Detection Options](http://manual-snort-org.s3-website-us-east-1.amazonaws.com/node33.html)



Instructor Note
Instructor Notes



11.5.4.2.4 Snort IDS/IPS Post detection options:
logto - The logto keyword tells Snort to log all packets that trigger this rule to a special output log file.

logto:"/var/log/snort/malware/ransomeware.alert"

session - The session keyword is built to extract user data from TCP Sessions.

session:printable;

react - The react keyword is used with a rule to terminate a session to block some sites or services.

react: block;

tag - The tag keyword allow rules to log more than just the single packet that triggered the rule.

tag:session,10,seconds;

detection_filter - defines a rate which must be exceeded by a source or destination host before a rule can generate an event.

detection_filter:track by_src, count 30, seconds 60;



References:

[Snort Post-Detection Options](http://manual-snort-org.s3-website-us-east-1.amazonaws.com/node34.html)



Instructor Note
Instructor Notes



11.5.4.2.5 Snort IDS/IPS Thresholding and suppression options:
type [limit | threshold | both]

limit alerts on the 1st event during defined period then ignores the rest.

Threshhold alerts every [x] times during defined period.

Both alerts once per time internal after seing [x] amopunt of occurances of event. It then ingores all other events during period.

track [by_src | by_dst] - rate is tracked either by source IP address, or destination IP address

count [#] - number of rule matching in [s] seconds that will cause event_filter limit to be exceeded

seconds [seconds] - time period over which count is accrued. [s] must be nonzero value

threshold:type threshold, track by_dst, count 10, seconds 60;



References:

[Snort Threshold Options](http://manual-snort-org.s3-website-us-east-1.amazonaws.com/node35.html)



Instructor Note
Instructor Notes



11.5.4.3 Snort rule examples
Look for anonymous ftp traffic:

alert tcp any any -> any 21 (msg:”Anonymous FTP Login”; content: “anonymous”; sid:2121; )
This will cause the pattern matcher to start looking at byte 6 in the payload)

alert tcp any any -> any 21 (msg:”Anonymous FTP Login”; content: “anonymous”; offset:5; sid:2121; )
This will search the first 14 bytes of the packet looking for the word “anonymous”.

alert tcp any any -> any 21 (msg:”Anonymous FTP Login”; content: “anonymous”; depth:14; sid:2121; )
Deactivates the case sensitivity of a text search.

alert tcp any any -> any 21 (msg:”Anonymous FTP Login”; content: “anonymous”; nocase; sid:2121; )
ICMP ping sweep

alert icmp any any -> 10.1.0.2 any (msg: "NMAP ping sweep Scan"; dsize:0; sid:10000004; rev: 1; )
Look for a specific set of Hex bits (NoOP sled)

alert tcp any any -> any any (msg:”NoOp sled”; content: “|9090 9090 9090|”; sid:9090; rev: 1; )
Incorrect telnet login attempt

alert tcp any 23 -> any any (msg:"TELNET login incorrect"; content:"Login incorrect"; nocase; flow:established,from_server; threshold: type both, track by_src, count 3, seconds 30; classtype:bad-unknown; sid:2323; rev:6; )
SYN/FIN Scan:

alert tcp any any -> any any ​(msg:"SCAN SYN FIN"; flow:stateless; flags:SF; reference: https://www.techtarget.com/searchnetworking/definition/SYN-scanning#:~:text=In%20SYN%20scanning,%20similar%20to,every%20port%20on%20the%20server; classtype:attempted-recon; sid:121212; rev:7;)
Samba exploit:

alert tcp any any -> any 139 (flow:to_server,established; content:"|eb2f 5feb 4a5e 89fb 893e 89f2|"; msg:"EXPLOIT x86 linux samba overflow"; reference:bugtraq,1816; reference:cve,CVE-1999-0811; classtype:attempted-admin; sid: 12345; )
Malicious HTTP User Agent:

alert tcp any any -> any 443 ( msg: “Snort 3 http_header sticky buffer Example”; flow:to_server,established; content:”User-Agent”; http_header; content:”malicious”; within:200; http_header; pcre:”/^User-Agent\s*:[^\n]*malicious/smi”; metadata: service http; sid:22222; )
PDF File download:

alert file any 443 -> any any ( msg: “PDF File Detected”; file_type: “PDF”; sid:8; )
TCP SYN Flood:

alert tcp any any -> 192.168.10.5 443 (msg: “TCP SYN flood”; flags:!A; flow: stateless; detection_filter: track by_dst, count 70, seconds 10; sid:2000003;)
alert tcp any any -> 10.10.0.40 80 (msg:"Possible DoS Attack Type : SYN flood"; flags: S; flow:stateless; sid:3; detection_filter:track by_dst, count 20, seconds 10;)
Teardrop attack:

alert udp any any -> 10.10.0.40 any (msg:"DOS Teardrop attack"; fragbits:M; id:242; reference:bugtraq,124; reference:cve,1999-0015; reference:nessus,10279; reference:url,www.cert.org/advisories/CA-1997-28.html; classtype:attempted-dos; sid:270; rev:6;)
ICMP Flood:

alert icmp any any -> 10.10.0.40 any (msg:"ICMP flood"; sid:1000001; rev:1; classtype:icmp-event; detection_filter:track by_dst, count 500, seconds 3;)


Advanced Snort rule example:

alert tcp any any -> any 443 ( msg:"MALWARE-CNC Malicious BitCoiner Miner download - Win.Trojan.Systema"; flow:to_server,established; content:"/aviatic/systema.exe"; nocase; http_raw_uri; http_uri; metadata:impact_flag red,policy balanced-ips drop,policy security-ips drop,ruleset community; reference:url,www.virustotal.com/en/file/583b585078f37f5d399a228f1b8021ca0a9e904a55792281048bae9cfe0e95c1/analysis/; reference:url,www.virustotal.com/en/file/e8bd297b1f59b7ea11db7d90e81002469a8f054f79638a57332ac448d819fb5d/analysis/; sid:30552; rev:2; )+


Rule Header

alert

action defined when match is found. This rule will create an alert placed in the alert file.

tcp

protocol must be tcp.

any any

Any source ip or source port. Since the traffic later specifies from client to server, the source port will be a random high port.

- >

specifies the traffic is matched only from source to destination and not both.

any 443

Any target IP address over port 443. As this port is for SSL/TLS, this matches all traffic to any HTTPs server.



Rule Options

( msg:"MALWARE-CNC Malicious BitCoiner Miner download - Win.Trojan.Systema";

Message to display in alert file when detected.

flow:to_server,established;

Flow from client to server only if the session is established. This avoids searching during the 3-way handshake or session teardown. This should match what is in the header. In this case we track the traffic using the destination port. If the flow is to_client then we should track the conversation on the source port.

content:"/aviatic/systema.exe",fast_pattern;

Content string to look for in packet

nocase;

Allows for content to be in upper or lower case.

http_raw_uri;

content modifier that restricts the search to the UNNORMALIZED request URI field.

http_uri;

content modifier that restricts the search to the NORMALIZED request URI field.

metadata:impact_flag red,policy balanced-ips drop,policy security-ips drop,ruleset community;

specifies a searies of metadata tags applied to rule.

reference:url,www.virustotal.com/en/file/583b585078f37f5d399a228f1b8021ca0a9e904a55792281048bae9cfe0e95c1/analysis/;

References related to the attack specifed for this detection rule

sid:30552;

Snort inique sid ID #

rev:2; )

Administrator defined rule revision number



References:

[Snorpy - Snort Rule Creator](http://www.cyb3rs3c.net/)



Instructor Note
Instructor Notes



11.5.4.4 Snort Demonstration
Use the "Internet Host" VM and implement snort rules as specified in the demonstration.

For this demonstration You will need to access your Internet host and capture traffic with interface eth0 (10.10.0.40) via terminator with multiple terminals.



Confirm that snort has been installed/configured correctly. This will also verify the Snort version installed.

student@internet-host-student-18#  snort --version +
            or +
            snort -V


Your output should display as follows:

   ,,_     -*> Snort! <*-
  o"  )~   Version 2.9.9.0 GRE (Build 56)
   ''''    By Martin Roesch & The Snort Team: http://www.snort.org/contact#team
           Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
           Copyright (C) 1998-2013 Sourcefire, Inc., et al.
           Using libpcap version 1.8.1
           Using PCRE version: 8.39 2016-06-14
           Using ZLIB version: 1.2.8


To start snort as a proccess. (You must have root privileges in order to run snort.)

student@internet-host-student-18:~$ su
Password:
root@internet-host-student-18:/# snort -D -l /var/log/snort/ -c /etc/snort/snort.conf
Syntax breakout:

-D - Run Snort in daemon mode. Alerts are sent to /var/log/snort/alert unless otherwise specified.

-l log-dir - Defines the output logging directory. Plain text alerts and packet logs go into this directory. Default logging directory is /var/log/snort.

-c config-file - Specifies the configuration or rule file to use for packet matching.



Your output will display the following:

Spawning daemon child...
My daemon child PID lives...
Daemon parent exiting (0)
root@internet-host:/# ps -ef | grep snort
If you do not see this output, there is likely an error with one of your rules. Try running the same command without the "-D" and it should give you an error message on why Snort is not running properly.


Check that snort is running via process snapshot (ps) command.

You may start multiple instances of snort on multiple interfaces (each will instance will create its own process.)



Run this to verify that the snort process is running:

root@internet-host:/etc/snort# ps -ef | grep snort


The output should display as follows

root      7697     1  0 17:18 ?        00:00:00 snort -D -l /var/log/snort/ -c /etc/snort/snort.conf
root      7708  3537  0 17:19 pts/2    00:00:00 grep snort
The first column of number is the actual process ID. The output also displays the command that was run on the system.



To check your rules:

Navigate to the directory where your rules are stored. The default location is /etc/snort/rules.

student@internet-host-student-18:~$ cd /etc/snort/rules
student@internet-host-student-18:/etc/snort/rules$ ls
icmp.rules
Based on the output, you can see that there is a icmp.rules file located in the rules directory.



You can display the contents of the using the cat (concatenate) command or open up a text editor like nano or vim.

student@internet-host-student-18:/etc/snort/rules$ cat icmp.rules
alert icmp any any -> any any (msg:ICMP detected; sid:111; rev:1;)


Test the default rule which will trigger on ANY icmp packet. Ping from your internet host to BLUE_HOST-1 and check the alerts file that snort generates.

student@internet-host-student-18:/etc/snort/rules$ ping 172.16.82.106 -c 3
PING 172.16.82.106 (172.16.82.106) 56(84) bytes of data.
64 bytes from 172.16.82.106: icmp_seq=1 ttl=59 time=4.38 ms
64 bytes from 172.16.82.106: icmp_seq=2 ttl=59 time=3.87 ms
64 bytes from 172.16.82.106: icmp_seq=3 ttl=59 time=3.66 ms

--- 172.16.82.106 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2002ms
rtt min/avg/max/mdev = 3.660/3.973/4.389/0.314 ms


Before we move any further, you have to know how to obtain an alert file. Snort alerts are typically located in the /var/log/snort directory. The location of the alert file within the log directory may not always up in the snort directory. Users can dictated where they want the alert files to be stored.



Run this command to enter the directory and list contents:

student@internet-host-student-18:~$ cd /var/log/snort
student@internet-host-student-18:/var/log/snort$ ls
alert  snort.log.1626373999
This command produced an output that displayed an alert file generated by snort as well as a log entry.



Lets view the alert file produced by the ping to BLUE_HOST-1

Run the command to cat (Concatenate) the alert file

student@internet-host-student-18:/var/log/snort$ cat alert
[**] [1:111:1] ICMP detected [**]
[Priority: 0]
07/15-18:33:25.608677 10.10.0.40 -> 172.16.82.106
ICMP TTL:64 TOS:0x0 ID:36681 IpLen:20 DgmLen:84 DF
Type:8  Code:0  ID:9874   Seq:1  ECHO

[**] [1:111:1] ICMP detected [**]
[Priority: 0]
07/15-18:33:25.613225 172.16.82.106 -> 10.10.0.40
ICMP TTL:59 TOS:0x0 ID:49742 IpLen:20 DgmLen:84
Type:0  Code:0  ID:9874  Seq:1  ECHO REPLY

[**] [1:111:1] ICMP detected [**]
[Priority: 0]
07/15-18:33:26.610522 10.10.0.40 -> 172.16.82.106
ICMP TTL:64 TOS:0x0 ID:36807 IpLen:20 DgmLen:84 DF
Type:8  Code:0  ID:9874   Seq:2  ECHO

[**] [1:111:1] ICMP detected [**]
[Priority: 0]
07/15-18:33:26.614124 172.16.82.106 -> 10.10.0.40
ICMP TTL:59 TOS:0x0 ID:49775 IpLen:20 DgmLen:84
Type:0  Code:0  ID:9874  Seq:2  ECHO REPLY

[**] [1:111:1] ICMP detected [**]
[Priority: 0]
07/15-18:33:27.612369 10.10.0.40 -> 172.16.82.106
ICMP TTL:64 TOS:0x0 ID:37026 IpLen:20 DgmLen:84 DF
Type:8  Code:0  ID:9874   Seq:3  ECHO

[**] [1:111:1] ICMP detected [**]
[Priority: 0]
07/15-18:33:27.615794 172.16.82.106 -> 10.10.0.40
ICMP TTL:59 TOS:0x0 ID:49996 IpLen:20 DgmLen:84
Type:0  Code:0  ID:9874  Seq:3  ECHO REPLY

---
The alert file displaying:

source and destination IP address

source - 10.10.0.40

destination - 172.16.82.106

IP protocol of ICMP

20 bytes (no options)

Time to Live

TTL 64

Datagram length

84 (packet length)

ICMP message code and type and meaning (Echo and Reply)

type 8 (request)

type 0 (reply)



The log files are created in pcap format and can be viewed in both tcpdump, wireshark and other programs.

Run this command using tcpdump:

student@internet-host-student-18:/var/log/snort$ sudo tcpdump -r snort.log.1626373999
[sudo] password for student:

**Output Truncated**

reading from file snort.log.1626373999, link-type EN10MB (Ethernet)
18:33:25.608677 IP 10.10.0.40 > 172.16.82.106: ICMP echo request, id 9874, seq 1, length 64
18:33:25.613225 IP 172.16.82.106 > 10.10.0.40: ICMP echo reply, id 9874, seq 1, length 64
18:33:26.610522 IP 10.10.0.40 > 172.16.82.106: ICMP echo request, id 9874, seq 2, length 64
18:33:26.614124 IP 172.16.82.106 > 10.10.0.40: ICMP echo reply, id 9874, seq 2, length 64
18:33:27.612369 IP 10.10.0.40 > 172.16.82.106: ICMP echo request, id 9874, seq 3, length 64
18:33:27.615794 IP 172.16.82.106 > 10.10.0.40: ICMP echo reply, id 9874, seq 3, length 64
18:49:41.426285 IP6 fe80::fc16:3eff:fe9f:f412 > ip6-allrouters: ICMP6, router solicitation, length 16
19:34:44.150593 IP6 fe80::f816:3eff:fe9f:f412 > ip6-allrouters: ICMP6, router solicitation, length 16
additional tcpdump options include:

-X print header (without layer 2) in hex and ASCII

-XX print header (with layer 2) in hex and ASCII

-v verbose

-vv very verbose

-n do not convert IP address and ports to names

-t don’t print time

-ttt print time between packets

-c count (read or collect x number of packets)

man tcpdump for more options



Run this tcpdump command syntax with options:

student@internet-host-student-18:/var/log/snort$ sudo tcpdump -r snort.log.1626373999 -vnXX -c 3
[sudo] password for student:

**Output Truncated**

reading from file snort.log.1626373999, link-type EN10MB (Ethernet)
18:33:25.608677 IP (tos 0x0, ttl 64, id 36681, offset 0, flags [DF], proto ICMP (1), length 84)
    10.10.0.40 > 172.16.82.106: ICMP echo request, id 9874, seq 1, length 64
	0x0000:  fa16 3e73 cf10 fa16 3e9f f412 0800 4500  ..>s....>.....E.
	0x0010:  0054 8f49 4000 4001 a2b3 0a0a 0028 ac10  .T.I@.@......(..
	0x0020:  526a 0800 1570 2692 0001 757f f060 0000  Rj...p&...u..`..
	0x0030:  0000 8e49 0900 0000 0000 1011 1213 1415  ...I............
	0x0040:  1617 1819 1a1b 1c1d 1e1f 2021 2223 2425  ...........!"#$%
	0x0050:  2627 2829 2a2b 2c2d 2e2f 3031 3233 3435  &'()*+,-./012345
	0x0060:  3637                                     67
18:33:25.613225 IP (tos 0x0, ttl 59, id 49742, offset 0, flags [none], proto ICMP (1), length 84)
    172.16.82.106 > 10.10.0.40: ICMP echo reply, id 9874, seq 1, length 64
	0x0000:  fa16 3e9f f412 fa16 3e73 cf10 0800 4500  ..>.....>s....E.
	0x0010:  0054 c24e 0000 3b01 b4ae ac10 526a 0a0a  .T.N..;.....Rj..
	0x0020:  0028 0000 1d70 2692 0001 757f f060 0000  .(...p&...u..`..
	0x0030:  0000 8e49 0900 0000 0000 1011 1213 1415  ...I............
	0x0040:  1617 1819 1a1b 1c1d 1e1f 2021 2223 2425  ...........!"#$%
	0x0050:  2627 2829 2a2b 2c2d 2e2f 3031 3233 3435  &'()*+,-./012345
	0x0060:  3637                                     67
18:33:26.610522 IP (tos 0x0, ttl 64, id 36807, offset 0, flags [DF], proto ICMP (1), length 84)
    10.10.0.40 > 172.16.82.106: ICMP echo request, id 9874, seq 2, length 64
	0x0000:  fa16 3e73 cf10 fa16 3e9f f412 0800 4500  ..>s....>.....E.
	0x0010:  0054 8fc7 4000 4001 a235 0a0a 0028 ac10  .T..@.@..5...(..
	0x0020:  526a 0800 e867 2692 0002 767f f060 0000  Rj...g&...v..`..
	0x0030:  0000 ba50 0900 0000 0000 1011 1213 1415  ...P............
	0x0040:  1617 1819 1a1b 1c1d 1e1f 2021 2223 2425  ...........!"#$%
	0x0050:  2627 2829 2a2b 2c2d 2e2f 3031 3233 3435  &'()*+,-./012345
	0x0060:  3637                                     67
This produces the hex dump and ASCII language



Using awk, sort, sed, and uniq to adjust your output.

root@internet-host:/var/log/snort# tcpdump -tnr /var/log/snort/snort.log.1540828602 | awk '{print $2} {print $4}' | sort | sed 's/:$//' | uniq -c
reading from file /var/log/snort/snort.log.1540828602, link-type EN10MB (Ethernet)
     38 10.1.0.2
     38 10.2.0.2
This results in a list of all IP addresses in the captured traffic.

This provides an example of the versatility of command line options and how you can change the output formats.



Snort can (predictably) read the log file as well and provide statistics on the packets captured

To parse the log file using snort.

root@internet-host:/var/log/snort# snort -r snort.log.[log_number]
Running in packet dump mode

        --== Initializing Snort ==--
Initializing Output Plugins!
pcap DAQ configured to read-file.
Acquiring network traffic from "snort.log.1540833520".

        --== Initialization Complete ==--

   ,,_     -*> Snort! <*-
  o"  )~   Version 2.9.9.0 GRE (Build 56)
   ''''    By Martin Roesch & The Snort Team: http://www.snort.org/contact#team
           Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
           Copyright (C) 1998-2013 Sourcefire, Inc., et al.
           Using libpcap version 1.8.1
           Using PCRE version: 8.39 2016-06-14
           Using ZLIB version: 1.2.8

Commencing packet processing (pid=9756)
WARNING: No preprocessors configured for policy 0.
10/29-18:08:37.478341 fe80::f816:3eff:fedb:4eb9 -> ff02::2
IPV6-ICMP TTL:255 TOS:0x0 ID:0 IpLen:40 DgmLen:56
=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

WARNING: No preprocessors configured for policy 0.
10/29-19:11:58.566398 fe80::f816:3eff:fedb:4eb9 -> ff02::2
IPV6-ICMP TTL:255 TOS:0x0 ID:0 IpLen:40 DgmLen:56
=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

** Output Truncated **

===============================================================================
Run time for packet processing was 0.1879 seconds
Snort processed 8 packets.
Snort ran for 0 days 0 hours 0 minutes 0 seconds
   Pkts/sec:            8
===============================================================================
Memory usage summary:
  Total non-mmapped bytes (arena):       782336
  Bytes in mapped regions (hblkhd):      21590016
  Total allocated space (uordblks):      670624
  Total free space (fordblks):           111712
  Topmost releasable block (keepcost):   101520
===============================================================================
Packet I/O Totals:
   Received:            8
   Analyzed:            8 (100.000%)
    Dropped:            0 (  0.000%)
   Filtered:            0 (  0.000%)
Outstanding:            0 (  0.000%)
   Injected:            0
===============================================================================
Breakdown by protocol (includes rebuilt packets):
        Eth:            8 (100.000%)
       VLAN:            0 (  0.000%)
        IP4:            6 ( 75.000%)
       Frag:            0 (  0.000%)
       ICMP:            6 ( 75.000%)
        UDP:            0 (  0.000%)
        TCP:            0 (  0.000%)
        IP6:            2 ( 25.000%)
    IP6 Ext:            2 ( 25.000%)
   IP6 Opts:            0 (  0.000%)
      Frag6:            0 (  0.000%)
      ICMP6:            2 ( 25.000%)
       UDP6:            0 (  0.000%)
       TCP6:            0 (  0.000%)
     Teredo:            0 (  0.000%)
    ICMP-IP:            0 (  0.000%)
    IP4/IP4:            0 (  0.000%)
    IP4/IP6:            0 (  0.000%)
    IP6/IP4:            0 (  0.000%)
    IP6/IP6:            0 (  0.000%)
 ** Output Truncated ***
        ARP:            0 (  0.000%)
        IPX:            0 (  0.000%)
   Eth Loop:            0 (  0.000%)
   Eth Disc:            0 (  0.000%)
   IP4 Disc:            0 (  0.000%)
   IP6 Disc:            0 (  0.000%)
   TCP Disc:            0 (  0.000%)
   UDP Disc:            0 (  0.000%)
  ICMP Disc:            0 (  0.000%)
All Discard:            0 (  0.000%)
      Other:            0 (  0.000%)
Bad Chk Sum:            0 (  0.000%)

      Total:            8
===============================================================================
Snort exiting


To Kill the Snort Process:

root@internet-host:/etc/snort#  ps -ef | grep snort
(find snort PID)

root@internet-host:/etc/snort#  kill -9 [PID]


References:



Instructor Note
Instructor Notes



11.5.4.5 Linking the rules to IDS execution
In this demonstration:

We will edit the default icmp rule (/etc/snort/rules/icmp.rules).

Test the rule by first sending a ping with the wrong payload to verify it does not trigger the alert.

Test the rule by sending a ping with the correct payload to verify it does trigger the alert.



Customize the icmp.rules file and change the matching condition.

The rule should only alert if an icmp packet with the hex string of "IDSRuleCheck" is present in the payload.

Give the rule the sid of "9000020" (any unique sid will work).

Change the msg to "It all began with" (Any message will work).

Comment out the previous "Alert on all ICMP traffic" rule.

Via your favorite text editor (vi/vim/atom), edit the icmp.rules file and comment out the "alert on any ICMP traffic" rule:

alert icmp any any -> any any (msg: "It all began with"; sid:9000020; content: "IDSRuleCheck";)
#alert icmp any any -> any any (msg: "Ping Alert"; sid:9000015;)


Run Snort as a daemon, pointing to the config file. Send logs to the /var/log/snort/ directory. -n limited the number of packets captured and then exits snort.

root@internet-host:/etc/snort#   snort -D -l /var/log/snort/ -c /etc/snort/rules/icmp.rules


Send a ping from Internet_Host to Blue_Host-1 with "IDSCheck"

We convert "IDSCheck" to hex (494453436865636b) and use the -p option to add a the binary payload to the icmp message. The pings sent with the payload information should not trigger an alert since it didn’t match the content exactly.

root@internet-host:/var/log/snort#  ping 172.16.82.106 -p 494453494453436865636b -c 8


View the alert file.

We should see that the alert file is still empty since the message is not what we specified for it to alert on.

Check your alert logs to ensure that the alert was not triggered by the traffic:

The alert file should be empty.

root@internet-host:/var/log/snort# ls -l

-rw-r--r-- 1 root root    0 Oct 30 13:14 alert
root@internet-host:/var/log/snort# cat alert
{empty file}


Kill and Retart Snort.

root@internet-host:/etc/snort# ps -ef | grep snort* (find snort PID)

root@internet-host:/etc/snort# kill -9 [PID]
root@internet-host:/etc/snort#   snort -D -l /var/log/snort/ -c /etc/snort/rules/icmp.rules


Send pings from Internet_Host to Blue_Host-1 with "IDSRuleCheck"

We convert "IDSRuleCheck" to hex (49445352756c65436865636b) and use the -p option to add a the binary payload to the icmp message. The pings sent with the payload information should trigger an alert.

root@internet-host:/var/log/snort#  ping 172.16.82.106 -p 49445352756c65436865636b -c 5


Check your alert logs to ensure that the alert was triggered by the traffic:

root@internet-host:/var/log/snort# cat alert

[**] [1:9000015:0] IDSRuleCheck [**]
[Priority: 0]
10/29-15:56:46.346271 10.10.0.40 -> 172.16.82.106
ICMP TTL:64 TOS:0x0 ID:15919 IpLen:20 DgmLen:84 DF
Type:8  Code:0  ID:5816   Seq:1  ECHO

[**] [1:9000015:0] IDSRuleCheck [**]
[Priority: 0]
10/29-15:56:46.347501 10.10.0.40 -> 172.16.82.106
ICMP TTL:63 TOS:0x0 ID:44159 IpLen:20 DgmLen:84
Type:0  Code:0  ID:5816  Seq:1  ECHO REPLY

** Output Truncated **


Read the log via snort.

root@internet-host:/etc/snort# snort -r snort.log.[lognumber]


Kill Snort again

root@internet-host:/etc/snort# ps -ef | grep snort* (find snort PID)

root@internet-host:/etc/snort# kill -9 [PID]


References:



Instructor Note
Instructor Notes



11.5.4.6 Snort Troubleshooting
Run Snort as a daemon, pointing to the config file. You notice that the process did not start (see the beginning of the demo to see what the output of a snort daemon running looks like).

root@internet-host:/etc/snort# sudo snort -D -c /etc/snort/snort.conf
Sometimes the snort service will not start and you’ll wonder why. You know the syntax is correct and you keep getting the output above.



One of the first things you can do is run snort without the -D. The output will give you an error and direct you to the error location.

root@internet-host:/etc/snort# sudo snort -c /etc/snort/snort.conf
Running in IDS mode

        --== Initializing Snort ==--
Initializing Output Plugins!
Initializing Preprocessors!
Initializing Plug-ins!
Parsing Rules file "/etc/snort/snort.conf"
ERROR: /etc/snort//etc/snort/rules/icmp.(0) Unable to open rules file "/etc/snort//etc/snort/rules/icmp.": No such file or directory.

Fatal Error, Quitting..


You can see that the file where the error exists is in the snort.conf file within the snort directory /etc/snort/snort.conf. Most snort rules file extensions end with a .rule or .rules. The error shows that the icmp. is missing the file extension.



You have to enter the /etc/snort directory to correct the problem.

root@internet-host:/etc/snort# ls
rules  snort.conf
root@internet-host:/etc/snort# cat snort.conf
include /etc/snort/rules/icmp.
#include rules/nm.rules
#include rules/shell.rules
#include rules/dzt.rules
You can see that the include /etc/snort/rules/icmp. is missing the file extension. You will have to nano into the script and make the change by adding the file extension. Keep in mind, this error can be within a rule as well so you may have to correct them too.



You can run the same command with a -T and get the same exact result as you did by running the command without -D. If everthing is working and your configurations are properly set, this the result you will get with the -T command.

root@internet-host:/etc/snort# sudo snort -T -c /etc/snort/snort.conf
Running in Test mode

        --== Initializing Snort ==--
Initializing Output Plugins!
Initializing Preprocessors!
Initializing Plug-ins!
Parsing Rules file "/etc/snort/snort.conf"
Tagged Packet Limit: 256
Log directory = /var/log/snort

+++++++++++++++++++++++++++++++++++++++++++++++++++
Initializing rule chains...
1 Snort rules read
    1 detection rules
    0 decoder rules
    0 preprocessor rules
1 Option Chains linked into 1 Chain Headers
0 Dynamic rules
+++++++++++++++++++++++++++++++++++++++++++++++++++

+-------------------[Rule Port Counts]---------------------------------------
|             tcp     udp    icmp      ip
|     src       0       0       0       0
|     dst       0       0       0       0
|     any       0       0       1       0
|      nc       0       0       0       0
|     s+d       0       0       0       0
+----------------------------------------------------------------------------

+-----------------------[detection-filter-config]------------------------------
| memory-cap : 1048576 bytes
+-----------------------[detection-filter-rules]-------------------------------
| none
-------------------------------------------------------------------------------

+-----------------------[rate-filter-config]-----------------------------------
| memory-cap : 1048576 bytes
+-----------------------[rate-filter-rules]------------------------------------
| none
-------------------------------------------------------------------------------

+-----------------------[event-filter-config]----------------------------------
| memory-cap : 1048576 bytes
+-----------------------[event-filter-global]----------------------------------
+-----------------------[event-filter-local]-----------------------------------
| none
+-----------------------[suppression]------------------------------------------
| none
-------------------------------------------------------------------------------
Rule application order: activation->dynamic->pass->drop->sdrop->reject->alert->log
Verifying Preprocessor Configurations!

[ Port Based Pattern Matching Memory ]
+-[AC-BNFA Search Info Summary]------------------------------
| Instances        : 1
| Patterns         : 1
| Pattern Chars    : 5
| Num States       : 5
| Num Match States : 1
| Memory           :   1.56Kbytes
|   Patterns       :   0.04K
|   Match Lists    :   0.07K
|   Transitions    :   1.05K
+-------------------------------------------------

        --== Initialization Complete ==--

   ,,_     -*> Snort! <*-
  o"  )~   Version 2.9.9.0 GRE (Build 56)
   ''''    By Martin Roesch & The Snort Team: http://www.snort.org/contact#team
           Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
           Copyright (C) 1998-2013 Sourcefire, Inc., et al.
           Using libpcap version 1.8.1
           Using PCRE version: 8.39 2016-06-14
           Using ZLIB version: 1.2.8


Snort successfully validated the configuration!
Snort exiting
Keep in mind that the -T command does not start the snort process. It is just a test and or troubleshooting command.


References:

https://snort-org-site.s3.amazonaws.com/production/document_files/files/000/000/142/original/snort_manual.pdf



Instructor Note
Instructor Notes



11.5.5 Interpret the effects of IDS / IPS rules on network traffic


References:



Instructor Note
Instructor Notes



11.5.5.1 Evaluating IDS/IPS Performance
Evaluating the performance of threat detection systems is a critical process in cybersecurity. It involves assessing how well a system can accurately identify and respond to potential threats. This uses for following terms to classify the threats:

True Positive (TP): A true positive occurs when the model correctly predicts the positive class. In other words, the model predicts that an event will happen, and it does happen.

System detects a threat, and there is a threat.

True Negative (TN): A true negative occurs when the model correctly predicts the negative class. In other words, the model predicts that an event will not happen, and it doesn’t happen.

System does not detect a threat, and there is no threat.

False Positive (FP): A false positive occurs when the model incorrectly predicts the positive class. In other words, the model predicts that an event will happen, but it doesn’t happen. This is also known as a Type I error.

System detects a threat, but there is no threat.

False Negative (FN): A false negative occurs when the model incorrectly predicts the negative class. In other words, the model predicts that an event will not happen, but it does happen. This is also known as a Type II error.

System does not detect a threat, but there is a threat.

There are several key metrics and methods used to evaluate the performance of these systems:

Accuracy:

Definition: Accuracy measures the overall correctness of the system by calculating the ratio of correctly predicted instances to the total instances.

Formula: Accuracy = (TP + TN) / (TP + TN + FP + FN)

Note: While accuracy is important, it might not be the only metric to consider, especially in imbalanced datasets where the number of non-threat instances significantly outweighs threat instances.

Precision:

Definition: Precision focuses on the relevant instances that the system has correctly predicted as threats, out of all the instances predicted as threats.

Formula: Precision = TP / (TP + FP)

Interpretation: Precision tells us how many of the predicted threats are actually threats. A higher precision means fewer false positives.



References:



Instructor Note
Instructor Notes



11.5.5.2 Failed IDS/IPS
Intrusion Detection and Prevention Systems are traffic filtering and direction devices, just like Firewalls, Routers, proxies, and switches. They can drop, reject and redirect packets or allow traffic to pass through to their destination. They can also log and alert on specifically defined traffic. However, should an IDS/IPS fail/crash for whatever reason it does revert to one of two states. Both options are usually possible but we must choose carefully.

Fails open - The system will allow all traffic through, regardless of the threat. This option is desirable if accessibility is more important than security.

Fails closed - The system will prevent all traffic through. This option is desirable if security is more important than accessibility.

Adversaries may intentionally try to test your defenses by forcing your IDS/IPS to crash. This is to determine your security posture. If your system fails open then they can mount further attacks freed from the detection and prevention measures the IDS/IPS provided. If your system fails closed then they might employ IDS/IPS evasions techniques discussed in the next section.



References:



Instructor Note
Instructor Notes



11.5.5.3 Attacking & Evading IDS/IPS
IDSs and IPSs can also be fooled. Although Intrusion Detection and Prevention Systems continue to advance in capability and accuracy, techniques exist to evade the systems.

Many of these are built around the delta, the difference, of how an IDS/IPS interprets a packet versus how a target host interprets a packet.

Insertion attack occurs when an IDS accepts a packet that the target host will not accept. This is done by adding "extra" packets that the host will eventually ignore but the IDS will accept.

Typically the packets will be sent out of order.

Extra packets are added (inserted) to the stream. Some with either lower than needed TTL’s or Bad Checksums.

Lower TTL’s will reach the IDS but not reach the victim.

Bad checksum will cause the Victim host to ignore this packet but the IDS will still include it in the evaluation.

The IDS will re-order the entire data stream (including the bad packet(s) ) in the proper order. It will evaluate the entire stream as harmless and will allow the stream to proceed.

The host will receive the data stream and in reconstructing the stream it will request retransmission of any of the "bad" packets with bad checksums. These retransmissions can be different than from the original transmissions and can be the key into turing the data into an exploit.

Packets with low TTL’s will not even reach the victim and may not even know of their existance.

It will then only see the attacker’s intended data.

insertion



Evasion attack is the mirror situation where a host accepts a packet that the IDS/IPS does not accept. This is typically a fragmentation overlap attack.

This is the easiest to exploit and most devastating to the accuracy of an IDS.

Entire sessions can be carried forth in packets that evade an IDS, and blatantly obvious attacks couched in such sessions will happen right under the nose of even the most sophisticated analysis engine.

Typically packets are sent out of order and using Fragment overlapping.

IDS and Hosts can treat overlapping packets in different ways. [SANS fragmentation paper](https://www.sans.org/reading-room/whitepapers/detection/ip-fragment-reassembly-scapy-33969). When reconstructing the flow, the IDS will detect that some packets overlap. It will construct the flow and discard the overlap data using the "Last" method. This means that each overlap overwrites the previous. (This is why sending the packets out or order is important.) It will look harmless and forward all the packets to the host.

The host will receive the packets but will treat the overlapping differently. It will generally use the "First" method. This means that the first fragment is always accepted and any follow on fragments in the same space are ignored. It will construct the data as intended by the attacker.

evasion



References:

[Insertion Attack Youtube Video](https://www.youtube.com/watch?v=5vDlc0I0Yz4)

[Evasion Attack Youtube Video](https://www.youtube.com/watch?v=xRf9_yWOVb4)

[SANS fragmentation paper](https://www.sans.org/reading-room/whitepapers/detection/ip-fragment-reassembly-scapy-33969)



Instructor Note
Instructor Notes



11.5.5.4 Technical Attacks on IDS/IPS
These concepts were initially written about in 1988 by Thomas H. Ptacek and Timothy N. Newsham of Secure Networks Inc., over 30 years ago, but remain viable even as the techniques have changed. [Link to article](http://cs.unc.edu/~fabian/course_papers/PtacekNewsham98.pdf)

Techniques to inject and evade include:

packet sequence manipulation

fragmenting payload to avoid alerting on signatures

overlapping fragments that are reassembled differently by the IDS and the target host.

Manipulating TCP headers - such as overlap sequence numbers

Manipulating IP options - Modifying the Total length or IP header length can prevent the IDS from finding the transport header. Attacker can also manipulate the options field.

Sending data during the TCP connection setup



References:

https://en.wikipedia.org/wiki/Intrusion_detection_system_evasion_techniques

https://www.sans.org/reading-room/whitepapers/detection/intrusion-detection-evasion-attackers-burglar-alarm-1284



Instructor Note
Instructor Notes



11.5.5.5 Non-Technical attacks against IDS/IPS
attacking during periods of low manning (such as Ramadan 2012 Saudi Aramco attack) [reference from Wikipedia](https://en.wikipedia.org/wiki/Shamoon)

attacking during a surge in activity (such as attacking Target Corp. Point of Sale machines during the November-December 2013 shopping season) [Google search of articles relating to attack](https://www.google.com/search?ei=Obj_XPCHFeGD_QbYg4HoCA&q=target+POS+attack+2013&oq=target+POS+attack+2013&gs_l=psy-ab.3..33i160.112333.118394..118538%E2%80%A6%E2%80%8B0.0..1.297.1710.19j2j1%E2%80%A6%E2%80%8B.2..0%E2%80%A6%E2%80%8B.1..gws-wiz%E2%80%A6%E2%80%8B%E2%80%A6%E2%80%8B.0i71j0i273j0i131i273j0i67j0j0i131j0i22i30j0i22i10i30j33i22i29i30j33i299.awemUCyCrmI)



References:



Instructor Note
Instructor Notes



11.5.5.6 Strengthening Defensive Systems


This is all well and good for an OCO Cyber Operations specialist, but what about the DCO specialist?

Linking IDS/IPS to other tools - Improvements in IDS/IPS include target-based IDS/IPS where it has knowledge of the host systems they are defending and how they interpret and reassemble packets. This can be accomplished by feeding Nmap, Nessus or p0f data into IDS/IPS configurations.

Multiconfig - The Multiconfig feature of Snort and other IDSs can have more detailed configurations for different VLANs and subnets within a network, providing more focused detection and prevention based on the devices in that subnet.

Tuning - Tuning an IDS via suppression and thresholding techniques will decrease the number of false positive alerts. All these tools and options allow DCO personnel to focus on true threats and not search for a poisoned needle in a haystack of harmless needles.

HIDS and File Integrity - HIDS, Host Based Intrusion Detection Systems such as OSSEC protect the individual hosts on which they are running. File integrity checking software such as Samhain, Tripwire, System File Checker and others validate the integrity of operating system and application files, often based on comparing hashes.

References:

https://insecure.org/stf/secnet_ids/secnet_ids.html

https://snort.org/documents (especially the Whitepapers and Webcast Slides sections)

http://pld.cs.luc.edu/courses/447/fall05/paxson_activemap.pdf
