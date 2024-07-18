# 2.0 Outcomes
- Explain OSI Layer 3 protocols, headers and technologies
- Describe IP networking
  - Explain IPv4 Addressing
    - Describe Classful IPv4 addressing and subnetting
    - Analyze IPv4 packet header
    - Identify IPv4 address types and scopes
    - Explain Fragmentation with its vulnerability
    - Explain OS Fingerprinting with TTL
    - Explain IPv4 Auto Configuration with vulnerability
    - Analyze ICMPv4 protocol and header structure
  - Explain IPv6 Addressing
    - Describe IPv6 addressing and subnetting
    - Analyze IPv6 packet header
    - Describe key differences between IPv4 and IPv6
    - Explain IPv6 address representation
    - Identify IPv6 address types and scopes
    - Explain IPv6 Auto Configuration with vulnerability
    - Analyze ICMPv6 protocol and header structure
    - Explain Neighbor discovery protocol (NDP)
  - Analyze internetworking routing
    - Discuss Routing Tables
    - Dynamic Routing Protocols operation and vulnerabilities
    - Compare Static routing vs. dynamic routing
    - Understand First Hop Redundancy Protocols and their vulnerabilities


The functions and protocols at Layer 3 (Network layer) of the OSI model are critically important in cybersecurity due to their role in facilitating end-to-end communication and routing of data across interconnected networks. At Layer 3, protocols such as IP (Internet Protocol) govern the logical addressing and routing of packets between different network segments or subnets. Understanding Layer 3 protocols is crucial for managing network traffic, enforcing access controls, and protecting against various cyber threats.

One of the primary functions of Layer 3 protocols is to provide logical addressing, allowing devices on different networks to communicate with each other. IP addresses serve as unique identifiers for devices and enable the routing of data packets across interconnected networks. By understanding IP addressing schemes, subnetting, and routing protocols such as OSPF (Open Shortest Path First) and BGP (Border Gateway Protocol), cybersecurity professionals can design and implement secure and efficient network architectures.

Layer 3 protocols also play a vital role in network segmentation and access control. By dividing a network into multiple subnets and implementing routing policies, organizations can enforce access controls and restrict the flow of traffic between different network segments. This helps prevent unauthorized access to sensitive resources and contains the spread of cyber threats such as malware and unauthorized access attempts.

Furthermore, Layer 3 protocols enable the implementation of security measures such as virtual private networks (VPNs) and network address translation (NAT). VPNs use Layer 3 tunneling protocols such as IPsec (Internet Protocol Security) to create secure communication channels over untrusted networks, ensuring the confidentiality and integrity of data transmitted between remote locations. NAT, on the other hand, allows organizations to conceal internal IP addresses from external networks, enhancing network security and privacy.

In summary, the functions and protocols at Layer 3 of the OSI model are essential for establishing logical communication paths, enforcing access controls, and implementing security measures in modern networks. By understanding and leveraging Layer 3 protocols effectively, cybersecurity professionals can design robust network architectures, mitigate cyber threats, and safeguard critical assets and information.

---
## 2.1 Describe IP Networking
**Network Layer**

Internetworking was developed because Local Area Networks (LAN) needed the ability to communicate with one another. ARPANet was the first network created to address this need in the 1960’s, this has evolved into the Internet Protocol (IP). The network layer of the OSI model is where this layer of internetworking is discussed and its parameters are defined. The protocol data unit at this layer is considered a packet and is the last structure generated before the data is encapsulated into a frame at the data-link layer. There are two different versions of IP, version 4 and version 6. The network layer is an extremely important layer in the OSI model that facilitates network to network communications and provides the following:
- Addressing Schemes for Network (Logical Addressing)
  - Each device on the network has a logical addresses associated with it. This address is independent of the hardware device and must be unique in an internetwork.
- Routing
  - The moving of data across a series of interconnected networks is the job of devices and software that exist at this layer. The network layer must handle incoming packets from various sources, determine their final destination, and send them to the appropriate interface and forwarding devices to be processed and routed once again.
- Encapsulation
  - Encapsulation of messages received from higher layers must be performed to be passed on to the data-link layer.
- IP Fragmentation and Reassembly
  - Due to constraints on bandwidth and other limiting factors, the network layer must be able to fragment packets that are too large and re-assemble the data in order at the destination device.
- Error Handling and Diagnostics
  - The network layer uses special helper protocols like ICMP and ARP that allow logically connected devices to exchange information about the status of the network or devices themselves.

**Internet Protocol Versions**

The network layer deals in two version of IP and ICMP, version 4 and version 6.
- IPv4
  - Was the first working network layer protocol which has dominated the networking world since 1970s. At the time it was believed that 4.3 billion addresses would never be reached. In 1992 we started seeing the shortages take place and had to start developing methods of extending IPv4 until a permanent solution could be found. This is where and why subnetting, private ip addressing, and Network Address Translation protocol where developed and implemented.
  - The most significant issue with IPv4 is the exhaustion of available IPv4 addresses. The limited address space (32 bits) results in the depletion of available IPv4 addresses, making it challenging to assign unique addresses to new devices joining the network.
  - To assist in managing the eventual depletion of IPv4 address:
    - Subnetting and Address Allocation:
      - Efficiently allocate IPv4 address space through subnetting and address aggregation.
      - Use Variable Length Subnet Masking (VLSM) and Classless Inter-Domain Routing (CIDR) to allocate IP addresses based on the actual requirements of each subnet, avoiding wastage of address space.
    - RFC 1918 Private addresses:
      - RFC 1918 defines three blocks of IPv4 address space reserved for private use:
        - 10.0.0.0/8 (10.0.0.0 - 10.255.255.255)
        - 172.16.0.0/12 (172.16.0.0 - 172.31.255.255)
        - 192.168.0.0/16 (192.168.0.0 - 192.168.255.255)
      - These address ranges are designated for use within private networks and are not globally routable on the public Internet.
    - Network Address Translation (NAT):
      - Implement NAT to conserve IPv4 addresses by allowing multiple devices within a private network to share a single public IP address.
      - NAT translates private IP addresses to a single public IP address when communicating with devices outside the private network, reducing the number of globally routable IPv4 addresses required.
- IPv6
  - In 2011 IPv6 was released to use world wide. IPv6 was released to eventually replace IPv4 because of IPv4’s lack of address space. Along with IPv6’s release the packet design was simplified from the IPv4 15 sections header IPv6 holds only 8 section with less wasted fields.
  - Transitioning to IPv6 is the most effective long-term solution to address IPv4 exhaustion. IPv6 offers a significantly larger address space, allowing for an almost infinite number of unique IP addresses.
  - Organizations are encouraged to plan and implement IPv6 deployment strategies to gradually transition their networks and services to IPv6.

References:  
https://en.wikipedia.org/wiki/ARPANET  
https://en.wikipedia.org/wiki/Internet_Protocol_version_4  
https://en.wikipedia.org/wiki/IPv6  


---
### 2.1.1 Explain IPv4 Addressing
- IPv4 (Internet Protocol version 4) is the fourth version of the Internet Protocol and is widely used to identify and locate devices on a network. IPv4 addresses are 32 bits in length and are typically represented in dotted-decimal notation, where each of the four octets is separated by a period.
- 32-Bit Address: IPv4 addresses are 32 bits long, allowing for a total of 232 unique addresses. However, due to the rapid growth of the internet, the IPv4 address space became exhausted, leading to the development and adoption of IPv6.
- Dotted-Decimal Notation: IPv4 addresses are commonly represented in dotted-decimal notation, where each of the four octets is expressed as a decimal number. For example, the address 192.168.0.1 is divided into four octets: 192, 168, 0, and 1.
- Address Classes: IPv4 originally defined address classes A, B, C, D, and E, each with a different range of available addresses. However, classful addressing has largely been replaced by Classless Inter-Domain Routing (CIDR), which allows for more flexible allocation of address blocks.
- IPv4 Address Types: There are several types of IPv4 addresses, including:
  - Unicast: Identifies a single network interface.
  - Broadcast: Sent to all devices on a network segment.
  - Multicast: Sent to a specific group of devices.
  - Anycast: Identifies the nearest of a group of devices.
- Private and Public Addresses:
  - Private IPv4 addresses are reserved for use within private networks and are not routable on the public internet.
  - Common private address ranges include:
    - 10.0.0.0 to 10.255.255.255
    - 172.16.0.0 to 172.31.255.255
    - 192.168.0.0 to 192.168.255.255
  - Public IPv4 addresses are globally unique and routable on the internet.
    - Public address are any IP address that is not already reserved.

References:  
https://en.wikipedia.org/wiki/Classful_network  
https://ipinfo.io/ips


---
#### 2.1.1.1 Describe Classful IPv4 addressing and subnetting
* Classful IPv4 addressing and subnetting refer to the original addressing scheme defined in the early days of the Internet, where IP addresses were divided into predefined classes. Classful addressing has largely been replaced by Classless Inter-Domain Routing (CIDR), which offers more flexibility in address allocation. However, understanding classful addressing is fundamental to grasping the evolution of IP addressing.

Classful IPv4 Addressing

![image](https://github.com/ruppertaj/WOBC/assets/93789685/d0d5b2f4-aad4-4d52-9037-1232095b690a)
Classes of IPv4 Networks

* Classes of IPv4 can be derived from the first 4 binary bits of the first octet.

    * Class A - The first binary bit is off (00000000 to 01111111).

        * Range from 0 to 127.

        * Default mask is 255.0.0.0 or (CIDR) of /8.

        * Reserved:

            * Network 0 is not usable.

            * Network 127 is reserved for the local loopback.

            * 10.0.0.0/8 is reserved for RFC 1918 private addressing.

            * 100.64.0.0/10 is reserved for carrier-grade NAT.

    * Class B - The first binary bit is on and the second bit is off (binary 10000000 to 10111111).

        * Range from 128 to 191.

        * Default mask is 255.255.0.0 or (CIDR) of /16.

        * Reserved:

            * 172.16.0.0/12 is reserved for RFC 1918 private addressing.

            * 169.254.0.0/16 is reserved for the Microsoft APIPA range.

    * Class C - The first 2 binary bits are on and the third bit is off (binary 11000000 to 11011111).

        * Range from 192 to 223.

        * Default mask is 255.255.255.0 or (CIDR) of /24.

        * Reserved:

            * Network 127 is reserved for the local loopback.

            * 192.168.0.0/16 is reserved for RFC 1918 private addressing.

    * Class D - The first 3 binary bits are on and the fourth bit is off (binary 11100000 to 11101111).

        * Range from 224 to 239.

        * Used for IPv4 Multicast. Multicast is considered one-to-many addressing. This is where 1 IP address can communicate with 1 or more different destinations.

        * Reserved:

            * 224.0.0.0/24 range is used for link-local multicast.

    * Class E - The first 4 binary bits are on (binary 11110000 to 11111111).

        * Range from 240 to 255.

        * Reserved for "Future use". Discussions were made to start using it when IPv4 addresses were exhausted. It would require a lot of configuration and reprogramming of software and devices across the world. IPv6 was already developed at the time so it was recommended to just migrate to it.

* Though "classful" networking is not in use today due to its wastefulness of IPs, it is important to understand how some routing protocols and other machines may read a network address different than what is intended. Classful subnetting meant that IPs were assigned in blocks of addresses based on the default mask for the address class (/8, /16, or /24). Subnetting was permitted as long as the subnets all used the same subnet mask. VLSM was not permitted to use classful addressing.



* Subnetting

    * IPv4 Subnetting is the process to sub divide the larger network into smaller, less wastefull, subnets. For example if we have a given network of 192.168.10.128/25, which there are a total of 128 IPs (128-255), with the first IP assigned to the network address (128) and the last to the broadcast address (255). That leaves 126 IPs to be assigned to one network. If we needed to support two networks, we would need to subnet our original network into something smaller. We do this by borrowing a bit from the host side for the network side.

    * The CIDR, /25 in this case, identifies 25 network bits are cut "ON" (1) to produce a subnet mask of 255.255.255.128 leaving 7 host bits or "OFF" bits (0).
```
11111111.11111111.11111111.10000000
```
    * By borrowing from the host portion we can create 2 networks with a CIDR of /26.

![image](https://github.com/ruppertaj/WOBC/assets/93789685/b2fe6b9e-81f3-4028-bb49-c0bab2d068fd)
Subnetting Example.png


* Network reconnaissance we typically take the IP and CIDR and reverse it into the network (subnet) and ip range.

    * Using this chart you can identify the network, ip range, and broadcast of any IP with a CIDR of /24 and greater.

    * CIDR’s of less than /24 follow a similar process except the increments can be in the 1st, 2nd, or 3rd octets.
```
| 1     2     4    8     16    32    64    128    256 |
| 256   128   64   32    16    8     4     2      1   |
| /24   /25   /26  /27   /28   /29   /30   /31    /32 |
```

![image](https://github.com/ruppertaj/WOBC/assets/93789685/e47f5838-9122-417a-867b-f136b60094dc)


References:

https://www.iana.org/numbers
https://www.iana.org/assignments/multicast-addresses/multicast-addresses.xhtml
https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing
https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing#IPv4_CIDR_blocks
https://en.wikipedia.org/wiki/Multicast_address
https://packetlife.net/media/library/15/IPv4_Subnetting.pdf
https://en.wikipedia.org/wiki/Classful_network


#### 2.1.1.2 Analyze IPv4 packet header
Analyze IPv4 packet header

![image](https://github.com/ruppertaj/WOBC/assets/93789685/89e9a394-4452-45cc-8f23-c6fb33f5233b)
IPv4 Header

![image](https://github.com/ruppertaj/WOBC/assets/93789685/bbb38800-23da-4507-af72-01c602a2b844)
IPv4 Structure


* Byte 0:

    * Version (High 4 bits): Indicates the version of the Internet Protocol used. For IPv4, the value is set to 4 or 0x40.

    * Header Length (IHL) (Low 4 bits): Specifies the length of the IPv4 header in 32-bit words.

        * The standard IHL is 5 (0x05) to indiate 5 WORDS (20 bytes) in the IP header.

        * Since the IPv4 header length can vary due to optional fields, this field helps identify where the data payload begins.

        * IHL from 6 to F (15) will indicate the presence of IPv4 options in multiples of 4 bytes.

* Byte 1:

    * Type of Service (TOS) (8 bits): From origional [RFC 791](https://datatracker.ietf.org/doc/html/rfc791), it was used for Quality of Service (QoS) prioritization. In [RFC 2474](https://datatracker.ietf.org/doc/html/rfc2474), this field was deprecated and replaced by Differentiated Services Code Point (DSCP) and Explicit Congestion Notification (ECN) fields in modern implementations.

        * DSCP (High 6 bits): Used to provide differentiated Quality of Service (QoS) treatment to packets as they traverse a network. It allows network administrators to prioritize certain types of traffic over others based on their requirements for latency, jitter, bandwidth, and reliability.

            * The DSCP field allows for 64 different values, ranging from 0 to 63 ([RFC 4594](https://datatracker.ietf.org/doc/html/rfc4594)). Use the [DSCP chart](http://www.patrickdenis.biz/blog/ip-precedence-dscp-tos-lookup-table/) to determine values.

            * These values are organized into several predefined classes, each representing a different level of service or treatment for packets.

            * Values in this field do not equate to decimal or hex. In actuality the values in this field are bit-shifted 2 places to the left (<<2). This means that a DSCP of (1) would be a (4) in decimal. A DSCP of (32) would be a (128) in decimal.

        * ECN (Low 2 bits): An extension to the Internet Protocol (IP) that enables end-to-end notification of network congestion without dropping packets. It allows network devices, such as routers, to notify endpoints (senders and receivers) of impending congestion in the network, allowing them to respond appropriately.

            * 00 – Not ECN-Capable - codepoint indicates that the packet’s sender is not ECN-capable or does not wish to receive ECN notifications.

            * 01 and 10 – ECN Capable - codepoint indicates that the packet’s sender is ECN-capable and willing to receive congestion notifications.

            * 11 – Congestion Experienced - codepoint is set by routers to indicate that congestion has been encountered along the packet’s path.

DSCP

32

16

8

4

2

1

2

1

HEX

8

4

2

1

8

4

2

1

DEC

128

64

32

16

8

4

2

1

* Bytes 2 and 3:

    * Total Length (16 bits): Indicates the total length of the IPv4 packet, including the header and the data payload. The maximum value is 65,535 bytes.

    * This field is largely controled by the Maximum Transmission Unit (MTU) for the connected network.

* Bytes 4 and 5:

    * Identification (16 bits): Used for fragmentation and reassembly of IP packets. Each packet sent by the sender is assigned a unique identification value.

        * The IP ID field is used to assign a unique identification value to each IPv4 packet sent by a host.

        * This identification value is incremented for each subsequent packet sent by the host.

        * The combination of the IP ID value and the source IP address uniquely identifies each packet, which helps in identifying and processing packets at the receiving end.

        * This allows the receiving host to identify fragments belonging to the same original packet and reassemble them in the correct order.

* Bytes 6 and 7:

    * Flags (High 3 bits): Contains control flags related to fragmentation:

        * Bit 0: Reserved, must be zero. This bit is sometimes referred to as the "Evil Bit" as defined in [RFC 3514](https://net.cybbh.io/public/networking/latest/02_network/fg.html).

        * Bit 1: Don’t Fragment (DF) flag. If set, indicates that the packet should not be fragmented.

            * Packets requiring fragmentation will be dropped by the router and an ICMP type 3 code 4 "Fragmentation Needed and Don’t Fragment was Set" will be sent back to the sender.

        * Bit 2: More Fragments (MF) flag. If set, indicates that this packet is a fragement and that more fragments will follow. This flag will be turned off for the very last fragment.

    * Fragment Offset (Low 13 bits): Indicates the position of the fragment within the original unfragmented packet, measured in units of 8 bytes.

        * The fragment offset is calculated by dividing the payload bytes by 8. This offset value is cumulative and is added to each fragment offset until the last fragement.

        * A payload of 1480 will have an offset of 1480/8 or 185. The offset values will be 0, 185, 370, 555, 740, etc.

* Byte 8:

    * Time to Live (TTL) (8 bits): Represents the maximum number of hops (routers) the packet can traverse before being discarded. Decremented by one at each router hop.

    * Default TTLs:

        * Linux: 64

        * Windows: 128

        * Cisco: 255

* Byte 9:

    * Protocol (8 bits): Specifies the protocol used in the data payload of the packet (e.g., TCP, UDP, ICMP).

        * ICMPv4: 1

        * TCP: 6

        * UDP: 17

        * EIGRP: 88

        * OSPF: 89

* Bytes 10 and 11:

    * Header Checksum (16 bits): Provides error detection for the IPv4 header. Calculated based on the header contents and verified by the receiving host.

* Bytes 12 to 15:

    * Source IP Address (32 bits): Specifies the IPv4 address of the sender of the packet.

        * Dotted decimal address are expresses as HEX.

        * 10.0.0.1 would be 0x0a000001

* Bytes 16 to 19:

    * Destination IP Address (32 bits): Specifies the IPv4 address of the intended recipient of the packet.

        * Dotted decimal address are expresses as HEX.

        * 192.168.0.1 would be 0xc0a80001

* Variable bytes from 20 to 59:

    * Options (variable length):

        * Always in multiples of 4 bytes (1 WORD).

        * Maximum options allowed is 40 bytes (10 WORDs).

        * Optional fields that may include various options such as Record Route, Timestamp, and Security.

        * Rarely used in practice due to limited support and potential security concerns.



Decoding an IPv4 Packet:

* IPv4 packets will have the label of 0x0800 in the Ethertype field of the Ethernet Header.
```
00 1f 29 5e 4d 26 00 50　56 bb 3a a0 08 00 45 00
00 3c 83 1b 40 00 40 06　15 0a c0 a8 14 46 4a 7d
83 1b d5 1d 00 19 6b 7f　c7 2d 00 00 00 00 a0 02
72 10 a2 b5 00 00 02 04　05 b4 04 02 08 0a 0a 99
44 36 00 00 00 00 01 03　03 07
```

    * `00 1f 29 5e 4d 26` is the destination MAC

    * `00 50 56 bb 3a a0` is the source MAC

    * `08 00` is the ethertype for IPv4

    * `45` to identify the Version is 4 and the IHL is 5 which means the IP header is 20 bytes in length. (IHL x 4)

    * `00` is the DSCP. Used for Quality of Service (QoS).

    * `00 3c` is the Total length of 60 bytes. This includes the 20 byte header and 40 bytes of payload.

    * `83 1b` is the Identification field. Value is 33563.

    * `40 00` is the Flags and fragmentation offset field. This value has the Dont Fragement (DF) turned on and no fragmentation offset.

        * `80 00` is the value for the Reserved (Evil bit).

        * `20 00` to `3F FF` is the range for the More Fragements (MF) bit and fragmentation offset.

    * `40` is the Time to Live field. Currently set to 64.

    * `06` is the Protocol field. Currently set to identify TCP.

        * `01` is for ICMPv4

        * `11` is for UDP

    * `15 0a` is the Checksum field

    * `c0 a8 14 46` is the source IP address. Currently set to 192.168.20.70.

    * `4a 7d 83 1b` is the destination IP address. Currently set to 74.125.131.27.

    * The remaining will be the payload.



DEMO of IPv4 header from Wireshark. Capture any traffic to show IP header.


![image](https://github.com/ruppertaj/WOBC/assets/93789685/bd7f10a7-8b85-4561-966c-d46b967fa200)
IPv4 Structure DEMO


* Options Field The options field is seldom used. Typically (without options) the IHL will only equal 5. If options are used then the header length will be greater than 5 (i.e. from 6 to 15). This means that options field is present and must be considered.

    * Strict source routing option is where every hop of the traffic is pre-decided and is placed in the IPv4 Options field. Routers must use the information in this field over any routing table information they may have. This can potentially be used to forward packets around security devices such as firewalls and IPS.

    * Loose Source Routing option is a bit more flexible than strict source routing. It will include a list of various hops that the packet must traverse. But this does not specify each and every hop.

    * Both of these options can create security concerns and is recommended that routers block packets containing these options unless they are essential for the network operation.

* Anomalous traffic The Internet Header Length (IHL) field can indicate whether IP Options have been enabled; options are seldom used so in the case where options are on without a clear indication or reason, this would cause concern. The fragment field is also something to take note of, overlapping fragments are a known way that malicious actors have looked to obfuscate information to get past firewalls or IPS/IDS. Fragment re-assembly is subject to the method a particular OS uses and therefore overlapping fragments may yield different payloads based on how the fragments are re-assembled and what parts are over-written in that process.



References:

https://en.wikipedia.org/wiki/Internet_Protocol_Options

http://www.patrickdenis.biz/blog/ip-precedence-dscp-tos-lookup-table/


#### 2.1.1.3 Identify IPv4 address types and scopes
* IPv4 address types:

    * Unicast IPs are a "one to one" communication between two nodes.

        * A unicast address will fall within a Class A, B, or C address range. Any address not reserved can be used to assign to a host.

        * Unicast can be done using either ICMP at the network layer or using TCP/UDP at the transport layer.

    * Multicast IPs are used for a "one to many" communications concept throughout a network. Multicast addresses are used by routing protocols, video streaming, and other various systems that have need to communication in a group. These addresses fall within the Class D address range.

        * Range 224.0.0.0/4 - 224.0.0.0 thru 239.255.255.255

        * Multicast can only be done by using a network layer protocol or UDP at the transport layer.

        * Reserved Multicast addresses:

            * 224.0.0.0 - 224.0.0.255 (224.0.0.0/24):

                * Reserved for local network control block. Used for protocols related to network configuration, maintenance, and management, such as OSPF (Open Shortest Path First) routing protocol.

            * 224.0.1.0/24 (224.0.1.0 - 224.0.1.255): Internetwork Control Block. Reserved for network services discovery. Used by protocols such as Cisco’s Hot Standby Router Protocol (HSRP) for discovering active routers.

            * 224.0.2.0/24 (224.0.2.0 - 224.0.2.255): Network Time Protocol (NTP) multicast group. Used for time synchronization.

            * 224.0.4.0/24 (224.0.4.0 - 224.0.4.255): Multicast DNS (mDNS). Used for local service discovery and resolution.

            * 224.0.5.0/24 (224.0.5.0 - 224.0.5.255): Reserved for Internet Group Management Protocol (IGMP) version 3.

            * 224.0.6.0/24 (224.0.6.0 - 224.0.6.255): Reserved for SDP (Session Description Protocol).

            * 224.0.7.0/24 (224.0.7.0 - 224.0.7.255): Reserved for SAP (Session Announcement Protocol).

            * 224.0.18.0/24 (224.0.18.0 - 224.0.18.255): Reserved for TRILL (Transparent Interconnection of Lots of Links) protocol.

            * 224.0.22.0/24 (224.0.22.0 - 224.0.22.255): Reserved for Precision Time Protocol (PTP) version 2.

            * 232.0.0.0/8 (excluding 232.0.0.0 - 232.255.255.255):

                * Reserved for source-specific multicast (SSM). SSM is a variant of multicast communication where receivers specify both the desired multicast group and the source from which they wish to receive the multicast traffic.

            * 239.0.0.0 - 239.255.255.255 (239.0.0.0/8):

                * Reserved for administratively scoped multicast addresses. These addresses are used for local or private multicast communication within a specific administrative domain and are not intended to be forwarded beyond that domain.

    * Broadcast A broadcast address is the last IP in every network subnet range. It is used to communicate to all nodes on the same network.

        * These are identified when all the "host bits" are turned on (all one’s).

        * For example: 192.168.0.255/24 is a directed broadcast address for the 192.168.0.0/24 network.

            * Directed broadcasts can be used for various purposes, such as:

                * Network management: Sending management or configuration commands to all devices within a specific subnet.

                * Wake-on-LAN (WoL): Waking up or powering on devices remotely by sending a directed broadcast packet containing a Wake-on-LAN magic packet.

                * Service discovery: Discovering services or devices within a local network segment.

        * Limited Broadcast using the 255.255.255.255 address.

            * Unlike directed broadcasts, which are targeted to a specific subnet, the limited broadcast address is used to send packets to all hosts on the local network, regardless of their subnet.

            * Here are some key points about the 255.255.255.255 broadcast address:

                * Local network scope: Packets sent to 255.255.255.255 are not forwarded by routers. They are only delivered to hosts within the same local network segment or subnet as the sender.

                * One-to-all communication: When a host sends a packet to this address, it is effectively sending it to all hosts on the local network. This makes it useful for scenarios where a host needs to communicate with all other hosts on the same network segment.

                * Broadcast domain: The limited broadcast address operates within the broadcast domain of a network. Devices within the same broadcast domain receive broadcasts sent to 255.255.255.255.

                * Broadcast storm risk: Since the limited broadcast address sends packets to all hosts on the local network, it can potentially cause a broadcast storm if not used judiciously. A broadcast storm occurs when there is a high volume of broadcast traffic on the network, which can degrade network performance or even cause network outages.

                * Use cases: Limited broadcast is often used for tasks like DHCP (Dynamic Host Configuration Protocol) address assignment, network discovery, or service advertisement within a local network.

        * Broadcast can only be done by using certain network layer protocols or UDP at the transport layer.



* IPv4 address scopes:

    * Public IP ranges are assigned by IANA throughout the world. These addresses are typically any Class A, B, or C address that is not otherwised reserved. For more information on public addressing visit https://www.iana.org/numbers.

    * Private These IPs are not globally routable across the Internet and are available for use by all for internal LANs. These addresses must be translated to a public address for traversal across the internet.

        * Class A scope 10.0.0.0/8 - 10.0.0.0 thru 10.255.255.255

        * Class B scope 172.16.0.0/12 - 172.16.0.0 thru 172.31.255.255

        * Class C scope 192.168.0.0/16 - 192.168.0.0 thru 192.168.255.255

    * Loopback address also called localhost. This is an internal address (127.0.0.1) linked back to the host machine. Can not be assigned to a device NIC. Can only be used to allow the system to address itself.

        * Scope 127.0.0.0/8 - 127.0.0.0 thru 127.255.255.255

    * Link-Local is used for direct node to node communications on the same physical or logical link, not a routable range. This range is used fo    * r Microsoft’s Automatic Private IP Addressing (APIPA). This is used to allow DHCP configured clients to resolve an IP address even if no DHCP servers are available. Systems will auto generate an address in this range if it fails to get an IP address from the DHCP server. These addresses allow devices to communicate with each other on the same network but not across any routed boundries.

Scope 169.254.0.0/16 - 169.254.0.0 thru 169.254.255.255

    * Multicast

        * 224.0.0.0/24 - Link-Local - multicast for host on the same network segment. Cannot traverse routed bounderies.

        * 239.255.0.0/16 - Local - scope is able to be controlled by an organization.

        * 239.192.0.0/14 - Organizational-local - routable within an organizations network.

        * 224.0.1.0-238.255.255.255 - Global - able to be routed across the internet.



References:

https://datatracker.ietf.org/doc/html/rfc1918
https://www.iana.org/numbers
https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml



Instructor Note
There are various other types of special IP assignments listed on the IANA website. The ones listed above are most commonly seen.



#### 2.1.1.4 Explain Fragmentation with it’s vulnerability
* IPv4 Fragmentation

* IP fragmentation breaks up a single IPv4 packet into multiple smaller packets. Every link in a network has a defined maximum transmission unit (MTU). Ethernet’s default MTU is 1500 bytes. An IP header is included in the 1500 byte MTU.

* The 14-22 byte Ethernet header is not counted within the 1500 byte MTU. Other Layer 2 framing protocols (Ethernet, Token Ring, FDDI, PPoE, etc) can have different MTUs.

* Routers are often the devices performing fragmentation in IPv4. Other devices can perform this action if they also perform in the routing capacity.

* In IPv4, routing devices perform fragmentation if the total size of the packet (header and data) coming from one network interface is greater than the MTU of the network out the exiting interface.

* IPv4 Flags: [IPv4 header byte offset 6], A 3 bit field that declares if the packet is a part of a fragmented data frame or not. Reading the field from left to right.

    * Bit 0 (128): reserved

        * should always be 0

        * See RFC 3514 for a description of the “evil bit.”

    * Bit 1 (64):

        * 0 = May Fragment

        * 1 = Don’t Fragment this packet

            * Packets requiring fragmentation with this bit set will be dropped by routers resulting an ICMP Type 3 Code 4 "Fragmentation Needed and Don’t Fragment was Set" message to be sent back to the source.

    * Bit 2 (32):

        * 0 = Not fragemented or Last Fragment

            * Last fragment will have an offset value set.

        * 1 = More Fragments follow (first fragement until 2nd to last fragement).

            * First fragment will not have an offset value set.

* Fragment Offset field is a 13-bit field found in the IPv4 header.

    * It indicates the position of the data payload of the current fragment relative to the beginning of the original unfragmented packet.

    * With only 13 bits assigned, the values can only be 0-8191.

        * The values in this field is determined by dividing the fragmented bytes per packet by 8.

    * It is determined by using the following formula:

        * **Offset = (MTU - (IHL x 4)) ÷ 8**

        * Value must divide evenly.

        * Decreases the MTU to ensure even division.

        * The fragment offset is calculated by dividing the payload bytes by 8. This offset value is cumulative and is added to each fragment offset until the last fragement.

        * A payload of 1480 will have an offset of 1480/8 or 185. The offset values will be 0, 185, 370, 555, 740, etc.


![image](https://github.com/ruppertaj/WOBC/assets/93789685/00333e4d-49da-4db5-9a01-6910d9e20afa)
IPv4 Fragmentation


* IPv6 Fragmentation

    * IPv6 inherently does not support fragmentation within it headers. It lacks the fields required. It can however include follow-on IPv6 Fragmentation headers should it be needed. IPv6 fragmentation must be done on the sending host using the fragmentation extension headers.

    * Routers in the traffic path will not fragment any IPv6 packets. Any packets larger than the supported MTU are dropped and an ICMPv6 Type 2 "packet too big" message is sent to the source. This is essentially like having the DF bit set to ON for all packets. Any needed fragmentation must be done by the source node.

    * The source node conducts a Path MTU Discovery (PMTU) by sending MTU discovery packets to the destination. If the source node receives a Type 2 "packet too big" message it will decrease the packet size. The smallest (generally) safe IPv6 MTU size is 1280 bytes. This guarantees delivery based on packet size but increases the number of packets needing to be sent. Even more if VPN or tunneling is used.

    * Fragmentation was removed in IPv6 for several reasons. Some thought fragmentation was inefficient. Any lost fragment makes the entire original packet unusable as there is no way to identify the missing fragment to be resent. Additionally security concerns of fragmentation overlapping attacks and the lack of a TCP/UDP header on fragment except the initial fragment were other reasons to remove fragmentation altogether.



DEMO using wireshark of the fragmentation process. Send a ping 10.2.0.2 -s 15000 -c 1 and capture the results.

[ICMP Fragmented pcap from www.Cloudshark.org](https://www.cloudshark.org/captures/004070781efd)



* IP Fragment Overlapping

    * IP fragment overlapping exploit happens when two or more packet fragments have fragment offsets that indicate that they overlap each other.

    * Example: a MTU of 1500 will have a offset of 185. 1500 MTU - 20 Bytes of IP header = 1480 Bytes. Each IP packet will include up to 1480 bytes of fragment information. To determine the offset value, this will be divided by 8 and will equal 185. So the first fragment will have the MF=1 and offset =185. The second fragment will increment the offset by 185 each time. So the second fragment offset will be 185, the third will be 370, the fourth 555, the fifth is 740 and so fourth. Each packet will have 1480 bytes of data.

    * In an overlap attack such as the teardrop attack, the offsets will not be sequential in chunks of 185 as it should. The offset could be changed to something like 175. This would mean that 80 bytes of the first fragment will be overwritten by the second fragment and so fourth. The resulting information will be much different than if each packet was examined individually.

    * This form of attack is successful if the attacker is aware of the host computers and networking equipment on the victim’s network. This is because different equipment types perform different process in order to reconstruct the fragmented packets. Armed with this knowledge, the attacker can craft his attack to reconstruct the fragmented packets in a more proprietary way to avoid detection. Using this process fragments can avoid detection by firewalls and IDS/IPS devices. This is because when they reconstruct the message using their reconstruction processes it will not see the intended information.

* Teardrop Attack

    * In a Teardrop attack, the attacker will use overlapping packets as well as additional random data. When constructed properly, the random data portions will be overwritten and result in the malicious payload. Although firewalls and IDS/IPS devices may not detect this payload.

    * This is a form of denial-of-service (DoS) attack that uses fragmented packets to bypass firewalls to a target a victim’s machine. The victim’s computer receiving the packets won’t be able reconstruct the packet properly due to a bug in TCP/IP fragmentation reassembly process, the packets will overlap each another, thus crashing the victim’s network device. Typically only older operating systems such as Windows 3.1x, Windows 95, Windows NT and versions of the Linux kernel prior to 2.1.63 are vulnerable to this attack.

[Teardrop pcap from wiki.wireshark.org](https://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=get&target=teardrop.cap)



References:

https://en.wikipedia.org/wiki/IPv4#Fragmentation_and_reassembly
https://www.cloudshark.org/captures/004070781efd
https://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=get&target=teardrop.cap
https://www.ietf.org/rfc/rfc3514.txt


#### 2.1.1.5 Explain OS Fingerprinting with TTL
OS fingerprinting is the process of analyze the TTL fields on a header packet to make an educated guess at which operating system sent the packet by your TTL maximum hops. Different systems can have varing TTLs that can help to identify them on the network, some of the systems are listed in the chart.

This will be covered more indepth in Lesson 6 Network Analysis.



![image](https://github.com/ruppertaj/WOBC/assets/93789685/f847e1ad-ee72-407a-b6ea-9771dd8f8781)
Figure 1. TTL Analysis


* Unless you capture the packet immediately from the source host, the TTL will not likely be set to these values.

* In general, it should not take more than about 30 hops to reach any destination on the internet.

* With this in mind we can make the following determination:

    * Linux: TTL from 34-64

    * Windows: TTL from 98-128
 
    * Cisco: TTL from 225-255



References:

https://en.wikipedia.org/wiki/TCP/IP_stack_fingerprinting


#### 2.1.1.6 Explain IPv4 Auto Configuration with vulnerability
IPv4 auto-configuration refers to the process by which IPv4 addresses are automatically assigned to devices without manual intervention.

* APIPA

    * Automatic Private IP Addressing (APIPA) is the automatic configuration of an ip address to a host machine and selects an address using a pseudo-random number generator with a uniform distribution in the range from 169.254.1.0 to 169.254.254.255.

    * The first 256 and last 256 addresses in the 169.254/16 prefix are reserved for future use and MUST NOT be selected by a host using this dynamic configuration mechanism.

    * When a host machine is set for Dynamic Host Configuration Protocol (DHCP) and is unable to locate a DHCP server, an APIPA address is given to the machine to allow it to communicate via Link-Local to other machines on the same physical or logical link.

* DHCP

    * Dynamic Host Control Protocol (DHCP) when configured on a host machine will send a broadcast DHCPDISCOVER message to and availible DHCP servers.

    * DHCP D.O.R.A process

        * DHCP D iscover:

            * When a device (client) connects to a network and needs to obtain an IP address, it sends out a DHCP Discover message to discover DHCP servers on the network.

            * The DHCP Discover message is broadcasted as a DHCP broadcast packet, typically using the destination IP address 255.255.255.255 and the destination MAC address ff:ff:ff:ff:ff:ff.

        * DHCP O ffer:

            * DHCP servers on the network that receive the DHCP Discover message respond with a DHCP Offer message.

            * The DHCP Offer message contains an available IP address and other network configuration parameters (such as subnet mask, default gateway, DNS server addresses) that the DHCP server is offering to the client.

            * The DHCP Offer message is typically sent as a unicast packet to the client’s MAC address.

        * DHCP R equest:

            * Upon receiving one or more DHCP Offer messages, the client selects one DHCP server and sends a DHCP Request message to that server.

            * The DHCP Request message includes the IP address offered by the selected DHCP server.

            * If the client receives multiple DHCP Offer messages, it may send DHCP Request messages to multiple servers, but it will ultimately accept only one offer.

        * DHCP A cknowledge (ACK):

            * The DHCP server that receives the DHCP Request message verifies the requested IP address’s availability and reserves it for the client.

            * The DHCP server sends a DHCP Acknowledge (ACK) message to the client, confirming the IP address assignment and providing additional configuration parameters.

            * The DHCP Acknowledge message is sent as a unicast packet to the client’s MAC address.

DEMO of [Cloudshark DHCP process](https://www.cloudshark.org/captures/c109b95db0af)

* Vulnerability

    * These processes do work as long as there are IPs available to be assigned, a legitimate DHCP server available, or trust of others hosts on the Link-Local. The vulnerability in that there is no verification or authorization being performed by default. These default auto configurations could allow an attacker to gain access into your network, assign out false IPs, and/or perform a denial/starvation attack.

    * Rogue DHCP servers are very common and easy to setup. A malicious person can setup a Rougue DHCP server to assign addresses for a particular network. In these configurations the attacker can assign whatever they want for the Gateway, DNS suffix and DNS server addresses. A malicious DNS server can result in legitimate Domain names being resolved to IP addresses of fake websites used to steal credentials or deploy malware.

    * DHCP Starvation attack. When a malicious user has to compete with the legitimate DHCP server for address assignments, the attacker can flood the DHCP server with several bogus DHCP requests in order to exaust its pool of addresses. Once this is done the rougue DHCP server is the only DHCP server with addresses to assign.

    * DHCP Security Considerations [RFC2131 Section 7](https://datatracker.ietf.org/doc/html/rfc2131#section-7)

    * Link-Local Security Considerations [RFC3927 Section 5](https://datatracker.ietf.org/doc/html/rfc3927#section-5)



References:

https://www.cloudshark.org/captures/c109b95db0af
https://datatracker.ietf.org/doc/html/rfc2131
https://www.ietf.org/rfc/rfc3927.txt


#### 2.1.1.7 Analyze ICMPv4 protocol and header structure
![image](https://github.com/ruppertaj/WOBC/assets/93789685/de5805fa-317e-47bc-b63d-fb1b77b1e096)
ICMP_Header


![image](https://github.com/ruppertaj/WOBC/assets/93789685/c07a96b5-c6cb-42ac-85d0-dda624e5d7d6)
ICMP_Header2


ICMPv4

* ICMP is used to provide feedback about network problems that may or do prevent packet delivery. This protocol was designed to provide error reporting, flow control and first-hop gateway redirection. While IP and UDP are unreliable, it is still important to have a way to notify the sender if something goes wrong in a transmission. TCP is able to realize and react when packets aren’t being delivered, but ICMP provides a method for discovering more serious problems like "TTL exceeded" or "need more fragments."

* Echo Request (Type 8):

    * Sent by a device to request an Echo Reply from another device.

    * Often used by the "ping" utility to test network connectivity and measure round-trip time.

    * Depending on the operating system Echo Requests (PING) can have different packet sizes and default payloads.

        * Linux:

            * Default size: 64 bytes (16 byte ICMP header + 48 byte payload)

            * Payload message: !\”#\$%&\‘()*+,-./01234567

        * Windows:

            * Default size: 48 bytes (16 byte ICMP header + 32 byte payload)

            * Payload message: abcdefghijklmnopqrstuvwabcdefghi

* Echo Reply (Type 0):

    * Sent by a device in response to an Echo Request.

    * Contains the same payload as the original Echo Request and is used to confirm network connectivity.

* Destination Unreachable (Type 3):

    * Destination Network Unreachable (Code 0):

        * Indicates that the network hosting the destination address is unreachable.

        * This can occur if there is no route to the destination network in the routing table.

    * Destination Host Unreachable (Code 1):

        * Indicates that the specific destination host is unreachable.

        * This can occur if there is no route to the destination host in the routing table or if the destination host is down.

    * Destination Protocol Unreachable (Code 2):

        * Indicates that the transport protocol specified in the packet’s header is not supported by the destination.

        * For example, if a UDP packet is sent to a destination that does not have a process listening on the specified UDP port, this error may be generated.

    * Destination Port Unreachable (Code 3):

        * Indicates that the specified port on the destination host is unreachable.

        * This typically occurs when there is no process listening on the specified port or if a firewall is blocking access to the port.

    * Fragmentation Needed and Don’t Fragment was Set (Code 4):

        * Indicates that the packet is too large to be transmitted without fragmentation, but the Don’t Fragment (DF) flag is set in the packet’s header.

        * This error is generated to inform the sender that the packet needs to be fragmented to be transmitted successfully.

    * Source Route Failed (Code 5):

        * Indicates that the source route specified in the packet’s header is invalid.

        * Source routing allows the sender to specify the route that the packet should take through the network, but if the specified route is invalid, this error may be generated.

    * Destination Network Unknown (Code 6):

        * Indicates that the destination network is unknown.

        * This error typically occurs when the destination network is not listed in the routing table.

    * Destination Host Unknown (Code 7):

        * Indicates that the destination host is unknown.

        * This error typically occurs when the destination IP address is not reachable or is not assigned to any host.

    * Source Host Isolated (Code 8):

        * Indicates that communication with the source host is administratively prohibited.

        * This error is generated by a router or firewall to indicate that the source host is isolated or not allowed to communicate with the destination.

    * Communication with Destination Network Administratively Prohibited (Code 9):

        * Indicates that communication with the destination network is administratively prohibited.

        * This error typically occurs when access to the destination network is restricted by network policies or firewall rules.

    * Communication with Destination Host Administratively Prohibited (Code 10):

        * Indicates that communication with the destination host is administratively prohibited.

        * This error typically occurs when access to the destination host is restricted by network policies or firewall rules.

    * Network Unreachable for Type of Service (Code 11):

        * Indicates that the network is unreachable for the specified type of service.

        * This typically occurs when the network does not support the requested type of service or quality of service.

    * Host Unreachable for Type of Service (Code 12):

        * Indicates that the destination host is unreachable for the specified type of service.

        * This typically occurs when the destination host does not support the requested type of service or quality of service.

    * Communication Administratively Prohibited (Code 13):

        * Indicates that communication with the destination is administratively prohibited.

        * This can occur due to network policies or firewall rules that explicitly block communication with the destination.

* Redirect (Type 5):

    * Used by routers to inform hosts of a better route to a particular destination.

    * Informs the host to update its routing table with the new route information.

        * Redirect Datagram for the Network (Code 0): This code indicates that the router has a better route to the destination network and is redirecting the packet to the sender’s specified gateway. It instructs the sender to update its routing table with the new gateway information.

        * Redirect Datagram for the Host (Code 1): This code indicates that the router has a better route to the destination host and is redirecting the packet to the sender’s specified gateway. It instructs the sender to update its routing table with the new gateway information.

        * Redirect Datagram for the Type of Service and Network (Code 2): This code is similar to Code 0 but also includes a Type of Service (ToS) component. It indicates that the router has a better route to the destination network with a specific Type of Service and is redirecting the packet accordingly.

        * Redirect Datagram for the Type of Service and Host (Code 3): This code is similar to Code 1 but also includes a Type of Service (ToS) component. It indicates that the router has a better route to the destination host with a specific Type of Service and is redirecting the packet accordingly.

* Time Exceeded (Type 11):

    * Indicates that a packet’s Time-to-Live (TTL) value has reached zero or that the packet’s hop limit has been exceeded.

    * Subtypes of Time Exceeded include:

        * Time to Live Exceeded in Transit (Code 0): Indicates that the TTL of the packet expired while in transit.

        * Fragment Reassembly Time Exceeded (Code 1): Indicates that the time allowed for reassembly of fragments has expired.

* Timestamp Request (Type 13):

    * Sent by a device to request a Timestamp Reply from another device.

    * Used to measure round-trip time and clock synchronization between devices.

* Timestamp Reply (Type 14):

    * Sent by a device in response to a Timestamp Request.

    * Contains timestamps indicating the time the request was received and the time the reply was sent.



DEMO of the ping and traceroute with Wireshark to Google’s DNS server (8.8.8.8).
The Ping Request shows in the details plane the IP header field the TTL is 64 and the ICMP header is a Type: 8 (echo request)

![image](https://github.com/ruppertaj/WOBC/assets/93789685/fd34b243-d031-49c8-8d8d-78b3373b381b)
Ping Request


The Ping Reply shows in the details plane the IP header field the TTl is 113 and the ICMP header is a Type: 0 (echo reply)

![image](https://github.com/ruppertaj/WOBC/assets/93789685/578cc3ca-e782-4ec3-b315-6a65bdb839de)
Ping Reply


Traceroute

* Traceroute is a diagnostic tool used to trace the route taken by IP packets from a source device to a destination device in an IPv4 network.

* It works by attempting to send messages to a target IP by incrementing its TTL by 1 each time until it reaches the target IP or after 30 hops.

    * Windows by default uses ICMP Type 8 (Echo Request) as the carrier protocol.

    * Linux by default uses UDP as the carrier protocol.

* Starting with a TTL of 1, if it should recieve a ICMP Type 11 (Time exceeded) message then it knows to increase the TTL by +1.

    * Traceroute uses the IP address in the ICMP Time exceeded message in its result of each hop along the route.

    * Many router hops may have ICMP disabled which will result in no reponse.

        * Traceroute identifies this with an asterisk (*).

        * Traceroute will still continue by increasing the TTL by 1.

* It repeats the TTL +1 process until it reaches a TTL of 30 or if it gets a response from the target IP.

* The captured IP’s of the router hops that responded with a ICMP Time exceeded are added to the chart as hops along the route to the target IP.

![image](https://github.com/ruppertaj/WOBC/assets/93789685/821282e4-88d0-4a49-a2b0-a14dd7417bc5)
Traceroute

* The Traceroute shows in the details plane the IP header field has a source IP of where the TTL was exceeded. In the ICMP header a Type: 11 (Time-to-live exceeded) Code: 0 (Time to live exceeded in transit) error code. Also note that the following fields contains the original request packet information with the time exceeded error (TTL=1).



Common ICMP attacks

* Fire-walking - Using traceroute and TTLs to map out a network. Using traceroute with TCP and UDP protocols an attacker could map the open ports on a firewall.

    * DEMO Firewalking

        * When performing traceroute. Linux will use UDP as its default. Windows will use ICMP Echo Requests as its default. Linux will require sudo when specifying any traceroute other than the default.
```
traceroute 8.8.8.8
```

        * Using traceroute with TCP. This will use TCP port 80 as the default.
```
sudo traceroute 8.8.8.8 -T
```

        * Using traceroute with TCP and a different port.
```
sudo traceroute 8.8.8.8 -T -p 443
```

        * Using traceroute with UDP and a different port.
```
sudo traceroute 8.8.8.8 -U -p 123
```

        * Using traceroute with ICMP (Windows Default)
```
sudo traceroute 8.8.8.8 -I
```

* Over-sized ICMP informational messages - These over-sized ICMP packets can cause a system to crash. Typically packets should not be greater than 65,535 bytes in size and anything greater would violate [RFC 791](https://tools.ietf.org/html/rfc791). Systems would not know how to process these packets and most likely would crash. The Ping-of-Death is one example of this. Attackers could use tools like hping2 to craft these packets.

* ICMP redirects: - Routers use ICMP redirect messages to inform hosts that a better route is available for a particular destination is available through another router on the same network. Hosts can only be assigned one IP address as its default gateway but the network could have more than one router to lead to remote networks. If the default gateway receives a packet on an interface, and through its routing table lookup it determines that the next hop router towards that network is out the same interface that the packet was received, it will forward the packet to the next hop and send the ICMP redirect message back to the host. The host will update its internal routing tables for that specific destination address.

    * An attacker can use ICMP redirects to perform a Layer 3 man-in-the-middle attack. If the attacker can intercept a message they can send an ICMP redirect back to the victim to tell it to route traffic through the attacker rather than the router.

    * Note: ICMP redirects are disabled by default if Hot Standby Router Protocol (HSRP) is configured on the interface.

* SMURF Attack: - SMURF attack is a form of amplification attack where an attacker can send very few packets and it will generate a lot of packets. The attack works by sending an ICMP echo request (PING) using a spoofed source address to a directed broadcast address of a network. This PING will reach all hosts on the network who will then respond to the spoofed IP address. All the hosts responding will create a lot of traffic and overload the victim’s device causing a DoS.

* IP unreachable messages to map a network - By default, routers will send an ICMP unreachable message back to the source if it drops a packet for whatever reason. This action can be used by attackers to map out the network topology.

* ICMP Covert Channel - Many networks allow ICMP traffic in and out of their networks. Malicious actors can disguise communication channels as ICMP traffic. This traffic will have typical ICMP headers but the payload will greatly vary depending on the type of traffic encapsulated.



References:

https://en.wikiversity.org/wiki/Wireshark/ICMP_Time_Exceeded
https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol
https://www.sans.org/reading-room/whitepapers/threats/icmp-attacks-illustrated-477
http://blog.alan-kelly.ie/blog/payload_comparsion/
https://tools.ietf.org/html/rfc791
https://www.exploit-db.com/docs/english/18581-covert-channel-over-icmp.pdf


### 2.1.2 Explain IPv6 Addressing
* IPv6 (Internet Protocol version 6) is the most recent version of the Internet Protocol, designed to succeed IPv4. IPv6 addresses are used to uniquely identify and locate devices on a network. IPv6 was introduced to address the limitations of IPv4, primarily the exhaustion of available IPv4 addresses due to the rapid growth of the internet.

* IPv6 addresses are 128 bits long, compared to the 32-bit addresses used in IPv4. This significantly expands the address space, allowing for a virtually unlimited number of unique addresses. The IPv6 address format is expressed as eight groups of four hexadecimal digits, separated by colons.

    * Hexadecimal Representation: IPv6 uses hexadecimal digits (0-9 and A-F) in groups of four, separated by colons. These groupings of 4 HEX are called "Hextets". This representation makes IPv6 addresses more concise than the dotted-decimal format used in IPv4.

    * Expanded Address Space: With 128 bits, IPv6 provides an enormous address space compared to the 32-bit address space of IPv4. The number of unique IPv6 addresses is approximately 2128, allowing for an abundance of unique addresses.

        * The 128-bit space if split into 2 64-bit parts called the Prefix and Interface ID.

        * In theory this grants the ability to create 264 of prefixs (Networks) with 264 of interface IDs (hosts) per network.

    * IPv6 Address Types: IPv6 defines different types of addresses, including unicast, multicast, and anycast addresses. Unicast addresses identify a single interface, multicast addresses represent a group of interfaces, and anycast addresses identify the nearest among a group of interfaces.

    * Global Unicast Addresses: Similar to public IPv4 addresses, global unicast IPv6 addresses are routable on the internet. They are assigned by Internet Assigned Numbers Authority (IANA) to Regional Internet Registries (RIRs), which then allocate them to Internet Service Providers (ISPs) and organizations.

    * Link-Local Addresses: Link-local addresses are used for communication on a single network segment (link). They are automatically configured by devices when no DHCP server is available, and they are not routable beyond the local network.

    * Unique Local Addresses: Unique local addresses are similar to IPv4 private addresses and are used for local communication within an organization. They are not routable on the global internet.

    * IPv6 Prefix Notation: IPv6 addresses often use a prefix notation to specify the network portion. For example, in the address 2001:0db8:85a3:0000:0000:8a2e:0370:7334, the prefix is 2001:0db8:85a3::/48, indicating the network portion.


#### 2.1.2.1 Describe IPv6 addressing and subnetting
* IPv6 addressing

    * In 2011 IPv6 was released to use world wide. IPv6 was released to eventually replace IPv4 because of IPv4’s lack of address space. Along with IPv6’s release the packet design was simplified from the IPv4 15 sections header IPv6 holds only 8 sections with less wasted fields.

    * IPv6 addresses are 128 bits in length and will support up to 340 undecillian addresses.

        * 64-bit Prefix (4 hextets) - Generally this is the network portion of the address.

            * Organizations asigned a 48-bit Prefix by IANA.

            * Last 16-bits of prefix is used for subnetting (allows upto 65,536 subnets).

        * 64-bit Interface ID (4 hextets) - Generally this is the host portion of the address.

            * Allows for 264 hosts or 18,446,744,073,709,551,616 (eighteen quintillion, four hundred forty-six quadrillion, seven hundred forty-four trillion, seventy-three billion, seven hundred nine million, five hundred fifty-one thousand, six hundred sixteen).

    * IPv6 addresses are typically represented as eight groups of hexadecimal digits separated by colons, such as 2001:0db8:85a3:0000:0000:8a2e:0370:7334.

    * Leading zeros within each group can be omitted, and consecutive groups of zeros can be abbreviated with a double colon (::), but the double colon can only be used once in an address to avoid ambiguity.

* Obstacles to transition:

    * Compatibility and Interoperability: During the transition period, both IPv4 and IPv6 networks need to coexist, requiring mechanisms for compatibility and interoperability. Dual-stack configurations, transition technologies, and network address translation (NAT) mechanisms are used to facilitate communication between IPv4 and IPv6 networks.

    * Legacy Infrastructure: Many existing networks, devices, and applications are built on IPv4 and may require significant updates or replacements to support IPv6. Legacy infrastructure poses a significant obstacle to IPv6 migration, especially for organizations with large and complex networks.

    * Cost and Investment: Transitioning to IPv6 often requires significant investments in equipment, software, training, and operational changes. For organizations with limited resources or competing priorities, the cost of migration can be a barrier.

    * Security Concerns: IPv6 introduces new security considerations and challenges, including the need for updated security policies, mechanisms, and tools. Organizations may be hesitant to adopt IPv6 due to concerns about potential security vulnerabilities and risks. Complexity of Deployment: Deploying IPv6 in large-scale networks or complex environments can be challenging due to the need for careful planning, coordination, and testing. Organizations may encounter technical issues, configuration errors, or unforeseen challenges during deployment.

    * Resistance to Change: Resistance to change or inertia within organizations can impede IPv6 adoption, especially in environments where IPv4 has been the standard for many years. Overcoming organizational resistance and fostering a culture of innovation and adaptation are essential for successful IPv6 migration.

[IPv6 adoption chart from Google](https://www.google.ca/intl/en/ipv6/statistics.html#tab=ipv6-adoption&tab=ipv6-adoption)

* IPv6 Subnetting

![image](https://github.com/ruppertaj/WOBC/assets/93789685/f376c675-3a09-4d37-a27b-5a2078149ac4)
IPv6 Subnetting Example


* With IPv6 subnetting, a ISP is allocated a range of IPv6 addresses, which in turn assigns out to a company or organization a block or subnet for use. These allocations can vary in size for the Network ID and Subnet portions. In the example it shows a Network ID portion of 48 bits, or 12 hex digits, allocated for the network. The Subnet portion is allotted 16 bits, or 4 hex digits, for use in subnetting into smaller networks. The Network ID and the Subnet portions combined are known as the Prefix Length, represented in this example as a /64. The Host or Interface ID portion will be used for the actual assignment for the IPv6 address. This length is 64 bits or 16 hex digits long.

References:

https://www.google.ca/intl/en/ipv6/statistics.html#tab=ipv6-adoption&tab=ipv6-adoption
https://www.iana.org/assignments/ipv6-address-space/ipv6-address-space.xhtml
https://www.iana.org/assignments/ipv6-unicast-address-assignments/ipv6-unicast-address-assignments.xhtml
https://packetlife.net/blog/2008/jul/7/ipv6-cheat-sheet/


#### 2.1.2.2 Analyze IPv6 packet header

![image](https://github.com/ruppertaj/WOBC/assets/93789685/fd53de39-9afd-434f-8698-0eff29fb0171)
IPv6 Header

![image](https://github.com/ruppertaj/WOBC/assets/93789685/953cc4db-e77f-4967-b353-8f2b49476ffc)
IPv6 Header

![image](https://github.com/ruppertaj/WOBC/assets/93789685/6353f999-cd04-4a76-8ea3-ccef8aa8e321)
IPv6 Structure


* Version (4 bits): Indicates the version of the Internet Protocol being used. For IPv6, this field is set to 6.

* Traffic Class (8 bits): Combines the functions of the IPv4 Type of Service (ToS) and Differentiated Services Code Point (DSCP) fields.
 
    * Used for quality of service (QoS) and packet prioritization.

* Flow Label (20 bits): Used to label packets belonging to the same flow, allowing routers to apply specialized handling to those packets.

    * It allows routers and network devices to identify packets belonging to the same flow or traffic stream and apply consistent treatment, such as prioritization or routing policies.

* Payload Length (16 bits): Specifies the length of the IPv6 payload, including any extension headers, in octets (8-bit units).

* Next Header (8 bits): Indicates the type of the next header following the IPv6 header.

    * Comparable to the protocol field in the IPv4 header with alot of the same values.

    * If the value corresponds to an IPv6 extension header, the processing of the packet continues with the specified extension header.

    * If the value corresponds to an upper-layer protocol (such as TCP or UDP), the packet payload is handed over to that protocol for further processing.

        * TCP: 6

        * UDP: 17

        * ICMPv6: 58

        * EIGRP: 88

        * OSPF: 89

* Hop Limit (8 bits): Similar to the Time-to-Live (TTL) field in IPv4, specifies the maximum number of hops (routers) the packet can traverse before being discarded.

    * This field is comparable to the TTL field in the IPv4 Header.

    * Decremented by one by each router that forwards the packet.

* Source Address (128 bits): Specifies the IPv6 address of the packet’s source.

    * Address is expressed in HEX.

    * Examples:

        * fe80:0000:0000:0000:0000:0000:0000:1

        * 2001:0db8:85a3:0000:0000:8a2e:0370:7334

* Destination Address (128 bits): Specifies the IPv6 address of the packet’s intended destination.

    * Address is expressed in HEX.

    * Examples:

        * fd00:1234:5678:9abc:0000:0000:0000:1

        * ff02:0000:0000:0000:0000:0000:0000:1

        * 2001:0db8:85a3:0000:0000:8a2e:0370:7334

Decoding an IPv6 Packet:

* IPv6 packets will have the label of 0x86DD in the Ethertype field of the Ethernet Header.
```
38 c9 86 2d 92 61 00 e0　4c 36 1c 43 86 dd 60 04
82 45 00 10 3a 40 20 01　0d b8 00 01 00 00 00 00
00 00 00 00 00 01 20 01　0d b8 00 02 00 00 00 00
00 00 00 00 00 02 80 00　31 e7 21 c1 00 07 5c 98
25 e4 00 02 4e 0f
```
* `38 c9 86 2d 92 61` is the destination MAC address

* `00 e0 4c 36 1c 43` is the source MAC address

* `86 dd` is the Ethertype for IPv6

* `60 04 82 45` is the Version, Traffic Class, and Flow Label fields.

    * `6` is to identify the version is 6.

    * `0 0` is the Traffic class. Similar to the DSCP field in IPv4.

    * `4 82 45` is the Flow Label field. Used by IPv6 to tell routers to route all packets together.

* `00 10` is the Payload Length field. Does not measure the header size as it is always 40 bytes. Currently set to 16 bytes.

* `3a` is the Next Header field. Currently set to identify ICMPv6.

    * `06` is for TCP

    * `11` is for UDP

* `40` is the Hop Limit field. Currently set to 64.

* 2`0 01　0d b8 00 01 00 00 00 00 00 00 00 00 00 01` is the source IP address. Currently set to 2001:db8:1::1.

* `20 01　0d b8 00 02 00 00 00 00 00 00 00 00 00 02` is the destination IP address. Currently set to 2001:db8:1::2.

* The remaining will be the payload.


![image](https://github.com/ruppertaj/WOBC/assets/93789685/88685a75-2366-41af-b6a9-a3c4bcbeebe7)
IPv6 Structure DEMO


DEMO [Example IPv6 pcap from www.cloudshark.org](https://www.cloudshark.org/captures/0b142cdc65e9)

* IPv6 inherently does not support fragmentation. Routers in the traffic path will not fragment any IPv6 packets. In fact any packets received with a larger size than its supported MTU will be dropped and an ICMPv6 Type 2 "packet too big" message will be sent to the source. This is essentially like having the DF bit set to "ON" (1) in an IPv4 packet. So any needed fragmentation will have to be done by the source node.

* The source node will conduct a process called Path MTU Discovery (PMTU). The source node will send MTU discovery packets to the destination and waits to receive any ICMPv6 Type 2 "packet too big" message. If it does, it knows it needs to decrease the packet size. The minimum safe IPv6 MTU size is 1280 bytes and will guarantee delivery based on packet size but will increase the amount of needed packets to be sent.

* Fragmentation was removed in IPv6 for several reasons. Many debated that fragmentation was inefficient. Any lost fragment makes the entire original packet unusable. This is because there is no way to identify the missing fragment that needs to be resent. So the entire packet needs to be resent and possibly re-fragmented. Additionally the security concerns of fragmentation overlapping attacks is another reason to remove fragmentation altogether.



References:

https://www.cloudshark.org/captures/0b142cdc65e9


#### 2.1.2.3 Describe key differences between IPv4 and IPv6


![image](https://github.com/ruppertaj/WOBC/assets/93789685/d527d120-a1c2-4d6b-9cc6-92e5eec28120)
IPv4 & IPv6 Comparison


* Some fields were kept the same (version, source, and destination address fields).

    * Version 4 or 6

    * IPv4 addresses are 32-bits in length

    * IPv6 addresses are 128-bits in length

* Other fields perform the same function but have different names

    * TTL → Hop count

    * Protocol → Next header

    * Type of Service (TOS) (otherwise known as DSCP/ECN) → Traffic class.

* IPv6 does have one new field defined by [RFC6437](https://datatracker.ietf.org/doc/html/rfc6437). The flow label field enhances the traffic class field by allowing the association of traffic belonging to the same "flow" or "conversation". Additionally, extension headers defined in [RFC2460 Section 4](https://datatracker.ietf.org/doc/html/rfc2460#section-4) are supported to enhance the functionality of the IPv6 header for specific functions.

* IPv6 does not have an IHL field. This is because it has a static length of 40 bytes whereas IPv4 has a variable length header from 20 bytes (IHL=5) to 60 bytes (IHL=F).

* IPv4 supports options that are appended to the header in 4-byte increments. Up to 40 bytes of options can be used. IPv6 does not use options but does support Extension Headers. Extension headers are not appended to the IPv6 header but rather are extra headers that follow the IPv6 header before the actual data.



References:

https://en.wikipedia.org/wiki/IPv6

https://datatracker.ietf.org/doc/html/rfc6437

https://datatracker.ietf.org/doc/html/rfc2460


#### 2.1.2.4 Explain IPv6 address representation
* There are 128 bits in an IPv6 address that are divided into eight 16 bit groupings separated by colons (:). In IPv6 the term for a 16 bit grouping are called a hextet. Within each hextet the 16 bits are represented by 4 hex digits. When displaying the IPv6 address, leading zeros can be dropped. This same thing is done with IPv4.

* When looking at an IPv4 addresses you can not diffrentiate the network portion or the host portion without pairing it with it’s subnet mask.

    * 100.10.10.10 for example is a unique address. But looking at it we do not know the actual network/subnet it resides on.

        * 100.10.10.10 /8 would mean that the first 8 bits are "network bits" and the remaining 24 bits are "host bits". This would put the host on the 100.0.0.0 /8 network.

        * 100.10.10.10 /16 would mean that the first 16 bits are "network bits" and the remaining 16 bits are "host bits". This would put the host on the 100.10.0.0 /16 network.

        * 100.10.10.10 /24 would mean that the first 24 bits are "network bits" and the remaining 8 bits are "host bits". This would put the host on the 100.10.10.0 /24 network.

* IPv6 addresses are inheriently split into 2 main parts.

    * The first 64 bits (or "Prefix") is used to represent the network portion.

    * The remaining 64 bits (or "Interface ID") is used to represent the host portion.

* IPv6 CIDR expresses the number of bits in the network portion of the address. In the case of IPv6 addresses this can be up to /64 and not more. The exception to this rule is when using the /128 CIDR which is used to express the host IP address such as ::1/128 or 2001:ABCD:1234:DEF0:1111:2222:3333:4444 /128

* IPv6 addresses can be very long. A method to help shorten the address is by dropping any leading zeros "0’s"

    * `:0001:` can be shortened to `:1:`

    * A series of 0’s can be shortened by replacing it with `::`.

        * `FE80:0000:0000:0000:0000:0000:0000:0001` can be simply expressed as `FE80::1`

    * When 2 or more consecutive 0’s are present, only one can be shortened with the `::`. It is the user’s choice which.

        * `FE80:0000:0000:0000:abcd:0000:0000:0001` can be shortened to `FE80::abcd:0:0:1` or `FE80:0:0:0:abcd::1`.

        * The `::` notation can only be used once within an IPv6 address to avoid ambiguity. If it were allowed to appear multiple times in an address, it would be challenging to determine how many groups of zeros should be compressed at each occurrence.

![image](https://github.com/ruppertaj/WOBC/assets/93789685/651f85e3-2d5e-4251-b1d2-bcc6e1e49867)
Zero Dropping


* Explanation of what is happening:

    * `2001:0123:0000:0000:0000:1234:0000:AB11` - This shows the full IPv6 address, all digits are shown.

    * `2001:123:0:0:0:1234:0:AB11` - Here the leading zeros are dropped, e.g. 0123 shortened to 123 and 0000 shortened to 0.

    * `2001:123::1234:0:AB11` - Here the leading zeros are dropped and a one time compression of continuous zeroes has been performed indicated by the double colon (::).



References:

https://datatracker.ietf.org/doc/html/rfc4291


#### 2.1.2.5 Identify IPv6 address types and scopes
* IPv6 address types:

    * Unicast Addresses IPs are a "one to one" communication between two nodes.

        * These are similar in function to that of IPv4 unicast addresses.

    * Multicast Addresses Used for one to many communications and routing protocols.

        * These perform the same function as the Class D or multicast addresses of IPv4.

        * Range ff00::/8 - ff00:: thru ffff::

    * Anycast Addresses These addresses can fall within the Global, Unique-Local, or Link-Local address scopes. They differ from unicast in that more than one device can be configured with the same address. These are typically used to address several network gateways. Each gateway can be configured with the same anycast address. Any of these devices can supply the service request for the client. These can also be used for servers when trying to load balance a particular service.



* IPv6 address scope:

    * Loopback Address IPv6 address used by a node on a vitural interface to send packets to itself. This is the same as the 127.0.0.1 is for IPv4.

Scope is ::1/128

    * Global Unicast Addresses IPv6 addressess that are routable over the Internet.

        * Scope is 2000::/3 - 2000:: thru 3fff::

            * 2001:0000:/32 - reserved for Teredo tunneling

            * 2001:20::/28 - reserved for [ORCHIDv2](https://datatracker.ietf.org/doc/html/rfc7343)

            * 2002::/16 - reserved for 6to4 tunneling

    * Unique-Local Addresses IPv6 addresses the are routable locally within a site, not globally routable across the Internet. These perform a similar function as the RFC 1918 private IPv4 addresses and will require NAT to translate the address to a Global Unicast address for communication over the Internet.

        * Scope is fc00::/7 - fc00:: thru fdff::

    * Multicast addresses

        * Scope ff00::/8 - ff00:: thru ffff::

            * ffx0::/8 - reserved

            * ffx1::/8 - interface-local - spans only a single interface on a host. Used for loopback multicast.

            * ffx2::/8 - link-local - spans the local network. Does not traverse network bounderies. Comparable to 224.0.0.0/24 for IPv4.

            * ffx3::/8 - realm-local - spans farther than link-local but under determination of the administrator. Should not bound farther than those below.

            * ffx4::/8 - admin-local - smallest scope that can be administratively configured.

            * ffx5::/8 - site-local - spans a single site of an organization.

            * ffx8::/8 - organization-local - spans to all sites in a single organization.

            * ffxe::/8 - global - spans all hosts on the internet and is unbounded.

            * ffxf::/8 - reserved

    * Link-Local Addresses IPv6 addresses that are assigned to a IPv6 enabled interface for direct link on link communcations. Automatic link-local assignment is done if a one is not manually assigned. Each IPv6 enabled device must have a link-local address defined for local communicaiton. These can not be used as routable addresses.

        * Scope fe80::/10 - fe80:: thru febf::

For a complete listing of IPv6 address assignments [IANA IPv6 Special Registry](https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml) or [RFC4291](https://datatracker.ietf.org/doc/html/rfc4291).



References:

https://www.iana.org/assignments/ipv6-address-space/ipv6-address-space.xhtml
https://datatracker.ietf.org/doc/html/rfc4291
https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml
https://www.iana.org/assignments/ipv6-multicast-addresses/ipv6-multicast-addresses.xhtml


#### 2.1.2.6 Explain IPv6 Auto Configuration with vulnerability

IPv6 Autoconfiguration is a mechanism that allows IPv6 hosts to automatically configure their IPv6 addresses and other network parameters without manual intervention.

* Stateless Address Autoconfiguration (SLAAC)(default):

    * SLAAC is the primary method of IPv6 address autoconfiguration and is similar to IPv4 DHCP in some respects but simpler.

    * In SLAAC, routers on the local network periodically multicast Router Advertisement (RA) messages (FF02::1) to announce their presence and provide network configuration information.

    * Hosts on the network receive these RA messages and use the information contained within them to configure their IPv6 addresses and other parameters.

    * Hosts can also send Router Solicitation (RS) message (FF02::2) to request network information. This is commonly done when a host first powers on. The router will respond with a RA message to the host sent using FF02::1.

    * Each host uses its unique identifier (based on the MAC address or another mechanism) and the network prefix advertised in the RA messages to generate its IPv6 address.

* Stateful/Stateless Address Autoconfiguration (DHCPv6):

    * DHCPv6 is an extension of the DHCP protocol used in IPv4 networks, and it provides additional configuration options beyond basic address assignment.

    * With DHCPv6, hosts can obtain IPv6 addresses, DNS server information, and other network configuration parameters from a DHCPv6 server.

    * DHCPv6 can be used in conjunction with SLAAC, allowing hosts to obtain additional configuration options from DHCPv6 while still using SLAAC for address assignment.

IPv6 zero configuration

* When a node has IPv6 enabled on it’s interface it is setup with an automatic assigning of link-local addresses that will work with zero configuration in the range of fe80::/10. Upon powering on, an IPv6 device will configured its own Link-Local address in the range of FE80::/10.

    * If configured for DHCPv6 it will perfom a process called Stateless Address Autoconfiguration (SLAAC) as defined in [RFC 4862](https://datatracker.ietf.org/doc/html/rfc4862), Neighbor Discovery Protocol (NDP) using ICMPv6. The host will send a Router Solicitation (RS) message to the multicast address of FF02::2 (all routers). This message is intended to reach any IPv6 configured routers on the same network link as itself. The router will respond with a Router Advertisement (RA) message sent to the requesting node at its solicited node multicast address of FF02::1:FFxx:xxxx (xx:xxxx is the last 24 bits of the requestors interface ID). The RA is also sent to the multicast address of FF02::1 (all nodes) at regular intervals. In the message it will include:

    * IPv6 Global routing prefix (first 64 bits)

    * Prefix length (up to a /64)

    * Gateway address (the router’s IP address)

    * Other additional options such as instructions to get further information from DHCPv6

* The host will initiate the process to generate its own interface ID (last 64 bits). It will use either:

    * EUI-64 - The host will use its 48-bit MAC address and insert "FFFE" between the 3 Byte OUI and 3 Byte Vendor assigned ID. This insertion of 16-bits will make the full 64-bit Interface ID. It will then "flip" the 7th bit of the interface ID. Changing that bit from a 0 to a 1 or 1 to a 0.

        * Typically *Nix systems and Cisco devices use EUI-64 by default.

        * Windows devices use Random Generation by default, but can be configured to use EUI-64.

        * A MAC address of fa:16:3e:c3:68:f2 will resolve an EUI-64 address of FE80::f816:3e ff:fe c3:68f2.

        * There are security concerns of EUI-64 in being able to reverse engineer it to a specific host MAC address.

        * Example 1 (Link-Local):

            * MAC: fa:16:3e:c3:68:f2

            * Append: ff:fe between OUI and Vendor assigned

            * Flip 7th bit

            * Result: FE80::f816:3eff:fec3:68f2

        * Example 2 (Global):

            * Prefix from RA: 2001:ABCD:1234:DEF0::

            * MAC: fa:16:3e:c3:68:f2

            * Append: ff:fe between OUI and Vendor assigned

            * Flip 7th bit

            * Result: 2001:ABCD:1234:DEF0:f816:3eff:fec3:68f2

    * Random generation - Random generation was developed to generate the interface ID using psudo random generation to avoid device fingerprinting.

        * Windows Vista and up use this process by default.

        * Can not be reversed to a MAC address but knowing that Windows using this method by default can be an indicator.

        * Examples:

            * Prefix from RA: 2001:ABCD:1234:DEF0::

            * Link-Local: FE80::cdc3:b3ac:1623:f552

            * Global: 2001:ABCD:1234:DEF0:182f:dd86:f2be:653b

DEMO pcap for [IPv6 traffic](https://weberblog.net/wp-content/uploads/2015/05/Basic-IPv4-IPv6-Messages-Knoppix-Telekom.zip)

* Advantage For typical home networks this is very useful. Users with little to no networking experience can easily setup their home networks with little intervention. All of the IP addresses, netmasks and gateways will be automatically configured for all devices.

* Disadvantages On an enterprise network with specific address, netmask and other configurations it is not feasible to use this option as it may be to simplistic. Enterprise networks tend to opt for more precise controls for their networks. Additionally if zero configuration was allowed it could lead to users connecting unauthorized devices onto a secure network with no oversight.

[RFC 3756 IPv6 Neighbor Discovery (ND) Trust Models and Threats](https://datatracker.ietf.org/doc/html/rfc3756)
[RFC 3971 SEcure Neighbor Discovery (SEND)](https://datatracker.ietf.org/doc/html/rfc3971)


* Man-in-th-Middle (MitM) attack with SLAAC - It is possible for a malicious actor to take advantage of SLAAC to create a MitM attack by impersonating a IPv6 router. IPv6 is not able to leverage ARP in order to perform MAC to IP resolutions for the local network. IPv6 utilizes a sub-set of the ICMPv6 protocol called "Neighbor Solicitation (NS)". One particular NS message called Router Advertisements (RA) messages are normally sent by routers to advertise the local network IPv6 Prefix. In addition to the prefix, these messages advertise the MAC address of the router. The hosts will accept this mesages and append their Interface-Id to generate their 128-bit IPv6 address for remote communication. If a malicious actor has percistance on the network they can send crafted RA messages for IPv6 clients to accept. By accepting these RA messages the hosts will record and save the sending MAC address as its "gateway" in the arp-cache.

    * DEMO: Performing a ICMPv6 SLAAC MitM attack with Scapy
```
a = IPv6()
a.dst = "ff02::1"   #IPv6 multicast for RA

b = ICMPv6ND_RA()

c = ICMPv6NDOptSrcLLAddr()
c.lladdr = "your MAC"    #This is to add to their ARP cache

d = ICMPv6NDOptMTU()

e = ICMPv6NDOptPrefixInfo()
e.prefixlen= 64     #Specify the prefix length needed
e.prefix= "2001:abcd:1234:abcd::"  #Can be any prefix that is not reserved already

a.show()
b.show()
c.show()
d.show()
e.show()

send(a/b/c/d/e)
```

References:

https://datatracker.ietf.org/doc/html/rfc4862
https://weberblog.net/basic-ipv6-messages-wireshark-capture/
https://datatracker.ietf.org/doc/html/rfc3756
https://datatracker.ietf.org/doc/html/rfc3971


#### 2.1.2.7 Analyze ICMPv6 protocol and header structure

ICMPv6

* This protocol includes all the same functionality as ICMPv4 with some added features like Fragmentation, Neighbor Discovery, and StateLess Address AutoConfiguration (SLAAC). Another change between ICMPv6 and ICMPv4 is that version 6 allows multicast transmission not just unicast transmission.

![image](https://github.com/ruppertaj/WOBC/assets/93789685/6fd8fe60-b5aa-4929-b63c-626075e17206)
ICMPv6 Ping Request


* The first image shows that the PC is performing a ping request to a network address of 2a01:2e0:3fe:1001:302::

![image](https://github.com/ruppertaj/WOBC/assets/93789685/fdab30be-4ccd-498e-9c73-9ccfe78c46d2)
ICMPv6 Neighbor Solicitation


* The second image shows after the router received the ping request, it sends out a Neighbor Solicitation (ICMPv6 Type 135) to the Solicited-Node multicast address, in this case ff02::1:ff2d:3b8e. The Solicited-Node address was derived by the least-significant 24 bits of the unicast address (2d:3b8e) and appending them to the prefix ff02::1:ff/104. The router’s source IPv6 is using its manual assigned Link-Local address (fe80::1). This Neighbor Solicitation process is similar to the IPv4 ARP request.

![image](https://github.com/ruppertaj/WOBC/assets/93789685/339db72b-1ce0-4376-94db-ed6d181be1f4)
ICMPv6 Neighbor Advertisement


* The third image shows the PC’s response, a Neighbor Advertisement (ICMPv6 Type 136), to the router’s Neighbor Solicitation. The PC’s IPv6 address is 2003:50:aa10:4243:221:6aff:fe2d:3b8e and the destination is back to the router’s Link-Local address (fe80::1). This Neighbor Advertisement process is similar to the IPv4 ARP reply.

![image](https://github.com/ruppertaj/WOBC/assets/93789685/54bd2a79-8830-4d2d-88bd-1e32dc743834)
ICMPv6 Ping Reply


* The last image shows the router’s ping reply to the PC.



References:

https://weberblog.net/basic-ipv6-messages-wireshark-capture/
https://en.wikipedia.org/wiki/Solicited-node_multicast_address
https://www.iana.org/assignments/ipv6-unicast-address-assignments/ipv6-unicast-address-assignments.xhtml



Instructor Note
The pcap images are from the [werberblog site](https://weberblog.net/basic-ipv6-messages-wireshark-capture/). Student’s can download the pcap and do the walk through themselves with the instructor.


#### 2.1.2.8 Explain Neighbor Discovery Protocol (NDP)

IPv6 nodes use NDP to discover other nodes on the local link. This is to determine other node’s link-layer addresses to find routers, and to maintain reachability information about the paths to active neighbor nodes. NDP is vulnerable to various attacks if not secured.

NDP defines five ICMPv6 packet types for the purpose of router solicitation, router advertisement, neighbor solicitation, neighbor advertisement, and network redirects.

* Router Solicitation (Type 133)

    * Hosts inquire with Router Solicitation messages to locate routers on an attached link. Routers which forward packets not addressed to them generate Router Advertisements immediately upon receipt of this message rather than at their next scheduled time.

    * Sent using the multicast address of FF02::2 (all routers) group.

* Router Advertisement (Type 134)

    * Routers advertise their presence together with various link and Internet parameters either periodically, or in response to a Router Solicitation message.

    * Sent using the multicast of FF02::1 (all nodes) group.

* Neighbor Solicitation (Type 135)

    * Neighbor solicitations are used by nodes to determine the link layer address of a neighbor, or to verify that a neighbor is still reachable via a cached link layer address.

    * Similar to an ARP Request when using IPv4. IPv6 does not use ARP however. It uses Neighbor Solicitation to request the MAC address of the destination.

    * Duplicate Address Detection (DAD). Sent by host to the IPv6 address it intends to use. This is to determine if the address is already in use.

* Neighbor Advertisement (Type 136)

    * Neighbor advertisements are used by nodes to respond to a Neighbor Solicitation message.

    * Similar to an ARP Reply when using IPv4. IPv6 does not use ARP however. It uses Neighbor Advertisement to respond to a Neighbor Solicitation.

* Redirect (Type 137)

    * Routers may inform hosts of a better first hop router for a destination.



References:

https://en.wikipedia.org/wiki/Neighbor_Discovery_Protocol

https://www.rfc-editor.org/rfc/rfc4861


## 2.2 Analyze Internetwork Routing
Internetworking is the ability of network to communicate with other networks via intermediate networking devices (routers, switches) and links (ethernet, fiber). IP, a layer 3 protocol, uses logical addresses. These logical addresses are used to determine how a packet gets forwarded from one network to another. To allow network-to-network communication a global addressing scheme is required so that each host can be uniquely distinguished. Every network is assigned a unique value (network ID) and all the hosts on that network share the same network ID but each has their own host ID. The combination of the network ID and host ID makes each address unique.



Routers, also called Gateways, are layer 3 devices that make their forwarding decisions based on the layer 3 logical address. When a router receives a packet, the packet is decapsulated to read the destination IP address. The router then will make a routing decision based on the routing table, encapsulate the packet with new layer 2 information and then forward it out a interface.



![image](https://github.com/ruppertaj/WOBC/assets/93789685/c69c630b-5ec4-4331-8ba3-c0f12bd0e142)
Routing Example


In the example above, the packet with a source IP of 192.168.1.10 arrives at the router’s interfcae G0/0. The router will forward this packet onto it’s destination of 172.16.1.15 out interface G0/1.



References:

https://en.wikipedia.org/wiki/Routing


### 2.2.1 Discuss Routing Tables
A router’s job is to connect different networks. To do this the router must have a routing table that contains the networks known by the router to be able to forward on the packet. In this and the following sections it will be discussed what and how these network routes are added.

First we need to understand the different types of networks that you may see in a routing table.

![image](https://github.com/ruppertaj/WOBC/assets/93789685/2f384af0-6974-4b73-87d3-5a9cee75b9ea)
Routing Table Anatomy


* Ultimate route is any routing table entry that has a next-hop IPv4 address, exit interface, or both.

* Level 1 route is any route with the subnet mask (CIDR) is equal to or less than the classful mask of the network address. A level 1 route can be a:

    * Network route - A network route that has a subnet mask equal to that of the classful mask.

        * Class A - 255.0.0.0 (/8)

        * Class B - 255.255.0.0 (/16)

        * Class C - 255.255.255.0 (/24)

    * Supernet route - A network route with a mask less (smaller) than the classful mask.

        * 192.168.0.0/16

        * These can be a range of IP addresses aggregated into a single, larger network address.

        * Commonly used as network summary routes.

    * Default route - A default route is a static route with the address 0.0.0.0/0 or ::.

* Parent route is a level 1 network that is subnetted. A parent route will never be an ultimate route.

* Level 2 child route are the subnets of a classful network address.

Different Routing Tables are displayed below.

Cisco Routing Table Example

![image](https://github.com/ruppertaj/WOBC/assets/93789685/e9c715d5-979e-41da-856c-3512ae1a6555)
Cisco Routing Table Example


Foundry Routing Table Example

![image](https://github.com/ruppertaj/WOBC/assets/93789685/915f48fb-2a33-487f-94d4-9c97e713ec2a)
Foundry Routing Table Example


Juniper Routing Table Example

![image](https://github.com/ruppertaj/WOBC/assets/93789685/798d4c1d-b987-40e6-abca-0aee4753a341)
Juniper Routing Table Example


Dell Routing Table Example

![image](https://github.com/ruppertaj/WOBC/assets/93789685/0dfd799c-c175-4d83-aacf-eef8a27bb2a7)
Dell Routing Table Example


* The primary functions of a router are to:

    * Determine the best path to send packets.

        * Builds and maintains routing tables to make this determination.

        * Uses directly connected networks, static routes, and dynamic routing protocols to assist in building and maintaining this routing table.

    * Forward packets toward their destination (this is called routing).

        * Strips the Frame header off packet from incoming interface.

        * Adds new Frame header to packet for outgoing interface.

* Similar to switches where it builds a CAM table built of MAC address to determine how to forward frames towards the destination, the router builds routing tables on where and how to forward packets. The router builds the table including information such as Route Source, Destination Network/CIDR, AD, Metric, Next-hop address, Route Timestamp and Outgoing Interface. As shown in the figure below.


![image](https://github.com/ruppertaj/WOBC/assets/93789685/083f7aaf-1133-4d31-be57-3a38bb48eb29)
Routing Table Entry


* The routing table includes routes to what it determines is the "best route" to the destination network. When a packet enters a router it will be decapsulated. The frame is stripped off and it will examine the destination address in the packet. Using this address it looks to find the "best match" in the routing table. Once the best match is determined it will use the next hop address and exit interface. It will re-encapsulate the packet into the appropriate frame for the exiting interface network and send it out.


![image](https://github.com/ruppertaj/WOBC/assets/93789685/08566b20-3791-4ffd-80c4-8fc4b1fed176)
Packet Routing Flow

Best Route = Longest Match

* Routers compare the destination address in the incoming packet to its entries in the routing table. It matches the address (bit by bit) to all the table entries and looks for the longest bit match it can find. Starting at the far left, it compares the bits up to the amounts of bits in the CIDR mask. (i.e. a /12 mask will match 12 bits and a /24 will match 24 bits.)

* Since the IP packet only contains the IP address and not the subnetmask, the router does not know what network the address belongs to. So this matching process tries to narrow down the address to a list of "known" networks.

* Once a route with the most matched bits is found, it will forward the packet to the next-hop ip address in the table entry and re-encapsulate the packet into a new frame appropriate for the exiting interface.



Routing Table Matching Process

![image](https://github.com/ruppertaj/WOBC/assets/93789685/d3f0c5cb-6f68-420d-a667-904f412ab031)
Routing Table Matching Process


Administrative Distance

* Routers uses an AD to determine the best source route to install into the IP routing table. The AD represents the "trustworthiness" of the route; the lower the AD, the more trustworthy the route source.

* For example, if a router learned about the 10.0.0.0/24 from EIGRP, OSPF and RIP, the EIGRP route entry would be in installed into the routing table. This is because EIGRP AD 90 is lower than OSPF AD 110 and RIP AD 120.

    * If anything should happen with the EIGRP route then the OSPF route is installed into the routing table.



Route AD

![image](https://github.com/ruppertaj/WOBC/assets/93789685/d8717172-90df-4d38-b580-0e4d16ffaee9)
Administrative Distance



* What if the router learned of the same network route via the same routing protocol?

    * Metric(s) then comes into account to determine the best path to a destination network.

    * Using 2 or more routes to a destination network is called "Load Balancing".

    * Many routing protocols only allow "equal cost" load balancing. This means that the metric must be the same for each "Best route".

    * Some routing protcols do allow unequal cost load balancing. This is where it can use the primary route as well as other routes that are close to the best route.

Metric

Some of the most common metrics that routing protocols can use are:

* hop

* bandwidth

* delay

* reliability

* load

* MTU

* cost

* administratively defined



Routing Protocol with Metric Name
```
RIP             Hop count
EIGRP           Bandwidth, Delay, Load, Reliability
OSPF            Cost (Bandwidth)
IS-IS           Cost (Assigned by Admin)
BGP             Policy assigned by Admin
```


Security Concern with the router lookup process

* The IPv4 protocol has an options field in its header and it is possible to add source routing information to specify the specific path for traffic to take regardless of what is in the routing table. This can allow attackers to manipulate the flow of traffic and possibly bypass some network security devices.

* Typically an IPv4 packet does not include options and can easily be scanned for using BPF filters.

    * ip[0] & 0x0f > 5

* Soon we will discuss routing protocols. By understanding the operation of these protocols a malicious attacker can "inject" fake routing updates in order to change your routing scheme.


### 2.2.2 Dynamic Routing Protocols operation and vulnerabilities
Operation

Dynamic routing protocols allow the automated updating of network routes within a routing Autonomous System (AS) network. Different routing protocols have different Administrative Distances (AD) and metrics to be used for route selection and entry into the routing table.

When the router is configured with a dynamic routing protocol, and finds neighboring routers with the same routing protocols, it will begin to share and learn about remote networks storing this information in the Router Information Database (RIB). This will be used to populate the routing table.


#### 2.2.2.1 Classful vs Classless
Classful vs Classless

![image](https://github.com/ruppertaj/WOBC/assets/93789685/0329fbe8-8453-4a46-8fe1-d607470b704d)


* Routing protocols are either Classful or Classless.

    * Classful routing protocols (RIPv1 and IGRP) do not send subnet mask information with their routing updates.

    * Classless routing protocols (RIPv2, EIGRP, OSPF, and IS-IS) support VLSM and CIDR which include the subnet mask information in their routing updates; classful protocols do not.

    * IPv6 routing protocols are all considered classless.


#### 2.2.2.2 Routed vs Routing Protocols
Routed vs Routing Protocols

![image](https://github.com/ruppertaj/WOBC/assets/93789685/0754115c-c3ad-47db-9ae9-c5d65b0e4069)


Routed protocols allows data to be routed. These protocols provide an addressing scheme and sub-netting. The addressing scheme identifies the individual host and the network to which it belongs. Each host address must be unique. All hosts on an internetwork must use the services of a routed protocol to communicate.

* IPv4

* IPv6

* IPX

* AppleTalk

Routing Protocols are used by routers to communicate routing information with each other. Unless all routes are manually entered into the router, the router needs to learn from other routers about the networks that they know. They use this shared information to populate their routing tables so that they can make better decisions when forwarding routed protocols such as IPv4.

Routing protocols are broken down to 2 types:

* Interior Gateway Protocol (IGP) - is a type of protocol used for exchanging routing information between gateways (commonly routers) within an autonomous system

    * RIP (v1, v2, ng)

    * EIGRP and EIGRP for IPv6

    * OSPF (v2 and v3)

    * IS-IS

* Exterior Gateway Protocol (EGP) - is a routing protocol used to exchange routing information between autonomous systems

    * BGP

Not all routing protocols support all "routed" protocols. If you are running more than one then its possible that you may have to run additional routing protocols to ensure that those routes are advertised.


#### 2.2.2.3 IGP vs EGP
IGP vs EGP

![image](https://github.com/ruppertaj/WOBC/assets/93789685/cae6b8d5-734c-4896-9c63-402305e8ca4c)


* Interior Gateway Protocols (IGP):

    * Routing protocols that are used within an Autonomous System (AS).

    * Referred to as intra-AS routing.

    * Organizations and service providers IGPs on their internal networks.

    * IGPs include RIP, EIGRP, OSPF, and IS-IS.

* Exterior Gateway Protocols (EGP):

    * Used primarily for routing between autonomous systems.

    * Referred to as inter-AS routing.

    * Service providers and large companies will interconnect their AS using an EGP.

    * The Border Gateway Protocol (BGP) is the only currently viable EGP and is the official routing protocol used by the Internet.

https://www.vskills.in/certification/tutorial/basic-network-support/routing-protocol-igp-and-egp-and-algorithms/


#### 2.2.2.4 Autonomous Systems
IANA and RIRs

![image](https://github.com/ruppertaj/WOBC/assets/93789685/a15769bc-5d60-40fb-b4a4-4079ece0f77a)
IANA


* IANA Regional Internet Registries (RIR):

    * RIRs work in coordination with IANA to ensure the fair and efficient distribution of IP address resources globally. IANA allocates large blocks of IP addresses to the RIRs, and the RIRs, in turn, allocate smaller blocks of IP addresses to ISPs, organizations, and end-users within their respective regions. This hierarchical distribution system helps manage the limited pool of IPv4 addresses and ensure that IP address resources are allocated efficiently and fairly.

    * ARIN (American Registry for Internet Numbers):

        * Responsible for the allocation and management of IP addresses in North America, parts of the Caribbean, and sub-equatorial Africa.

    * RIPE NCC (Réseaux IP Européens Network Coordination Centre):

        * Responsible for the allocation and management of IP addresses in Europe, Central Asia, and the Middle East.

    * APNIC (Asia-Pacific Network Information Centre):

         * Responsible for the allocation and management of IP addresses in the Asia-Pacific region.

    * LACNIC (Latin America and Caribbean Network Information Centre):

        * Responsible for the allocation and management of IP addresses in Latin America and parts of the Caribbean.

    * AfriNIC (African Network Information Centre):

        * Responsible for the allocation and management of IP addresses in Africa.

* Autonomous systems

    * An Autonomous System (AS) is a collection of IP networks and routers under the control of one entity (such as an Internet service provider, a university, or a large enterprise) that presents a common routing policy to the Internet.

    * Autonomous Systems are identified by unique numbers called Autonomous System Numbers (ASNs), which are assigned by regional Internet registries (RIRs) such as ARIN, RIPE NCC, APNIC, LACNIC, and AfriNIC.

    * Each administrative entity is assigned a 16-bit (prior to 2007) or 32-bit number (after 2007) to uniquely identify itself to everyone on the internet.
```
AS109   CISCO-EU-109 Cisco Systems Global ASN
AS193   FORD-ASN - Lockheed Martin Western Development Labs
AS721   DoD Network Information Center Network
AS3598  MICROSOFT-CORP-AS - Microsoft Corporation
AS15169 GOOGLE - Google Inc.
```
    * AS numbers are assigned in blocks by the Internet Assigned Numbers Authority (IANA) to Regional Internet registries (RIRs).

    * The appropriate RIR then assigns AS numbers to entities within its designated area from the block assigned by the IANA.

    * Entities wishing to receive an AS number must complete the application process of their local RIR and be approved before being assigned an AS number.



References:

https://en.wikipedia.org/wiki/Autonomous_system_(Internet)

https://www.bgplookingglass.com/list-of-autonomous-system-numbers

APNIC: https://ftp.apnic.net/stats/apnic/

RIPE NCC: https://ftp.ripe.net/ripe/stats/

AFRINIC: https://ftp.afrinic.net/pub/stats/afrinic/

ARIN: https://ftp.arin.net/pub/stats/arin/

LACNIC: https://ftp.lacnic.net/pub/stats/lacnic/


#### 2.2.2.5 Distance Vector Routing Protocols
Distance Vector Routing

![image](https://github.com/ruppertaj/WOBC/assets/93789685/fad4004f-7302-478f-a187-e3023d9eb93f)


Distance Vector protocols are simplistic in their operation. They share entire routing tables with their directly connected neighbors and from these shared tables they determine two factors:

* Distance: This identifies how far away the destination network is from the router and is based on a metric such as the hop count, cost, bandwidth, delay, and more. It takes the learned distance from their neighbor, adds the distance to their neighbor, and this gives them a total distance.

* Vector: This specifies the direction to the remote network. The router advertises a path that it has learned which allows access to a remote network via one of its interfaces.

A router using a distance vector routing protocol will not have complete knowledge of the network or the entire path to a remote network. Distance vector protocols is typically called "routing by rumor". This means they only know what their directly connected neighbors tell them.

There are four distance vector IPv4 IGPs:

* RIPv1: First generation legacy protocol

* RIPv2: Simple distance vector routing protocol

* IGRP: First generation Cisco proprietary protocol (obsolete and replaced by EIGRP)

* EIGRP: Advanced version of distance vector routing


#### 2.2.2.6 Link State Routing Protocols
Link State Routing

![image](https://github.com/ruppertaj/WOBC/assets/93789685/2d611f52-3c31-4f1f-9139-f72895594a46)


Compared to distance vector routing protocols, a router configured with a link-state routing protocol can create a complete view of the network. This is built by gathering information from all of the other routers to build a network topology.

Link state routing protocols tend to flood the network with Link State Advertisements (LSAs). Each router receives these updates and begins to build a map of the entire network. It will use its algorithms to compute the best routes from this map to all remote networks. After this is done no periodic updates are sent unless there is a change in the topology.

Link-state protocols work best in situations where:

* The network design is hierarchical, usually occurring in large networks

* Fast convergence of the network is crucial

* The administrators have good knowledge of the implemented link-state routing protocol

There are two link-state IPv4 IGPs:

* OSPF: Popular open standards-based routing protocol

* IS-IS: Popular in service provider networks


#### 2.2.2.7 Distance Vector vs Link State
This chart shows the comparision between different routing protocols:


```
Protocol	Type	Convergance	Class	AD	Metric  	Hop Limit	Classless	Algorithm	Transport Type	Routing updates
RIPv1           IGP     Slow            DV      120     Hop Count       15              NO              Bellman-Ford    UDP port 520    Broadcast full tables every 30 Sec
RIPv2           IGP     Slow            DV      120     Hop Count       15              Yes             Bellman-Ford    UDP port 520    Multicast 224.0.0.9 every 30 sec
RIPng           IGP     Slow            DV      120     Hop Count       15              Yes             Bellman-Ford    UDP port 521    Multicast FF02::9 every 30 sec
EIGRP           IGP     Very Fast       DV(h)   90      B/D/L/R         224             Yes             DUAL            IP protocol 88  Multicast 224.0.0.10
EIGRP IPv6      IGP     Very Fast       DV(h)   90      B/D/L/R         224             Yes             Dual            IP protocol 88  Multicast FF02::A
OSPF v2         IGP     Fast            LS      110     Cost            none            Yes             Dijkstra (SPF)  IP protocol 89  Multicast 224.0.0.5 and 224.0.0.6
OSPF v3         IGP     Fast            LS      110     Cost            none            Yes             Dijkstra (SPF)  IP protocol 89  Multicast FF02::5 and FF02::6
IS-IS           IGP     Fast            LS      115     Cost            none            Yes             Dijkstra (SPF)  L2 Protocol     Sends directly in a frame
BGP             EGP     Average         DV      20/200  Policy          none            Yes             Best Path       TCP port 179    Unicasts updates to neighbors

KEY:
Protocol: Routing protocol name
Type: either interior or exterior routing protocol
Convergence: How fast they are to share routing information throughout the intranet.
Class: either link state or distance vector
AD: Administrative distance. Trustworthiness of the information source. Higher is more trustworthy.
Algorithm: How it computes the "best path" to the destination network using its metrics.
Transport Type: How is sends it update over the network.
Routing updates: Destination address it uses to send updates to neighbor routers supporting the same protocol.
```


#### 2.2.2.7 Routing Protocol vulnerabilities
Like most other protocols, routing protocols are susceptible to various forms of attacks. These attacks are possible if the malicious actor can determine the protocols in use and the networks being advertised. This can be done either from passive sniffing or from a current router configuration file. Some common attacks are:

* Distributed Denial of Service (DDOS) - Attackers send more packets to the router than they can handle or process. This will cause the router to drop packets if proper QoS is not implemented.

* Packet Mistreating Attacks (PMA) - Similar to DOS attacks, packet mistreating injects packets with malicious codes designed to confuse and disrupt the router and network.

* Routing Table Poisoning (RTP) - Attackers can send specially crafted routing protocol packets to the router to poison the router’s tables. Enabling authentication can help mitigate this attack.

* Hit and Run DDOS (HAR) - DDOS attack on a specific network or router.

* Persistent Attacks (PA) - similar to hit and run, in which they both look to inject frequent harmful data packages into the router and network, helping the hackers gain control. The attacker can redirect traffic as they want, send wrong routing updates, or simply delete the configuration of that router.



References:

https://www.intelligentcio.com/eu/2017/10/16/the-5-most-common-router-attacks-on-a-network/


#### 2.2.2.9 BGP


BGP is one of only 2 Exterior Gateway Routing Protocols (EGP) created. The other called simply Exterior Gateway Protocol (EGP) was developed in 1982 by Eric C Rosen and David Mills and specified in [RFC 827](https://tools.ietf.org/html/rfc827). It was a simple protocol that was eventually made obsolete by BGP version 4 published in [RFC 4271](https://tools.ietf.org/html/rfc4271).

BGP operates differently compared to IGP protocols. Rather than automatically advertising all internal networks, BGP is configured to specify the precise network and CIDR it will advertise. Instead of making best path selection based of metrics, it uses "paths" (which is loosly similar to hops used by RIP), network policies, or rule-sets. This makes BGP one of the most complicated routing protocols to configure. Where simple configuration errors with an IGP will have an impact on traffic within your network. Whereas a misconfiguration with BGP could have broad ramifications on the traffic routing throughout the entire world.

[Wikipedia BGP link](https://en.wikipedia.org/wiki/Border_Gateway_Protocol)

* Roadmap of the Internet - If DNS is the "address-book" of the Internet then BGP is the Roadmap or "Google Maps" of the Internet. It defines the path all traffic takes through the Internet. The Internet is nothing more than a web of millions of interconnected networks.

* Routes traffic between Autonomous System (AS) Number - Internet Service Providers (ISP) and large organizations are assigned an Autonomous System (AS) Number by IANA. Each AS is viewed as a single entity to the rest of the world but within the AS it can contain thousands of subnetworks and routers. [List of AS numbers and owners according to bgplokingglass.com](http://www.bgplookingglass.com/list-of-autonomous-system-numbers)

    * Think of an AS like a city or town and highways and interstates are the BGP pathways between them.

* Advertises IP CIDR address blocks - Each AS is used to represent a CIDR block(s) of IP addresses and can contain thousands of individual routers and subnetworks. Rather than advertise each individual network address and CIDR throughout the AS like IGP do, BGP is manually configured to advertise "summary routes" that encompass all the internal networks. [How does BGP work video](https://www.youtube.com/watch?v=z8INzy9E628)

    * Think of this like street and building numbers in a town or city.

* Establishes Peer relationships - BGP is an application layer protocol that communicates using TCP port 179. ISPs use BGP in order to share routing information with their peers. Each ISP’s edge router uses TCP to establish "peer" relationships between other ISP edge routers in another AS to share addressing information. Rather than sending their updates to any BGP listening router, BGP must be manually configured to communicate with 'peer' neighbor routers. This eventually forms a web of communicating routers. [APNIC BGP map](http://thyme.apnic.net/BGP/)

* Complicated configuration - Does not operate and share routes automatically like other IGP. Network addresses must be manually configured to be advertised. Due to lack of trust between ISPs they employ series of filters and policies which makes BGP must harder and more complicated to configure.

   * This complicated configuration can lead to many errors and attacks over the internet.

* Complicated and slow path selection - BGP uses a series of items in its path determination. [BGP path selection reference from CiscoZine.com](https://www.ciscozine.com/bgp-best-path-selection/). "Best Path" in BGP does not mean its the most optimal path. It only routes by AS #'s and not the attributes within the AS themselves. Typically BGP prefers the route that takes the packet through the fewest amount of AS’s.


##### 2.2.2.9.1 BGP Hijacking


Each individual organization has the ability to enforce the policies within their networks. However, there is no one governing organization that can enforce the internet. Each individual network is privately owned and controlled in various countries throughout the world. Each county is governed by their own rules, regulations and laws. To allow for the explosive growth of the Internet, it operated on a "trust" model. This means that ISPs were allowed to connect and share their network information with the rest of the world and were trusted that they would "play nice" with others. There was no way to realistically prevent intentional or accidental advertising of networks that the organization does not own.

BGP Hijacking works by:

Illegitimate advertising of addresses - BGP Hijacking (also called prefix hijacking, route hijacking or IP hijacking) works by illegitimately taking over IP CIDR address blocks and corrupting Internet routing tables by falsely advertising addresses of addresses you do not own.

Attack Vector

BGP propagates false information - When an AS announces a route to IP prefixes that it does not actually control, this announcement, if not filtered, can spread and be added to routing tables in BGP routers across the Internet. From then until somebody notices and corrects the routes, traffic to those IPs will be routed to that AS. It would be like claiming territory if there were no local government to verify and enforce property deeds.

* Purpose - As a result of BGP hijacking, Internet traffic can traverse incorrect paths for the purpose of:

    * stealing prefixes - mostly temporarily. This is usually noticed within minutes to hours. Although repairing issue can take minutes to hours as well depending on finding the right technicians to resolve the issue. Usually larger organizations can repair the issue faster than smaller ones due to their contacts and influence.

    * monitoring traffic - this is useful to monitor traffic that the attacker may not be "in line" of. This will divert all traffic to a target through your network.

    * intercept (and possibly modify) Internet traffic - similar to monitoring, packets can also be modified since it will traverse the attackers network infrastructure.

    * 'black holing' traffic- since the traffic was diverted, the attack’s intent could send traffic to the proverbial "bit bucket" and simple discard the packets.

    * direct users to a fake website as part of a man-in-the-middle attack. Rather than taking users to a legitimate website, an attacker can direct traffic to a fake (cloned) website.

BGP favors the shortest, most specific path to the desired IP address - In order for the BGP hijack to be successful, the route announcement must either:

1. Advertise a more specific route. This is easily done by announcing smaller range of IP addresses than what other AS’s had previously announced. (i.e. 192.168.1.0 /24 is more specific than 192.168.0.0 /16)

2. Offer a shorter route to certain blocks of IP addresses. If the address can be advertised and the path is perceived to be "shorter" it will overwrite a legitimate path. (i.e. route to ip prefix with 4 AS 'hops" is better than route with 5 AS 'hops' )

[Cloudfare](https://www.cloudflare.com/learning/security/glossary/bgp-hijacking/)

Defense

Ultimately it is difficult to defend against. Each ISP can only control their own advertisements and not what is advertised from other ISPs. There are some implementation to help guard against it but each has its own challenges.

* IP prefix filtering -The ISP can filter what IP prefixes (address blocks) it should advertise and accept. This can help prevent any accidental route hijacking but its not feasible to enforce all ISPs to perform this.

* BGP hijacking detection -Signs of BGP Hijacking can include:

    * Tracking the change in TTL of incoming packets. This can be easily "mangled" by a MitM attacker to hide.

    * Increased Round Trip Time (RTT) which increases latency. This can be managed depending on proximity to the primary prefix owner. If closer, then latency can be minimized. Else the attack can be localized to a "Region".

    * Monitoring misdirected traffic (change in AS path from tools like Looking Glass). Hard to discover without active monitoring.

* Making BGP more secure - Was designed to make the Internet work but not designed with security in mind. BGPsec is being developed but unsure when it will be adopted everywhere.



References:

https://www.vskills.in/certification/tutorial/basic-network-support/routing-protocol-igp-and-egp-and-algorithms/
https://www.iana.org/numbers
https://www.iana.org/assignments/as-numbers/as-numbers.xhtml
https://tools.ietf.org/html/rfc827
https://tools.ietf.org/html/rfc4271
https://en.wikipedia.org/wiki/Border_Gateway_Protocol
http://www.bgplookingglass.com/list-of-autonomous-system-numbers
https://www.youtube.com/watch?v=z8INzy9E628
http://thyme.apnic.net/BGP/
https://www.ciscozine.com/bgp-best-path-selection/
https://www.cloudflare.com/learning/security/glossary/bgp-hijacking/
https://www.cloudflare.com/learning/security/glossary/bgp-hijacking/
https://en.wikipedia.org/wiki/BGP_hijacking


##### 2.2.2.9.2 BGP Hijacking Public incidents
Below is a list of several examples of BGP Hijacking.

* [April 1997](https://web.archive.org/web/20090227181607/http://www.merit.edu/mail.archives/nanog/1997-04/msg00380.html): The ["AS 7007 incident"](https://en.wikipedia.org/wiki/AS_7007_incident)

* [December 24, 2004](https://web.archive.org/web/20080228131639/http://www.renesys.com/blog/2005/12/internetwide_nearcatastrophela.shtml): TTNet in Turkey hijacks the Internet

* [May 7, 2005](https://www.ccsl.carleton.ca/paper-archive/twan-ssn-06.pdf): Google’s May 2005 Outage

* [January 22, 2006](https://dyn.com/blog/coned-steals-the-net/): Con-Edison hijacks big chunk of the Internet

* [February 24, 2008](https://web.archive.org/web/20080405030750/http://www.ripe.net/news/study-youtube-hijacking.html): Pakistan’s attempt to block YouTube access within their country takes down YouTube entirely.

* [November 11, 2008](https://dyn.com/blog/brazil-leak-if-a-tree-falls-in/): The Brazilian ISP CTBC - Companhia de Telecomunicações do Brasil Central leaked their internal table into the global BGP table. It lasts over 5 minutes. Although, it was detected by a RIPE route server and then it was not propagated, affecting only their own ISP customers and few others.

* [April 8, 2010](https://web.archive.org/web/20190415002259/https://bgpmon.net/chinese-isp-hijacked-10-of-the-internet/): Chinese ISP hijacks the Internet

* [July 2013](https://bgpmon.net/how-hacking-team-helped-italian-special-operations-group-with-bgp-routing-hijack/): linkhttps://en.wikipedia.org/wiki/Hacking_Team[The Hacking Team] aided Raggruppamento Operativo Speciale (ROS - Special Operations Group of the Italian National Military police) in regaining access to Remote Access Tool (RAT) clients after they abruptly lost access to one of their control servers when the Santrex IPv4 prefix 46.166.163.0/24 became permanently unreachable. ROS and the Hacking Team worked with the Italian network operator Aruba S.p.A. (AS31034) to get the prefix announced in BGP in order to regain access to the control server.

* [February, 2014](https://www.wired.com/2014/08/isp-bitcoin-theft/): Canadian ISP used to redirect data from ISPs.- In 22 incidents between February and May a hacker redirected traffic for roughly 30 seconds each session. Bitcoin and other crypto-currency mining operations were targeted and currency was stolen. Arti

* [January 2017](https://www.theverge.com/2017/1/7/14195118/iran-porn-block-censorship-overflow-bgp-hijack): Iranian pornography censorship.

* [April 2017](https://www.noction.com/blog/bgp-hijacking): Russian telecommunication company Rostelecom (AS12389) originated 37 prefixes for numerous other Autonomous Systems. The hijacked prefixes belonged to financial institutions (most notably Master Card and Visa), other telecom companies, and a [variety of other organizations](https://bgpmon.net/bgpstream-and-the-curious-case-of-as12389/). Even though the possible hijacking lasted no more than 7 minutes it is still not clear if the traffic got intercepted or modified.

* [December 2017](https://bgpmon.net/popular-destinations-rerouted-to-russia/): Eighty high-traffic prefixes normally announced by Google, Apple, Facebook, Microsoft, Twitch, NTT Communications, Riot Games, and others, were announced by a Russian AS, DV-LINK-AS (AS39523).[19][20]

* [April 2018](https://arstechnica.com/information-technology/2018/04/suspicious-event-hijacks-amazon-traffic-for-2-hours-steals-cryptocurrency/): Roughly 1300 IP addresses within Amazon Web Services space, dedicated to [Amazon Route 53](https://en.wikipedia.org/wiki/Amazon_Route_53), were hijacked by eNet (or a customer thereof), an ISP in Columbus, Ohio. Several peering partners, such as Hurricane Electric, blindly propagated the announcements.

* [July 2018](https://www.cyberscoop.com/telegram-iran-bgp-hijacking/): Iran Telecommunication Company (AS58224) originated 10 prefixes of [Telegram Messenger](https://en.wikipedia.org/wiki/Telegram_(software)).

* [November 2018](https://blog.thousandeyes.com/internet-vulnerability-takes-down-google/): US-based China Telecom site originated Google addresses.

* [November 2018](https://arstechnica.com/information-technology/2018/12/how-3ves-bgp-hijackers-eluded-the-internet-and-made-29m/): A group called "3ve" used BGP hijacking to make 29M in ad clicking.

* [April 1 2020](https://www.manrs.org/2020/04/not-just-another-bgp-hijack/). Many networks witnessed a massive BGP hijack by AS12389 (Rostelecom).

* [April 5 2020](https://www.zdnet.com/article/russian-telco-hijacks-internet-traffic-for-google-aws-cloudflare-and-others/). Russian telco hijacks internet traffic for Google, AWS, Cloudflare, and others. (another link)

* [September 29 2020](https://securityboulevard.com/2020/09/inadvertent-routing-error-causing-major-outage/). Radware customers experienced cloud service interruptions. The outage was caused by a so-called BGP Hijacking incident as a consequence of an unintended and unfortunate technical error in one of the world’s largest ISPs, Telstra. While Radware immediately detected and cooperated closely with Telstra to mitigate the problem, the interruptions and suffered outages were out of Radware’s direct control.

* [April 16 2021](https://www.catchpoint.com/blog/vodafone-idea-bgp-leak). Large BGP routing leak out of India: over 30,000 BGP prefixes hijacked via Vodaphone Idea Ltd (AS55410) causing 13X spike in inbound traffic. Prefixes were from around the globe but mostly US including Google, Microsoft, Akamai, and Cloudflare. (another link)

* [October 4 2021](https://www.theverge.com/2021/10/4/22709806/facebook-says-the-six-hour-outage). Facebook along with Instagram, Messenger, Whatsapp, and OculusVR were BGP routes were taken down by a mistaken BGP update. Cloudfare reports that the service saw a ton of BGP updates from Facebook (most of which were route withdrawals, or erasing lines on the map leading to Facebook) right before it went dark.



References:

https://en.wikipedia.org/wiki/BGP_hijacking#Public_incidents


##### 2.2.2.9.3 BGP Demo


Step 1:

Go to: https://www.whatismyip.com/ to get your IP address.

Step 2:

Goto: https://stat.ripe.net/ and paste in your IP address. It will tell you that it is part of a broader advertised address prefix. Select the choice of the broader prefix.

You can go through all the details on the main IP "At a Glance" tab. This can map out (by percentage) where various IP address blocks are located.

Step 3:

Click the "Routing" tab on the left side. Scroll down to the BGPlay window. It will give you a message that says "This query includes more nodes/events than normal. Rendering this graph may cause your browser to become temporarily unresponsive. Do you wish to continue?" Click "Yes".

BGPlay will show you the AS that is advertising the address and paths of other up/down stream AS#'s that it is advertising to. Optionally you can goto https://stat.ripe.net/special/bgplay to display this view.

Step 4:

This site will take you to a top level site to view each of each of Assigned Numbers Authority (IANA)'s Regional Internet Registries (RIRs) BGP map. This will graphically display the peer relationships of AS’s. APNIC BGP Map. From this map you can demo the same AS that you found from above and it will show its peer relationships.

Extra:

Ping any major DNS address to resolve the IP address (i.e. www.cisco.com, www.dell.com, us.army.mil, etc) and use the previous steps to portray that ip address within BGP.

This link will take you to a list of "active" ASes and prefixes in the past 14 days for demo purposes. http://bgpupdates.potaroo.net/instability/bgpupd.html



References:

http://www.bgplookingglass.com/
https://www.whatismyip.com/
https://stat.ripe.net/
http://bgpupdates.potaroo.net/instability/bgpupd.html


### 2.2.3 Compare Static routing vs. dynamic routing


References:

https://www.techtarget.com/searchnetworking/answer/Static-and-dynamic-routing

https://www.routeralley.com/guides/static_dynamic_routing.pdf

https://www.geeksforgeeks.org/difference-between-static-and-dynamic-routing/

https://www.tutorialspoint.com/difference-between-static-routing-and-dynamic-routing


#### 2.2.3.1 Static Routing
Static Routing

![image](https://github.com/ruppertaj/WOBC/assets/93789685/c03cd8cc-1dfc-4673-9ef0-0037a2a82464)


Static routes are manually configured on each router by a network administrator to route traffic for every specific remote network. This is common for small networks with few a routes but becomes cumbersome on larger networks. They also provide security for some larger networks as all traffic takes predetermined routes.

Static routing provides some advantages over dynamic routing, including:

* Static routes do not advertise over the network, resulting in better security.

* Static routes do not use bandwidth like dynamic routing protocols to send updates and no CPU cycles are used to calculate and communicate routes.

* The path a static route uses to send data is predetermined.



Static routing has the following disadvantages:

* Initial configuration and maintenance is time-consuming.

* Configuration is prone to error, especially on large networks.

* Administrator must intervene to update routing information or to bypass network faults.

* Does not scale well with growing networks; maintenance becomes cumbersome.

* Requires complete knowledge of the whole network for proper implementation.



References:

https://www.dummies.com/programming/networking/cisco/pros-and-cons-of-static-routing/

https://www.hitechwhizz.com/2020/11/5-advantages-and-disadvantages-drawbacks-benefits-of-static-routing.html


#### 2.2.3.2 Dynamic Routing
Dynamic Routing

![image](https://github.com/ruppertaj/WOBC/assets/93789685/3b9ca2e2-6de0-4715-9a1a-483ba2b0e1db)


Routing protocols allow routers to dynamically exchange routing information to build routing tables. If 2 or more routers share the same protocol they can communicate with each other. The purpose of dynamic routing protocols includes:

* Discover new remote networks

* Maintaining current routing information

* Choose best path to remote networks

* Recalculate a new path to a remote network should the primary fail

Dynamic routing provides some advantages over static routing, including:

* Easier to configure and maintain.

* Administrator does not need to intervene to update tables during network outages.

* Scales very well on growing networks.

Dynamic routing has the following disadvantages:

* Routing protocols flood the network updates which consumes bandwidth and can be intercepted.

* Uses extensive CPU and RAM to run its algorithms and build its databases.

* Path data can travel is not deterministic and can change fluidly.



References:

https://www.hitechwhizz.com/2020/11/7-advantages-and-disadvantages-drawbacks-benefits-of-dynamic-routing.html


#### 2.2.3.3 Routing Protocol Security Issues
* Routing table poisoning - The issue with routing protocols is that they inherently trust neighbors running the same routing protocol. This means that an attacker can "inject" fake or falsified routing updates into the network to either direct traffic to his system or to cause a DOS.



References:

https://www.giac.org/paper/gcih/239/security-ip-routing-protocols/102313

https://www.intelligentcio.com/eu/2017/10/16/the-5-most-common-router-attacks-on-a-network/#


### 2.2.4 Understand First Hop Redundancy Protocols and their vulnerabilities
First Hop Redundancy Protocol

![image](https://github.com/ruppertaj/WOBC/assets/93789685/64a9c057-634e-408b-8bc8-9f23c784512c)
First Hop Redundancy Protocol


Redundancy on networks are critical should a fault occur. One limitation on user PCs is that you can only configure one default gateway. Should this device fail the users cannot get out of their local network. Even if 2 or more routers are configured for redundancy, each interface will have a different IP address and both cannot be configured on users. FHRP provides a mechanism to provide alternate default gateways in switched networks where two or more routers are connected to the same network.

FHRP works by assigning a virtual router to 2 or more gateway routers. This works by configuring a FHRP protocol on all participating gateway interfaces to share a "floating IP" address and MAC. Each interface will have its unique IP assigned to the interface but all will share this floating IP and MAC.



Several types of FHRPs were developed:

* Hot Standby Router Protocol (HSRP)

    * A Cisco-proprietary FHRP designed to allow for transparent fail-over of IPv4 networks.

    * One router interface will be set as "active" and the others set as "standby".

    * Once the active interface will forward traffic to other networks.

    * Standby interfaces serve as backups in case the active fails.

    * Active interface sends multicast "Hello" packets to inform the backups that its still operational.

* HSRP for IPv6 - Cisco-proprietary FHRP providing the same functionality as HSRP but for IPv6 addressing.

* Virtual Router Redundancy Protocol version 2 (VRRPv2)

    * An industry-standard protocol defined in RFC 3768 that offers similar functionality to HSRP.

    * Like HSRP, VRRP allows multiple routers to work together to provide redundancy for the default gateway.

    * One router is elected as the master router, and the others are backup routers.

    * The master router sends periodic advertisements to inform the backup routers of its status.

    * If the master router fails, one of the backup routers is elected as the new master.

* VRRPv3 - VRRP for IPv6 addressing.

* Gateway Load Balancing Protocol (GLBP)

    * GLBP is another Cisco proprietary protocol that extends the functionality of HSRP and VRRP by providing load balancing in addition to redundancy.

    * GLBP allows multiple routers to share the traffic load for a virtual IP address, providing both redundancy and increased network capacity.

    * GLBP uses an active virtual gateway (AVG) to assign different virtual MAC addresses to different routers, distributing traffic across multiple gateways.

    * GLBP for IPv6 - CGLBP for IPv6 addressing.



HSRP Attack:

Routers must exchange HSRP hello packets at the default interval of three seconds. Packets are sent using the multicast address of 224.0.0.2 (the "all routers" IPv4 multicast address). Since multicasts are flooded over the network similar to Broadcasts, they can be intercepted by any host with layer two connectivity and can inspect the HSRP parameters.

To usurp the active router, the attacker only needs to inject false HSRP hellos claiming the active role with a higher priority.



References:

https://en.wikipedia.org/wiki/First-hop_redundancy_protocol

https://study-ccna.com/cisco-fhrp-explained/

https://www.expertnetworkconsultant.com/configuring/understanding-first-hop-redundancy-protocols-fhrp/

https://www.computernetworkingnotes.com/ccna-study-guide/first-hop-redundancy-protocol-explained.html



ACTIVITY: Frame and Packet Headers
