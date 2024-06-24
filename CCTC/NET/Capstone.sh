CAPSTONE
Hostname: UNKNOWN
IP: 10.50.37.126
creds: net3_student11:password11 (netY = Networking Class Identifier & studentX = Student Number & passwordX = Student Number)
Known Ports: UNKNOWN
Action: Execute proper movement and redirection techniques

The Capstone environment will test your knowledge and skills on all the topics covered in the CCTC Networking course. You will not be able to complete this activity with the CTFD alone.

You will not find the questions or answers to this Capstone within the CTFD or in past activities.

You will have to conduct reconnaissance within the new environment to find the questions. The CTFD is only a repository for the BASE64 converted answers.

Any system, you reach or login to, you should check the "/usr/share/cctc/" directory. This is where any/all files of interest or instructions will be provided. You should always check this directory for information, just in case.

Most tools have been removed from hosts, which will alter/dictate the way you approach gathering flags. If you want to use a tool/command from within the host (example: tcpdump, netcat, arp, etc…​) you can check to see if it is present, and you can find the tool/command via the "whereis" or "which" commands. This will provide the directory path that the tool/command can be accessed from. You may need to use the full path in some cases. Don't forget to conduct passive reconnaissance on any system you can access and active recon to find other systems and ports to interact with.

Use tools such as ssh tunnels, netcat, curl, wget, ftp, and proxychains from your own INTERNET_HOST to navigate throughout the environment and to reach and interact with devices and services.

When creating tunnels your authorized port ranges to utilize are NSS00 - NSS99
N = NetX (1-8)
SS = Student Number - (ie 01 - 40)
00-99 = available port forward ranges
i.e. Net1_student1 can use 10100 - 10199 and Net4_student14 can use 41400 - 41499

If asked to submit your answer in base64 format, you can use the following example as a reference:

If the question asks you to submit an answer of cheese in all caps converted to base64:

echo "CHEESE" | base64
Q0hFRVNFCg==

flag = capstone


# Using the questions found on Capstone-02 web-page.
# What is the Answer to Network Fundamentals Question 1?
# APIPA uses the IP network range of 169.254.0.0/16. What RFC number governs this? Enter only the BASE64 conversion of the number.
echo "3927" | base64 # RFC 3927 regarding special ip addresses

# IPv6 Uses SLAAC to resolve its Global address from the Router. What multicast destination address does it use to Solicit the router?
echo "FF02::2" | base64 # SLAAC reaches out to FF02::2 which is for only routers

# Which type of ARP is sent in order to perform a MitM attack? Specify the answer in ALL CAPS and convert to BASE64.
echo "GRATUITOUS" | base64

# An attacker built a FRAME that looks like this:
# | Destination MAC | Source MAC | 0x8100 | 1 | 0x8100 | 100 | 0x0800 | IPv4 Header | TCP Header | Data | FCS |
# What form of attack is being performed? Supply your answer in ALL CAPS and convert to BASE64.
echo "DOUBLE TAGGING" |base64

# A router receives a 5000 byte packet on eth0. The MTU for the outbound interface (eth1) is 1500. What would the fragmentation offset increment be with the conditions below?
# Origional packet Size = 5000 bytes
# MTU for outboud interface = 1500
# Packet IHL = 7
# Supply only the BASE64 conversion of the number.
(MTU - (IHL x 4)) / 8 = frag offset

Max_Data = 1500 - 28 = 1472 bytes
In_Data = 5000 - 20 = 4980 bytes
Frag_1 holds 1472 (4980 - 1472 = 3508) Frag_Offset = 0
Frag_2 holds 1472 (3500 - 1472 = 2036) Frag_Offset = 185
Frag_3 holds 1472 (2020 - 1472 = 564) Frag_Offset = 370
Frag_4 = 564; Frag_Offset = 555

Frag_Offset = Max_Data / 8 (1472 / 8 = 184)


-------------------------------------------------------------------------------

Question 1:

Using BPF’s, determine how many packets with a DSCP of 26 being sent to the host 10.0.0.103.

Provide the number of packets converted to BASE64.
sudo tcpdump -n 'ip[1]>>2=26&&ip[16:4]=0x0a000067' -r capstone-bpf.pcap | wc -l
-or-
sudo tcpdump -n 'ip[1]&252=104&&ip[16:4]=0x0a000067' -r capstone-bpf.pcap | wc -l
-or-
wireshark: ip.dsfield.dscp == 26 && ip.dst==10.0.0.103

-------------------------------------------------------------------------------

Question 2:

What is the total number of fragmented packets?

Provide the number of packets converted to BASE64.
sudo tcpdump -n 'ip[6]&32=32 || ip[6:2]&8191>0' -r capstone-bpf.pcap | wc -l  # found in miro board

-------------------------------------------------------------------------------

Question 3:

How many packets have the DF flag set and has ONLY the RST and FIN TCP Flags set?

Provide the number of packets converted to BASE64.
sudo tcpdump -n 'ip[6]&64=64 && tcp[13]=5' -r capstone-bpf.pcap | wc -l

-------------------------------------------------------------------------------

Question 4:

An attacker is targeting the host 10.0.0.104 with either a TCP full or half open scan. Based off the pcap, how many ports are open?

Provide the number of ports converted to BASE64.
sudo tcpdump -n 'ip[16:4]=0x0a000068 && tcp[13]=2' -r capstone-bpf.pcap | wc -l  # gets attempts on ip
sudo tcpdump -n 'ip[12:4]=0x0a000068 && tcp[13]=20' -r capstone-bpf.pcap | wc -l # gets denials from ip

attempts - denials = open ports

-------------------------------------------------------------------------------

# RAW Sockets are created in ________ space. Specify the one word BASE64 conversion of your answer in ALL CAPS.
echo "KERNEL" | base64

# Which module would you need to import to convert data into a corresponding 2-digit hex representation?
# Specify the module in lowercase and converted to BASE64.
echo "binascii" | base64

# What is the proper format to pro-grammatically pack the IPv4 RAW header?
# Specify the answer in the proper case. Include only what is between the single or double quotes and not the quotes themselves or the "!".
# Provide the answer converted to BASE64.
echo "BBHHHBBH4s4s" | base64

# What is the default (and most common) encoding used when converting data to be sent over the network.
# Provide your answer in ALL CAPS and converted to BASE64.
echo "UTF-8" | base64

# What type of header does TCP build to perform the checksum function?
# i.e. [ANSWER] Header
# Provide your answer in ALL CAPS and converted to BASE64.
echo "PSEUDO" | base64

---------------------------------------------------------------------------------

# Capstone-05 is attempting to attack this box from a different network on a port(s) associated with the W32/Blaster Worm - 135
# What is the message referenced by “Hint-04a.png”. Provide the message (exactly as you received it) converted to BASE64
tcpdump -i eth1 port 135 -vn


# RIPv2 seems to be running on the 10.1.1.0/25 network sniff the traffic to find what networks is avertising updates IP will be the next environment pivot to access from IH
tcpdump -i eth0 port 520 -vn
