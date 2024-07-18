7.0 Outcomes
- Describe Methods Used for Passive External Discovery
  - Dig, Whois and Other Tools
    - Dig
    - Whois
    - Zone Transfer
  - Netcraft
  - Collect Historical Content
  - Google Searches
  - SHODAN
  - Passive OS Fingerprinting (p0f)
- Describe Methods Used for Active External Discovery
  - Network Scanning and Banner Grabbing
    - PING
    - NMAP
    - Netcat
    - Curl and Wget
    - /dev/tcp
- Describe Methods Used for Passive Internal Network Reconnaissance
  - Packet Sniffers
  - Native Host Tools
- Describe Methods Used for Active Internal Network Reconnaissance
  - ARP Requests
- Perform Network Forensics
  - Map a Network Through Correlation of Relevant Network Artifacts Gathered Through Reconnaissance and Analysis

---
### 7.0.1 Section Introduction
As a defender it is important to know what systems, OS’s, and services are on the network along with normal communication patterns.

As an attacker, discovery of systems and services is crucial to formulating a plan of attack. An attacker spends 90 percent of their time performing reconnaissance and 10 percent of their time performing an actual attack.

There are four general approaches to Network Reconnaissance; Active External, Active Internal, Passive External and Passive Internal.



Active:

- Active reconnaissance refers to the proactive and deliberate exploration of a target network or system to gather information.
- Active scanning is the process of transmitting packets to a remote host and analyzing corresponding replies to locate and identify devices.
  - Port Scanning: This involves scanning the target system for open ports and services. Tools like Nmap are commonly used for this purpose. Knowing which ports are open can provide insight into the services running on the system and potential vulnerabilities.
  - Network Scanning: This involves scanning the target network for devices and their characteristics. Tools like NetScanTools or Angry IP Scanner can be used to identify hosts, their IP addresses, and other network information.
  - Vulnerability Scanning: This involves scanning for known vulnerabilities in the target system or network. Tools like Nessus or OpenVAS can automatically scan for vulnerabilities in systems and provide reports on potential weaknesses.
  - DNS Enumeration: This involves gathering information about the domain name system (DNS) of the target organization. Tools like nslookup or dig can be used to query DNS servers for information such as hostnames, IP addresses, and mail exchange (MX) records.
  - Web Application Scanning: This involves scanning web applications for vulnerabilities such as SQL injection, cross-site scripting (XSS), or directory traversal. Tools like Burp Suite or OWASP ZAP can be used to scan web applications for security flaws.
  - Social Engineering: While not strictly a technical method, social engineering involves manipulating individuals within the target organization to divulge sensitive information. This can include techniques such as phishing, pretexting, or impersonation.

---
Passive:

- Passive reconnaissance involves gathering information about a target system, network, or organization without directly interacting with it.
- On the offensive side, the client listens for beacons and other traffic sent periodically by a target. On the defensive side, passive scanning can be done using an IDS, it watches the network and look for irregular traffic or other indicators of compromise. A passive scan generally takes more time, since the client must listen and wait for traffic versus actively probing
  - Open Source Intelligence (OSINT): This involves collecting information from publicly available sources such as websites, social media profiles, public records, news articles, and online forums. OSINT tools and techniques can be used to gather information about an organization’s employees, infrastructure, technologies used, and potential vulnerabilities.
  - Network Traffic Analysis: Passive network traffic analysis involves monitoring network traffic passively to gather information about the target network. This can include analyzing network packets, monitoring DNS traffic, and observing patterns of communication to identify hosts, services, and potential vulnerabilities.
  - Domain Name System (DNS) Analysis: DNS reconnaissance involves gathering information about domain names, IP addresses, and other DNS records associated with the target organization. This can include querying DNS servers for information, performing zone transfers, and analyzing DNS cache data to gather intelligence about the target’s infrastructure.
  - WHOIS Lookup: WHOIS is a protocol used to query databases of registered domain names and IP addresses. WHOIS lookup tools can be used to gather information about domain ownership, registration dates, contact information, and other details that may be useful for reconnaissance purposes.
  - Passive DNS Analysis: Passive DNS analysis involves collecting and analyzing historical DNS data to identify patterns of domain ownership, domain associations, and changes in DNS records over time. Passive DNS databases can be queried to gather intelligence about domain names, IP addresses, and hostnames associated with the target organization.
  - Google Dorking: Google Dorking (also known as Google hacking) involves using advanced search techniques and operators to uncover sensitive information, files, or vulnerabilities exposed on the internet. By crafting specific search queries, attackers can discover publicly accessible documents, directories, login pages, and other resources that may contain valuable information about the target.

---
Internal:
- Internal reconnaissance, also known as internal scanning or internal network reconnaissance, involves gathering information about a target network from within the network itself.
- This phase typically occurs after an attacker has gained some level of access to the internal network, either through social engineering, phishing, malware, or exploiting vulnerabilities in external-facing systems.
- Internal reconnaissance is crucial for attackers seeking to escalate privileges, move laterally within the network, and identify high-value targets.
- It’s also an essential step in red teaming exercises and security assessments conducted by organizations to evaluate the security posture of their internal networks.

---
External:
- External reconnaissance, also known as external scanning or external network reconnaissance, involves gathering information about a target network from outside the network perimeter.
- This phase is typically the first step in a cyber attack or security assessment and is aimed at identifying potential entry points, vulnerabilities, and attack surfaces.
-  External reconnaissance is crucial for attackers seeking to gain initial access to a target network and for organizations conducting security assessments to identify and mitigate external threats.

![image](https://github.com/ruppertaj/WOBC/assets/93789685/d9a84ce9-b029-4274-bd5c-4d463e0b9e92)

- Passive recon - is when you gather information about a target without directly interacting with the target. In networking it means to gather information about a target without sending packets to the target. Target is not likely to generate logs or artifacts to inform them they are being targeted.
  - Open source intelligence (OSINT) to gather:
    - IP addresses
    - domain names
    - email addresses
    - names
    - hostnames
    - dns records
    - software running (to associate with CVE)
  - Using tools like:
    - Google Hacking (search engines)
    - Netcraft
    - Shodan
    - Social Media
    - DNS

- Active recon - is when you interact directly with a computer system in order to gather system specific information about the target. In networking it means to gather information about a target by sending packets to the target in order to solicit information. Target with potentially generate logs and create artifacts. The main drawback of active reconnaissance compared to passive reconnaissance is that direct interaction with the host has a chance of triggering the systems IDS/IPS and alerting people to your activity.
  - Used to find out information such as:
    - open/closed ports
    - OS of a machine
    - services running
    - banner grabbing
    - discovering new hosts
    - find vulnerable applications on a host
  - Using tools like:
    - Nmap
    - Ping
    - Traceroute
    - Netcat
    - Nessus
    - Nikito

---
### 7.0.2 Network Footprinting, Scanning, Enumeration, and Vulnerability Assessment
Network footprinting, scanning, enumeration, and Vulnerability Assessment are essential steps in the reconnaissance phase of a cybersecurity assessment or attack. Each step involves gathering information about a target network to understand its structure, devices, services, and potential vulnerabilities.


References:

[Penetration Testing Standard(PTES)](http://www.pentest-standard.org/index.php/Main_Page)
[OSINT Framework](https://osintframework.com/)
[Security Sift Passive Resonnaissance](https://www.securitysift.com/passive-reconnaissance/)

---
#### 7.0.2.1 Network Footprinting
Network footprinting involves gathering information about a target network’s infrastructure, organization, and digital footprint. This information helps attackers or security professionals understand the scope and layout of the network.

This is the process of collecting information related to our target
- Network - information related to the target network
  - DNS Domain Name
  - DNS Sub-domains
  - IP address blocks
  - Firewall/IDS/IPS discovery
  - External/Internal Websites
  - TCP/UDP services
  - VPN endpoints
  - Network Protocols
- Systems - information related to the target system(s)
  - Hostname
  - IP/MAC address
  - User accounts
  - Group accounts
  - System Banners
  - Routing Tables
  - ARP Cache
  - SNMP data
- Organization - information related to the target organization
  - Employees
  - Email addresses
  - Phone Numbers
  - Organization website
  - Security Policies
  - Org Charts

---
#### 7.0.2.2 Network Scanning
Scanning involves actively probing the target network to identify live hosts, open ports, and services running on those ports. This phase aims to discover potential entry points and vulnerabilities.

- Port Scanning - open TCP/UDP ports and services
- Network Scanning - Ip addresses, Operating systems, Network topology and Network devices
- Vulnerability Scanning - scanning/detecting known vulnerabilities or weaknesses.

---
#### 7.0.2.3 Network Enumeration
Enumeration involves extracting more detailed information about the target network, such as user accounts, shares, applications, and configurations. This phase aims to gather as much information as possible to plan further attacks or security measures.

- Types of information enumerated
  - Network Resource and shares
  - Users and Groups
  - Routing tables
  - Auditing and Service settings
  - Machine names
  - Applications and banners
  - SNMP and DNS details
  - Other common services and ports

---
#### 7.0.2.4 Vulnerability Assessment
Vulnerability assessment is a systematic process of identifying, quantifying, and prioritizing security vulnerabilities in a system, network, or application. It’s a critical component of cybersecurity risk management and helps organizations understand their exposure to potential threats.

Process of indetifying vulnerabilities on a system, network or communication channels. Some of the top vulnerabilities to look for are:

- Injection - SQL, NoSQL, OS or LDAP.
- Broken Authentication - improperly configured authentication and session management.
- Sensitive Data Exposure - Many webistes have sensitive data stored with little or no security
- XML External Entities - old or poorly configured XML processors
- Broken Access Control - not using least permissions policy for user accounts
- Security Misconfiguration - using default or poorly configured security configurations
- Cross-Site Scripting - XSS flaws or no data input validation
- Insecure Deserialization - misconfiguration allowing remote code execution
- Using Components with Known Vulnerabilities - using software/hardware with known vulnerabilities
- Insufficient Logging and Monitoring - insufficient logging/monitoring or not being able to parse through the logs


References:  
https://owasp.org/www-project-top-ten/

---
## 7.1 Describe Methods Used for Passive External Discovery
Passive host and service discovery is much less straight forward and requires more time than active discovery methods, but it carries less risk of discovery by administrators and Network System Monitoring "NSM" (IPS/IDS). Passive approaches require knowledge of particular systems, their nuances, and how they generate network traffic. In general, the passive reconnaissance approach can be categorized as attempted gathering of information about a target network or host without direct interaction.

Network owners must understand what information can be gleaned from their network traffic and have a full understanding of their network footprint. Information can be gathered from a target passively by eavesdropping on a target using tools such as Wireshark, tcpdump, and tshark.

Performing Passive Reconnaissance commonly involves identifying the topics in the following sections:



References:  
https://www.securitysift.com/passive-reconnaissance

---
### 7.1.1 Passive Recon Activities
Passive reconnaissance, commonly known as "passive recon" or "passive information gathering," entails the collection of information about a target without direct engagement with its systems. The objective is to quietly acquire data without triggering any alerts from the target. Open source intelligence (OSIT) gathering is most commonly used in this phase. This phase is crucial in cybersecurity assessments, ethical hacking, and penetration testing processes.

- OSINT sources can be divided up into six different categories of information flow:
  - Media:, print newspapers, magazines, radio, and television from across and between countries.
  - Internet, online publications, blogs, discussion groups, citizen media (i.e. – cell phone videos, and user created content), YouTube, and other social media websites (i.e. – Facebook, Twitter, Instagram, etc.). This source also outpaces a variety of other sources due to its timeliness and ease of access.
  - Public Government Data, public government reports, budgets, hearings, telephone directories, press conferences, websites, and speeches. Although this source comes from an official source they are publicly accessible and may be used openly and freely. Professional and Academic Publications, information acquired from journals, conferences, symposia, academic papers, dissertations, and theses.
  - Commercial Data, commercial imagery, financial and industrial assessments, and databases.
  - Grey literature, technical reports, preprints, patents, working papers, business documents, unpublished works, and newsletters.



References:  
http://www.pentest-standard.org/  
https://osintframework.com/  
https://www.securitysift.com/passive-reconnaissance/

---
#### 7.1.1.1 IP Addresses and Sub-domains
Usually one of the first steps in passive reconnaissance, it’s important to identify the net ranges and sub-domains associated with your target(s) as this will help scope the remainder of your activities.

- Use passive tools to collect the target’s owned IP address blocks
  - IANA or one of their IRR’s
  - https://www.iana.org/assignments/ipv4-address-space/ipv4-address-space.xhtml
- Collect all the DNS domain and sub-domain names.
  - `dig` - Queries the DNS server over UDP port 53. You can pull various DNS records registered on the DNS server.
  - `whois` - Queries the DNS Registrar over TCP port 43.
    - A domain name registrar is a business that handles the reservation of domain names as well as the assignment of IP addresses for those domain names. A domain name registrar is a business that handles the reservation of domain names as well as the assignment of IP addresses for those domain names.
  - https://sitereport.netcraft.com/
  - http://whois.domaintools.com/
  - http://viewdns.info/
  - https://dnsdumpster.com/
  - https://viz.greynoise.io/
  - https://search.censys.io/
  - https://web-check.xyz/
  - https://centralops.net/co/
  - [Fierce](https://github.com/mschwager/fierce) - is an IP and DNS recon tool is written in PERL, famous for helping IT sec professionals to find target IPs associated with domain names.
  - [Unicornscan](https://github.com/dneufeld/unicornscan) - is one of the top intel-gathering tools for security research. It has also a built-in correlation engine that aims to be efficient, flexible and scalable at the same time.
- Trace the IP route to the target using:
  - Traceroute (using TCP, UDP or ICMP)
  - https://visualtraceroute.net/
  - http://www.visualroute.com/
- BGP advertized prefixes
  - https://bgpview.io/
  - https://hackertarget.com/as-ip-lookup/

---
#### 7.1.1.2 Identifying External/3rd Party sites
- This is not typically in the scope for penetration testing but should not be overlooked as advesaries can (and do) expoit this.
- This involves external companies that support or collaborate with your target. These may have softer security.
- Target’s competitors may have details about your target that they collected for themselves.
- Look for potential [supply chain attack](https://www.csoonline.com/article/561323/supply-chain-attacks-show-why-you-should-be-wary-of-third-party-providers.html).



References:  
https://en.wikipedia.org/wiki/Supply_chain_attack  
https://gbhackers.com/cryptocurrency-miner-ubuntu-snap-store/  
https://www.radware.com/blog/security/2018/05/nigelthorn-malware-abuses-chrome-extensions/  
https://www.helpnetsecurity.com/2019/07/18/malicious-python-packages/

---
#### 7.1.1.3 Identifying People
Identifying names, email addresses, phone numbers, and other personal information can be valuable for pretexting, phishing or other social engineering activities. Use open-source to collect information on subject browse social media sites:

- Company website (example: [www.ccboe.net](https://net.cybbh.io/public/networking/latest/07_discovery/www.ccboe.net))
- Third-party data repositories (companies that host data for your targeted organization)
- Tools such as:
  - [Maltego](https://www.maltego.com/) - provides the ability to lookup email addresses based on a given domain.
  - [Recon-ng](https://github.com/lanmaster53/recon-ng) - built in the Kali Linux distribution to perform reconnaissance on remote targets.
  - [theHarvester](https://github.com/laramies/theHarvester) - fetch valuable information about any subdomain names, virtual hosts, open ports and email address of any company/website.
  - [Jigsaw](https://www.jigsawsecurityenterprise.com/) - gather information about any company employees. For companies like Google, Linkedin, or Microsoft, where you can just pick up one of their domain names (like google.com), and then gather all their employee’s emails on the different company departments.
  - [SpiderFoot](https://www.spiderfoot.net/) - automate OSINT and have fast results for reconnaissance, threat intelligence, and perimeter monitoring.
  - [Creepy](https://www.geocreepy.com/) - geo-location OSINT tool for infosec professionals. It offers the ability to get full geolocation data from any individuals by querying social networking platforms like Twitter, Flickr, Facebook, etc.
- Message boards:
- User Forums:
  - https://www.mirc.com/
  - https://discord.com/
  - https://www.reddit.com/
- Search Engines:
  - https://www.google.com/
  - https://www.bing.com/
  - https://www.yahoo.com/
  - https://duckduckgo.com/
  - https://www.ask.com/
  - https://search.brave.com/
  - https://www.search.com/
  - https://info.com/ - Meta Search engine (Google, Yahoo!, Ask, Bing, Yandex, Open Directory)
  - http://www.baidu.com/ - China
  - http://soso.com/ - China
  - https://www.sogou.com/ - China
  - https://www.petalsearch.com/ - China (huawei)
  - https://yandex.com/ - Russian
  - https://www.ecosia.org/ - environment-friendly search engine
  - https://www.naver.com/ - South Korean
  - https://www.seznam.cz/ - Czech Republic
  - https://www.mojeek.com/ - UK
  - https://www.qwant.com/ - France
  - https://swisscows.com/ - Switzerland
  - https://metager.org/ - Germany
  - https://www.qwant.com/ - European Union
  - https://qmamu.com/ - India
  - https://halalgoogling.com/ - Islamic
  - https://www.egerin.com/ - Kurdish
  - https://www.alleba.com/ - Philippines
  - https://www.eniro.se/ - Sweeden
  - https://www.goo.ne.jp/ - Japan
  - https://www.najdi.si/ - Slovenia
  - https://www.onet.pl/ - Poland
  - https://www.orange.fr/portail - France
  - https://www.parseek.com/ - Iran
  - https://www.sapo.pt/ - Portugal
  - https://search.ch/ - Switzerland
  - https://www.walla.co.il/ - Israel
  - https://www.najdi.si/ - Slovenia
- Specialty Search Engines:
  - https://www.iseek.com/#/web
  - https://www.2lingual.com/ - Searching in 2 Languages
  - https://www.criminalip.io/ - Cyber Threat Intelligence Search Engine and Attack Surface Management(ASM) platform.
  - https://bevigil.com/search - Search for assets like Subdomains, URLs, Parameters in mobile applications
- Social Media:
  - https://www.facebook.com/
  - https://www.whatsapp.com/
  - https://www.instagram.com/
  - https://www.tumblr.com/
  - https://www.tiktok.com/
  - https://twitter.com/
  - https://www.reddit.com/
  - https://www.linkedin.com/
  - https://www.pinterest.com/
  - https://www.quora.com/
  - https://www.viber.com/
  - https://www.snapchat.com/
  - https://telegram.org/
  - https://vk.com/ - Russian
  - https://ok.ru/ - Russian
  - https://www.wechat.com/ - China
  - https://www.imqq.com/ - China
  - https://qzone.qq.com/ - China
  - https://www.weibo.com/ - China
  - https://tieba.baidu.com/ - China
  - https://www.renren.com/ - China
  - https://www.kakaocorp.com/ - South Korea
  - https://cafe.naver.com/ - South Korea
  - https://mixi.jp/ - Japan
- Job Portals (To find job titles):
  - https://www.monster.com/
  - https://www.linkedin.com/
  - https://www.glassdoor.com/
  - https://www.indeed.com/
- Document and File Metadata Search and Tools:
  - https://www.filechef.com/
  - https://www.filesearch.link/ - File Search Engine
  - https://www.dedigger.com/ - Find public files in Google Drive
  - https://filepursuit.com/ - Search the web for files, videos, audios, eBooks & much more.
  - https://www.searchftps.net/ - Search and download files located on public FTP servers.
- Whois records
  - https://lookup.icann.org/en
  - https://who.is/
  - https://www.whois.com/whois/
  - https://whois.domaintools.com/
  - https://www.godaddy.com/whois
  - https://mxtoolbox.com/whois.aspx
  - https://www.domain.com/whois/whois
- Family Tree:
  - [Ancestry.com](https://www.ancestry.com/)
  - [FamilyTree.com](https://www.familytree.com/)
  - [Family Search](https://www.familysearch.org/)
  - [Family Tree DNA](https://www.familytreedna.com/)
- Email Tracking: (Hidden Images, Link Redirection) - who is checking emails
  - [YesWare](https://www.yesware.com/)
  - [HubSpot](https://www.hubspot.com/products/sales/email-tracking)
  - [Staff Base](https://staffbase.com/)
  - [GetNotify](https://www.getnotify.com/)
  - [ReadNotify](https://www.readnotify.com/)
  - [WhoReadMe](https://whoreadme.com/)
  - [DidTheyReadIt](https://www.didtheyreadit.com/)
  - [Social Engineering Toolkit (SET)](https://trustedsec.com/resources/tools/the-social-engineer-toolkit-set)
- Other people "look-up" pages:
  - https://usersearch.org/index.php
  - https://instantusername.com/
  - http://com.lullar.com/
  - https://www.truepeoplesearch.com/
  - https://www.peekyou.com/
  - https://haveibeenpwned.com/
  - https://www.beenverified.com/
  - https://checkusernames.com/
  - https://knowem.com/
  - https://www.zabasearch.com/
  - https://www.whitepages.com/
- File Metadata Tools:
  - [FOCA](https://github.com/ElevenPaths/FOCA)
  - [metagoofil](https://github.com/laramies/metagoofil)
  - [EXIF Tool](https://github.com/alchemy-fr/exiftool)
  - File Explorer (Windows)
  - Finder (macOS)

---
#### 7.1.1.4 Identifying Technologies
Identifying the types and versions of the systems and software applications in use by an organization is an important precursor to identifying potential vulnerabilities. You can ID technologies from many sources including:

- File extensions ( https://www.computerhope.com/issues/ch001789.htm ) - many are specific to certain applications operating systems
- Server responses - Various tools can identify specific signatures in network traffic.
- Job postings/interviews
  - https://www.monster.com/
  - https://www.linkedin.com/
  - https://www.glassdoor.com/
  - https://www.indeed.com/
- Directory listings on the target webpage

```
Login splash pages
```

- Website content
  - X-Powered-By
  - [Builtwith](https://builtwith.com/) identifies technologies webisites were built with.
  - [Wappalyzer](https://www.wappalyzer.com/) determines technology as you browse the website.
  - [Pentest-Tools Website Recon](https://pentest-tools.com/information-gathering/website-reconnaissance-discover-web-application-technologies)
- Content-Types
  - Server Software and Version
  - Cookie Information
  - Builtwith - detect which technologies are used on any website on the internet.
  - Tools:
    - wget
    - HTTrack
    - Pavu
    - WebRipper 2.0 (www.calluna-software.com)
    - WinWSD
    - DomainPunch
    - WebExtractor
- Public acquisition records
- [Shodan.io](https://www.shodan.io/)
- Spyse - is another OSINT search engine that lets anyone grab critical information about any website in the world. Quite simply, Spyse is an infosec crawler that gets useful information for red and blue teams during the reconnaissance process.
- Document Searches
- Google Hacking - [Database](https://www.exploit-db.com/google-hacking-database)
  - https://dorksearch.com/
  - [Google dork cheatsheet](https://gist.github.com/sundowndev/283efaddbcf896ab405488330d1bbc06)
    - site:
    ```
    site:.gov "Secret"
    site:linkedin.com intitle:starbucks "network engineer"
    ```

    - intitle:
    ```
    intitle:"Welcome to Windows 2000 Internet Services"
    intitle:"Nessus Scan Report" "This file was generated by Nessus"
    intitle:"index of" inurl:ftp
    ```

    - inurl:
    ```
    inurl:admin/login
    inurl:/admin.html
    ```
    - filetype:
    ```
    filetype:pdf "Confidential"
    filetype:ppt "Networking"
    ```

- System fingerprinting tools:
  - Ettercap – passive TCP/IP stack fingerprinting.
  - NetworkMiner – passive DHCP and TCP/IP stack fingerprinting (combines p0f, Ettercap and Satori databases)
  - p0f – comprehensive passive TCP/IP stack fingerprinting.
  - NetSleuth – free passive fingerprinting and analysis tool
  - PacketFence – open source NAC with passive DHCP fingerprinting.
  - PRADS – Passive Real-time Asset Detection System. Passive comprehensive TCP/IP stack fingerprinting and service detection
  - Satori – passive CDP, DHCP, ICMP, HPSP, HTTP, TCP/IP and other stack fingerprinting.
  - SinFP – single-port active/passive fingerprinting.
  - XProbe2 – active TCP/IP stack fingerprinting.
  - Device Fingerprint Website - Displays the passive TCP SYN fingerprint of your browser’s computer (or intermediate proxy)

---
#### 7.1.1.5 Identifying Content of Interest
Identifying web and email portals, log files, backup or archived files, or sensitive information contained within HTML comments or client-side scripts is important for vulnerability discovery and future penetration testing activities.

- Site content can reveal potential access points (e.g. web portals), sensitive data (login credentials), and more. As you browse the site be on the lookout for the following:
  - Externally facing web portals, webmail, and administrative consoles - As you navigate the site, you will want to take note of any interesting functionality that could prove useful for future penetration testing activities such as externally-facing web portals, email services, or administrative consoles. It’s possible you might come across these as you browse but you may also want to look for them with targeted Google searches.
  - Test pages - Be on the lookout for test infrastructure as well. Often test pages have fewer security controls or robust error messages when compared to their production counterparts, yet they frequently reside on (and provide access to) the same production infrastructure.
  - Log files - Log files are sometimes left exposed and publicly accessible via Google search results. Logs can contain everything from robust errors to configuration data, IP addresses, usernames and even clear text passwords
  - Backup files - Sometimes web admins retain old, possibly vulnerable versions of website pages or text versions of server-side code (php, asp, etc) that can be downloaded and reviewed offline.
  - Configuration files - Configuration files can contain sensitive connection strings, passwords, IP addresses and other valuable information.
  - Database dump files - Similar to configuration files, database dump files can contain sensitive information such as table structures and queries (for use in SQL injection testing), names, email addresses, usernames, and passwords. Searching for filetypes of sql, dbf, mdf, dat, or mdb (among others) can uncover these files.
  - Client-side code - Review of client-side HTML and scripts can reveal sensitive data or even vulnerabilities such as unsafe handling of user-provided data. BurpSuite Pro has an engagement tool called “Find Scripts” which will search the specified hosts(s) in your site map and extract content for review.
  - /etc/passwd and /etc/shadow or SAM database
    - Windows usually stores passwords in these locations:
      - Security Accounts Manager (SAM) database (C:\WINDOWS\system32\config) or (HKEY_LOCAL_MACHINE\SAM)
      - SAM file is not accessible while the OS is running. Use an external bootable CD or USB.
      - Active Directory database file that’s stored locally or spread across domain controllers (ntds.dit)
      - hashes passwords with NTLM
    - Linux and other UNIX variants typically store passwords in these files:
      - /etc/passwd (readable by everyone) - Contains the usernames
      - /etc/shadow (accessible by the system and the root account only) - Contains the passwords.
      - /etc/security/passwd (accessible by the system and the root account only)
      - /.secure/etc/passwd (accessible by the system and the root account only)
      - hashes passwords with:
        - $1 = MD5
        - $2 =Blowfish
        - $2a=eksblowfish
        - $5 =SHA-256
        - $6 =SHA-512

---
#### 7.1.1.6 Identifying Vulnerabilities
It’s possible to identify critical vulnerabilities that can be exploited with further active penetration testing activities solely by examining publicly available information

- Vulnerability Focus:
  - Network
  - OS
  - Applications
  - Service
  - Configuration Errors
- OS Fingerprinting
  - p0f ( https://lcamtuf.coredump.cx/p0f3/ )
  - Ettercap ( https://www.ettercap-project.org/ )
- The following are some of the methods you might use to identify vulnerabilities:
  - Researching known software vulnerabilities based on identified technologies
  - Examining URLs - the url may indicate what is used to host webpage.
    - .aspx may mean SharePoint
    - ASP.NET may indicate a Microsoft IIS
  - Passive scanning via an intercepting proxy
  - Shrink-wrap code - an act of exploiting holes in unpatched or poorly configured software.
  - Reviewing error messages
    - ICMP
    - HTTP(s) status codes ( https://en.wikipedia.org/wiki/List_of_HTTP_status_codes )
- Tools:
  - Saint (https://www.carson-saint.com/products/saint-security-suite/vulnerability-management/)
    - Linux or Mac
    - Identifies Vulnerabilities on:
      - Network devices
      - Operation systems
      - Desktop Apps
      - Web Apps
      - Databases
  - Nessus ( https://www.tenable.com/ )
    - Linux, Windows and Mac
    - Malware/Botnet detection
  - GFI LanGuard ( https://www.gfi.com/ )
    - Patch Management
    - Vulnerability Assesment
    - Network Auditing
    - Change Management
    - Inventory Management
  - Shadow Security Scanner ( https://www.safety-lab.com/ )
  - Core Impact ( https://coresecurity.com/ )
  - Qualys ( https://qualys.com/ )
  - OvenVAS ( https://openvas.org/ )
  - Retina CS ( https://eeye.com/ )
  - NextPost ( https://rapid7.com/ )
  - Wapiti ( https://wapiti.sourceforge.io/ )
  - MetaSploit (https://github.com/rapid7/metasploit-framework)
    - Network enumeration and discovery
    - Evade detection on remote hosts
    - Exploit development and execution
    - Work with the MFSconsole
    - Scan remote targets
    - Exploit vulnerabilities and collect valuable data
  - OvenVAS ( https://openvas.org/ ) - Open Vulnerability Assessment System
    - Simultaneous host discovery
    - Network mapper and port scanner
    - Fully integrated with SQL Databases like SQLite
    - Full support for Linux and Windows
  - Burp Suite Scanner (https://portswigger.net/burp)
    - Web Vulnerability scanner
  - Nikto (https://cirt.net/Nikto2)
    - Scans multiple ports on a server
    - IDS evasion techniques
    - Apache and cgiwrap username enumeration
    - Identifies installed software via headers, favicons and files
    - Scans specified CGI directories
  - WPScan (https://wpscan.com/wordpress-security-scanner)
    - Non-intrusive security scans
    - WP username enumeration
    - WP bruteforce attack & weak password cracking
    - WP plugins vulnerability enumeration
    - Schedule WordPress security scans
  - Web SSL Certificates
    - https://www.digicert.com/
    - https://www.ssllabs.com/
    - https://www.sslshopper.com/
- Vulnerability databases
  - NIST: ( https://nvd.nist.gov/ )
  - CVE: ( https://www.cvedetails.com/ )
  - Rapid 7: ( https://www.rapid7.com/ja/db/ )
  - Mitre Vulnerability Database: ( https://cve.mitre.org/ )
  - Open Source Vulnerability Database: ( https://www.whitesourcesoftware.com/vulnerability-database/ )

References:  
https://www.securitysift.com/passive-reconnaissance/  


---
##### 7.1.1.6.1 Compliance Auditing
Compliance auditing is a systematic examination wherein an organization’s conformity to regulatory guidelines, industry standards, and internal policies is scrutinized and assessed. The main objective is to verify that the organization is conducting its operations in alignment with relevant laws, regulations, and established protocols. The purpose of conducting compliance audits is to pinpoint any variances from the specified standards and initiate corrective measures when deemed necessary.

Compliance auditing standards refer to the established criteria and guidelines that organizations follow when conducting audits to assess their adherence to regulatory requirements, industry standards, and internal policies. These standards provide a framework for conducting thorough and effective compliance audits.

- PCI DSS - Payment Card Industry Data Security Standard (PCI DSS) compliance is designed to protect businesses and their customers against payment card theft and fraud. If your business accepts, stores, or transmits card data, PCI DSS compliance validation is required by card brands such as Visa, MasterCard and Discover.
- NERC - The North American Electric Reliability Corporation (NERC) Critical Infrastructure Protection (CIP) exists to improve the reliability of the critical bulk power SCADA systems that create and transport electricity around the continent, and the goal of a NERC compliance program is to ensure that the bulk electric system in North America is reliable, adequate and secure. It’s not enough to just plan for natural disasters or accidents-the bulk power system now must be planned, designed, built and operated in a manner that also takes into account modern threats to security, including attacks from cyber criminals. NERC compliance programs are required to help prevent these attacks.
- FISMA - The Federal Information Security Management Act (FISMA) requires Federal agencies to develop, document, and implement an information security program to safeguard their systems and data. In addition to government agencies, FISMA also applies to contractors and third parties that use or operate an information system on behalf of a Federal agency.
- SOX - Sarbanes-Oxley Act (SOX) requires that publicly-traded companies ensure their internal business processes are properly monitored and managed. Financial reporting processes are driven by IT systems, so IT needs to be configured securely and maintained properly. The Securities and Exchange Commission (SEC) has identified five areas that need to be addressed to meet SOX internal control requirements and support SOX compliance, two of which are risk assessment and monitoring.
- GLBA - The Gramm-Leach-Bliley Act is a U.S. federal law created to control how financial institutions deal with a consumer’s non-public personal information (NPI). This is information that a financial institution collects when providing a financial product or service that can identify an individual and that isn’t otherwise publicly available.
  - The Act has three main elements:
    - The Privacy Rule, which regulates the collection and use of NPI
    - The Safeguards Rule, which requires financial institutions to implement a security program to protect NPI
    - Pretexting provisions, which prohibits access to NPI under false pretense
- HIPAA - The Health Insurance Portability and Accountability Act (HIPAA) protects the privacy and security of personal health information (PHI). Any healthcare organization that stores, processes, or transmits PHI must meet HIPAA compliance requirements, including any business associates that perform functions or provide services on their behalf.
- GDPR - The General Data Protection Regulation (GDPR compliance) protects the personal data of EU citizens regardless of the geographical location of the organization or the data. Organizations around the world must be compliant with GDPR by 25th May 2018. Changes to people, processes, and technology are required to ensure that personal data is correctly controlled, processed, maintained, retained, and secured. Penalties for infringement of the General Data Protection Regulation can be up to €20,000,000 or 4% of worldwide annual turnover, whichever is the greater amount.
- CIS Benchmarks - The Center of Internet Security (CIS) is a non-for-profit organization that develops their own Configuration Policy Benchmarks, or CIS benchmarks, that allow organizations to improve their security and compliance programs and posture. This initiative aims to create community developed security configuration baselines, or CIS benchmarks, for IT and Security products that are commonly found throughout organizations.
- SCAP - The Security Content Automation Protocol (SCAP) is a method that uses open standards to organize and express security-related information. It’s not a regulation or a mandate, but it allows federal agencies to automate a great deal of manual processes and make data standardization and comparisons a lot easier.
- FDCC - The Federal Desktop Core Configuration (FDCC compliance) is an older federal standard that defines a standardized desktop configuration to improve security. Although FDCC benchmarks have been superseded by USGCB benchmarks in 2010 and 2011, many agencies are still working on their FDCC compliance. If you’re one of them, we can help you achieve FDCC compliance.
- USGCB - The United States Government Configuration Baseline (USGCB) is a United States government-wide initiative that guides federal agencies on what they can do to improve and maintain effective configuration settings focusing primarily on security. This initiative aims to create security configuration baselines for IT and security products, specifically on desktops and laptops, deployed across federal agencies. While it’s not a standalone regulation like FISMA, USGCB compliance is a core requirement of FISMA.


---
### 7.1.2 Dig, Whois and Other Tools
DNS is critical to the operation of the Internet for resolving hostnames to IP addresses. Therefore, DNS servers contain vast amounts of data that can be used to gain information.


#### 7.1.2.1 Whois
- [RFC 3912](https://tools.ietf.org/html/rfc3912)
TCP-based transaction-oriented query/response protocol that is widely used to provide information services to Internet users. While originally used to provide "white pages" services and information about registered domain names, current deployments cover a much broader range of information services. The protocol delivers its content in a human-readable format.
- The WHOIS lookup helps determine where the site is hosted, who owns the IP block, and may list organizational contacts that may be useful for social engineering.
- WHOIS works by querying DNS registrars databases over TCP port 43.
  - A domain name registrar is a business that handles the reservation of domain names as well as the assignment of IP addresses for those domain names. Examples of Domain Registrars are:
    - [Domain.com](https://www.domain.com/)
    - [Bluehost](https://www.bluehost.com/)
    - [Network Solutions](https://www.networksolutions.com/)
    - [HostGator](https://www.hostgator.com/)
    - [GoDaddy](https://www.godaddy.com/)
    - [NameCheap](https://www.namecheap.com/)
    - [DreamHost](https://www.dreamhost.com/)
    - [BuyDomains](https://www.buydomains.com/)
- Most whois queries will return false information as most people opt for privacy of their domain information in order to protect against email harvesting, spam, and social engineering attempts on the administrative contact.
```
instructor@net1:~$ whois ccboe.net
```

![image](https://github.com/ruppertaj/WOBC/assets/93789685/cc76be7e-65ac-49b9-a245-6368458d91ba)
whois



References:  
https://tools.ietf.org/html/rfc3912  
https://manpages.debian.org/buster/whois/whois.1.en.html  
https://www.cloudflare.com/learning/dns/glossary/what-is-a-domain-name-registrar/  
https://en.wikipedia.org/wiki/Domain_name_registrar  
https://www.wpbeginner.com/beginners-guide/how-to-choose-the-best-domain-registrar/

Instructor Note
Ask the students to identify answers to the questions below:

*What does ccboe stand for?*  
Columbia County Board of Education

*Who is the DNS registrar?*  
Network Solutions, LLC

*When does the domain registration expire?*  
June 30, 2021

*How many Name Servers are there?*  
2, NS1.CL.BELLSOUTH.NET, NS2.CL.BELLSOUTH.NET

*Who is the administrator?*
James Van Meter

*What is the administrator’s email address?*  
[hostmaster@ccboe.net](mailto:hostmaster@ccboe.net)

*What is the administrator’s phone number?*  
1-706-541-2721

*Where is the location of the technology department possibly located?*  
6430 Pollards Pond Road, Appling, GA 30802  
[Google Maps Link](https://www.google.com/maps/place/6430+Pollards+Pond+Road,+Appling,+GA+30802/@33.5482663,-82.3162756,3a,90y,101.87h,81.27t/data=!3m6!1e1!3m4!1sdTMwjVOn-YvUmdVH23fnWA!2e0!7i13312!8i6656!4m5!3m4!1s0x88f778a4c4a55173:0x3114865d3466cc52!8m2!3d33.547855!4d-82.316066)

- It quickly becomes apparent that if not sanitized properly, a multitude of information can be gleaned from the whois query. Occasionally, net range is displayed with a CIDR and could prove useful for future DNS reverse lookups.

*Should this be avoided and if so, how?*  
Register the domain with anonymous registration services under a pseudonym. Often times domain name registrars will offer whois privacy (also known as domain privacy) as a service that in turn replaces the user’s information in the WHOIS with information of the forwarding service aka proxy of the registrar.

*How might these be used as an defense tool?*  
If your system is being scanned or attacked you can use a WHOIS to possibly begin determining where the source of the malicious traffic is coming from.


---
#### 7.1.2.2 DIG
Dig is a tool that returns key DNS information and can be used to supplement the query for specific records.
```
instructor@net1:~$ dig ccboe.net
instructor@net1:~$ dig ccboe.net MX
instructor@net1:~$ dig ccboe.net SOA
instructor@net1:~$ dig ccboe.net TXT
```

![image](https://github.com/ruppertaj/WOBC/assets/93789685/cd486ae5-5664-4817-b1a7-3ad1635816e3)
dig1


![image](https://github.com/ruppertaj/WOBC/assets/93789685/403efb83-a5b1-4871-91cd-39255f5cdbae)
dig2


This method can be further enhanced with tools such as dnsrecon that will brute-force with a word-list to find hidden sub-domains using words such as sales, training, admin, etc. This method is considered semi-active, generating logs for unlisted sub-domains would look quite suspicious.



References:

[dig Man Page](https://manpages.debian.org/buster/dnsutils/dig.1.en.html)

Instructor Note
Ask the students to identify answers to the questions below:

*Who is the SOA?*  


*What type of mail server is listed?*  


---
7.1.2.3 Zone Transfers
A zone transfer is typical between primary and secondary DNS servers to update records on a domain. This information, if allowed to be transferred externally through misconfiguration, allows hostnames, IP’s, and IP blocks to be discovered. With this information, targets can be determined with information for possible social engineering.
```
instructor@net1:~$ dig axfr @nsztm1.digi.ninja zonetransfer.me
```

![image](https://github.com/ruppertaj/WOBC/assets/93789685/d8fc4155-43ae-4f2b-91b7-8f3748575754)
zonetransfer


[DigiNinja’s Zone Transfer Me](https://digi.ninja/projects/zonetransferme.php)


Instructor Note
Lead the students through a zone transfer using the following syntax:

This zone transfer includes tons of information, the website will guide you along and you may format questions based on what you see.

*What sub-domains have been found?*  

*What mail servers are being used?*  

*Can you determine location with the LOC file?*  


---
### 7.1.3 Netcraft
Netcraft.com can also be used to find extra information about a url, including the netblock owners and hosting history. The date first seen is December 1996 for "www.ccboe.net". Combine this with sites such as [the wayback machine](https://archive.org/web/) and see what you can come up with.

The key takeaway is that the traffic generated looks like normal DNS queries and the target is none the wiser that they are being probed for information. For further non attribution, use a third party web-site such as [dns stuff](https://www.dnsstuff.com/tools) or [central ops](https://centralops.net/co/) to perform the queries.

References:  
https://sitereport.netcraft.com/  

Instructor Note
Go to the website below and walkthrough an example with the students:

[Netcraft: www.ccboe.net](https://toolbar.netcraft.com/site_report?url=http://www.ccboe.net)

*When was the domain first registered?*  
1996


---
### 7.1.4 Collect Historical Content
Organizations often change their associated websites over time. As more emphasis is placed on security, these organizations have made more and more of their information private over time. A company may have posted their organizational charts, contact information for important people and even device type specifics on their websites in the past. There are many organizations that take snapshots of pages over time and archive these results. The Wayback Machine is the most popular example of this and can be a useful tool if you are looking for information you know was hosted in the past, but is not available now.

http://archive.org/web/

---
### 7.1.5 Google Searches
Google is the most popular internet search engine. People use it everyday to find websites about whatever topic they are searching for. Many people do not realize how robust the searching algorithms are and how they can be used to find sensitive information that can be very valuable when performing passive reconnaissance.

Here are some common Google hacking techniques:

- Filetype Search:
  - Syntax: filetype:
  - Example: filetype:pdf site:example.com
  - Purpose: Finds specific file types on a given site.
- Site-specific Search:
  - Syntax: site:
  - Example: site:example.com
  - Purpose: Limits the search to a specific website.
- Intitle and Inurl Searches:
  - Syntax: intitle: and inurl:
  - Example: intitle:"index of" inurl:backup
  - Purpose: Searches for specific words in the title or URL.
- Link Search:
  - Syntax: link:
  - Example: link:example.com
  - Purpose: Finds pages that link to a specified website.
- Cache Search:
  - Syntax: cache:
  - Example: cache:example.com
  - Purpose: Displays the cached version of a webpage.
- Related Search:
  - Syntax: related:
  - Example: related:example.com
  - Purpose: Finds websites similar to the specified domain.
- Wildcard Search:
  - Syntax: *
  - Example: site:example.*
  - Purpose: Uses a wildcard to search across multiple top-level domains.
- Combining Operators:
  - Syntax: OR, - (exclude), + (include)
  - Example: site:example.com OR site:example.net -inurl:blog
  - Purpose: Combines operators to refine search results.
- Specific File Search:
  - Syntax: ext:
  - Example: ext:sql
  - Purpose: Finds specific file types.


---
#### 7.1.5.1 Identifying sub-domains with Google searches
```
*ccboe.net -site:*.ccboe.net
```

Instructor Note
Ask the students to identify answers to the questions below:

*What sub-domains have been found?*  


*Were there any email addresses found?*  


---
#### 7.1.5.2 Identifying technologies with Google searches
```
site:*.ccboe.net "Powered by"
```
Many technologies like WordPress (for content management) will tend to have "Powered by" in the page footer

Job site listings, Linkedin, and other methods may also help find technologies.

---
### 7.1.6 SHODAN
[Shodan](https://www.shodan.io/)

![image](https://github.com/ruppertaj/WOBC/assets/93789685/e135958a-d0fc-4c9e-ab8c-ae50738c27da)
dig2

Shodan searches can reveal clues about technologies that are exposed with simple searches such as cam, phone, printer, Cisco. It is also useful for exposing remote access services, improperly configured services such as SMB, and network infrastructure.

Once an item of interest is selected, you can obtain copious amounts of information such as open services, banners, location, and applicable CVE vulnerabilities.

---
### 7.1.7 Passive OS Fingerprinting (p0f)
Passive OS Fingerprinter (p0f) is a tool which allows the passive scanning of network traffic. Passive OS fingerprinting focuses on uniqueness in IP and TCP implementations to discover which OS sent the traffic. Specifically, p0f looks at the initial TTL, the fragmentation flag, the default packet length of an IP header, the Windows size, and TCP options in TCP SYN and SYN/ACK packets.



p0f.fp (p0f signature file)
Whenever p0f fingerprints traffic it reads from the "p0f.fp" file to identify the operating system and other details.

p0f Signature Database
```
/etc/p0f/p0f.fp
```

---
#### 7.1.7.1 Module Specifications
Formatted as follows: [module: direction]
```
Table 1. Module Specifications
Name	        Description
module          name of the fingerprinting module (tcp, http, etc.)
direction       direction of the traffic, 'request' from client to server or 'response' for server to client
                For the TCP module, 'client' matches initial SYN, and 'server' matches SYN+ACK
```


Signature Groups

A signature must be preceded by a 'label' describing the fingerprinted information.
```
label = type:class:name:flavor
```

```
Table 2. Signature Groups
Name	   Description
type       typically an 's' for specific signatures and 'g' for more generic ones.
class      this provides the distinction between OS-identifying signatures (win, unix, cisco, etc.), if a '!' is indicated, that corresponds 
to more application-related signatures (NMap, Apache, Mozilla, etc.)
name       human-readable short name for what the fingerprint actually identifies (Linux, MacOS, Internet Explorer, Mozilla)
flavor     This is for any further information that needs to be appended to the label, such as "Xmas Scan" for NMap or version numbers for Linux "2.x"
```


MTU Signatures
```
Table 3. MTU Signatures
Name	              Description
label = Ethernet      self explanatory
sig = 1500            MTU size specification
```


TCP Signatures
```
sig = ver:ittl:olen:mss:wsize,scale:olayout:quirks:pclass
```

```
Table 4. TCP Signatures
Name	    Description
ver         IP version field. It is 4,6, or * if the version is unimportant to the signature
ittl        initial TTL of the IP packet
olen        IP options length. It is usually 0 for IPv4 and always 0 for IPv6
mss         maximum segment size (mss) that is specified in the TCP options. The * is used to designate that the mss varies
wsize       Windows’ size of the TCP segment. This is expressed as a fixed number, a multiple of the mss, or of the MTU. A rare but possible value is *
scale       is the Window scale (ws) value found in TCP options. If the ws option is not found, this value is 0
olayout     this field represents the TCP option types in the order they appear in the packet, separated by commas. When generating a signature for comparison with the database, this field should be the first that is generated. Eight possible options are:
```

```
Table 5. Olayout Options (continued from above)
Name	       Description
eol+n          explicit end of options followed by n bytes of padding
nop            No Operation (no-op) option
mss            maximum segment size option
ws             Window scaling option
sok            selective ACK permitted option
sack           selective ACK (rarely ever seen)
ts             timestamp option
?n             unknown option ID
quirks         properties observed in the IP or TCP headers. Two common quirks are df for the don’t-fragment flag being set and id+ for when the DF flag is set and the IP identification field is not zero.
pclass         is the payload size of the packet. This is almost always 0, because there is no payload in the three-way handshake.
```


HTTP signatures

p0f can also determine http signatures based on user agent strings and other information contained within a packet.
```
sig = ver:horder:habsent:expsw
```
```
Table 6. HTTP Signatures
Name          Description
ver           0, for HTTP/1.0, 1 for HTTP/1.1, or * for any
horder        ordered list of headers that should appear in matching traffic.
habsent       list of headers that must not appear in the matching traffic. Useful for noting the absence of standard headers such as "host"
expsw         expected substrings in the 'user-agent' or 'server' field. This is used to detect dishonest software.
```


References:

[p0f Man Page](https://manpages.debian.org/buster/p0f/p0f.1.en.html)

[NullByte: Conduct Passive OS Fingerprinting with P0f](https://null-byte.wonderhowto.com/how-to/hack-like-pro-conduct-passive-os-fingerprinting-with-p0f-0151191/)

---
### 7.1.8 Social Tactics
Social Tactics is a broad term that governs "people manipulation". This is a practice employed in most marketing today. Its studies human behavior and reactions that many may (or may not) be aware that they are doing. Similar strategies can be used to manipulate an individual into taking certain actions that they may not normally do. Social tactics can be broken down into separate venues which we will discuss individually.

---
#### 7.1.8.1 Social Engineering
Social Engineering - hacking the person. Typically involves human-to-human interactions. Can be riskier because you may have to expose your identity.

- Friendliness/Liking - Using flattery and friendliness to get what you want. People are easily persuaded by other people that they like. People were more likely to buy if they liked the person selling it to them. Some of the many biases favoring more attractive people are discussed.
- Impersonation/Authority - Pretending or pretexting to be another person with the goal of gaining access physically to a system or building. Several impersonation roles fall under the category of someone with authority. People will tend to obey authority figures, even if they are asked to perform objectionable acts.
- Conformity/Social Proof - Tendency to see an action as appropriate when others are doing it. People will do things that they see other people are doing.
- Decoying/mental buffer-overflow - People are limited in what we can focus our attention on at any moment. Exploit this limitation by distractions to conceal what they are truly seeking.
- Diffusion of responsibility - When individuals believe that many others are present or have done a similar act, they as individuals do not bear the full burned of responsibility. It alleviates the stress on the employee and makes it easier for them to comply. "Don’t worry, I will call the Police so you don’t need to worry about it."
- Reverse Social Engineering - Complex questions can yield data. The attacker appears to be in a position of authority. Employees will ask for information.
  - Components: Sabotage, Advertising, and Assisting. You can break someone’s computer while they are out then show up while they are there and pretend to be tech support and ask " I heard someone’s computer was not working".
  - Questions: Language structure that forces the execution of instructions. A person can ask seemingly random questions that may not seem like much but they can be fishing for valuable information.
  - Job Interview: post a really attractive job position and ensure the link is sent through the target company. If any respond to the ad you can set up an interview to ask questions about setting up security in a network and people tend to divulge details about their own network.
- Commitment and consistency – If people commit, orally or in writing, to an idea or goal, they are more likely to honor that commitment because of establishing that idea or goal as being congruent with their self-image. Even if the original incentive or motivation is removed after they have already agreed, they will continue to honor the agreement.
- Reciprocity/Quid pro quo - Reciprocity is an expectation that you will treat others the way they treat you. Reciprocity is based on a universal understanding that people give back to others who have given first.
- Scarcity/Urgency - Perceived scarcity of an item or time will generate demand.
- Sympathy - People want to help others who are in desperate need. Playing the victim in desperate need, crying baby, etc. Sharing of unhappiness or suffering. Implies concern, or a wish to alleviate negative feelings others are experiencing.
- Guilt - Feeling of obligation for not pleasing, not helping, or not placating another. Acceptance of responsibility for someone else’s misfortune or problem because it is bothersome to see that someone suffers.
- Equivocation - An equivocal statement or question starts out sounding reasonable and gets the target to agree to certain ideas or requests by deliberately attempting to create uncertainty or ambiguity. After that, the meaning of key terms is changed, thus causing the victim to agree to things they would have never accepted at the beginning.
- Ignorance - Pretending to be uninformed to manipulate a victim to give you information.
- Affiliation - Name dropping to establish credibility. Reduces the target’s suspicion of the attacker’s motives.
- Honeytrap - Practice with the use of romantic or sexual relationships for a particular gain.



References:  
https://faculty.nps.edu/ncrowe/oldstudents/laribeethesis.htm  
https://en.wikipedia.org/wiki/Social_engineering_%28security%29


---
#### 7.1.8.2 Technical based
Technical based - utilizes technical means to perform manipulation on a person without needing human-to-human interaction. These can include the use of phones, cell phones, computers, and social media. Less risk because you do not typically expose yourself.

- phishing - Phisher sends an e-mail that appears to come from a legitimate business—a bank, or credit card company—requesting "verification" of information and warning of some dire consequence if it is not provided. The e-mail usually contains a link to a fraudulent web page that seems legitimate—with company logos and content—and has a form requesting everything from a home address to an ATM card’s PIN or a credit card number.
- spear phishing - Although similar to "phishing", spear phishing is a technique that fraudulently obtains private information by sending highly customized emails to few end users. It is the main difference between phishing attacks because phishing campaigns focus on sending out high volumes of generalized emails with the expectation that only a few people will respond.
- whaling - similar to spear phishing except the target is a VIP.
- vishing - Using a telephone system to gain access to private personal and financial information from the public.
- smishing - The act of using SMS text messaging to lure victims into a specific course of action. Like Phishing it can be clicking on a malicious link or divulging information
- pharming - Attack intended to redirect a website’s traffic to another (fake) site. Pharming can be conducted either by changing the hosts file on a victim’s computer or by exploitation of a vulnerability in DNS server software. DNS servers are computers responsible for resolving Internet names into their real IP addresses. Compromised DNS servers are sometimes referred to as "poisoned". Pharming requires unprotected access to target a computer, such as altering a customer’s home computer, rather than a corporate business server.
- Malvertising - The use of online advertising to spread malware. It typically involves injecting malicious or malware-laden advertisements into legitimate online advertising networks and webpages. Online advertisements provide a solid platform for spreading malware because significant effort is put into them in order to attract users and sell or advertise the product. Because advertising content can be inserted into high-profile and reputable websites, malvertising provides malefactors an opportunity to push their attacks to web users who might not otherwise see the ads, due to firewalls, more safety precautions, or the like. Malvertising is "attractive to attackers because they 'can be easily spread across a large number of legitimate websites without directly compromising those websites'."
- Watering Hole - Water holing is a targeted social engineering strategy that capitalizes on the trust users have in websites they regularly visit. The victim feels safe to do things they would not do in a different situation. A wary person might, for example, purposefully avoid clicking a link in an unsolicited email, but the same person would not hesitate to follow a link on a website they often visit. So, the attacker prepares a trap for the unwary prey at a favored watering hole. This strategy has been successfully used to gain access to some (supposedly) very secure systems.
- Device Lean Behind (Road Apple) - The hacker leaves a USB drive, CD-RW, phone, or other storage devices around an office and writes a tempting label on it, like salary information or a famous musician (if it’s a CD). Oftentimes, if someone finds a USB drive, they’ll just start to use it on their own.
- Evil Troll - Intentional trolling of social media to antagonize and bait others into conflict. In doing so, the troll may be able to manipulate the victim into revealing sensitive or secret information out of anger or to prove a point.
- Rogue Security (Scareware) - A form of malware which impersonates a fake or simulated anti-spyware or security scanner. It tricks you into believing you are getting protection, when in fact you are infecting your network with malware and the social engineer is stealing your data.
- Bluetooth
  - Bluejacking. This is the practice of sending unsolicited messages to nearby Bluetooth devices. Bluejacking messages are typically text, but can also be images or sounds. Bluejacking is relatively harmless, but does cause some confusion when users start receiving messages.
  - Bluesnarfing. Any unauthorized access to or theft of information from a Bluetooth connection is bluesnarfing. A bluesnarfing attack can access information, such as email, contact lists, calendars, and text messages. Attackers use tools such as hcitool and obexftp.
  - Bluebugging. Bluebugging attacks allow an attacker to take over a mobile phone. Attackers can listen in on phone conversations, enable call forwarding, send messages, and more.
  - Car whisperer. The attack takes advantage of a common flaw in Bluetooth vehicle implementation wherein certain car manufacturers use the same 1234 or 0000 passkeys for authentication and encryption. Hackers can use a laptop and a Bluetooth antenna to connect and listen in on hands-free conversations or talk directly to the people in the car. Secure your car’s audio, Bluetooth headset, and entertainment system by changing the manufacturer’s PIN code.
  - Location tracking. A Bluetooth attack used for locating and tracking devices. Those usually prone to this attack are fitness enthusiasts because their fitness wearables are always connected to their Bluetooth.
  - BlueBorne. To perform a BlueBorne attack, hackers need to infect your device with malware. That will allow an attacker to take control of the device. What makes things even worse is that, once your device is infected, it can infect other devices it connects to. If your device’s software is outdated and doesn’t use a VPN, it is vulnerable to BlueBorne attacks.

---
#### 7.1.8.3 Other Types
Other types - These do not typically involve using technical means or human-to-human interaction.

- Shoulder Surfing - looking over the victim’s shoulders to collect information.
- Eavesdropping - It is the process of intercepting unauthorized communication to gather information
- Dumpster Diving - looking for treasure in someone else’s trash.
- Tailgating (piggybacking) - When an unauthorized person physically follows an employee into a restricted corporate area or system.
- Baiting - offering something enticing to an end user in exchange for private data. The “bait” comes in many forms, both digital – such as a music or movie download, and physical – such as a branded flash drive labeled “Executive Salary Summary Q3 2017” that is left out on a desk for someone to find. Once the bait is taken, malicious software is delivered directly into the victim’s computer.
- War Driving/Chalking - identifying open Wi-Fi hotspots.


References:  
[Development of Methodical Social engineering Taxonomy Project](https://faculty.nps.edu/ncrowe/oldstudents/laribeethesis.htm)  
[Cialdini’s 6 Principles of Persuasion Science](http://www.atlas101.ca/pm/concepts/cialdinis-6-principles-of-persuasion-science/)


---
## 7.2 Describe Methods Used for Active External Discovery
Active external discovery involves actively identifying and probing the external-facing assets, systems, and vulnerabilities of an organization or network from an external viewpoint. This is a key component of the reconnaissance phase in cybersecurity assessments, penetration testing, and ethical hacking. In contrast to passive reconnaissance, where information is collected without direct interaction with the target, active external discovery entails the deployment of probes and requests to collect information and pinpoint potential weaknesses.

---
### 7.2.1 Network Scanning and Banner Grabbing
Network scanning is obviously a critical part of reconnaissance, as it allows you to take a look into the hardware structure and software capabilities of a target. One of the main goals is to discern the vulnerabilities of your target, whether it be an adversary or your own organization. Scanning can be approached in several different manners, but here we will focus on it categorically. The biggest difference in this stage compared to passive is that we will now send packets to our target. This greatly increases the chance of discovery.

---
#### 7.2.1.1 Scanning Nature
- Active - this method aims to provide a comprehensive report of possible open or closed ports at the time of the scan. Active scanning typically performs very fast, and can contain options to vary that speed. However, it is flawed when attempting to detect ports that are filtered by firewalls. A well-known disadvantage of active scanning is that it is very intrusive. Active probes typically solicit a response that would not have been sent otherwise. This traffic is more likely to be detected and logged by the host. In this methodology, packets (whether legal or illegal combinations) will be sent to a target, hence "active". The "stealth" strategies discussed later are still considered active by this definition. in this section, we will focus on active scanning.
- Passive - identifies network services by observing traffic generated by servers and hosts as it passes an observation point. Distinctively, passive scanning has the advantage of being non-intrusive. In fact, it generally cannot be detected without in-depth and purposeful investigation. Due to the obscure nature of passive scanning, it can run long-term to better detect active services running on transient hosts such as machines that are frequently powered off or hosts temporarily disconnected from the network. Passive scanning can also detect services that active scanning may miss due to firewall configurations. In this methodology, the service acts more as a sniffer, and no "hard" packet is sent out.


---
#### 7.2.1.2 Scanning Strategy
- Remote to Local - refers to a remote host, outside the boundary of a specific network, performing some sort of scan on hosts internal to an enterprise network. This is one of the most commonly used pen-testing or attack methods. It is likely to come from unknown external adversaries. This form of scanning is risky and can put defenders on alert. To avoid this you can try methods of scanning to make it not look like a scan. This can be done by scanning random ports over random amounts of time. You can also source the scans from different IP addresses.
- Local to Remote - occurs when a host, within the administrative control of an enterprise network, scans systems outside the network boundary. This strategy may cause serious legal issues against an enterprise network without the appropriate permissions since its infrastructure could be used for malicious purposes against Internet systems. This can be ideal for offense. Imagine having a persistance on a 3rd party target that your primary target does business with and perform scans from this 3rd party.
- Local to Local - refers to a host that scans systems within the boundaries of an enterprise in which it resides. Local to local scanning activity can occur within or between network subnets and is normally employed by network/security admins per policy. This is common when attackers are on the network and are trying to discover other hosts and perform lateral movement.
- Remote to Remote - does not depend on certain boundaries. It mainly refers to worldwide scanning campaigns. Rather than focusing on a specific network as a target, it aims at probing and exploiting the Internet’s services vices. This strategy is often distributed, possesses sophisticated stealth capabilities, and is typically highly coordinated.


---
#### 7.2.1.3 Scanning Approach
- Aim
  - Wide Target Scanning:
    - Scope: Wide target scanning involves scanning a broad range of IP addresses or a large network segment.
    - Purpose: The primary goal of wide target scanning is to gather information about a large number of systems within a network or across the internet.
    - Approach: Wide target scanning typically involves using scanning tools like Nmap, Masscan, or Shodan to sweep through a wide range of IP addresses, identifying active hosts, open ports, and potentially vulnerable services.
    - Advantages:
      - Provides a comprehensive overview of the network landscape.
      - Helps identify potential entry points and weak spots across a large network.
    - Challenges:
      - Generates a large volume of data that may require extensive analysis.
      - May result in network congestion or trigger security alerts if performed without proper authorization.
  - Target-Specific Scanning:
    - Scope: Target-specific scanning focuses on a specific set of IP addresses or a particular subset of systems within a network.
    - Purpose: The goal of target-specific scanning is to gather detailed information about specific systems or assets of interest.
    - Approach: Target-specific scanning involves selecting specific IP addresses or systems based on predefined criteria, such as criticality, importance, or suspicion of vulnerability. The scanning is tailored to gather detailed information relevant to the selected targets.
    - Advantages:
      - Allows for a more focused and efficient use of resources.
      - Provides in-depth information about specific systems or assets of interest.
    - Challenges:
      - Requires prior knowledge or intelligence about the target to select appropriate systems for scanning.
      - May overlook potential vulnerabilities or entry points in other parts of the network.
- Method
  - Single Source Scan - operates from a one to many fashion
    - operates from a one (source) to one (or many) targets fashion
    - vertical scan - consists of a port scan of some or all ports on a single computer
    - horizontal scan – scans a single port, a range of ports, or specific ports across multiple IP addresses
    - strobe scan - port scan of multiple ports across multiple IP addresses
    - block scan - port scan against all ports on multiple IP addresses
  - Distributed Scan - multiple systems in a union to scan a network or host of interest
    - multiple source systems act in a union strategy to scan a network or host of interest
    - reduces the scanning footprint of any single system and thus decreases the likelihood of being detected


---
#### 7.2.1.4 Service Discovery (Port Scanning)
Service Discovery sends TCP or UDP packets to hosts on specific ports. This method queries which hosts are up and which sockets are bound. Because it is most likely that multiple packets are sent to multiple hosts, these techniques are very noticeable on the network unless a large amount of time (low and slow) is taken while completing these scans. For purposes intended to avoid detection, "stealth scans" can be employed. These techniques attempt to avoid filtering devices by using alternative sets of flag combinations to appear as legitimate traffic.

The most common methods of port scanning are SYN scans and TCP Full Connect Scans, with the first considered to be "stealth". Other types of "stealth" scans will be explored later in this section.

---
### 7.2.2 PING
Active External Network Reconnaissance: Scans with FPING or PING

Broadcast Ping

A broadcast ping sends an ICMP echo request to the network broadcast address. Send one ICMP packet that every host receives and all active hosts should respond. Most systems no longer respond to a broadcast ping.


Using ping and ping sweep

A Ping or ping sweep sends an ICMP echo request (icmp type 8) to one or many usable address on a network. It waits to receive a ICMP echo repy (icmp type 0) from active devices. If used, there should be a delay between pings, and hosts pinged should not be sequential.

This is effective if there are no firewalls, but it is very noisy. It is common for firewalls to block ICMP echo requests/replys. If this is the case, then using only ping for reconnaissance will give actors conducting the recon false information thinking there are no other active hosts on the network. Many modern OS’s like Windows 7 drop an ICMP Echo Request by default for security reasons.

A ping sweep in IPv6 is infeasible because there are too many addresses in a typical /64 network.
```
ping [options] destination
```

Options:

- `-c count`: Specify the number of packets to send (e.g., ping -c 4 will send four packets).
- `-i interval`: Specify the interval between packets in seconds.
- `-t timeout`: Specify the maximum time to wait for a response.
- `-s packetsize`: Specify the size of the data portion of the packet.
- `-q`: Quiet output. Displays only summary information at the end.
- `-W timeout`: Similar to -t, this option specifies the timeout in seconds but is supported on some systems instead of -t.
- `-f`: Flood ping. Sends a large number of packets rapidly for testing network performance.
- `-v`: Verbose output. Displays detailed information about each packet.
- `-p`: specify a pattern (in hex) to be sent in the ICMP echo request packets.

Ping sweep

- `-c (--count count)` - Stop after sending (and receiving) count.
```
for i in {1..254}; do (ping -c 1 192.168.65.$i | grep "bytes from" &) ; done
```

Using FPING:

- `-g (--generate) addr/mask` - Generate a target list from a supplied IP netmask, or a starting and ending IP.
- `-a (--alive)` - Show systems that are alive.
```
fping -g -a 10.1.0.0/24
```

Using NMAP:

- `-sn`: Ping Scan - disable port scan
```
nmap –sn 10.0.0.0/24 (was -sP which is now deprecated)
```

References:  
[Fping Man Page](https://manpages.debian.org/buster/fping/fping.8.en.html)  
[NMAP Man Page](https://manpages.debian.org/buster/nmap/nmap.1.en.html)  
[Ping Man Page](https://manpages.debian.org/buster/inetutils-ping/ping.1.en.html)


---
### 7.2.3 NMAP
Active External Network Reconnaissance: Scans with NMAP

NMAP (Network Mapper) is a popular open source tool for network discovery, exploration and security auditing. NMAP is a command line tool but has a Graphical User Interface (GUI) version call ZENMAP that comes installed when NMAP is installed.

[NMAP.org](https://nmap.org/)

The default scanning method depends on whether the scan is executed as a user or root. When conducted as a user, the default scan employs a TCP full connect (-sT) as creating RAW SOCKETS, required for other scans, necessitates permissions that a user typically lacks. On the other hand, when executed as a root user, the default scan type is a SYN Scan (-sS). Regardless of the chosen scan method, if specific ports are not designated, NMAP will automatically scan the 1000 most commonly used TCP or UDP ports.

- When NMAP starts its port discovery the result can be one of six states: open, closed, filtered, unfiltered, open|filtered, or closed|filtered.
  - The six port states recognized by Nmap:
    - open - An application is actively accepting TCP connections, UDP datagrams or SCTP associations on this port. Open TCP ports are determined by receiving a SYN/ACK response while no response is common for UDP open ports. Finding these is often the primary goal of port scanning. Security-minded people know that each open port is an avenue for attack. Attackers and pen-testers want to exploit the open ports, while administrators try to close or protect them with firewalls without thwarting legitimate users. Open ports are also interesting for non-security scans because they show services available for use on the network.
    - closed - A closed port is accessible (it receives and responds to Nmap probe packets), but there is no application listening on it. This is typically determined by receiving a RST flag on TCP ports or an ICMP Destination unreachable, Destination port unreachable (Type 3 Code 3) on a UDP port. They can be helpful in showing that a host is up on an IP address (host discovery, or ping scanning), and as part of OS detection. Because closed ports are reachable, it may be worth scanning later in case some open up. Administrators may want to consider blocking such ports with a firewall. Then they would appear in the filtered state, discussed next.
    - filtered - Nmap cannot determine whether the port is open because packet filtering prevents its probes from reaching the port. If a RST or ICMP message was not received from the probed port then it can be assumed that the port may be filtering these probes. The filtering could be from a dedicated firewall device, router rules, or host-based firewall software. These ports frustrate attackers because they provide so little information. Sometimes they respond with ICMP error messages such as type 3 code 13 (destination unreachable: communication administratively prohibited), but filters that simply drop probes without responding are far more common. This forces Nmap to retry several times just in case the probe was dropped due to network congestion rather than filtering. This slows down the scan dramatically.
    - unfiltered - The unfiltered state means that a port is accessible, but Nmap is unable to determine whether it is open or closed. Only the ACK scan, which is used to map firewall rulesets, classifies ports into this state. Scanning unfiltered ports with other scan types such as Window scan, SYN scan, or FIN scan, may help resolve whether the port is open.
    - open|filtered - Nmap places ports in this state when it is unable to determine whether a port is open or filtered. This occurs for scan types in which open ports give no response. The lack of response could also mean that a packet filter dropped the probe or any response it elicited. So Nmap does not know for sure whether the port is open or being filtered. The UDP, IP protocol, FIN, NULL, and Xmas scans classify ports this way.
    - closed|filtered - This state is used when Nmap is unable to determine whether a port is closed or filtered. It is only used for the IP ID idle scan.

---
- SYN Scan

SYN scan sends only one TCP packet with the SYN flag set to each destination port and waits for a SYN/ACK or RST. This is also known as a Stealth Scan. This method reports if there is an application listening on the target port and does not register on the host system, because no ACK is sent to the target. This method does not retrieve any information about the service.
```
nmap –sS 172.16.32.2
hping3 172.16.32.2 -S -V -p 443
```

- TCP Three-Way Handshake:
  - In a typical TCP connection, a three-way handshake occurs:
    - The scanning tool (Nmap) sends a SYN (synchronize) packet to the target port.
    - If the port is open and accepting connections, the target system responds with a SYN-ACK (synchronize-acknowledge) packet.
    - Finally, the scanning tool sends an ACK (acknowledge) packet to complete the connection setup.
- Packet Generation:
  - In a TCP SYN scan, Nmap sends SYN packets to the target ports to initiate a connection.
  - Unlike a TCP Full Connect scan, it does not complete the three-way handshake by sending an ACK packet after receiving a SYN-ACK response.
- Target Response:
  - If the target port responds with a SYN-ACK packet, indicating that the port is open and accepting connections, Nmap does not complete the connection setup.
  - If the port is closed or filtered (firewalled), the target system typically responds with an RST (reset) packet to indicate that the connection cannot be established.
- Interpreting Results:
  - If Nmap receives a SYN-ACK packet in response to the SYN packet, it marks the port as open.
  - If Nmap receives an RST packet in response to the SYN packet, it marks the port as closed.
  - If Nmap does not receive any response, it typically indicates that the port is filtered (firewalled).
- Use Cases:
  - TCP SYN scans are fast and stealthy, making them suitable for scanning large numbers of ports quickly.
  - They are commonly used for reconnaissance to identify open ports and potentially vulnerable services on target systems.
  - TCP SYN scans are less likely to be logged and detected compared to TCP Full Connect scans because they do not complete the TCP connection setup.


---
- Full Connect Scan

Full-Connect scan establishes a complete TCP three-way handshake with a system. The advantage of this method is that a fully functional connection to the target host is made which allows information to be gathered from the listening service (aka banner grabbing). The down side to this method is that the connection is logged on the system being targeted. If done many times, a netstat on that system shows many established connections between the source and target.
```
nmap –sT –sV 10.16.32.23
(Full TCP connect, service versioning)
nmap –sT 172.16.32.2

```
- TCP Three-Way Handshake:
  - In a typical TCP connection, a three-way handshake occurs:
    - The scanning tool (Nmap) sends a SYN (synchronize) packet to the target port.
    - If the port is open and accepting connections, the target system responds with a SYN-ACK (synchronize-acknowledge) packet.
    - Finally, the scanning tool sends an ACK (acknowledge) packet to complete the connection setup.
- Packet Generation:
  - In a TCP Full Connect scan, Nmap sends SYN packets to the target ports to initiate a connection.
  - If the target port responds with a SYN-ACK packet, indicating that the port is open and accepting connections, Nmap proceeds to complete the connection by sending an ACK packet.
  - If the port is closed or filtered (firewalled), the target system typically responds with an RST (reset) packet to indicate that the connection cannot be established.
- Target Response:
  - If the target port responds with a SYN-ACK packet, indicating that the port is open, Nmap completes the TCP connection by sending an ACK packet.
  - If the port is closed or filtered, the target system typically responds with an RST packet, indicating that the connection cannot be established.
  - Nmap analyzes the responses to determine the status of each scanned port.
- Interpreting Results:
  - If Nmap receives a SYN-ACK packet followed by an ACK packet, it marks the port as open.
  - If Nmap receives an RST packet in response to the SYN packet, it marks the port as closed.
  - If Nmap does not receive any response, it typically indicates that the port is filtered (firewalled).
- Use Cases:
  - TCP Full Connect scans are reliable and thorough, providing accurate information about the status of each scanned port.
  - They are useful for reconnaissance to identify open ports and potentially vulnerable services on target systems.
  - TCP Full Connect scans are more likely to be logged and detected compared to other scan types (e.g., SYN scans, NULL scans), but they provide more detailed information about the target system’s TCP/IP stack behavior.


---
- Null Scan

A null scan has no flags set and a sequence number of 0. All legitimate traffic has flags set, causing any null scan traffic to stand out if viewed. This scan is useful to penetrate firewalls and routers set to filter certain flags out since it uses no flags. Open and filtered ports should have no response, filtered ports may also send an ICMP unreachable message, and closed ports should send a RST packet.
```
nmap -sN 10.50.1.1
hping3 -c 1 -V -p 80 -s 5050 -Y 10.50.1.1
```

- TCP Flags:
  - TCP (Transmission Control Protocol) packets contain various flags, including SYN, ACK, FIN, RST, PSH, URG, and SYN-ACK.
  - In a null scan, Nmap sends TCP packets with none of these flags set, making the packet effectively "empty" in terms of TCP flags.
- Packet Generation:
  - Nmap generates TCP packets with no TCP flags set and sends them to the target system.
  - This essentially means that no specific request or action is being made by the sender, as no flags are set in the TCP header.
- Target Response:
  - If a port is open and the system receives a null packet, it may respond in various ways depending on its configuration:
    - Some systems may respond with an RST (Reset) packet to indicate that the port is closed.
    - Other systems may simply drop the packet without any response.
    - In some cases, the system may respond with different behavior, which can be indicative of its TCP/IP stack implementation.
- Interpreting Results:
  - If Nmap receives an RST packet in response to the null packet, it marks the port as closed.
  - If Nmap does not receive any response, it typically indicates that the port is open or filtered (firewalled). However, as with other TCP scans, this can also happen if the target system is configured not to respond to null packets.
- Stealthiness:
  - Null scans are considered stealthy because they send packets with no TCP flags set, making them less likely to be detected by intrusion detection/prevention systems (IDS/IPS).
  - Some firewalls and security devices may not be configured to detect or block null packets, allowing the scan to proceed undetected.
- Use Cases:
  - Null scans are used for reconnaissance to identify open ports and potentially vulnerable services on target systems.
  - They can be effective in certain scenarios where other scanning techniques might be detected or blocked.


---
- FIN Scan

A fin scan is a packet with just the FIN flag set. The packet tries to close a connection that does not exist as a way to obtain information. Like the null scan it works to go through firewalls and routers, in addition to being considered stealthier due to the illegal flag combination. Open and filtered ports should have no response, filtered ports may also send an ICMP unreachable message, and closed ports should send a RST packet.
```
nmap -sF 25.50.75.100
hping3 -c 1 -V -p 80 -s 5050 -F 25.50.75.100
```

- TCP Flags:
  - TCP (Transmission Control Protocol) packets contain various flags, including SYN, ACK, FIN, RST, and others.
  - The FIN (Finish) flag is used to indicate the end of data transmission in a TCP connection.
- Packet Generation:
  - In a FIN scan, Nmap generates TCP packets with only the FIN flag set and sends them to the target system.
  - The absence of the SYN flag (used to initiate a connection) in the packet means that no connection is established.
- Target Response:
  - If a port is open and the system receives a packet with the FIN flag, it should typically respond with an RST (Reset) packet to indicate that the port is closed.
  - If a port is closed, some systems might respond with an RST packet, while others might simply drop the packet without any response.
- Interpreting Results:
  - If Nmap receives an RST packet in response to the FIN packet, it marks the port as closed.
  - If Nmap does not receive any response, it typically indicates that the port is open or filtered (firewalled). However, it’s important to note that this can also happen if the target system is configured not to respond to FIN packets.
- Stealthiness:
  - FIN scans are considered stealthy because they don’t complete the TCP handshake, making them less likely to be logged by intrusion detection/prevention systems (IDS/IPS).
  - Some older or poorly configured firewalls and security devices may not detect or block FIN packets, allowing the scan to proceed undetected.
- Use Cases:
  - FIN scans are often used to perform reconnaissance on target systems while minimizing the chance of detection.
  - They can be useful for identifying open ports and potentially vulnerable services without triggering alerts on monitored networks.


---
- XMAS Tree Scan

A christmas tree scan is a packet with varying definitions. From nmap it is defined as a packet with FIN, PSH, and URG flags set, while ISS (IBM Internet Security Systems) defines it as all flags are set. Open and filtered ports should have no response, filtered ports may also send an ICMP unreachable message, and closed ports should send a RST packet.
```
nmap -sX 7.92.5.19
hping3 -c 1 -V -p 80 -s 5050 -M 0 -UPF 7.92.5.19
```

- TCP Flags:
  - TCP (Transmission Control Protocol) packets contain various flags, including FIN, URG, PSH, RST, SYN, and ACK.
  - In an Xmas scan, Nmap sets the FIN (Finish), URG (Urgent), and PSH (Push) flags in the TCP header.
- Packet Generation:
  - Nmap generates TCP packets with the FIN, URG, and PSH flags set and sends them to the target system.
  - This combination of flags is unusual and may bypass certain firewall or intrusion detection system (IDS) configurations.
- Target Response:
  - If a port is open and the system receives an Xmas packet, it may respond in various ways depending on its configuration:
    - Some systems may respond with an RST (Reset) packet to indicate that the port is closed.
    - Other systems may simply drop the packet without any response.
    - In some cases, the system may respond with different behavior, which can be indicative of its TCP/IP stack implementation.
- Interpreting Results:
  - If Nmap receives an RST packet in response to the Xmas packet, it marks the port as closed.
  - If Nmap does not receive any response, it typically indicates that the port is open or filtered (firewalled). However, as with other TCP scans, this can also happen if the target system is configured not to respond to Xmas packets.
- Stealthiness:
  - Xmas scans are considered stealthy because they send packets with unusual combinations of TCP flags, which may evade detection by some security devices.
  - Some firewalls and IDS/IPS systems may not be configured to detect or block Xmas packets, allowing the scan to proceed undetected.
- Use Cases:
  - Xmas scans are used for reconnaissance to identify open ports and potentially vulnerable services on target systems.
  - They can be effective in certain scenarios where other scanning techniques might be detected or blocked.


---
- UDP Scan

A UDP Scan can be used to find *nix hosts that are blocking TCP and ICMP traffic. Since UDP is a stateless protocol it is often used to get through stateful firewalls. This kind of scan is not very useful for service discovery because UDP is connection-less. UDP is dependent on the application as to how or if there is a response.
```
nmap –sU -v 10.10.100.3
```

- UDP Basics:
  - UDP is a connectionless protocol, meaning it doesn’t establish a connection before sending data.
  - It sends packets (datagrams) without verifying whether the recipient is available or ready to receive the data.
  - UDP is often used for real-time communication where speed and efficiency are more critical than reliability.
- UDP Scan Operation:
  - In a UDP scan, the scanning tool sends UDP packets to specific ports on the target system.
  - The scanning tool doesn’t wait for a response. Instead, it sends the packets and moves on to the next port.
  - If a UDP packet is received by the target system on a closed port, the system typically responds with an ICMP port unreachable message.
  - If a UDP packet is received on an open port, the target system may not send any response, as UDP doesn’t require acknowledgment.
  - Therefore, determining whether a UDP port is open or closed can be more challenging compared to TCP ports.
- Interpreting Results:
  - When analyzing the results of a UDP scan, the absence of a response doesn’t necessarily mean the port is closed. It could be open, but the target system might be configured not to respond to UDP packets.
  - Confirmation of an open UDP port often requires additional techniques, such as application-specific probes or packet sniffing to detect responses from the target system.
  - False positives and false negatives are common in UDP scanning due to the unreliable nature of UDP.
- Use Cases:
  - UDP scanning is commonly used for discovering services and applications that might be running on non-standard ports or where TCP scanning might not provide accurate results.
  - It’s particularly useful for identifying services like DNS (Domain Name System), SNMP (Simple Network Management Protocol), and DHCP (Dynamic Host Configuration Protocol), which primarily rely on UDP.


---
- Idle Scan

An idle scan is a more complex stealth technique that utilizes the previously discussed SYN scan. The scan aims to gather port information using a zombie station on the network where the scanning process appears to have been initiated by the zombie IP address instead of the actual source station who will spoof this address later in the process. This scanning method exploits IP fragmentation identification sequences and implements IP address spoofing.
```
nmap -sI 10.10.5.6 25.23.4.7
```

- Principle of IP ID Sequence Prediction:
  - Some systems increment their IP ID (Identification) field for each packet they send, including packets destined for other hosts.
  - If a system receives packets that it hasn’t initiated (like those from an idle scan), its IP ID sequence can reveal whether the scanned port is open, closed, or filtered.
- Preparation Phase:
  - The scanning process starts with identifying a suitable "zombie" system that meets specific criteria:
    - It must be idle (not actively communicating with other hosts).
    - It must have predictable IP ID sequence generation behavior.
    - It must be able to reach the target host.
    - The attacker sends crafted SYN packets to the zombie host, making it initiate connections to the target host as part of the idle scan.
- Idle Scan Execution:
  - The attacker sends SYN packets to the zombie host, requesting connections to the desired target port.
  - The zombie host sends the SYN packets to the target as if they were originated by the zombie.
  - The attacker monitors the changes in the IP ID sequence of packets received from the target.
  - By analyzing the changes in the IP ID sequence, the attacker can infer whether the target port is open, closed, or filtered without directly interacting with the target.
- Interpreting Results:
  - If the IP ID sequence increases after sending a SYN packet to the target port, it indicates that the port is open.
  - If the IP ID sequence remains the same or changes unpredictably, it suggests that the port is closed or filtered.
  - The attacker correlates the IP ID sequence changes with the SYN packets sent to determine the status of each scanned port.
- Stealthiness and Anonymity:
  - Idle scans are considered stealthy and hard to detect because they leverage third-party hosts (zombies) to perform the scanning.
  - Since the scans appear to originate from the zombie host, the target system logs show activity from the zombie, not from the attacker.
- Use Cases:
  - Idle scans are useful when stealth is paramount, such as in penetration testing or ethical hacking scenarios.
  - They can help identify open ports and services on a target system without triggering alarms or raising suspicion.


---
- Decoy scan

A decoy scan sends multiple packets to each port with different source addresses. This makes it difficult to detect the source but generates lot of traffic. Using ME in your IP list specifies where it is used in the order, and with larger amounts of IPs can mean that yours will not display.
```
nmap -D 1.2.3.4, 5.6.7.8,ME 100.200.10.20
```

- Decoy IP Addresses:
  - In a decoy scan, the attacker specifies multiple IP addresses (decoy hosts) in addition to their own IP address.
  - These decoy IP addresses are chosen to be addresses that are unlikely to be associated with the attacker, such as IPs from other networks or even legitimate hosts on the internet.
- Packet Generation:
  - Nmap generates TCP SYN packets (or other types of probes) as part of the scan.
  - In addition to sending SYN packets from the attacker’s IP address, Nmap also sends SYN packets from the specified decoy IP addresses.
  - The target system receives these packets and logs them as potential scan attempts.
- Target Response:
  - When the target system receives SYN packets from multiple IP addresses, it may become confused about the true source of the scan.
  - The target system may log the decoy IP addresses as potential sources of the scan, making it harder to trace the scan back to the real attacker.
- Interpreting Results:
  - From the perspective of the target system, it appears as if the scan is originating from multiple sources (decoy hosts) rather than just one.
  - This can make it more difficult for the target system to identify the true source of the scan or to distinguish it from legitimate network traffic.
- Stealthiness:
  - Decoy scans are considered stealthy because they blend the attacker’s activity with legitimate traffic from decoy hosts.
  - By using decoy IP addresses, the attacker can make it harder for intrusion detection systems (IDS) and network administrators to detect and respond to the scan.
- Use Cases:
  - Decoy scans are often used by attackers to conceal their true identity and evade detection during reconnaissance activities.
  - They can be particularly useful when conducting penetration tests or security assessments where stealth is important.


---
- Window Scan

A window scan functions like an ACK scan but uses the windows size of the responses to determine whether it is open or closed. An ACK scan returns most results as filtered and can be fairly inaccurate. By using the window size the scan can better determine if it is open, closed, or filtered. If the window field is non zero it will display as open, a zero window field will display as closed, and either no response or ICMP unreachable will display as filtered.
```
nmap -sW 10.66.35.10
```

---
- RPC scan

A RPC scan is looking for services that use RPC (remote Procedure Call). RPC allows for remote commands to be run on machines and this scan will determine the services and version of the service when run. In updated versions of nmap -sR is aliased to -sV (version scanning) and activates version scanning with the RPC scanning.
```
nmap -sR 10.50.22.29
```

---
- FTP bounce scan

A FTP bounce scan uses an intermediate ftp server to send files to a third party to determine open ports. This scan requires an anonymous login.
```
nmap -b 10.1.1.3 10.2.5.1
```

---
- OS fingerprinting scan

An OS fingerprinting scan uses TCP/IP stack fingerprinting to determine what OS is being used. By sending TCP and UDP packets it gathers information such as window size, TCP option ordering and IP ID sampling. It runs that information against its OS database. If a match is found it provides Vendor, OS, Generation, and device type.
```
nmap -O 6.2.9.5
```

---
- Version scan

A version scan uses open ports and the nmap-service-probes databases to query services to confirm the service running on a port and provide the version of the service running. This allows exploits to be properly chosen for use since different versions and patches are susceptible to different things.
```
nmap -sV 10.30.50.70
```

---
-Maimon scan

A maimon scan is a FIN/ACK probe. Named after the discoverer, it is meant to determine open and closed ports on BSD derived systems. Other systems will generate a RST packet regardless of the port’s state. No response indicates either open or filtered, RST closed, and ICMP unreachable error as filtered.
```
nmap -sM 10.90.20.80
```

---
- ICMP echo discovery probe

An ICMP echo ping uses the ping program to send an echo request(8) expecting an echo reply(0) back from available hosts. many devices are set to either drop or reject pings now making this an ineffective scan against properly defended networks. This is expected to be used mainly by system admins against their internal network.
```
nmap -PE 88.55.22.77
```

---
- Timestamp Discovery Probe

A timestamp probe functions in the same fashion and with the same issues and a ICMP echo discovery probe. However, it uses a ICMP code 14(timestamp reply) instead.
```
nmap -PP 10.9.8.7
```

---
- Netmask Request Discovery Probe

A netmask request probe uses the same basis as both the ICMP echo discovery probe and the timestamp discovery probe. For this scan, however, it uses the ICMP code 18(address mask reply) instead.
```
nmap -PM -Pn 5.3.7.9
```

---
- TCP SYN Discovery Ping

A syn/ack discovery ping sends an empty TCP packet with only the SYN flag set. When sent, this scan expects a RST packet if the port is closed or a SYN/ACK if the port is open. By default it uses only port 80 and is designed to work only for privileged users on Unix boxes. The scan automatically uses a workaround if the user is not privileged. Returns improper results
```
nmap -PS21-50 55.66.77.22
```

---
- TCP ACK Discovery Ping

A TCP discovery ping works like the SYN Discovery ping but sets the ACK flag instead of the SYN flag. Both are offered to better allow a user access around or through a firewall. Only works on the same network
```
nmap -PA21-50 1.9.2.8
hping3 -c 1 -V -p 80 -s 5050 -A 10.9.2.8 (TCP ACK Scan)
```

---
- UDP Discovery Ping

A UDP Discovery scan uses the same idea as both the SYN Discovery ping and the ACK Discovery ping. The difference here is that instead of a TCP packet it uses a UDP packet. Packets are empty except for a few ports (53 and 161). ICMP unreachable messages indicate a closed port, any other ICMP message or no response indicates a down/unreachable host, open ports also will drop responses if there is no payload. The lack of true responses makes this an unreliable scan, but it is able to get around firewalls designed for TCP. Does not return a proper response
```
nmap -PU21-50 45.60.75.90
```

---
- SCTP INIT Scan

A SCTP INIT scan has characteristics of both TCP and UDP with other features as well. This is the SCTP version of the TCP SYN scan and is able to get through most firewalls. It is considered fairly stealthy and gives reliable open, closed, and filtered results. An INIT-ACK shows as open, no response shows as filtered, and ABORT shows as closed.
```
nmap -sY 17.34.51.68
```

---
- NMAP - TIME-OUT
- `-T0` - Paranoid - 300 Sec
- `-T1` - Sneaky - 15 Sec
- `-T2` - Polite - 1 Sec
- `-T3` - Normal - 1 Sec
- `-T4` - Aggresive - 500 ms
- `-T5` - Insane - 250 ms


---
- NMAP - DELAY
  - `--scan-delay <time>` - Minimum delay between probes
    - Nmap to wait at least the given amount of time between each probe it sends to a given host.
  - `--max-scan-delay <time>` - Max delay between probes
    - Specifies the largest delay that Nmap will allow.


---
- NMAP - RATE LIMIT
  - `--min-rate <number>` - Minimum packets per second
    - Nmap will do its best to send packets as fast as or faster than the given rate.
  - `--max-rate <number>` - Max packets per second
    - Nmap will try to keep the sending rate at or above the given rate of packets per second.


---
- Additional "nmap" Options
  - `-n` disables name resolution
  - `-R` resolves names to IP addresses
  - `-iR` choose random targets
  - `-p` port ranges
  - `-F` Fast mode
  - `-v` verbosity level
  - `-d` debugging level
  - `-6` IPv6 scanning
  - `-A` OS detection, version detection, script scanning, and traceroute
  - `-PE` - ICMP Ping
  - `-Pn` - No Ping



References:  
[Nmap Reference Guide](https://nmap.org/book/man.html)  
[Nmap Man Page](https://manpages.debian.org/buster/nmap/nmap.1.en.html)  
[Nmap Timing Options](https://nmap.org/book/man-performance.html#:~:text=When%20the%20%2D%2Dmin%2Drate,rate%20in%20packets%20per%20second.)  


---
###7.2.4 Firewalking
- Firewalking
  - Firewalking is a technique used to determine if packets can pass through a firewall without being blocked. It involves sending packets with TTL values set to expire just before reaching the firewall, and observing whether ICMP Time Exceeded messages are returned by the firewall or other devices.
  - Firewalking can help identify open ports and services allowed through a firewall, as well as potential security holes or misconfigurations in firewall rules.
  - Firewalking requires careful selection of TTL values and may not always yield conclusive results, especially if the firewall or intermediate devices are configured to block ICMP messages or hide their presence.
- Traceroute:
  - Traceroute is a tool used to trace the route packets take from the local machine to a destination host. It works by sending packets with incrementally increasing Time-To-Live (TTL) values and observing the ICMP Time Exceeded messages returned by intermediate routers. **This allows the traceroute tool to map out the network path taken by packets to reach the destination.** 
  - Traceroute is commonly used to diagnose network connectivity issues, identify routing loops or delays, and troubleshoot network performance problems.
  - Traceroute does not have the capability to bypass firewalls or security devices, as it relies on the cooperation of intermediate routers to return ICMP Time Exceeded messages.
```
traceroute 172.16.82.106
traceroute 172.16.82.106 -p 123
sudo traceroute 172.16.82.106 -I
sudo traceroute 172.16.82.106 -T
sudo traceroute 172.16.82.106 -T -p 443
```

References:

[Firewalk : Can Attackers See Through Your Firewall?](https://www.giac.org/paper/gsec/312/firewalk-attackers-firewall/100588)


---
### 7.2.5 Netcat
Active External Network Reconnaissance: Scans with Netcat

Netcat, also known as "nc," is a versatile networking utility that allows for reading from and writing to network connections using TCP or UDP protocols. It’s often referred to as the "Swiss Army knife" of networking tools due to its wide range of functionalities. Netcat is available on most Unix-like operating systems, including Linux, macOS, and BSD, as well as on Windows platforms.

Netcat is a tool that can be used to create various inbound/outbound tcp (or udp) connections.

- Some actions that Netcat can perform:
  - Port Scanning: Netcat can be used to perform basic port scanning by attempting to connect to a range of ports on a target host. This can help identify open ports and services running on a system.
  - File Transfer: Netcat allows for the transfer of files between systems over a network connection. It can act as both a client and a server, facilitating the transfer of data in either direction.
  - Remote Shell Access: Netcat can be used to establish a simple remote shell session between two systems, allowing for command execution and interaction with a remote system’s shell.
  - Port Forwarding: Netcat can be used to set up port forwarding or redirection, allowing traffic destined for one port on a system to be forwarded to another port on a different system.
  - Chat and Messaging: Netcat can facilitate real-time chat or messaging between two systems by establishing a network connection and allowing users to exchange messages.
  - Network Debugging: Netcat can be used for network debugging and troubleshooting purposes, such as testing network connectivity, checking firewall rules, and analyzing network traffic.

> It is important to ensure you identify what version of netcat you have installed, this will let you know what options you can and cannot use!

```
nc [OPTIONS] [TARGET IP] [TARGET PORT]

nc -h       (Help Menu)
man nc      (Man Pages)
```
- `-z` : Port scanning mode i.e. zero I/O mode.
- `-v` : Be verbose [use twice -vv to be more verbose].
- `-n` : Use numeric-only IP addresses i.e. do not use DNS to resolve ip addresses.
- `-w1` : Set time out value to 1. Else it will use the default TCP timeout period of 3-5 seconds.
- `-u` : To switch to UDP.



Example Scan syntax’s will look similar to this:

Netcat does not use the (-p) to specify ports to scan. The (-p) is only used with the (-l) to specify a listening port.

- To specify the ports to scan (connect) they simply need to be entered after the IP address separated by a space.
- You can specify one port or a range of ports using the hyphen (-).
- Netcat does not allow the use of commas (,). To separate ports they must be separate by a space.


---
- To scan one TCP port
```
nc -zv [TARGET IP] 443
nc -zv [TARGET IP] 80
nc -zv [TARGET IP] 21
nc -zv [TARGET IP] 22
nc -zv [TARGET IP] 23
nc -zv [TARGET IP] 25
```

---
- To scan one UDP port
```
nc -zuv [TARGET IP] 443
nc -zuv [TARGET IP] 67
nc -zuv [TARGET IP] 53
nc -zuv [TARGET IP] 69
nc -zuv [TARGET IP] 53
```

---
- To scan a range of ports
```
## really fast scanner with 1 timeout value ##
netcat -v -z -n -w 1 [TARGET IP] 1-1023
```

---
- To scan Discontiguous ports
```
netcat -v -z -n -w 1 [TARGET IP] 21-23 25 80 443
```

---
- Example BASH TCP scan script using netcat and a for loop:

Netcat can only scan one IP address at a time and is not able to scan whole network blocks like NMAP can. We can however create a script using a for loop to scan a range of IP address and ports.

Create the `scan.sh` file:
```
nano scan.sh
```

Copy and paste the following contents into the `scan.sh` file:
```
#!/bin/bash

echo "Enter network address (e.g. 192.168.0): "
read net
echo "Enter starting host range (e.g. 1): "
read start
echo "Enter ending host range (e.g. 254): "
read end
echo "Enter ports space-delimited (e.g. 21-23 80): "
read ports

for ((i=$start; $i<=$end; i++))

do
    nc -nvzw1 $net.$i $ports 2>&1 | grep -E 'succ|open'
done

# (-v) running verbosely (-v on Linux, -vv on Windows),
# (-n) not resolving names. numeric only IP(no D.S)
# (-z) without sending any data. zero-I/O mode(used for scanning)
# (-w1) waiting no more than 1second for a connection to occur
# (2>&1) redirect STDERR to STDOUT. Results of scan are errors and need to redirect to output to grep
# ( | grep -E 'succ|open') for Debian/Ubuntu to display only open connections
```

Make the `scan.sh` file executable:
```
chmod +x scan.sh
```

---
- Example BASH UDP scan script using netcat and a for loop:

Netcat can only scan one IP address at a time and is not able to scan whole network blocks like NMAP can. We can however create a script using a for loop to scan a range of IP address and ports.
```
#!/bin/bash

echo "Enter network address (e.g. 192.168.0): "
read net
echo "Enter starting host range (e.g. 1): "
read start
echo "Enter ending host range (e.g. 254): "
read end
echo "Enter ports space-delimited (e.g. 21-23 80): "
read ports

for ((i=$start; $i<=$end; i++))

do
    nc -nuvz $net.$i $ports 2>&1 | grep -E 'succ|open'
done

# (-v) running verbosely (-v on Linux, -vv on Windows),
# (-n) not resolving names. numeric only IP(no D.S)
# (-z) without sending any data. zero-I/O mode(used for scanning)
# (-w1) waiting no more than 1second for a connection to occur
# (2>&1) redirect STDERR to STDOUT. Results of scan are errors and need to redirect to output to grep
# ( | grep -E 'succ|open') for Debian/Ubuntu to display only open connections
```

---
- One-liner to scan a range of IPs for specific ports using Netcat:
-E (--extended-regexp) - Interpret PATTERNS as extended regular expressions.
- Horizontal Scanning - Many or all ports on one target.
  - TCP
  ```
  for i in {1..254}; do nc -nvzw1 172.16.82.$i 20-23 80 2>&1 & done | grep -E 'succ|open'
  ```

  - UDP
  ```
  for i in {1..254}; do nc -nuvzw1 172.16.82.$i 1000-2000 2>&1 & done | grep -E 'succ|open'
  ```

Depending on the flavor of linux you are using, netcat open port output can respond with "open" (Debian) or "succeeded" (Ubuntu).



- Vertical Scanning - One, many, or all ports across several targets.
  - TCP
  ```
  nc -nzvw1 172.16.82.106 21-23 80 2>&1 | grep -E 'succ|open'
  ```

  - UDP
  ```
  nc -nuzvw1 172.16.82.106 1000-2000 2>&1 | grep -E 'succ|open'
  ```

---
- Netcat Banner Grabbing

SSH Ports:
```
nc 10.10.0.40 22
 SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u4
```

Telnet ports:
```
nc -t 10.10.0.40 23
 ���� ��#��'����������!����Debian GNU/Linux 10
 blue-internet-host-student-19 login:
```

HTTP Ports:
```
echo "GET /" | nc 10.10.0.40 80
 <html>
 <h2>This is the webserver on Internet Host</h2>
 </html>
```

References:  
[Netcat Official Site](http://netcat.sourceforge.net/)  
[Cyberciti Netcat Example](https://www.cyberciti.biz/faq/linux-port-scanning/)  
[Netcat Man Page](https://manpages.debian.org/buster/netcat-openbsd/netcat.1.en.html)  
[Grep Man Page](https://manpages.debian.org/buster/grep/grep.1.en.html)  

---
### 7.2.6 Curl and Wget
- Curl

Curl is a Linux command line tool which has the purpose of transfering data to and from servers. It can be used with any of the following protocols (HTTP, FTP, IMAP, POP3, SCP, SFTP, SMTP, TFTP, TELNET and LDAP). For this class you will mainly be using it to interact with service ports in order to see if they return any flags, or to identify what service is actually running on the port with banner grabbing.

Curl defaults to HTTP unless otherwise specified with the appropriate protocol designator.
```
curl http://www.google.com

curl http://www.google.com:443

curl http://www.google.com/file.txt

curl http://www.google.com/file.txt -o output.txt
```

```
curl ftp://123.45.67.8

curl ftp://123.45.67.8/file.txt

curl ftp://123.45.67.8/file.txt -o output.txt
```

---
- Wget

Wget works much the same way as curl, only it is used to download files from the server instead of just reading the content that is there.

Also like curl, it defaults to HTTP, but can be used with HTTPS and FTP. Wget can follow links in HTML, XHTML, and CSS pages.

Using the option of -r will download everything at the location in the folder structure and will place it in a new folder on your local system which is named after the url or IP address where the files were downloaded.
```
wget -r http://172.16.82.106

wget -r http://172.16.82.106:80
```

```
wget -r ftp://172.16.82.106
```

References:  
[Curl Man Page](https://manpages.debian.org/stretch/curl/curl.1.en.html)  
[Wget Man Page](https://manpages.debian.org/buster/wget/wget.1.en.html)  


---
## 7.3 Describe Methods Used for Passive Internal Network Reconnaissance
Passive internal network reconnaissance involves discreetly acquiring information about an organization’s internal network infrastructure without engaging directly with the systems. This reconnaissance method is commonly employed in the early phases of cybersecurity assessments, penetration testing, or ethical hacking within the internal network environment. In contrast to active reconnaissance, which entails the use of probes and requests, passive internal network reconnaissance centers on the unobtrusive collection of data without causing alerts or disruptions to the network’s functionality. In this phase we commonly use commands on the internal system itself to collect information.


---
### 7.3.1 Packet Sniffers
Passive Internal Network Reconnaissance: Traffic Sniffing

- Sniffing network traffic is one of the most useful passive techniques, but possibly the most involved. Even without a SPAN port, useful traffic is broadcast on a switched network. ARP/NDP and DHCP requests tell about hosts; CDP and STP inform about infrastructure devices; and the Server Message Block (SMB) Protocol is always seeking peers. If the point of presence is a server, other hosts send traffic to it, then use TTLs and ephemeral ports to guess what type of OS is generating the traffic. Passive OS fingerprinting gives a much more precise guess. Remember, TTLs, MAC addresses, and IP addresses can tell if the sending system is on the local network or has to be routed.
- Capturing raw signals from the wire is an easy way to learn about a network and how devices and applications communicate. Hardware-based sniffers are best for capturing raw signals from the wire, though they range in price and accessibility. Software-based sniffers rely on the NIC of the host system to relay traffic through the OS and usually cannot see all signals on the wire, such as the preamble and a frame’s CRC, limiting their use in some situations. Another limiting factor of software sniffers is the operating mode of the NIC, of which two exist:
  - Non-promiscuous — default mode for most NICs. Only passes traffic destined for its MAC address, its multicast groups, or broadcast.
  - Promiscuous — the NIC passes all signals to the OS. Most Unix-based systems support promiscuous mode natively; Windows requires additional drivers to enable promiscuous mode, such as WinPcap. Most software sniffers use the standard BPF syntax. The most common output file format is the standard .pcap file (packet capture).
  - tcpdump — A command-line tool native to most Linux systems and has been ported to Windows and many Berkeley Software Distribution (BSD)-based systems.
  - Wireshark — A graphical user interface (GUI)-based tool with its own display filter syntax. Available on Windows and most Linux distributions.


---
### 7.3.2 Native Host Tools
Passive Internal Network Reconnaissance: Information Gathering on Hosts


---
#### 7.3.2.1 IP Address
```
Windows: ipconfig
Linux: ifconfig (depreciated)
Linux: ip address
```

```
student@internet-host-student-01:~$ ip address
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1450 qdisc mq state UP group default qlen 1000
    link/ether fa:16:3e:b0:af:e0 brd ff:ff:ff:ff:ff:ff
    inet 10.10.0.40/27 brd 10.10.0.63 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::f816:3eff:feb0:afe0/64 scope link
       valid_lft forever preferred_lft forever
```

---
#### 7.3.2.2 System DNS
Displays all current TCP/IP network configuration values and refreshes Dynamic Host Configuration Protocol (DHCP) and Domain Name System (DNS) settings. Used without parameters, ipconfig displays Internet Protocol version 4 (IPv4) and IPv6 addresses, subnet mask, and default gateway for all adapters. Additional provided valuable:

- Linux:
```
cat /etc/resolv.conf
```

- Windows:
```
ipconfig /displaydns
```

Displays the contents of the DNS client resolver cache, which includes both entries preloaded from the local Hosts file and any recently obtained resource records for name queries resolved by the computer. The DNS Client service uses this information to resolve frequently queried names quickly, before querying its configured DNS servers.
```
ipconfig /all
```

Displays the full TCP/IP configuration for all adapters. Adapters can represent physical interfaces, such as installed network adapters, or logical interfaces, such as dial-up connections.


---
#### 7.3.2.3 ARP (Address Resolution Protocol)
This will display all cached IPv4 to MAC address resolutions. This will typically allways have the Gateway IP address and MAC address entered. It will have additional entries if its communicated with other local devices recently.
```
Windows: arp -a
Linux: arp -a (depreciated)
Linux: ip neighbor
```

```
student@internet-host-student-01:~$ ip neighbor
10.10.0.62 dev eth0 lladdr fa:16:3e:b2:eb:3b REACHABLE
```


---
#### 7.3.2.4 Netstat/ss
Netstat/SS can be used to view all open TCP and UDP ports on a system. This can be useful to identify services running on the system and communicating applications.

The `ss` command (Socket Statistics) in Linux is used to display detailed information about network sockets and connections. It is a powerful alternative to the older netstat command.
```
Windows: netstat
Linux: netstat (depreciated)
Linux: ss
```

Example options useful for both netstat and ss: `-a` = Displays all active connections and ports. `-n` = No determination of protocol names. Shows 22 not SSH. `-t` = Display only TCP connections. `-u` = Display only UDP connections. `-p` = Shows which processes are using which sockets. `-l` = Displays only listening sockets. `-r` = Display routing information. `-e` = Display extended socket information. `-h` = Display help message with usage information. `-s` = Display summary statistics. `-o` = Show timer information (TCP).
```
student@internet-host-student-01:~$ ss -antlp
State       Recv-Q Send-Q                 Local Address:Port                                Peer Address:Port
LISTEN      0      128                                *:23                                             *:*
LISTEN      0      128                        127.0.0.1:6010                                           *:*
LISTEN      0      128                        127.0.0.1:6011                                           *:*
LISTEN      0      128                                *:80                                             *:*
LISTEN      0      128                                *:22                                             *:*
LISTEN      0      128                              ::1:6010                                          :::*
LISTEN      0      128                              ::1:6011                                          :::*
LISTEN      0      2                                 :::3389                                          :::*
LISTEN      0      128                               :::80                                            :::*
LISTEN      0      32                                :::21                                            :::*
LISTEN      0      128                               :::22                                            :::*
LISTEN      0      2                                ::1:3350                                          :::*
```

References:  
[ss Man page](https://manpages.debian.org/buster/iproute2/ss.8.en.html)  
[netstat Man page](https://manpages.debian.org/buster/net-tools/netstat.8.en.html)  


---
#### 7.3.2.5 Services File
The services file provides a list of well-known port numbers mapped to each commonly associated service and any optional aliases that the service may use. Each OS maintains this file, which follows a simple structure.
```
Windows: %SystemRoot%\system32\drivers\etc\services

Linux/Unix: /etc/services
```

Keep in mind that the port mappings are just a simple translation from port to service name. It is possible for an HTTP server to be listening on port 23, but the OS which is using the services file would still list telnet.

services file format:
```
<service> <port>/<protocol> <aliases> #Comments
```

Example:
```
http 80/tcp www www-http #World Wide Web
```

In this example, TCP port 80 is associated with the http service and two optional aliases, www and www-http, are given. The services file is located most commonly in the /etc/ directory and the table below shows common locations by OS.
```
Protocol & Port Common Service
TCP 21 FTP
TCP 22 Secure Shell (SSH)
TCP 23 Telnet
TCP 25 SMTP (email)
TCP/UDP 53 DNS
UDP 67/68 DHCP
TCP 80 HTTP
TCP 110 POP3 (email)
UDP 123 Network Time
Protocol (NTP)
TCP 443 HTTPS
TCP 445 Server Message Block (SMB) (File Sharing)
UDP 514 Syslog
```

References:  
https://man7.org/linux/man-pages/man5/services.5.html  
https://www.cs.clemson.edu/course/cpsc424/material/TCP%20UDP%20Services/etc-services.pdf  
https://www.ibm.com/docs/en/rational-synergy/7.2.1?topic=server-services-file  


---
#### 7.3.2.6 Operating System Information
**Linux**

To determine Linux operating system information from the command line, you can use various commands depending on the specific information you need:

- Distribution Information:
```
lsb_release -a
```

Provides detailed distribution information, including the release number, codename, and description. cat /etc/*-release: Displays distribution-specific information stored in release files.

- Kernel Version:
```
uname -a
```

Shows kernel version, system architecture, and other system information. cat /proc/version: Displays kernel version and build information.

- System Architecture:
```
arch
```

Shows the system architecture.

- Hardware Information:
```
lshw: Lists detailed hardware configuration.
lscpu: Displays CPU information.
lsblk: Lists block devices (disk drives).
```

---
**Windows**

To determine Windows operating system information from the command line:

- Operating System Version:
```
systeminfo: Displays detailed system information, including OS version, build number, and installed hotfixes.
```

- Kernel Version:
```
ver: Displays the Windows version.
```

- System Architecture:
```
wmic os get osarchitecture: Shows the system architecture.
```

- Hardware Information:
```
wmic cpu get name: Displays CPU information.
wmic diskdrive get caption: Lists disk drives.
wmic memorychip get capacity: Shows installed memory capacity.
```

---
#### 7.3.2.7 Local Processes
```
Windows: tasklist
Linux/Unix: top
Linux/Unix: ps
```

`ps -elf` - `ps` displays information about a selection of the active processes. `-e` - Select all processes. Identical to `-A`. `-l` - Long format. The `-y` option is often useful with this. `-f` - Do full-format listing.


```
student@internet-host-student-01:~$ ps -elf
F S UID        PID  PPID  C PRI  NI ADDR SZ WCHAN  STIME TTY          TIME CMD
4 S root         1     0  0  80   0 - 14322 -      Jul01 ?        00:00:43 /sbin/init
1 S root         2     0  0  80   0 -     0 -      Jul01 ?        00:00:00 [kthreadd]
1 S root         3     2  0  80   0 -     0 -      Jul01 ?        00:00:00 [ksoftirqd/0]
1 S root         5     2  0  60 -20 -     0 -      Jul01 ?        00:00:00 [kworker/0:0H]
1 S root         7     2  0  80   0 -     0 -      Jul01 ?        00:00:19 [rcu_sched]
1 S root         8     2  0  80   0 -     0 -      Jul01 ?        00:00:00 [rcu_bh]
1 S root         9     2  0 -40   - -     0 -      Jul01 ?        00:00:02 [migration/0]
1 S root        10     2  0  60 -20 -     0 -      Jul01 ?        00:00:00 [lru-add-drain]
5 S root        11     2  0 -40   - -     0 -      Jul01 ?        00:00:01 [watchdog/0]
1 S root        12     2  0  80   0 -     0 -      Jul01 ?        00:00:00 [cpuhp/0]
1 S root        13     2  0  80   0 -     0 -      Jul01 ?        00:00:00 [cpuhp/1]
5 S root        14     2  0 -40   - -     0 -      Jul01 ?        00:00:01 [watchdog/1]
1 S root        15     2  0 -40   - -     0 -      Jul01 ?        00:00:01 [migration/1]
1 S root        16     2  0  80   0 -     0 -      Jul01 ?        00:00:00 [ksoftirqd/1]
1 S root        18     2  0  60 -20 -     0 -      Jul01 ?        00:00:00 [kworker/1:0H]
5 S root        19     2  0  80   0 -     0 -      Jul01 ?        00:00:00 [kdevtmpfs]
1 S root        20     2  0  60 -20 -     0 -      Jul01 ?        00:00:00 [netns]
1 S root        21     2  0  80   0 -     0 -      Jul01 ?        00:00:00 [khungtaskd]
1 S root        22     2  0  80   0 -     0 -      Jul01 ?        00:00:00 [oom_reaper]
1 S root        23     2  0  60 -20 -     0 -      Jul01 ?        00:00:00 [writeback]
1 S root        24     2  0  80   0 -     0 -      Jul01 ?        00:00:00 [kcompactd0]
1 S root        26     2  0  85   5 -     0 -      Jul01 ?        00:00:00 [ksmd]
1 S root        27     2  0  99  19 -     0 -      Jul01 ?        00:00:00 [khugepaged]
1 S root        28     2  0  60 -20 -     0 -      Jul01 ?        00:00:00 [crypto]
1 S root        29     2  0  60 -20 -     0 -      Jul01 ?        00:00:00 [kintegrityd]
1 S root        30     2  0  60 -20 -     0 -      Jul01 ?        00:00:00 [bioset]
1 S root        31     2  0  60 -20 -     0 -      Jul01 ?        00:00:00 [kblockd]
1 S root        32     2  0  60 -20 -     0 -      Jul01 ?        00:00:00 [devfreq_wq]
1 S root        33     2  0  60 -20 -     0 -      Jul01 ?        00:00:00 [watchdogd]
1 S root        34     2  0  80   0 -     0 -      Jul01 ?        00:00:00 [kswapd0]
1 S root        35     2  0  60 -20 -     0 -      Jul01 ?        00:00:00 [vmstat]
1 S root        47     2  0  60 -20 -     0 -      Jul01 ?        00:00:00 [kthrotld]
1 S root        48     2  0  60 -20 -     0 -      Jul01 ?        00:00:00 [ipv6_addrconf]
1 S root        84     2  0  60 -20 -     0 -      Jul01 ?        00:00:00 [bioset]
1 S root        85     2  0  60 -20 -     0 -      Jul01 ?        00:00:00 [bioset]
1 S root        86     2  0  60 -20 -     0 -      Jul01 ?        00:00:00 [bioset]
1 S root        87     2  0  60 -20 -     0 -      Jul01 ?        00:00:00 [ata_sff]
1 S root        88     2  0  60 -20 -     0 -      Jul01 ?        00:00:00 [bioset]
1 S root        90     2  0  60 -20 -     0 -      Jul01 ?        00:00:00 [bioset]
1 S root        91     2  0  60 -20 -     0 -      Jul01 ?        00:00:00 [bioset]
1 S root        92     2  0  60 -20 -     0 -      Jul01 ?        00:00:00 [bioset]
1 S root        93     2  0  60 -20 -     0 -      Jul01 ?        00:00:00 [bioset]
1 S root       120     2  0  60 -20 -     0 -      Jul01 ?        00:00:00 [bioset]
1 S root       121     2  0  80   0 -     0 -      Jul01 ?        00:00:00 [scsi_eh_0]
1 S root       122     2  0  60 -20 -     0 -      Jul01 ?        00:00:00 [scsi_tmf_0]
1 S root       123     2  0  80   0 -     0 -      Jul01 ?        00:00:00 [scsi_eh_1]
1 S root       124     2  0  60 -20 -     0 -      Jul01 ?        00:00:00 [scsi_tmf_1]
1 S root       126     2  0  60 -20 -     0 -      Jul01 ?        00:00:00 [bioset]
1 S root       157     2  0  60 -20 -     0 -      Jul01 ?        00:00:04 [kworker/1:1H]
1 S root       159     2  0  80   0 -     0 -      Jul01 ?        00:00:09 [jbd2/vda1-8]
1 S root       160     2  0  60 -20 -     0 -      Jul01 ?        00:00:00 [ext4-rsv-conver]
1 S root       206     2  0  60 -20 -     0 -      Jul01 ?        00:00:06 [kworker/0:1H]
4 S root       208     1  0  80   0 - 16130 -      Jul01 ?        00:00:29 /lib/systemd/systemd-journald
1 S root       215     2  0  80   0 -     0 -      Jul01 ?        00:00:00 [kauditd]
4 S root       222     1  0  80   0 - 11662 -      Jul01 ?        00:00:00 /lib/systemd/systemd-udevd
1 S root       270     2  0  80   0 -     0 -      Jul01 ?        00:00:00 [hwrng]
1 S root       274     2  0  60 -20 -     0 -      Jul01 ?        00:00:00 [ttm_swap]
1 S root       424     1  0  80   0 -  5089 -      Jul01 ?        00:00:02 /sbin/dhclient -4 -v -pf /run/dhclient.eth0.pid -lf
4 S root       531     1  0  80   0 -  9515 -      Jul01 ?        00:00:01 /lib/systemd/systemd-logind
4 S root       532     1  0  80   0 -  9048 -      Jul01 ?        00:00:26 /usr/sbin/inetd
4 S root       536     1  0  80   0 -  7400 -      Jul01 ?        00:00:01 /usr/sbin/cron -f
4 S avahi      537     1  0  80   0 - 11753 -      Jul01 ?        00:00:00 avahi-daemon: running [internet-host-student-20.loc
4 S root       538     1  0  80   0 -  2782 -      Jul01 ?        00:00:00 /bin/bash /usr/share/cctc/autorun.sh
4 S root       542     1  0  80   0 - 62528 -      Jul01 ?        00:00:06 /usr/sbin/rsyslogd -n
0 S root       546   538  0  80   0 -  7170 -      Jul01 ?        00:00:00 /usr/bin/python3 /usr/share/cctc/datagram_socket_re
1 S avahi      548   537  0  80   0 - 11753 -      Jul01 ?        00:00:00 avahi-daemon: chroot helper
4 S root       549     1  0  80   0 -  8981 -      Jul01 ?        00:00:16 /usr/sbin/irqbalance --foreground
4 S rtkit      550     1  0  81   1 - 44327 -      Jul01 ?        00:00:06 /usr/lib/rtkit/rtkit-daemon
4 S unscd      556     1  0  80   0 -  4201 -      Jul01 ?        00:00:02 /usr/sbin/nscd -d
4 S message+   557     1  0  80   0 -  9205 -      Jul01 ?        00:02:00 /usr/bin/dbus-daemon --system --address=systemd: --
4 S root       614     1  0  80   0 -  1456 -      Jul01 ttyS0    00:00:00 /sbin/agetty --keep-baud 115200,38400,9600 ttyS0 vt
4 S root       615     1  0  80   0 -  1110 -      Jul01 tty1     00:00:00 /sbin/agetty --noclear tty1 linux
4 S root       621     1  0  80   0 - 72452 -      Jul01 ?        00:00:00 /usr/sbin/lightdm
1 S root       632     1  0  80   0 -  6622 -      Jul01 ?        00:00:00 /usr/sbin/xrdp-sesman
5 S root       637     1  0  80   0 - 37772 -      Jul01 ?        00:00:00 nginx: master process /usr/sbin/nginx -g daemon on;
5 S www-data   638   637  0  80   0 - 37856 -      Jul01 ?        00:00:00 nginx: worker process
5 S www-data   639   637  0  80   0 - 37856 -      Jul01 ?        00:00:44 nginx: worker process
5 S ntp        653     1  0  80   0 - 24463 -      Jul01 ?        00:00:36 /usr/sbin/ntpd -p /var/run/ntpd.pid -g -u 105:109
1 S xrdp       661     1  0  80   0 -  5730 -      Jul01 ?        00:00:03 /usr/sbin/xrdp
4 S root       668     1  0  80   0 - 15915 -      Jul01 ?        00:00:03 /usr/sbin/sshd -D
4 S root       671   621  0  80   0 - 93765 -      Jul01 tty7     00:00:13 /usr/lib/xorg/Xorg :0 -seat seat0 -auth /var/run/li
5 S root       726     1  0  80   0 - 44033 -      Jul01 ?        00:05:02 /usr/bin/python -O /usr/share/wicd/daemon/wicd-daem
0 S root       740   726  0  80   0 - 25129 -      Jul01 ?        00:02:06 /usr/bin/python -O /usr/share/wicd/daemon/monitor.p
4 S root       745   621  0  80   0 - 58809 -      Jul01 ?        00:00:00 lightdm --session-child 18 21
4 S lightdm    751     1  0  80   0 - 14132 -      Jul01 ?        00:00:00 /lib/systemd/systemd --user
5 S lightdm    776   751  0  80   0 - 21741 -      Jul01 ?        00:00:00 (sd-pam)
4 S lightdm    784   745  0  80   0 - 154428 -     Jul01 ?        00:02:32 /usr/sbin/lightdm-gtk-greeter
0 S lightdm    808     1  0  80   0 - 87168 -      Jul01 ?        00:00:00 /usr/lib/at-spi2-core/at-spi-bus-launcher --launch-
0 S lightdm    813   751  0  80   0 -  9137 -      Jul01 ?        00:00:00 /usr/bin/dbus-daemon --session --address=systemd: -
0 S lightdm    816   808  0  80   0 -  9137 -      Jul01 ?        00:00:00 /usr/bin/dbus-daemon --config-file=/usr/share/defau
0 S lightdm    825     1  0  80   0 - 55077 -      Jul01 ?        00:00:00 /usr/lib/at-spi2-core/at-spi2-registryd --use-gnome
0 S lightdm    829   751  0  80   0 - 71040 -      Jul01 ?        00:00:00 /usr/lib/gvfs/gvfsd
0 S lightdm    839   751  0  80   0 - 88036 -      Jul01 ?        00:00:00 /usr/lib/gvfs/gvfsd-fuse /run/user/112/gvfs -f -o b
0 S root       997   621  0  80   0 - 22394 -      Jul01 ?        00:00:00 lightdm --session-child 14 21
1 S root      9663     2  0  80   0 -     0 -      00:00 ?        00:00:08 [kworker/0:2]
0 S student  16098 18446  0  80   0 -  9137 SyS_ep Jul06 ?        00:00:00 /usr/bin/dbus-daemon --session --address=systemd: -
0 S student  16103 18446  0  80   0 - 71040 SyS_po Jul06 ?        00:00:00 /usr/lib/gvfs/gvfsd
0 S student  16108 18446  0  80   0 - 88036 -      Jul06 ?        00:00:00 /usr/lib/gvfs/gvfsd-fuse /run/user/1001/gvfs -f -o
4 S root     18441   668  0  80   0 - 25361 -      Jul02 ?        00:00:00 sshd: student [priv]
4 S student  18446     1  0  80   0 - 14135 SyS_ep Jul02 ?        00:00:00 /lib/systemd/systemd --user
5 S student  18448 18446  0  80   0 - 21741 -      Jul02 ?        00:00:00 (sd-pam)
5 S student  18456 18441  0  80   0 - 25361 -      Jul02 ?        00:00:01 sshd: student@pts/0
0 S student  18457 18456  0  80   0 -  3172 -      Jul02 pts/0    00:00:00 -bash
4 S root     18492 18457  0  80   0 - 13918 -      Jul02 pts/0    00:00:00 sudo su
4 S root     18497 18492  0  80   0 - 14259 -      Jul02 pts/0    00:00:00 su
4 S root     18498 18497  0  80   0 -  3157 -      Jul02 pts/0    00:00:00 bash
1 S root     19773     2  0  80   0 -     0 -      Jul05 ?        00:00:05 [kworker/u4:1]
5 S proftpd  20188     1  0  80   0 - 31669 -      Jul04 ?        00:00:02 proftpd: (accepting connections)
1 S root     21128     2  0  60 -20 -     0 -      Jul06 ?        00:00:00 [cfg80211]
4 S root     23465   668  0  80   0 - 25361 -      13:49 ?        00:00:00 sshd: student [priv]
5 S student  23471 23465  0  80   0 - 25361 -      13:49 ?        00:00:00 sshd: student@pts/1
0 S student  23472 23471  0  80   0 -  3172 core_s 13:49 pts/1    00:00:00 -bash
1 S root     23473     2  0  80   0 -     0 -      13:49 ?        00:00:00 [kworker/u4:0]
1 S root     23697     2  0  80   0 -     0 -      14:03 ?        00:00:00 [kworker/1:0]
4 S root     24352   668  0  80   0 - 25361 -      14:43 ?        00:00:00 sshd: student [priv]
5 S student  24360 24352  0  80   0 - 25361 -      14:43 ?        00:00:00 sshd: student@pts/2
0 S student  24361 24360  0  80   0 -  3172 -      14:43 pts/2    00:00:00 -bash
1 S root     24671     2  0  80   0 -     0 -      15:00 ?        00:00:00 [kworker/0:0]
1 S root     24686     2  0  80   0 -     0 -      15:01 ?        00:00:00 [kworker/1:2]
1 S root     24762     2  0  80   0 -     0 -      15:06 ?        00:00:00 [kworker/0:1]
0 R student  24773 24361  0  80   0 -  7450 -      15:06 pts/2    00:00:00 ps -elf
```

---
`top` - The top program provides a dynamic real-time view of a running system.


```
student@internet-host-student-01:~$ top

top - 15:08:01 up 7 days, 18:12,  3 users,  load average: 0.01, 0.06, 0.07
Tasks: 121 total,   1 running, 120 sleeping,   0 stopped,   0 zombie
%Cpu(s):  0.0 us,  0.1 sy,  0.0 ni, 99.1 id,  0.8 wa,  0.0 hi,  0.0 si,  0.0 st
KiB Mem :  4050832 total,  3088400 free,   149388 used,   813044 buff/cache
KiB Swap:        0 total,        0 free,        0 used.  3560824 avail Mem

  PID USER      PR  NI    VIRT    RES    SHR S  %CPU %MEM     TIME+ COMMAND
    1 root      20   0   57288   7120   5344 S   0.0  0.2   0:43.38 systemd
    2 root      20   0       0      0      0 S   0.0  0.0   0:00.17 kthreadd
    3 root      20   0       0      0      0 S   0.0  0.0   0:00.06 ksoftirqd/0
    5 root       0 -20       0      0      0 S   0.0  0.0   0:00.00 kworker/0:0H
    7 root      20   0       0      0      0 S   0.0  0.0   0:19.07 rcu_sched
    8 root      20   0       0      0      0 S   0.0  0.0   0:00.00 rcu_bh
    9 root      rt   0       0      0      0 S   0.0  0.0   0:02.24 migration/0
   10 root       0 -20       0      0      0 S   0.0  0.0   0:00.00 lru-add-drain
   11 root      rt   0       0      0      0 S   0.0  0.0   0:01.63 watchdog/0
   12 root      20   0       0      0      0 S   0.0  0.0   0:00.00 cpuhp/0
   13 root      20   0       0      0      0 S   0.0  0.0   0:00.00 cpuhp/1
   14 root      rt   0       0      0      0 S   0.0  0.0   0:01.50 watchdog/1
   15 root      rt   0       0      0      0 S   0.0  0.0   0:01.94 migration/1
   16 root      20   0       0      0      0 S   0.0  0.0   0:00.34 ksoftirqd/1
   18 root       0 -20       0      0      0 S   0.0  0.0   0:00.00 kworker/1:0H
   19 root      20   0       0      0      0 S   0.0  0.0   0:00.00 kdevtmpfs
   20 root       0 -20       0      0      0 S   0.0  0.0   0:00.00 netns
   21 root      20   0       0      0      0 S   0.0  0.0   0:00.58 khungtaskd
   22 root      20   0       0      0      0 S   0.0  0.0   0:00.00 oom_reaper
   23 root       0 -20       0      0      0 S   0.0  0.0   0:00.00 writeback
   24 root      20   0       0      0      0 S   0.0  0.0   0:00.00 kcompactd0
   26 root      25   5       0      0      0 S   0.0  0.0   0:00.00 ksmd
   27 root      39  19       0      0      0 S   0.0  0.0   0:00.00 khugepaged
   28 root       0 -20       0      0      0 S   0.0  0.0   0:00.00 crypto
   29 root       0 -20       0      0      0 S   0.0  0.0   0:00.00 kintegrityd
   30 root       0 -20       0      0      0 S   0.0  0.0   0:00.00 bioset
   31 root       0 -20       0      0      0 S   0.0  0.0   0:00.00 kblockd
   32 root       0 -20       0      0      0 S   0.0  0.0   0:00.00 devfreq_wq
   33 root       0 -20       0      0      0 S   0.0  0.0   0:00.00 watchdogd
   34 root      20   0       0      0      0 S   0.0  0.0   0:00.00 kswapd0
   35 root       0 -20       0      0      0 S   0.0  0.0   0:00.00 vmstat
   47 root       0 -20       0      0      0 S   0.0  0.0   0:00.00 kthrotld
   48 root       0 -20       0      0      0 S   0.0  0.0   0:00.00 ipv6_addrconf
   84 root       0 -20       0      0      0 S   0.0  0.0   0:00.00 bioset
   85 root       0 -20       0      0      0 S   0.0  0.0   0:00.00 bioset
   86 root       0 -20       0      0      0 S   0.0  0.0   0:00.00 bioset
   87 root       0 -20       0      0      0 S   0.0  0.0   0:00.00 ata_sff
   88 root       0 -20       0      0      0 S   0.0  0.0   0:00.00 bioset
   90 root       0 -20       0      0      0 S   0.0  0.0   0:00.00 bioset
   91 root       0 -20       0      0      0 S   0.0  0.0   0:00.00 bioset
   92 root       0 -20       0      0      0 S   0.0  0.0   0:00.00 bioset
   93 root       0 -20       0      0      0 S   0.0  0.0   0:00.00 bioset
  120 root       0 -20       0      0      0 S   0.0  0.0   0:00.00 bioset
  121 root      20   0       0      0      0 S   0.0  0.0   0:00.00 scsi_eh_0
  122 root       0 -20       0      0      0 S   0.0  0.0   0:00.00 scsi_tmf_0
  123 root      20   0       0      0      0 S   0.0  0.0   0:00.00 scsi_eh_1
  124 root       0 -20       0      0      0 S   0.0  0.0   0:00.00 scsi_tmf_1
  126 root       0 -20       0      0      0 S   0.0  0.0   0:00.00 bioset
  157 root       0 -20       0      0      0 S   0.0  0.0   0:04.90 kworker/1:1H
  159 root      20   0       0      0      0 S   0.0  0.0   0:09.94 jbd2/vda1-8
```

References:  
[ps Man page](https://manpages.debian.org/buster/procps/ps.1.en.html)  
[top Man page](https://manpages.debian.org/buster/procps/top.1.en.html)  


---
#### 7.4.2.8 which or whereis
In order to determine if particular applications are install and available on a system you can use which or whereis to find the path to where its install. A response will verify the application is installed while no response will mean that the application is not install or that the current user has not access to it.

- `which [program]` returns the pathnames of the files
- `whereis [program]` locates the binary, source and manual files for the specified command names.


References:  
[which Man page](https://manpages.debian.org/buster/debianutils/which.1.en.html)  
[whereis Man page](https://manpages.debian.org/buster/util-linux/whereis.1.en.html)  


---
#### 7.3.2.9 Routing Table
```
Windows: route print
Linux/Unix: ip route
Linux/Unix: netstat -r
```

Although end hosts are not routers they do however perform some routing functions. Usually the limits of this are:

- Inbound:
  - Am I the destination of this packet?
  - Do I know and have access to the target if it is not me? (must have ip forwarding enabled)
- Outbound:
  - Is the target of this packet to a device on the same network as me? (Send to target’s local MAC address)
  - Is the target of this packet to a device on a different network as me? (Send to gateway MAC address)

```
student@internet-host-student-01:~$ ip route
default via 10.10.0.62 dev eth0
10.10.0.32/27 dev eth0 proto kernel scope link src 10.10.0.40
```

`route` - routing table entry.
```
student@internet-host-student-01:~$ netstat -r
Kernel IP routing table
Destination     Gateway         Genmask         Flags   MSS Window  irtt Iface
default         10.10.0.62      0.0.0.0         UG        0 0          0 eth0
10.10.0.32      0.0.0.0         255.255.255.224 U         0 0          0 eth0
```
`-r (--route)` - Display the kernel routing tables.

References:  
[ip Man page](https://manpages.debian.org/buster/iproute2/ip.8.en.html)  
[netstat Man page](https://manpages.debian.org/buster/net-tools/netstat.8.en.html)  


---
#### 7.3.2.10 Find
Find can be used to search for a particular string pattern.
```
find [where to start searching from] [expression determines what to find] [-options] [what to find] 2> /dev/null
```

```
student@internet-host-student-01:~$ find / -name passwd 2> /dev/null
/usr/bin/passwd
/usr/share/doc/passwd
/usr/share/bash-completion/completions/passwd
/usr/share/lintian/overrides/passwd
/etc/pam.d/passwd
/etc/cron.daily/passwd
/etc/passwd
```

- `/` - specifies to start searching from system root.
- `-name *pattern*` - Base of file name (the path with the leading directories removed) matches shell pattern pattern.
- `-iname *pattern*` - Like -name, but the match is case insensitive.
- `*filename*` - specify the name of the file to search for. Can use wildcards (*) before or after.
- `2> /dev/null` - removes error responses such as "Permission denied"

References:  
[find Man page](https://manpages.debian.org/buster/findutils/find.1.en.html)  


---
## 7.4 Describe Methods Used for Active Internal Network Reconnaissance
Active Internal Reconnaissance looks very similar to Active External Reconnaissance and uses many of the same tools such as PING, NMAP and Netcat. They are employed in the same manner as Active External Recon except that the targeted addresses, ports, and services may be different.

Active internal network reconnaissance involves the proactive identification and probing of assets, systems, and vulnerabilities within an organization’s internal network. This phase is a crucial element of cybersecurity assessments, penetration testing, or ethical hacking conducted within the internal network environment. In comparison to passive reconnaissance, which entails observation without direct interaction, active internal network reconnaissance utilizes a variety of tools and techniques to actively deploy probes, requests, and queries for gathering information and evaluating potential weaknesses.

In this phase we will commonly used commands on the local system to probe or interact with other systems on the internal network. With SSH Tunneling, we can leverage tools on our local system to route our traffic through the internal system, enabling us to examine or engage with internal systems.


---
### 7.4.1 ARP Scan
As we have learned before, ARP is used to resolve IP addresses to MAC addresses. By exploiting this protocol, we can learn the IPs an MAC addresses of devices in the local network segment. The responses that return are only for the local segment, so the requests must be run internally from the desired location. This is a low level scan that can potentially be overlooked on many networks.

- ARP Scanning
```
sudo arp-scan --interface=eth0 --localnet

sudo arp-scan --interface=eth0 10.1.0.0/24

arping –c 1 –i eth0 172.16.32.2 (can only scan a single host, results vary)

for ip in $(sew 1 254) ; do if ping -c 1 10.1.0.$ip>/dev/null; then echo "10.1.0.$ip UP"; fi ;done

nmap –PR 172.16.32.2(legitimate scan that often does not show results)

nmap -PR -6 fe80::f816:3eff:fed9:5116/64(takes a long time to run)
```

References:  
[arp-scan Man page](https://manpages.debian.org/buster/arp-scan/arp-scan.1.en.html)  


---
### 7.4.2 PING Scan
A PING scan, also known as an ICMP Echo scan or simply a Ping scan, is a type of network reconnaissance technique used to determine the reachability of hosts on a network. It works by sending ICMP Echo Request packets (PING) to a range of IP addresses and listening for ICMP Echo Reply packets (PONG) that are returned by live hosts.

```
ping -c 1 172.16.82.106

for i in {1..254}; do (ping -c 1 172.16.82.$i | grep "bytes from" &) ; done

sudo nmap -sP 172.16.82.96/27
```

---
### 7.4.3 /DEV/TCP
`/dev/tcp` is a special virtual filesystem in Linux that provides access to TCP sockets as if they were files. It allows you to create client or server connections to remote hosts using Bash shell commands or scripts, without the need for external utilities or libraries.

Performing TCP scanning using /dev/tcp in Bash is not directly supported because /dev/tcp is primarily used for creating client connections to remote hosts, not for scanning multiple hosts and ports. However, you can create a script in Bash to perform TCP scanning using /dev/tcp for a single host and port.

One of the advantages about /dev/tcp is that it can be used without root level privileges. This can allow the ability to perform a TCP port scan on a network when other tools like NMAP or Netcat are not available.

Since /dev/tcp is normally installed by default of most Linux systems with the Bash shell, this can a major vulnerability and a possible tool to use in reconnaissance.

- Banner Grabbing with /dev/tcp
```
exec 3<>/dev/tcp/tgt_ip/tgt_port; echo -e "" >&3; cat <&3
```

  - `exec 3<>/dev/tcp/tgt_ip/tgt_port`: Opens a file descriptor (FD) 3 for reading and writing to the specified hostname and port using /dev/tcp.
  - `echo -e ""`: Sends data to the port to interogate it.
  - `cat <&3`: Reads the response from the server on file descriptor 3 and displays it on the console.
- To conduct a portscan using /dev/tcp.
  - One-liner:
  ```
  for p in {1..1023}; do(echo >/dev/tcp/172.16.82.106/$p) >/dev/null 2>&1 && echo "$p open"; done
  ```

  - Script:
  ```
  #!/bin/bash
  echo "Enter the IP address you want to do a full port scan on."
  read address
  rm $address.txt
  for p in {1..65535};
  do
        timeout 1 bash -c "echo >/dev/tcp/$address/$p" >/dev/null 2>&1  &&
        echo "$p open" >> $address.txt ||
        echo "$p is closed"
  done
  cat $address.txt
  ```

    - This script prompts the user to provide a single IP address to run a full port scan on.
    - It removes any previous output files ran by the script with the same IP address.
    - It iterates through all avalable ports and then reports all reachable ports as "is open" and all closed ports as "is closed".
    - It saves the open ports results to a file and cats the contents of that file after the script completes.

References:  
[Advanced Bash-Scripting Guide: Chapter 29. /dev and /proc](https://tldp.org/LDP/abs/html/devref1.html)  
[/dev/tcp as a weapon](https://securityreliks.wordpress.com/2010/08/20/devtcp-as-a-weapon/)  


---
## 7.5 Perform Network Forensics
---
### 7.5.1 Map a Network
**Map a network through correlation of relevant network artifacts gathered through Reconnaissance and analysis**

Mapping a network refers to the process of discovering and documenting the devices, resources, and topology of a computer network. This includes identifying all devices connected to the network, such as computers, servers, routers, switches, printers, and other networked devices, as well as understanding the relationships between these devices and how they communicate with each other.
- Networks can be very small (1 or 2 systems) to very large (1000+). Visualizing the network can be very challenging.
- Creating a physical map of the network is very valuable to Network Defenders for troubleshooting but this information can be a huge vulnerability if this information falls into the wrong hands.
- Understanding how to create a Network map is invaluable.
- The concepts below will be crucial for the rest of the course activities and exercises.
- Different units and missions may require accompanying documents to your network map(s) and network map standards may vary between units in addition to whether you are offensive or defensive.


---
Offensive Mapping:

- Diagram devices - Use specific images/drawings for different devices. Depending on the data available it may not be possible to see all devices on the network for a variety of reasons such as the layer that a device functions at, or where a device is located in a network.
  - Routers - Image to depict different vendors/models.
  - Switches - This type of device is often not seen offensively due to the layers that they function at.
  - Hosts - Image to depict desktop/laptop or operating system.
  - Servers - Should be classified separatly from hosts. Knowing where and what servers are can provide additional context and information for future planning.
  - Firewalls - These provide more powerful filtering compared to router ACL’s.
  - Clouds - This pertains to both cloud services utilized and elements outside of the target network.

![image](https://github.com/ruppertaj/WOBC/assets/93789685/cc639b43-e4f9-4173-bc6c-55df3651e5da)
Map

---
- Types of lines:
  - Solid - Direct connection between devices
  - Dashed - Devices are able to talk but it has not been confirmed that they are directly connected i.e. there is a chance of a device between them.

![image](https://github.com/ruppertaj/WOBC/assets/93789685/389f3770-7460-4040-9b38-dd38d68ed35e)
Map

---
- Additional Written Information - This is information that should accompany devices and additional groupings
  - Device names - Naming schema allows you to confirm what machine you are on and often tells you how many devices/ what unidentified devices may be called.
  - IP address and MAC address - needed to directly address specific device.
  - Number and types of interfaces - Systems with more than one interface means that it can potentially be connected to several networks. This system can be a potential pivot system.
  - Operating system - Identify the OS, version and patches applied. This will potentially lead to possible vulnerabilities and exploits.
  - Versions/patches - This will help identify security features, functions, and vulnerabilities available.
  - Credentials - usernames and passwords to access the system.
  - Ports/Services - all open service ports on system.
  - Protocols running - Other than TCP/UDP it may be useful to know if ICMP is allowed/running. Identify any other protocols discovered.

---
- Device Coloring:
  - Red - Non viable target
  - Yellow - Possible target; non verified credentials or possible exploitable vulnerability
  - Green - Valid target with verified credentials or exploitable vulnerability

![image](https://github.com/ruppertaj/WOBC/assets/93789685/c4caab7d-6b30-4d7f-b66a-7371c81fbff3)
Map

---
- Additional Groupings:
  - Routing Protocols
  - VLANS
  - NAT boundaries
  - Tunnels
  - Job Role

![image](https://github.com/ruppertaj/WOBC/assets/93789685/09cc3a7a-1983-4448-8523-e20a0df7b030)
Map


References:  
[Draw.io Map Template](https://1drv.ms/u/s!Arz6vf8sVG8vgpMsQ1RRtb0rcP7x4w?e=R9tlao)  
[network Diagram 101](http://networkdiagram101.com/)  
https://app.diagrams.net/  
https://app.diagrams.net/  
https://draw.chat/  
https://cloud.smartdraw.com/  
https://app.ziteboard.com/  
https://app.ziteboard.com/  
https://www.tutorialspoint.com/whiteboard.htm  
https://whiteboard.explaineverything.com/  
