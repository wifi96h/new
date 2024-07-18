# 1.0 Outcomes
- Explain OSI Layer 1 data communications and technologies
  - Explain and compare binary, decimal, hexadecimal and base64 formats
  - Describe LAN topologies and devices
- Explain OSI Layer 2 protocols, headers and technologies
  - Describe LAN technologies and their benefits and hindrances
  - Explain why and how frames are interpreted by different devices
  - Identify how switches affect network traffic and the visibility of network traffic by other hosts
  - Describe MAC addressing
  - Analyze 802.3 frame headers
  - Describe the contents of an Ethernet header and frame
  - Describe an 802.1Q virtual local area network (VLAN) frame and how its frames differ from a standard 802.3 frame
  - Describe the address resolution protocol (ARP)
  - Explain man-in-the-middle (MitM) with ARP
  - Explain VTP with its vulnerabilities
  - Explain DTP with its vulnerabilities
  - Explain CDP, FDP and LLDP and the security vulnerabilities
  - Explain STP with its vulnerabilities
  - Explain Port Security with its vulnerabilities
  - Describe VLANS and Security vulnerabilities


Outcome: This section of facilitation serves as a cornerstone for reinforcing network fundamentals among students while offering instructors the chance to gauge the requisite level of network-based knowledge necessary for success in subsequent modules. It acts as an informal yet essential component, focusing on crucial aspects such as mathematical operations in networking, standard terminology, comprehension of OSI and TCP/IP models, familiarity with network protocols, proficiency in header construction, and understanding basic routing and switching behaviors and protocols. By solidifying these foundational concepts, students can build a robust understanding of network fundamentals, paving the way for deeper exploration and mastery of advanced topics in subsequent modules.

The functions and protocols at Layer 1 (Physical layer) and Layer 2 (Data Link layer) of the OSI model are of paramount importance in cybersecurity due to their foundational role in network communication and data transmission. At Layer 1, protocols govern the physical aspects of networking, including the medium of transmission (such as copper, fiber optic, or wireless), signal modulation, and data encoding. Understanding these protocols is critical for ensuring the integrity and reliability of data transmission, as well as for identifying vulnerabilities related to physical infrastructure, such as cable tampering or signal interception.

Layer 2 protocols, on the other hand, are responsible for framing data into packets and managing the flow of data across local network segments. Protocols like Ethernet and Wi-Fi operate at this layer, providing mechanisms for addressing, error detection, and flow control. Knowledge of Layer 2 protocols is essential for securing network connections, preventing unauthorized access, and mitigating risks associated with MAC address spoofing, ARP spoofing, and VLAN hopping attacks.

In the context of cybersecurity, Layer 1 and Layer 2 vulnerabilities can be exploited by malicious actors to compromise network integrity, intercept sensitive information, or launch attacks against network infrastructure. For example, physical layer vulnerabilities, such as unauthorized physical access to network devices or cable tapping, can enable attackers to eavesdrop on communications or conduct man-in-the-middle attacks. Similarly, data link layer vulnerabilities, such as MAC address spoofing or ARP poisoning, can be exploited to gain unauthorized access to network resources or disrupt network operations.

By understanding the functions and protocols at Layer 1 and Layer 2, cybersecurity professionals can implement appropriate security controls and countermeasures to protect against these threats. This may include implementing physical security measures to safeguard network infrastructure, using encryption to secure data transmission over untrusted networks, and deploying network access controls to authenticate and authorize devices connecting to the network. Overall, a comprehensive understanding of Layer 1 and Layer 2 protocols is essential for building a robust cybersecurity posture and defending against a wide range of cyber threats.

---
## 1.1 Discuss Networking Standards 
Networking standards play a crucial role in the realm of information technology, acting as the foundational framework that enables diverse devices and systems to communicate effectively within a network. These standards are essentially a set of guidelines, rules, and conventions that prescribe how data should be transmitted, received, and processed across various networked components. Their significance lies in ensuring interoperability and facilitating seamless communication, fostering a cohesive and efficient networking environment. These standards allow for:
- Interoperability:
  - Networking standards provide a common language and set of protocols that devices and systems must adhere to for effective communication. By establishing a standardized approach to data transmission and reception, these standards enable devices from different manufacturers and developers to work together seamlessly. This interoperability is essential for creating heterogeneous networks where diverse devices, ranging from computers and printers to routers and switches, can collaborate efficiently.
- Seamless Communication:
  - The standards dictate how data is formatted, packaged, and transmitted across the network. This uniformity ensures that devices can understand and interpret the data correctly, promoting smooth communication. Whether it’s a file transfer, an email exchange, or a video stream, adherence to networking standards guarantees that the information flows consistently across the network, irrespective of the devices involved.
- Structured Framework:
  - Networking standards often follow a structured framework, such as the OSI model, which divides the networking process into distinct layers. Each layer has a specific function, and adherence to this framework allows for modular design and development. This structured approach simplifies troubleshooting, maintenance, and upgrades as changes can be localized to specific layers without affecting the entire network architecture.
- Reliability and Efficiency:
  - By defining the rules for error detection, correction, and flow control, networking standards contribute to the reliability and efficiency of data transmission. Protocols like TCP (Transmission Control Protocol) ensure the reliable delivery of data, while others, like UDP (User Datagram Protocol), focus on speed and efficiency. These standards strike a balance between reliability and performance based on the specific needs of the applications and services running on the network.
- Scalability and Future-Proofing:
  - Networking standards provide a scalable foundation that accommodates the growth and expansion of networks over time. As technology evolves, new standards emerge to address the changing needs of communication. For example, the transition from IPv4 to IPv6 was driven by the need for a larger address space to accommodate the growing number of devices connected to the Internet. Adherence to standards ensures that networks can evolve and incorporate new technologies seamlessly.
- Security:
  - Many networking standards include security protocols and measures to protect data integrity and confidentiality. Encryption standards, authentication mechanisms, and secure communication protocols contribute to safeguarding sensitive information as it traverses the network. Security standards are critical in today’s interconnected world, where cyber threats are a constant concern.


---
### 1.1.1 OSI Model 
- The Open Systems Interconnection (OSI) Model is a conceptual framework that standardizes the functions of a telecommunication or computing system into seven abstraction layers. It was developed by the International Organization for Standardization (ISO) to facilitate communication and interoperability between different systems and networks. Each layer in the OSI Model performs specific functions, and the model helps in understanding, designing, and discussing network architecture and protocols. Each layer operates independentantly of the other layers but services the other layers.
- Discuss the layers of the OSI model starting from the application and down. Explain how typical network traffic like web utilizes each of the 7 layers.

![image](https://github.com/ruppertaj/WOBC/assets/93789685/ea704974-6203-4820-9ab6-234cf6121ebd)
Figure 1. OSI_Model

1. Application Layer: provides a network interface to the software applications that communicate over the network. It supports communication services directly to end-users or applications and provides network services such as file transfers, email, and remote login.
- Protocols that operate at this layer:
  - Remote Login: SSH (Secure Shell) and Telnet
  - Web: HTTP (Hypertext Transfer Protocol) and HTTPs
  - File Transfer: FTP (File Transfer Protocol), SFTP (SSH FTP), and FTPS (FTP Secure)
  - Email: SMTP (Simple Mail Transfer Protocol), POP (Post Office Protocol), and IMAP (Internet Message Access Protocol)
2. Presentation Layer: deals with the syntax and semantics of the information exchanged between systems. It translates data between the application layer and the lower layers, ensuring that the data is in a readable format. Tasks include data compression, encryption, and character set conversions. There are no protocols that operate at this layer. This layer deal more with encoding and file formatting.
- Character encodings:
  - ASCII Encoding: American Standard Code for Information Interchange represents text characters using 7 or 8 bits, mapping each character to a numeric value.
  - Unicode Encoding: A character encoding standard that encompasses most of the world’s writing systems, assigning unique numerical values to characters, emojis, and symbols.
  - UTF-8 Encoding: A variable-width character encoding capable of encoding all Unicode characters using one to four bytes, commonly used in web pages and email.
  - UTF-16 Encoding: A character encoding capable of encoding all Unicode characters using two or four bytes, often used in programming languages like Java and JavaScript.
  - UTF-32 Encoding: A fixed-width encoding scheme that represents each Unicode code point with four bytes, ensuring straightforward indexing but resulting in larger file sizes compared to UTF-8 and UTF-16.
  - Base64 Encoding: Converts binary data into ASCII characters, useful for encoding binary data such as images or attachments in emails or transmitting binary data over text-based protocols.
  - URL Encoding: Converts special characters into a format that can be transmitted over the Internet, replacing reserved characters with percent-encoded representations.
- File formats:
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
    -  Flash Video (.flv): Format developed by Adobe for streaming video content over the internet, commonly used for web-based video players and online streaming platforms.
- Compression:
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
- Encryption:
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
3. Session Layer: establishes, manages, and terminates communication sessions between applications. It controls dialogues (full-duplex or half-duplex), maintains synchronization, and manages data exchange between applications. Sometimes the protocols that operate at this layer act as a "shim protocol" between various communicating devices.
- Protocols that operate at this layer:
  - NetBIOS (Network Basic Input/Output System)
  - RPC (Remote Procedure Call)
  - PPTP (Point-to-Point Tunneling Protocol)
  - SMB (Server Message Block) can operate like a "shim protocol" between various communicating devices.
  - SOCKS (Socket Secure)
4. Transport Layer: ensures end-to-end communication, providing error detection, error correction, and flow control. It breaks down larger messages into smaller segments, sends them across the network, and reassembles them at the destination.
- Protocols that operate at this layer:
  - Transmission Control Protocol (TCP): TCP is a connection-oriented protocol that provides reliable and ordered delivery of data packets. It establishes a virtual connection between the sender and receiver, manages packet acknowledgment, retransmission, and flow control to ensure data integrity and delivery. TCP is widely used for applications that require error-free data transmission, such as web browsing, email, and file transfer.
  - User Datagram Protocol (UDP): UDP is a connectionless protocol that provides fast, but unreliable, delivery of data packets. Unlike TCP, UDP does not establish a connection or guarantee packet delivery, making it faster but less reliable. It is commonly used for real-time communication applications like video streaming, online gaming, and Voice over IP (VoIP), where occasional packet loss is acceptable.
5. Network Layer: is responsible for logical addressing, routing, and forwarding. It enables devices to communicate across different networks by determining the best path for data to travel from the source to the destination. IP (Internet Protocol) and IPv6 operates at this layer.
- Protocols that operate at this layer:
  - Internet Protocol version 4 (IPv4): IPv4 is the most widely used version of the Internet Protocol. It uses 32-bit addresses, allowing for approximately 4.3 billion unique addresses. However, due to the exhaustion of available IPv4 addresses, IPv6 has been developed as its successor.
  - Internet Protocol version 6 (IPv6): IPv6 is designed to address the limitations of IPv4 by using a 128-bit address space, providing a vastly larger number of possible addresses. It offers improved security, better support for mobile devices, and more efficient routing compared to IPv4.
  - Internet Control Message Protocol (ICMP): ICMP is used for network diagnostics and error reporting. It allows routers and hosts to communicate error messages, such as "destination unreachable" or "time exceeded," back to the source host.
  - Internet Group Management Protocol (IGMP): IGMP is used by IPv4 systems to manage multicast group membership. It enables hosts to inform routers about their desire to receive multicast traffic for specific multicast groups.
  - Neighbor Discovery Protocol (NDP): NDP is used in IPv6 networks for address resolution, router discovery, and neighbor detection. It replaces Address Resolution Protocol (ARP) in IPv4 networks.
  - Open Shortest Path First (OSPF): OSPF is an interior gateway routing protocol used within autonomous systems. It employs the shortest path first (SPF) algorithm to calculate the best route between routers, considering factors such as link cost and network congestion.
  - Routing Information Protocol (RIP): RIP is another interior gateway routing protocol used within autonomous systems. It uses the distance-vector routing algorithm and is simpler to configure compared to OSPF, although it may be less efficient in larger networks.
6. Data-Link Layer: is responsible for creating a reliable link between two directly connected nodes. It handles issues such as framing, addressing, and error detection. It also manages access to the physical medium and controls how data is placed on the medium.
- Protocols that operate at this layer:
  - Ethernet: Ethernet is the most widely used data link layer protocol. It defines standards for the physical and data link layers, including how data is framed for transmission over Ethernet networks and how devices on the same network share the communication medium. Ethernet uses MAC (Media Access Control) addresses to identify devices on the network.
  - IEEE 802.11 (Wi-Fi): The IEEE 802.11 standard governs wireless local area network (WLAN) technologies, commonly known as Wi-Fi. It defines how wireless devices communicate with each other over radio frequencies, including protocols for data framing, channel access, and security.
  - Ethernet VLAN Tagging (IEEE 802.1Q): IEEE 802.1Q is a protocol used to implement virtual LANs (VLANs) on Ethernet networks. It adds a VLAN tag to Ethernet frames, allowing devices to distinguish between different VLANs and route traffic accordingly.
  - Address Resolution Protocol (ARP): ARP is used to map IP addresses to MAC addresses on a local network. When a device needs to communicate with another device on the same network, it sends an ARP request to discover the MAC address associated with the IP address.
  - Reverse Address Resolution Protocol (RARP): RARP performs the opposite function of ARP. It maps MAC addresses to IP addresses, typically used by diskless workstations to obtain their IP addresses from a server based on their MAC addresses.
  - Link Layer Discovery Protocol (LLDP): LLDP is a vendor-neutral protocol used to discover information about neighboring devices on a network. It allows network devices to exchange information about their identity, capabilities, and status.
  - Cisco Discovery Protocol (CDP): Similar to LLDP, CDP is a proprietary protocol developed by Cisco. It enables Cisco devices to discover and share information about neighboring Cisco devices on a network, including device type, IP address, and software version.
7. Physical Layer: deals with the physical connection between devices. It defines the hardware elements, such as cables, connectors, and the transmission medium (e.g., copper wires, fiber optics). It is concerned with the raw transmission of bits over a physical medium. The protocols define the electrical, mechanical, and functional specifications for transmitting raw bit streams over physical mediums.
- Protocols that operate at this layer:
  - Ethernet Physical Layer Standards (IEEE 802.3): IEEE 802.3 standards define the physical and electrical characteristics of Ethernet networks. They specify parameters such as cable types (e.g., twisted pair, fiber optic), signaling methods (e.g., Manchester encoding, 4B5B encoding), and data transmission rates (e.g., 10 Mbps, 100 Mbps, 1 Gbps, 10 Gbps).
  - IEEE 802.11 (Wi-Fi): Wi-Fi is a family of wireless networking standards for local area networks (LANs). It defines physical layer specifications for radio frequency transmission over the air, including modulation techniques, channel widths, and data rates used in Wi-Fi networks.
  - Bluetooth: Bluetooth is a wireless technology standard for short-range communication between devices. It defines physical layer specifications for radio frequency transmission, including frequency bands, modulation techniques, and power levels used in Bluetooth devices.

Importance of the OSI Model
- The OSI model describes networking functions as a set of layered, modular components, each responsible for particular functions. The model is theoretical in nature as certain networking protocols don’t always fall nicely within a specific layer. It merely provides a framework for breaking down complex networking components in a way that can be more easily understood. Without the model’s structure to help frame the conversation related to protocol interaction and other functions, discussion of networking topics would be nearly impossible.

```
Table 1. The OSI Model
OSI Layer	                   PDU	                                   Common Protocols
7 - Application                    Data                                    DNS, HTTP, TELNET
6 - Presentation                   Data                                    SSL, TLS, JPEG, GIF
5 - Session                        Data                                    NetBIOS, PPTP, RPC, NFS
4 - Transport                      Segment/Datagram                        TCP, UDP
3 - Network                        Packet                                  IP, ICMP, IGMP
2 - Data Link                      Frames                                  PPP, ATM, 802.2/3 Ethernet, Frame Relay
1 - Physical                       Bits                                    Bluetooth, USB, 802.11 (Wi-Fi), DSL, 1000Base-T
```

References:  
https://en.wikipedia.org/wiki/OSI_model  
https://www.networkworld.com/article/964816/the-osi-model-explained-and-how-to-easily-remember-its-7-layers.html  
https://osi-model.com/  


---
### 1.1.2 Internet Standards Organizations

Other than the OSI or TCP/IP models, it’s also important to understand some other organizations that have been developing Internet and Networking Standards.
- Internet Engineering Task Force (IETF): The IETF is a large open international community of network designers, operators, vendors, and researchers who are concerned with the evolution and operation of the Internet. It focuses on the development of protocols and standards, with working groups dedicated to specific areas such as routing, security, and web technologies.
  - Main focus: repository of Request for Comment (RFC) which is a series of documents published by the Internet Engineering Task Force (IETF) and other organizations involved in the development of Internet standards and protocols. RFCs serve as the primary means for documenting specifications, protocols, procedures, and other technical aspects of the Internet.
- Internet Assigned Numbers Authority (IANA): IANA is responsible for the global coordination of the DNS root, IP addressing, internet numbers, and other Internet protocol resources. While not primarily a standards development organization, IANA’s role in managing critical Internet resources is vital to the functioning of the Internet.
  - Main Focus:
    - Allocation of IPv4 and IPv6 addresses
    - Management of Well Know port assignments
    - Multicast address assignment
    - Protocol number assignment
    - Assigns MAC OUI to organizations
    - Manages assignments of Autonomous System (AS) to organizations
    - Maintains all the DNS root servers
  - Regional Internet Registries (RIRs): RIRs, such as ARIN, RIPE NCC, and APNIC, are responsible for the allocation and registration of Internet number resources, including IP addresses. While their primary role is resource allocation, they also contribute to the development and promotion of Internet standards related to addressing and routing.
    - American Registry for Internet Numbers (ARIN): ARIN serves the United States, Canada, and parts of the Caribbean region. It allocates and manages IP addresses (both IPv4 and IPv6), autonomous system numbers (ASNs), and related resources within its service region.
    - Réseaux IP Européens Network Coordination Centre (RIPE NCC): RIPE NCC serves Europe, the Middle East, and parts of Central Asia. It allocates and manages IP addresses (IPv4 and IPv6), ASNs, and related resources for its service region.
    - Asia-Pacific Network Information Centre (APNIC): APNIC serves the Asia-Pacific region, including East Asia, Southeast Asia, South Asia, and Oceania. It allocates and manages IP addresses (IPv4 and IPv6), ASNs, and related resources within its service region.
    - Latin America and Caribbean Network Information Centre (LACNIC): LACNIC serves Latin America and the Caribbean region. It allocates and manages IP addresses (IPv4 and IPv6), ASNs, and related resources within its service region.
    - African Network Information Centre (AFRINIC): AFRINIC serves the African continent. It allocates and manages IP addresses (IPv4 and IPv6), ASNs, and related resources within its service region.
  - Institute of Electrical and Electronics Engineers (IEEE): While the IEEE is a broader organization covering various fields of technology, it plays a significant role in developing standards for networking and communication technologies. The IEEE 802 working groups, for example, have developed standards for LANs and wireless networks.
    - Some of the standards they deal with:
      - IEEE 802.11: Wireless LAN standards, commonly known as Wi-Fi, specifying protocols for wireless communication between devices.
      - IEEE 802.3: Ethernet standards, defining specifications for wired local area network (LAN) communication.
      - IEEE 802.1Q: Virtual LAN (VLAN) standards, providing protocols for creating and managing virtual LANs within Ethernet networks.
      - IEEE 802.16: Broadband Wireless Access (BWA) standards, often referred to as WiMAX, for wireless metropolitan area networks (MANs).
      - IEEE 802.1X: Port-based network access control standards, used for authenticating and authorizing devices connecting to a LAN or WLAN.
      - IEEE 802.1ad: Provider Bridging (PB) standards, also known as "Q-in-Q," for implementing virtual LAN (VLAN) stacking in Ethernet networks.

```
Organization	Website	What they are known for:
IETF       https://www.ietf.org/standards/                          Mostly known for developing and publishing "white paper" standards known as Request for Comment (RFC).
                                                                    Some notable ones are:
                                                                    * IPv4 (791)
                                                                    * IPv6 (2460)
                                                                    * TCP (793)
                                                                    * UDP (768)
                                                                    * HTTP 1.1 (2616)
                                                                    * List of other from Wikipedia

IANA       https://www.iana.org/                                    Controls all internet numbers such as:
                                                                    * MAC OUI numbers
                                                                    * Ethertypes
                                                                    * IPv4 and IPv6 addresses
                                                                    * IPv4 and IPv6 Multi-cast addresses
                                                                    * Protocol Numbers
                                                                    * Port Numbers
                                                                    * 16/32-bit AS Numbers
                                                                    * Domain Names (Root)
                                                                    * ARP Operation Codes

IEEE       https://www.ieee.org/                                   
           https://en.wikipedia.org/wiki/Institute_of_Electrical_and_Electronics_Engineers
           https://en.wikipedia.org/wiki/IEEE_Standards_Association
```

Most notably they developed standards for Local Area Networks (802 series) such as:
- 802.1 - LAN and WAN bridging and security
- 802.2 - LLC sub-layer
- 802.3 - Ethernet (CSMA/CD)
- 802.11 - Wireless LAN
- 802.15 - Wireless PAN

References:  
https://www.ietf.org/standards/  
https://www.iana.org/  
https://www.ieee.org/  
https://en.wikipedia.org/wiki/Institute_of_Electrical_and_Electronics_Engineers  
https://en.wikipedia.org/wiki/IEEE_Standards_Association  


---
## 1.2 Explain OSI Layer 1 data communications and technologies 
Layer 1 or the physical layer is responsible for the transmission and reception of unstructured raw data between a device and a physical transmission medium (twisted-pair cable, coaxial cable, and fiber-optic cable). It converts the digital bits into electrical, radio, or optical signals. Layer specifications define characteristics such as voltage levels, the timing of voltage changes, physical data rates, maximum transmission distances, modulation scheme, channel access method and physical connectors. This includes the layout of pins, voltages, line impedance, cable specifications, signal timing and frequency for wireless devices. Bit rate control is done at the physical layer and may define transmission mode as simplex, half duplex, and full duplex. The components of a physical layer can be described in terms of network interface cards (NICs), connectors and interfaces, and cables that facilitate the transmission of data from source to destination. Physical layer specifications are included in the specifications for the ubiquitous Bluetooth, Ethernet, and USB standards.

The physical layer is the lowest layer of the OSI model, it is where data is physically sent across the network as ones and zeros. Additionally, voltage levels, data rates, maximum transmission distance, and physical connections are defined at the physical layer. The devices that exist at this layer do not have knowledge of the contents of messages being sent across, they simply take the input bits and re-transmit them as output bits.


---
### 1.2.1 Explain and compare Binary, Decimal, Hexadecimal and Base64 formats 

There must be an understanding of fundamental number conversions and math that occurs in networking before moving on to more advanced topics involving headers.


---
#### 1.2.1.1 Binary

- Binary (Base 2)
Used internally by nearly all computers, is base 2. Uses two symbols which are "0" and "1", expressed from switches displaying OFF and ON respectively.
  - Depending on its place value (as it moves right to left) it will have an incremental value of the powers of 2. (i.e. 20=1, 21=2, 22=4, 23=8, 24=16, etc.).
- Common Format
  - Base 2 - Lowest level format and is the base language used by computer systems. Uses a series of "0" and "1" in groupings of 8-bits or 1 byte.
  - 01000010 01100001 01110011 01100101 00100000 00110010
- Representation of binary information : Bits=1, Nibbles=4, Bytes=8, etc.
The bit is a binary representation of the smallest set of information in a computer. A collection of these bits must be used to store large amounts of information. The most common groupings and associated terms are listed below:

![image](https://github.com/ruppertaj/WOBC/assets/93789685/670d7c2a-bf99-46b8-8c32-3fa1398ea228)
Figure 2. Comparison of Common Binary Data Groupings

- Bit - The most basic unit of information in computing and digital communications.
  - Values of a bit can vary greatly depending on which 'powers of 2' position its holding.
  - The name is a contraction of binary digit.
  - The bit represents a logical state with one of two possible values.
  - These values are most commonly represented as either "1" or "0", but other representations such as true/false, yes/no, +/−, or on/off are common.
- Nibble - is a four-bit aggregation, or half an octet. It is also known as half-byte or tetrade.
  - The decimal values of each nibble (hex) can vary depending on whether it’s in the high-order or low-order.
  - Low-order can be from 0x00 (0) to 0x0F (15)
  - High-order can be in incremental sums of 16, 32, 64 and 128.
  - In a networking or telecommunication context, the nibble is often called a semi-octet, quadbit, or quartet.
  - A nibble has sixteen possible values (o-15 or rather 0-9 and A-F). A nibble can be represented by a single hexadecimal digit and called a hex digit.
  - A full byte (octet) is represented by two hexadecimal digits; therefore, it is common to display a byte of information as two nibbles.
  - Sometimes the set of all 256 byte values is represented as a 16×16 table, which gives easily readable hexadecimal codes for each value.
  ```
  HEX        8    4    2    1    8    4    2    1

  Decimal   128   64   32   16   8    4    2    1
  ```

- Byte - A unit of digital information that most commonly consists of eight bits.
  - Values that can be achieved are 0 to 255 or 0x00 to 0xFF.
  - Historically, the byte was the number of bits used to encode a single character of text in a computer and for this reason it is the smallest addressable unit of memory in many computer architectures.
  - To disambiguate arbitrarily sized bytes from the common 8-bit definition, network protocol documents such as The Internet Protocol (RFC 791)(1981) refer to an 8-bit byte as an octet.
  - Those bits in an octet are usually counted with numbering from 0 to 7 or 7 to 0 depending on the endianness. The first bit is number 0, making the eighth bit number 7.
  ```
  2^7   2^6    2^5    2^4    2^3    2^2    2^1    2^0    
  128   64     32     16     8      4      2      1
  ```

- Halfword - a unit of digital addressable information in a grouping of 2 (combined) bytes (16-bits).
  - Values can range from 0x0000 (0) to 0xFFFF (65,535).
  ```
  2^15    2^14     2^13    2^12    2^11    2^10    2^9    2^8         2^7   2^6    2^5    2^4    2^3    2^2    2^1    2^0

  32768   16384    8192    4096    2048    1024    512    256         128   64     32     16     8      4      2      1
  ```

- Words - a unit of digital addressable information in a grouping of 4 (combined) bytes (32-bits).
  - Values can range from 0x00000000 (0) to 0xFFFFFFFF (4,294,967,295).

References:  
https://www.advanced-ict.info/interactive/binary.html


---
#### 1.2.1.2 Decimal
- Decimal (Base 10)
  - The most used system of numbers in the world, is used in arithmetic. Uses ten symbols which are "0–9". Like binary it’s place value will increment by the powers of 10 as it moves from right to left.
- Common Format
  - Base 10 - Basis for the numbering system used by humans.
  - Place values are powers of 10. (100=1, 101=10, 102=100, 103=1000, etc. )
  - 66 97 115 101 32 49 48
  ```
  10^5    10^4    10^3    10^2    10^1    10^0

  100000  10000   1000    100     10      1
  ```

References:  
https://en.wikipedia.org/wiki/Decimal  


---
#### 1.2.1.3 Hexadecimal 

- Hexadecimal (Base 16)
  - Often used in computing as a more compact representation of binary (1 hex digit per 4 bits).
  - The sixteen digits are "0–9" followed by "A–F" or "a–f".
    - A = 10, B = 11, C = 12, D = 13, E = 14, F = 15.
  - It’s place values are 8, 4, 2, or 1 as it moves from left to right.
  - The combination of these 4 bits will give you the values of the HEX digits ( 0-15 or 16 total).
- Common Format
  - Base 16 - Used by computers and humans to express larger decimal numbers or long streams of binary into more manageable groupings.
  - 0x42 0xE3 0x73 0xA5 0x20 0x31 0x2B
  ```
  HEX        8    4    2    1    8    4    2    1

  Decimal   128   64   32   16   8    4    2    1
  ```

![image](https://github.com/ruppertaj/WOBC/assets/93789685/7e32cc0a-42ef-4b4e-9849-8be9ca16c280)
Figure 3. Binary, Decimal, and Hex Comparison Table

References:  
https://en.wikipedia.org/wiki/Hexadecimal  
https://www.advanced-ict.info/interactive/binary_hexadecimal.html  


---
#### 1.2.1.4 Decimal to Hexadecimal Conversion

When converting Decimal to Hexadecimal (or converting Hexacedimal to Decimal) it is easiest to convert to 8-bit, 16-bit, or 32-bit binary first.
- Convert from Decimal to Hex
  1. Convert the decimal number to its binary equivalent.
  - 0 - 255 will be contained within 1 byte
  - 256 - 65,535 will be contained within 2 bytes.
  - 65,536 - 4,294,967,296 will be contained within 4 bytes.
  2. Split the byte(s) into 4-bit nibbles with values of 8, 4, 2, and 1 for each nibble.
  - 1 byte will have 2 nibbles, 2 bytes with have 4 nibbles, and 4 bytes will have 8 nibbles.
  3. Convert the values of each 4-bit nibble back into decimal
  - Each nibble of 4 bits will give you a value from 0 to 15.
  - 10 = A, 11 = B, 12 = C, 13 = D, 14 = E, and 15 = F
  4. Order each hexadecimal digit in order from left to right.
  5. The symbol of 0x is placed in front of the value to designate it as a hexidecimal number.
- Convert from Hex to Decimal
  1. Align each Hex digit to the bit chart
  - 2 Hex to 1-byte, 4 Hex to 2-bytes, 8 hex to 4-bytes.
  - The leftmost Hex will align with the High order bits while the rightmost Hex will align with the lowest-order bits.
  2. Convert each Hex to its decimal equivalent.
  - A = 10, B = 11, C = 12, D = 13, E = 14, F = 15
  3. Convert each decimal to its binary equivalent and place into each 4-bit nibble.
  4. Add up all the bits that are turned on.
  - 1 byte will return values from 0 - 255
  - 2 bytes will return values from 256 - 65,535
  - 4 bytes will return values from 65,536 - 4,294,967,296

![image](https://github.com/ruppertaj/WOBC/assets/93789685/cec127c8-520f-4c6b-b313-37b094d10407)
Figure 4. HEX/DEC Conversation Table

One Byte Decimal to/from Hex Conversion.

![image](https://github.com/ruppertaj/WOBC/assets/93789685/a07ae1f0-90e2-482f-ac84-bb3cd570fe36)

Two Byte Decimal to/from Hex Conversion.

![image](https://github.com/ruppertaj/WOBC/assets/93789685/603014c6-4a5c-4401-b997-ecf22ea36a01)

Four Byte Decimal to/from Hex Conversion.

![image](https://github.com/ruppertaj/WOBC/assets/93789685/37b96b0f-c648-402e-80ac-dc3d5787a950)

References:  
https://en.wikipedia.org/wiki/Hexadecimal


---
#### 1.2.1.5 Base64 
- Tetrasexagesimal (Base 64)
  - This system is conveniently coded into ASCII by using the 26 letters of the Latin alphabet in both upper and lower case (52 total) plus 10 numerals (62 total) and then adding two special characters
- Common Format
  - Base 64 - Like HEX, it allows groupings up to 6-bits of binary (0-63 decimal).
  - Characters used are (A-Z), (a-z), (0-9), and (+, /). That is (26) + (26) + (10) + (2) respectively.
  - In order to be compatible with binary, it uses 4 groupings of 6-bits (24 total bits) so that it will equate to 3 bytes of binary ( 24 bits).
  - For data not consuming the full 24-bits, it will use "=" signs for each 6 unused bits at the end as padding. Not more than 2 "=" will be used.
  - MTI=, MTIzNA==, MTIzNDU2Nzg=, QmFzZSA2NA==
  ```
  2^5 2^4 2^3 2^2 2^1 2^0     2^5 2^4 2^3 2^2 2^1 2^0     2^5 2^4 2^3 2^2 2^1 2^0     2^5 2^4 2^3 2^2 2^1 2^0
  32  16  8   4   2   1       32  16  8   4   2   1       32  16  8   4   2   1       32  16  8   4   2   1       
  ```

![image](https://github.com/ruppertaj/WOBC/assets/93789685/afc867a1-4640-4be2-83cc-e31e1102b106)

References:  
https://en.wikipedia.org/wiki/Base64  
https://www.base64decode.org/  
https://www.base64encode.org/  


---
### 1.2.2 Describe LAN topologies and devices 

LAN (Local Area Network) topologies refer to the physical or logical layout of devices and connections within a local network. We will discuss the common topology types.

---
#### 1.2.2.1 Topologies  
- Bus
A bus network is a network topology in which nodes are directly connected to a common half-duplex link called a bus.

![image](https://github.com/ruppertaj/WOBC/assets/93789685/ae7e5c41-c310-4268-853f-b8620410e9a9)
Figure 5. Bus Topology

- Star
A star network is an implementation of a spoke–hub distribution paradigm in computer networks. In a star network, every host is connected to a central hub. In its simplest form, one central hub acts as a conduit to transmit messages.

![image](https://github.com/ruppertaj/WOBC/assets/93789685/7e5d1709-bbd6-4393-86d2-068eaf097c05)
Figure 6. Star Topology

- Ring
A ring network is a network topology in which each node connects to exactly two other nodes, forming a single continuous pathway for signals through each node – a ring. Data travels from node to node, with each node along the way handling every packet.

![image](https://github.com/ruppertaj/WOBC/assets/93789685/9dd571bb-613b-43b1-9c35-b310777d40d4)
Figure 7. Ring Topology

- Mesh
A mesh network is a local network topology in which the infrastructure nodes (i.e. bridges, switches, and other infrastructure devices) connect directly, dynamically and non-hierarchically to as many other nodes as possible and cooperate with one another to efficiently route data from/to clients. This lack of dependency on one node allows for every node to participate in the relay of information. Mesh networks dynamically self-organize and self-configure, which can reduce installation overhead. The ability to self-configure enables dynamic distribution of workloads, particularly in the event a few nodes should fail. This in turn contributes to fault-tolerance and reduced maintenance costs.

![image](https://github.com/ruppertaj/WOBC/assets/93789685/accad673-f9d8-4e5e-826d-c2296dcb25af)
Figure 8. Mesh Topology

- Wireless
A wireless network is a computer network that uses wireless data connections between network nodes. Note: All wireless connections eventually connect to a wired network.

![image](https://github.com/ruppertaj/WOBC/assets/93789685/301bff11-b7b9-4706-a624-afe8112669ba)
Figure 9. Wireless Topology

- Hierarchial
The hierarchical topology model is made up of the following:
  - A core layer of high-end switches optimized for network availability and performance.
  - A distribution layer of switches implementing forwarding decisions.
  - An access layer connecting users via hubs, bridges, or switches.

![image](https://github.com/ruppertaj/WOBC/assets/93789685/05408e8e-ce58-4640-b00b-7f4af1e7994e)
Figure 10. Hierarchial Topology


---
#### 1.2.2.2 Devices 
- Hubs are devices that allow multiple nodes to connect on the same wire (Collision Domain). https://en.wikipedia.org/wiki/Ethernet_hub
- Switches are devices that allow multiple nodes to connect on the network, but on their own collision domain. The layer 2 originating MAC address of the frame are learned from the incoming frames and are stored in the mac address table memory, also called a Content Addressable Memory (CAM) table. https://en.wikipedia.org/wiki/Network_switch
- Repeaters are devices that allow a connection to be extended beyond the normal operational cable or wireless limits.

References:  
https://en.wikipedia.org/wiki/Ethernet_hub  
https://en.wikipedia.org/wiki/Network_switch  


---
#### 1.2.2.3 Ethernet Timing 

Ethernet timing refers to the synchronization mechanisms used in Ethernet networks to ensure proper transmission and reception of data frames.
- Bit Time - is the period of time is required for a bit to be placed and sensed on the media. Network speeds are measured by how many bits can be placed or sensed on the media in 1 second. Each increase in speed requires more bits to be sent during the same 1 second internal. To accomplish this the bit-times are reduced.
```
Speed	    Bit-time
10 Mbps     100ns

100 Mbps    10ns

1 Gbps      1ns

10 Gbps     .1ns

100 Gbps    .01ns
```

References:  
http://ictechnotes.blogspot.com/2011/06/ethernet-timing.html  


---
## 1.3 Explain OSI Layer 2 protocols, headers and technologies

Layer 2 of the OSI (Open Systems Interconnection) model, also known as the Data Link Layer, is responsible for the efficient and reliable transfer of data between adjacent nodes on a network segment. Layer 2 protocols, headers, and technologies operate at this layer to facilitate communication within the local network.


### 1.3.1 Describe LAN technologies and their benefits and hindrances  

LAN (Local Area Network) technologies are used to connect devices within a limited geographical area, such as a home, office, or campus.There are many LAN technologies in use today. These technologies are mostly governed by IEEE standards such as:
```
Technology	     Standard                                   	                Advantages                               	Disadvantages
Ethernet             IEEE 802.3, 802.3u, 802.3z, 802.3ae, 802.3de                       Low cost                                        Does not prioritize traffic for QoS
                                                                                        Easy to install maintain and troubleshoot       Cabling infrastructure required

                                                                                        Fast and consistent data transfer speed         

Wireless             IEEE 802.11 (WI-Fi 0), 802.11b (Wi-Fi 1), 802.11a (Wi-Fi 2),       No cables                       Network interferance
                     802.11g (Wi-Fi 3), 802.11n (Wi-Fi 4), 802.11ac (Wi-Fi 5),          Easy install and deployment     Traffic in the open
                     802.11ax (Wi-Fi 6), 802.11be (Wi-Fi 7)                                                             Authenication needed
                                                                                                                        Slow and inconsistent data transfer speed
                                                                                                                        Half Duplex communications

Token Ring           IEEE 802.5                                                         Fair access for all nodes       More complex compared to Ethernet

                                                                                        Eliminates collisions of contention-based access methods
```

This course will be focusing on Ethernet.

References:  
https://en.wikipedia.org/wiki/IEEE_802.3  
https://en.wikipedia.org/wiki/IEEE_802.11  
https://en.wikipedia.org/wiki/Token_Ring  


---
### 1.3.2 Data Link Sub-layers  
- Data link layer is unique because it has the function to communicate in "logical" and "physical". To accommodate this the functionality of this layer is divided into two logical sub-layers. An upper sub-layer, LLC, to interact with the network layer above and a lower sub-layer, MAC, to interact with the physical layer.
  - Media Access Control (MAC):
    - The MAC sub-layer is responsible for controlling access to the physical transmission medium.
    - Handles the transmission and reception of data frames over the physical medium, including addressing, framing, and error checking.
    - Act as a sublayer governing protocol access to the physical medium, physical addressing, and acts as an interface between the LLC and physical layer. Most of the frame construction happens at this layer.
      - Provides the destination MAC address.
      - Either a broadcast (FF:FF:FF:FF:FF:FF) to address all nodes on LAN.
      - Unicast MAC (4A:30:10:19:10:1A) to address one node on LAN.
      - Multicast MAC (01:00:5E:00:00:C8) to address a group of nodes on a LAN. Will have a Multicast address as the destination IP.
    - Provides the source MAC address.
      - Always a Unicast MAC.
    - Calculates the Cyclic Redundancy Check (CRC) on the Frame and appends to the Frame Check Sequence (FCS) field.
    - Controls access to/from the medium.
      - Sending bit-rate (bit speed)
      - Duplex (Half or Full) and CSMA/CD functions
      - Frame delimiting and recognition
  - Logical Link Control (LLC):
    - The LLC sub-layer is responsible for establishing, maintaining, and terminating logical links between network devices.
    - Provides services such as error detection and flow control to ensure reliable data transmission over the physical medium.
    - LLC defines the framing and addressing mechanism for data frames and handles the multiplexing of network layer protocols.
    - It acts as an interface between the Network Layer (Layer 3) and the MAC sub-layer, enabling communication between the two layers regardless of the underlying physical media.
    - Manages communication between devices over a single link of the network that includes error checking and data flow.
    - Multiplexes protocols to be sent over the MAC sub-layer.
    - Follows the IEEE 802.2 standard.
    - This layer provides the Ethertype to the MAC sublayer in the frame construction to identify the encapsulated protocol.
      - 0x0800 for IPv4
      - 0x0806 for ARP
      - 0x86dd for IPv6
      - 0x8100 for 802.1q VLAN tag

References:  
https://en.wikipedia.org/wiki/Logical_link_control  
https://en.wikipedia.org/wiki/Medium_access_control  
https://en.wikipedia.org/wiki/IEEE_802.2  


---
### 1.3.2 Explain why and how frames are interpreted by different devices 
Frames are fundamental units of data transmission at the Data Link Layer (Layer 2) of the OSI model. They contain data encapsulated within headers and trailers that provide essential information for transmitting and receiving data over a network. Different network devices interpret frames in various ways based on their roles and functionalities.


---
#### 1.3.2.1 Message Formatting Method and Terminology 
The structure that is used for sending information over a network is often referred to as a message. This message varies greatly between different protocols and technologies. While exact formatting of particular messages are dependent on the technology or protocol being used, they typically utilize a similar formatting method consisting of a header, data, and footer.
- Header - The header contains information related to control and communication processes between different protocol elements for different devices. This typically consists of information such as the source and destination address, clock information for transmission synchronization, and alert signals to indicate a packet is being transmitted.
- Data - This is the actual data being transmitted which contains the payload. This payload may include another higher level message that consists of the same elements. For example, the data may contain information used to setup a logical connection before data is sent.
- Footer - Commonly referred to as the trailer. The contents vary between communication methods or protocols. Usually the cyclical redundancy check (CRC) error-checking component is placed here. This is not always required for each protocol, but is especially important at the data-link layer.

![image](https://github.com/ruppertaj/WOBC/assets/93789685/986ffcd4-dfe4-4107-9933-f0b71e74c379)
Figure 11. Message Format

It is important to understand that the data of any particular message sent in networking may contain higher-level information consisting of a header, data, and footer related to upper layer protocols. This will occur multiple times as data is passed down or up a protocol stack and is known as encapsulation or decapsulation.

The actual data transmission is vertical, however each layer is programmed as if the transmission is horizontal. This is possible with the use of protocols and interfaces. `

Protocols and Interfaces
- Protocols - Protocols refer to communications occurring at the same layer within the OSI model (horizontal). Protocols allow communication to take place logically at layer 4 on two separate devices as if they were directly connected at layer 4.
- Interfaces - Interfaces refer to information moving between different layers in the OSI model (vertical) on the same device. In order for protocols to communicate effectively they must pass information up and down the stack.

Encapsulation and Decapsulation
- The communication between every layer other than the Physical layer is logical in nature. Therefore in order to pass information between protocol layers a protocol data unit (PDU) must be used. Each PDU for each protocol layer has specifications for the features or requirements at its layer. The PDU is passed down to a lower layer for transmission, the next lower layer is providing the service of handling the previous layer’s PDU. This is why the previous layer’s PDU is now referred to as an service data unit (SDU).
  - Protocol Data Units for each OSI Layer:
  - Application, Presentation, and Session = Data
  - Transport = Segment (TCP) or Datagram (UDP)
  - Network = Packet
  - Data Link = Frame
  - Physical = Bits

![image](https://github.com/ruppertaj/WOBC/assets/93789685/cc4c38f0-4bf2-4368-8110-7318a1b0d046)
Figure 12. PDU/SDU Representation

- The passing of information among the layers through this process may seem complex due to the formatting that must take place multiple times with PDU assembly and disassembly. However, this is necessary in providing modularity for network communication to take place.


---
### 1.3.3 Identify how switches affect network traffic and the visibility of network traffic by other hosts 
- Switch Operation A switch allows multiple users to access the network and can provide segmentation to isolate traffic flow and reduce collisions, relieving network congestion in most cases. All switches add small latency delays due to packet processing. These delays could be caused by port speed, frame processing (Cut-through or Store and Forward), port delay, and buffering delay. Deploying switches unnecessarily can actually slow down network performance.
  - Building the MAC-Address Table:
    - Switches contain a special type of computer memory called Content-addressable memory (CAM) which allows very fast searching and table lookups. CAM is much faster than RAM. This is essential for switches to do very fast table lookups. CAM is a very expensive type of memory and generates very high levels of heat. Thus CAM is not typically used in most other types of electronic devices. It is used to "look up" information (such as MAC addresses) and requires it to have an exact match.
    - Switches will dynamically build the MAC address table by examining the source MAC address of the frames received on a port. The switch determines that if it receives a frame on an interface, whatever the source address is, that device can be reached if traffic was sent back through that interface.
  - Switch frame forwarding process:
    - When a switch receives a frame, it will identify and check the destination MAC address information on the frame against the switch’s MAC address table.
    - If the MAC address is found in the table, it will then send it out to the appropriate interface only.
    - If the MAC address is not found in the MAC address table, then it will flood the frame out of all ports (except the source port) in an attempt to get the frame to the destination MAC address. If a reply is sent back, the switch will store the new MAC address information in its MAC address table and finally forward the frame. If no response is received, then the frame will be dropped.
    - If the frame is a broadcast MAC address (FF:FF:FF:FF:FF:FF) then the frame will be flooded out all ports (except the source port).
    - If the frame is a multicast MAC address (01:00:5E:00:00:C8) then the frame can be:
      - Sent out specific ports assigned to the group as managed by Cisco Group Management Protocol (CGMP) or Internet Group Management Protocol (IGMP) snooping.
      - Flooded out all ports (except the source port) if no Cisco Group Management Protocol (CGMP) or Internet Group Management Protocol (IGMP) snooping.
  - Switching Modes:
    - Store-and-Forward accepts and analyzes the entire frame before forwarding it to its destination. It takes more time to examine the entire frame, but it allows the switch to catch certain frame errors and collisions and keep them from propagating bad frames through the network. This method is required to switch frames between links of different speeds; this is due to bit-timing. The speed at which the bits enter one interface may be slower than the speed at which the switch needs to send the bits to a different interface.
    - Cut-Through (sometimes called fast forward) only examines the destination address before forwarding it to its destination segment. This is the fastest switching mode but requires the interfaces to be the same speed.
    - Fragment-Free read at least 64 bytes of the Ethernet frame before switching it to avoid forwarding Ethernet runt frames (Ethernet frames smaller than 64 bytes). A frame should have a minimum of 46 bytes of payload plus its 18-byte frame header.
  - The switch’s operation of using the MAC address table to forward traffic out to only the designated ports, helps reduce network traffic and allows for a more efficient flow of traffic. If a host does happen to receive a frame not intended for them, the host will simply drop it.

References:  
https://en.wikipedia.org/wiki/Cut-through_switching  
https://en.wikipedia.org/wiki/Bit_time  
https://en.wikipedia.org/wiki/Internet_Group_Management_Protocol  
https://en.wikipedia.org/wiki/Network_switch  
https://www.cbtnuggets.com/blog/technology/networking/cam-table-overflow-attack-explained  


---
#### 1.3.3.1 CAM Table Overflow/Media Access Control (MAC) Attack 
- CAM Table Overflow/Media Access Control (MAC) Attack
  - A CAM (Content Addressable Memory) table overflow attack, also known as a MAC (Media Access Control) flooding attack, is a type of security exploit that targets network switches. This attack aims to overwhelm a switch’s CAM table, which is used to store MAC address-to-port mappings, leading to a denial of service (DoS) condition or facilitating a man-in-the-middle attack.
  - This attack focuses on the Content Addressable Memory (CAM) table that stores the MAC addresses on a switch. A switch with only one VLAN will just have one CAM table. A switch will create a serarate CAM table for each VLAN supported by the switch.
  - CAM tables have a fixed memory size and this is what makes them a target for attack. The amount of MAC address the switch can "learn" varies depending on the vendor of the switch and factor such as:
    - Entry-level switches designed for home or small office use may have smaller CAM tables, typically in the range of a few hundred to many one thousand entries.
    - Switches used in larger enterprise networks often have larger CAM tables to accommodate a higher number of devices. These tables can range from several thousand to tens of thousands of entrie
    - High-end switches used in data centers or large-scale enterprise environments may have even larger CAM tables. These switches are designed to handle extensive network traffic and support a large number of connected devices.
  - Similar to a buffer overflow attack, the goal is to fill the switches table with "learned" MAC addresses and see what happens. The attacker sits on one port and generates a vast number of "spoofed" MAC entries. When the CAM table is full, all additional MACs will not be learned and will default to "open". This means that traffic without a CAM entry will be flooded out on all ports of the VLAN in question. Traffic with a CAM entry won’t be affected, but neighbor switches could be.
  - Depending on the switch in question, this type of attack can be mitigated.
```
switch(config)# interface fa0/10
switch(config-if)# switchport port security
switch(config-if)# switchport port security maximum 1
switch(config-if)# switchport port security violation shutdown
```


---
### 1.3.4 Describe MAC addressing 
A Layer 2 Ethernet switch uses the destination MAC addresses to make forwarding decisions. It is completely unaware of the protocol being carried in the data portion of the frame, such as an IPv4 packet. The switch makes its forwarding decisions based only on the Layer 2 Ethernet MAC addresses.

![image](https://github.com/ruppertaj/WOBC/assets/93789685/14356b88-1e46-4f81-8c9f-613a3107f199)
Figure 13. Ethernet Frame

- Unique identifier assigned to a Network Interface (NIC) used for layer 2 addressing for communications between nodes.
  - MAC addresses are only locally significant.
  - MAC addresses are used to communicate with devices on the same newtwork only.
  - MAC addresses are removed/replaced by each OSI Layer 3 device or above.
  - Devices with the same MAC address on the same network will create conflilcts.
  - Devices with the same MAC address on different networks will not create any conflicts.
- Length:
  - 48 bits or 6 bytes in length represented by 12 hexadecimal digits.
  - Different Formatting:
  - Windows: 01-23-45-12-34-56
  - Unix/Linux: 01:23:45:12:34:56
  - Cisco: 1234.5612.3456
- MAC Address is split into two main parts:
  - Organizationally Unique Identifier (OUI) - First 24 bits or 3 bytes or 6 HEX.
    - The OUI is typically assigned by IANA to a vendor, manufacturer, or other organization.
      - Virtual Machines (VM) do not normally use a particular OUI and may randomly assign their MAC addresses.
  - Vendor assigned - Last 24 bits or 3 bytes or 6 HEX.
- IANA controls the assignment of the OUIs.
- Universal versus local (U/L bit) (7th bit from the left in the MAC address)
  - Universally Administered Addresses (UAA) - bit set to '0'
  - Locally administered (LAA) - bit set to '1'
- Unicast versus multicast (I/G bit) (8th bit from the left in the MAC address)
  - Unicast bit set to '0' the frame is meant to reach only one receiving NIC.
    - Unicast MAC with 8th bit off: fa:16:3e:12:1d:99
  - Multicast bit set to '1' the frame is treated as multicast frames and are flooded to all points on the network.
    - Typically starts with 01 in the first byte.
    - Multicast MAC with 8th bit on: 01:00:5e:00:00:00.
- Broadcast - Frames are addressed to reach every computer on a given LAN segment using an address of all 'f’s.
  - FF-FF-FF-FF-FF-FF or FF:FF:FF:FF:FF:FF or ffff.ffff.ffff

![image](https://github.com/ruppertaj/WOBC/assets/93789685/95d08614-c2ad-4da0-b7d4-2126444e74f8)
Figure 14. MAC Address

References:  
https://www.iana.org/assignments/ethernet-numbers/ethernet-numbers.xhtml  
https://en.wikipedia.org/wiki/Organizationally_unique_identifier  
https://ouilookup.com/  
https://www.wireshark.org/tools/oui-lookup.html  
https://en.wikipedia.org/wiki/Multicast_address  
http://www.tcpipguide.com/free/t_TCPIPAddressResolutionForIPMulticastAddresses.htm  


---
#### 1.3.4.1 MAC Spoofing 
- Spoofing is the act of disguising a communication from an unknown source as being from a known or trusted source. Spoofing is an attack vector done at several different layers of the OSI. At the Data-link layer attackers will commonly spoof the MAC-address.
- Originally MAC addresses were hard coded into the firmware of the NIC and could not be easily changed. This is why MAC addresses were commonly called "Firmware", "Hardware", or "Burned-in" addresses. In order to facilitate MAC spoofing attacks it required crafting of special frames with the MAC address pre-programmed in.
- Today most MAC addresses are programmed using the software. This makes modification of a device’s MAC address much simpler. In order to perform a MAC spoofing attack the malicious actor can either change their MAC address to a known or trusted address or create crafted frames with the MAC address already programmed in. MAC spoofing can be used to perform:
  - ARP-Cache poisoning - modify the ARP cache of devices on the same network segment.
  - ARP Man-in-the-middle (MitM) attacks - Specially crafted ARP messages to force 2 or more victims to send traffic thru the attacker’s system. Here the attacker can sniff or alter traffic.
---
DEMO MAC Spoofing

Scapy Script to demonstrate MAC Spoofing
```
a=Ether()
a.dst="ff:ff:ff:ff:ff:ff"   #Specify any target MAC you require
a.src="01:02:03:aa:bb:cc"   #Insert your Spoofed MAC here
a.type=0x0800

b=IP()
b.proto=6               #specifies that TCP is encapsulated. Change to 1 for ICMP or 17 for UDP.
b.src="10.10.0.40"      #Any source IP
b.dst="172.16.82.106"   #Target IP

c=TCP()
c.sport=54321
c.dport=80

d="message"

sendp(a/b/c/d)
```

References:  
https://www.geeksforgeeks.org/what-is-mac-spoofing-attack/  
https://en.wikipedia.org/wiki/MAC_spoofing  


---
### 1.3.5 Analyze 802.3 frame headers 
In this section, we are going to step you through how to analyze a packet down to the frame, identifying different parts of the frame, and where they are located in the packet.
- STEP 1: Open the following link: https://www.cloudshark.org/captures/fe65ed807bc3
- STEP 2: In the packet list pane (top section), click the first frame listed. You should see Echo (ping) request under the Info heading. This should highlight the line blue.
- STEP 3: Examine the first line in the packet details pane (lower left section). This line displays the length of the frame; 74 bytes in this example.
- STEP 4: The second line in the packet details pane shows that it is an Ethernet II frame. The source and destination MAC addresses are also displayed.
- STEP 5: Click the arrow sign at the beginning of the second line in the packet details pane to obtain more information about the Ethernet II frame. You should see the Destination, Source, and Type.
- STEP 6: Click on the Destination, observe the Packet Bytes pane (bottom right section) displays the highlighted hex and ASCII equivalent. You can see that the Destination starts at byte 0 and ends at byte 5. That is a total of 6 bytes or 48 bits.
- STEP 7: Click on the Source, observe the Packet Bytes pane (bottom right section) displays the highlighted hex and ASCII equivalent. You can see that the Source starts at byte 6 and ends at byte 11. That is a total of 6 bytes or 48 bits.
- STEP 8: Click on the Type, observe that the Type comes after the Source and is only 1 byte in size. The Type of frame is identified as 0x0800 or IPv4.

References:  
https://www.cloudshark.org  


---
### 1.3.6 Describe the contents of an Ethernet header and frame 

![image](https://github.com/ruppertaj/WOBC/assets/93789685/164d6b8a-fb8d-48fc-b9ec-316ce1b58eb7)
Figure 15. Ethernet Frame with preamble

![image](https://github.com/ruppertaj/WOBC/assets/93789685/2cec7db1-72a1-481c-8b1a-6a4f07adb2c6)
Figure 16. Common Ethernet Type II Frame

- Specification Information:
Defined by IEEE 802.3 standard, major participants in the development of the commonly used Ethernet II frame include XEC, Intel, and Xerox.
- Structure:
  - Preamble (7 bytes) +Consists of alternating 1’s and 0’s to allow network synchronization with receiver clocks. Ethernet is self-clocked, the clock is extracted from the signal. The clock is used to set the bit-timing. This is so that the receiver knows what speed the bits will be arriving at. This is stripped off at the NIC and not visible by packet analyzer software.
  - SFD (Start Frame Delimiter) (1 byte field) Marks the end of the preamble, and the beginning of the Ethernet frame and send an announcement that data is about to be sent to any other hosts on the same network segment. This is stripped off at the NIC and not visible by packet analyzer software.
  - Destination MAC Addresses (6 bytes)
    - Initial 6 bytes (48 bits) contain the Destination MAC address.
    - This can be Unicast, Multicast, or Broadcst MAC address.
    - This is sent first to assist in switch operation of the cut-through mode.
  - Source MAC Addresses (6 bytes)
    - Next 6 bytes (48 bits) contain the Source MAC Address.
    - This is always a Unicast MAC address.
    - It is worth noting that this is pretty much the only time that the destination address comes before the source. The source address will come first in most other headers that we deal with in this course.
  - Ethertype (2 bytes) Used to indicate the next protocol encapsulated in the frame. This is provided by the LLC sub-layer.
    - Common Ethertypes controlled by IANA.org <https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml#ieee-802-numbers-1>:
      - 0x0800 - IPv4
      - 0x0806 - ARP
      - 0x86DD - IPv6
      - 0x8100 - VLAN Tagging 802.1q
      - 0x88A8 - Service VLAN tag identifier (S-Tag) (Q-in-Q tunnel)
      - 0x8863(4) - PPP over Ethernet (PPPoE)
      - 0x8847(8) - MPLS
      - 0x8892 - PROFINET Protocol
  - Data / Payload (46-1500 bytes)
    - Consists of the encapsulated upper layer headers and data payload which may be 46-1500 bytes.
    - The minimum 46 bytes is based on the fact that the smallest "legal" ethernet frame size is 64 bytes; so 46 bytes of data with 18 bytes of Frame header equates to 64 bytes. Anything less than 64-bytes is assumed to be a collision fragment (or "runt"). "Padding" is used when there is less than 46-bytes of data.
    - The maximum data bytes is determined by the MTU for the network segment. The MTU is the maximum size of the payload of the frame of the particular network. Ethernet II by default has a max MTU of 1500 bytes. This MTU is the amount of encapsulated data. MTU of 1500 plus the 18 byte header equates to 1518 bytes. Anything greater than this may be considered a "Jumbo" frame.
    - This typically is the size of the IP packet but can be the size of other encapsulated protocols like ARP or IPv6.
    - The Frame header is not calculated in to this size. So the frame size could be 1518 bytes (or more) in total when the 18 byte header is added. It’s worth noting that the 1500 bytes is of total encapsulated information and not exclusively user data. This 1500 bytes includes the 20+ byte IPv4 header and 20+ byte TCP header. If VPN or tunneling is involved then the extra headers must also fit within this 1500 bytes.
    - MTU defaults <https://en.wikipedia.org/wiki/Maximum_transmission_unit>:
      - 1500 - Ethernet
      - 17914 - 16 MBPS Token Ring
      - 4464 - 4 MBPS Token Ring
      - 4352 - FDDI
      - 2304 - IEEE 802.11 Wi-FI (WLAN)
      - 1280 - IPv6 path
      - 1492 - IEEE 802.3/802.2
      - 1480 - PPoE (WAN Miniport)
      - 576 - X.25
    - If there are any other headers included, such as IPSEC, IPv4 or TCP options, then this would mean that even less user data can be encapsulated.
  - FCS/CRC (Frame Check Sequence / Cyclical Redundancy Check) (4 bytes)
    - Mathematical formula calculated on the entire frame. This calculation is appended in the FCS field so that the receiver can determine if the contents of the frame were corrupted in transit. This is stripped off at the NIC and not visible by packet analyzer software.

References:  
https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml#ieee-802-numbers-1  
https://en.wikipedia.org/wiki/Maximum_transmission_unit


---
### 1.3.7 Describe an 802.1Q virtual local area network (VLAN) frame and how its frames differ from a standard 802.3 frame 
An 802.1Q Virtual Local Area Network (VLAN) frame is a type of Ethernet frame that includes additional information for VLAN tagging. This tagging allows network administrators to logically segment a single physical network into multiple virtual networks, known as VLANs, to improve network performance, security, and manageability.

![image](https://github.com/ruppertaj/WOBC/assets/93789685/0864acab-4316-489d-b16f-42740bf1e7ef)
Figure 17. 802.1Q VLAN Tagged Frame

802.1Q is used to add a "tag" to identify to the receiving switch/router as to what VLAN the frame is being sent from. This tag is an additional 4 bytes of data that is appended between the Source MAC address and Ethertype field. This in essence increases the size of the frame header from its original 18 bytes to 22 bytes. The Ethertype field is "shoved over" from byte offset [12] to byte offset [16]. This tag is only applied across Trunk links. The switch/router is responsible to add this 4-byte tag when sending over any trunk links and to remove the tag when needing to send over an Access port. For example, prior to sending to a PC or printer.
- Structure:
  - MAC Header (12 byte field)
    - Initial 6 bytes contain the Destination MAC address
    - Next 6 bytes contain the Source MAC Address
  - VLAN Tag (4 byte field)
    - Tag Protocol ID (2 byte field)
Initial 2 bytes contain the new effective Ethertype field of 0x8100 indicating tagging
    - Tag Control Information (2 byte field)
      - Priority Code Point (3 bits)
This is used to add prioritization or QoS to VLANs
      - Drop Eligible Indicator (1 bit)
This adds drop eligibility to VLAN traffic in case of congestion
    - VLAN ID (12 bit field)
To specify the VLAN number. Can be 0x000 to 0xfff or 0* to 4095.
      - 1 to 1005 Normal range
      - 1003 to 1005 – reserved for Token Ring
      - 1006 to 4094 – Extended Range
  - Ethertype (2 byte field)
Used to indicate the next protocol encapsulated in the frame.
  - Data / Payload (46-1500 byte field)
Consists of the encapsulated upper layer headers and data payload which may be 46-1500 bytes
  - FCS/CRC (Frame Check Sequence / Cyclical Redundancy Check) (4 byte field)
A new calculation is conducted to accommodate the addition of the new tag information. This calculation is done by the switch or router that added the tag. This also will be stripped off by the receiving NIC and will not be viable by the network analyzer.
---
DEMO of VLAN tagging with ICMP

Demo of ICMP messages over VLAN trunk links from www.cloudshark.org <https://www.cloudshark.org/captures/001010a25ef6>

References:  
https://www.cloudshark.org/captures/001010a25ef6  
https://en.wikipedia.org/wiki/IEEE_802.1Q  


---
#### 1.3.7.1 Networks without VLANs  
Networks without VLANs operate as a single broadcast domain, where all devices connected to the same physical network segment can communicate with each other without any logical segmentation.
- Single Broadcast Domain:
  - In networks without VLANs, all devices connected to the same physical network segment receive broadcast traffic intended for the entire segment.
  - Broadcast traffic includes protocols such as ARP (Address Resolution Protocol) and DHCP (Dynamic Host Configuration Protocol), as well as other network-wide announcements. Each physical interface on a router is assigned to a different network. Will need one physical interface per network required. Future planning is critical as additional added networks can be difficult and costly to install.
  - All hosts on the switched LAN are part of the same network and only a router can segment networks.
  - In normal operation, when a switch receives a broadcast frame on one of its ports, it forwards the frame out all other ports except the port where the broadcast was received.
  - On a switch with only 1 vlan configured (vlan 1 by default) all ports belong to same broadcast domain.
- Flat Network Structure:
  - Networks without VLANs typically have a flat network structure, where all devices are part of the same logical network.
  - Devices within the network can communicate directly with each other without the need for routing between subnets or VLANs.
- Limited Segmentation and Isolation:
  - Without VLANs, there is limited segmentation and isolation of network traffic.
  - Devices in different departments, groups, or security zones share the same broadcast domain and have unrestricted access to each other’s traffic, which can present security and performance challenges.
- Broadcast Storms and Traffic Congestion:
  - In networks without VLANs, broadcast storms can occur if a device generates a large amount of broadcast traffic, overwhelming the network and causing performance degradation.
  - Similarly, network congestion can occur as all devices share the same network bandwidth, leading to potential bottlenecks.


---
#### 1.3.7.2 Networks with VLANs  
Networks with VLANs (Virtual Local Area Networks) offer greater flexibility, security, and efficiency compared to traditional networks without VLANs. VLANs allow network administrators to logically segment a single physical network into multiple virtual networks, each with its own broadcast domain.
- Logical Segmentation:
  - VLANs allow network administrators to logically segment the network into multiple broadcast domains, regardless of the physical network topology. Devices within the same VLAN can communicate with each other as if they were on the same physical network segment, while traffic between VLANs typically requires routing.
  - When VLANs are implemented on a switch, the transmission of unicast, multicast, and broadcast traffic from a host in a particular VLAN are restricted to the devices that are in that VLAN only.
- Broadcast Isolation:
  - Each VLAN forms a separate broadcast domain, reducing the scope of broadcast traffic. Broadcast traffic generated within a VLAN is only forwarded to devices within that VLAN, improving network efficiency and reducing unnecessary traffic on other VLANs.
- Enhanced Security:
  - VLANs provide enhanced security by segregating network traffic and controlling communication between different groups of devices. Access control lists (ACLs) and firewall policies can be applied at VLAN boundaries to restrict traffic flow between VLANs based on security policies.
- Improved Performance:
  - By dividing the network into smaller broadcast domains, VLANs can reduce broadcast traffic and network congestion, leading to improved performance and better overall network efficiency.
- Flexibility:
  - VLANs provide flexibility in network design and management, allowing administrators to easily add, remove, or modify VLAN configurations without physical reconfiguration of network infrastructure.
  - All the "tagging" processes are completely transparent to the "user" and is handled by the intermediary network devices.
  - When the switch receives a frame on a port configured in access mode and assigned a VLAN, the switch will then determine what interface to send the frame out. If the outgoing interface happens to be a trunk port, the switch inserts the VLAN tag in the frame header, recalculates the Frame Check Sequence (FCS), and sends the tagged frame out of that trunk port. Inversely, when a switch receives a tagged frame from a trunk link and it determines that the outgoing interface is an access port, the switch will remove the vlan tag and the FCS is recalculated again. The Type field is also reverted back to its original value. The 4-byte tag is removed and the Type field reverts back to its original location at [12:2].


---
#### 1.3.7.3 VLAN Types 
There are 5 main types of VLANs. Only 1 VLAN can be assigned to any switch port. The only exception to this is the voice VLAN. The voice VLAN can be assigned with a data VLAN.

The VLAN Types are:
- Default - VLAN 1 is the default vlan. VLAN 1 will always be present on the switch and can not be deleted. All ports will be assigned to VLAN 1. When VLAN assignment is removed from a port it will automaticcally be assigned to VLAN 1.
- Data - VLANs assigned for user traffic.
  - Data VLANs are used to separate user data traffic based on different groups, departments, or functions.
  - Devices within the same data VLAN can communicate with each other as if they are on the same physical network.
- Voice - VLAN assigned for use for voice traffic only. Typically uses CDP messages from VOIP phones to be asigned.
  - Voice VLANs are used to separate voice traffic from data traffic in networks that support Voice over IP (VoIP) systems.
  - This VLAN is configured to carry voice traffic, ensuring quality of service (QoS) for voice communications.
- Management - A form of data VLAN used for switch/router remote management purposes.
  - A management VLAN is a VLAN used for managing networking devices such as switches, routers, and access points.
  - This VLAN is often used for remote device management, configuration, and monitoring purposes.
  - It helps secure management traffic by segregating it from user data traffic.
- Native - VLAN used for switch/router generated traffic.
  - These are used for control traffic such as CDP, VTP, DTP, and STP. These do not normally have "tags" applied.
  - Native VLANs by default is VLAN 1 but is highly recommended to change.
  - The native VLAN is used on trunk links to carry untagged frames.
  - Frames from the native VLAN are not tagged when traversing trunk links, while frames from other VLANs are tagged.


---
#### 1.3.7.4 Describe an 802.1AD Double Tagging VLANs 

![image](https://github.com/ruppertaj/WOBC/assets/93789685/45490b68-b92c-4067-80b1-2dbae3fe84cb)
Figure 18. 801.1ad Frame

IEEE 802.1ad is an Ethernet networking standard informally known as "Q-in-Q". The was added as an amendment to IEEE standard IEEE 802.1Q-1998. This technique was commonly used for provider bridging or tagging. A service provider could tag already tagged user frames across a service providers network and then strip it off at the other end; this is a form of tunneling.

This technique allowed the ability to insert more than one 4 byte tag into the frame. Each additional tag is inserted before the previous tag. The tags are then removed in reverse order. The first tag will be the typical 0x8100 Ethertype and include the user provided VLAN ID. Each additional tag will use 0x88A8 (standard) or 0x9100 (non-standard) Ethertype and include the provider’s VLAN ID.
- Standard VLAN Tagging (IEEE 802.1Q):
  - In a standard VLAN tagging scenario, each Ethernet frame includes a 4-byte VLAN tag inserted between the source MAC address and the EtherType/Length field.
  - Ethertype uses is 0x8100.
  - This VLAN tag contains information such as the VLAN ID (VID) that identifies the VLAN to which the frame belongs.
  - IEEE 802.1Q supports up to 4096 VLANs (VLAN IDs 1-4094), allowing network administrators to segment a network into multiple virtual LANs.
- QinQ VLAN Tagging:
  - QinQ extends VLAN tagging by adding another layer of VLAN tags, effectively allowing VLAN tagging within VLAN tagging.
  - In a QinQ scenario, the original Ethernet frame is encapsulated within another VLAN tag, creating a "tagged outer frame" with its own VLAN ID.
  - This outer VLAN tag provides a second level of VLAN identification, allowing for hierarchical VLAN structures.
  - The original VLAN tag remains intact, providing the VLAN segmentation information within the inner frame.
  - Outer VLAN tag uses the Ethertype of 0x88A8.
- Usage and Benefits:
  - QinQ VLAN tagging is commonly used in service provider networks, particularly in metro Ethernet deployments.
  - It allows service providers to deliver multiple customer VLANs transparently over a single Ethernet link, preserving the VLAN segmentation of each customer.
  - By using QinQ, service providers can avoid VLAN ID conflicts between different customers' VLANs and simplify VLAN management.
  - QinQ also enables the creation of "service VLANs" or "provider VLANs" to carry traffic from multiple customer VLANs over a shared infrastructure while maintaining isolation between customers.
- Frame Format:
  - In QinQ VLAN tagging, the Ethernet frame contains two 802.1Q headers:
  - The outer VLAN tag (or "service tag") contains the service provider’s VLAN ID.
  - The inner VLAN tag (or "customer tag") contains the customer’s VLAN ID.
  - The outer VLAN tag precedes the inner VLAN tag, and the original Ethernet frame is encapsulated between them.
- IEEE 802.1ad was created for the following reasons:
  - 802.1Q has a 12-bit VLAN ID field, which has a theoretical maximum of 4096 tags (212). With the growth of network this has become a limitation. A double-tagged frame however has two 12 byte VLAN ID fields. This can have a theoretical max of 4096×4096 or 16,777,216 VLAN IDs.
  - A tag stack creates a mechanism for some Internet Service Providers to encapsulate customer tagged 802.1Q traffic within another tag thus creating a Q-in-Q frame. The second (outer tag) is used to identify and segregate traffic from different customers; the inner tag is preserved from the original frame.
  - Using Q-in-Q provides a means of constructing Layer 2 tunnels, or even applying Quality of service (QoS) policies.
  - 802.1ad is upward compatible with 802.1Q. Although 802.1ad is limited to two tags, there is no ceiling on the standard limiting a single frame to more than two tags, allowing for growth in the protocol. In practice Service Provider topologies often anticipate and utilize frames having more than two tags.
  - It is easier for networking equipment makers to modify their existing equipment by creating multiple 802.1Q headers than to modify their equipment to implement some hypothetical new non-802.1Q extended VLAN ID field header.
---
DEMO of 801.1ad headers

802.1ad pcap from www.cloudshark.org <https://www.cloudshark.org/captures/8532dae7e770>


References:  
https://www.cloudshark.org/captures/8532dae7e770  


---
#### 1.3.7.5 Describe VLANS and Security vulnerabilities  
- VLAN hopping Attack
  - VLAN hopping is an exploit method of attacking networked devices on separate virtual LAN (VLAN) without traversing a router or other Layer 3 device. The concept behind VLAN hopping attacks is for the attacker on one VLAN to gain access to traffic on other VLANs that would normally not be accessible. Keep in mind that VLAN hopping is typically a one-way attack. It will not be possible to get any response from the target device unless methods are setup on the target to respond with similar vlan hopping methods.
  - There are three primary methods of VLAN hopping:
    - Switch Spoofing
      - In this attack, an attacking host imitates a trunking switch by crafting Dynamic Trunking Protocol (DTP) frames in order to form a trunk link with the switch. With a trunk link formed the attacker can then use tagging and trunking protocols such as ISL or 802.1q. Traffic for all VLANs is then accessible to the attacking host.
      ```
      switch(config)# interface fastethernet 1/10
      switch(config-if)# switchport mode access
      switch(config-if)# switchport nonegotiate
      switch(config-if)# switchport access vlan 10
      switch(config)# iterface gigabit 0/1
      switch(config-if)# switchport trunk encapsulation dot1q
      switch(config-if)# switchport mode trunk
      switch(config-if)# switchport nonegotiate
      ```

      - Tagging
        - This attack typically requires the attacker add the target 802.1Q tag manually to an Ethernet frame even though it is an access port. This process is normally done by the switch. The switch will receive the frame and forward it out the trunk port leading to the target without it needing to be routed. This method requires that the attacker and victim are separated by a trunk and success depends on the switch firmware being vulnerable.
      - Double Tagging
        - This attack works if the attacker knows what the "native VLAN" that is used on your organization. Typically VLAN 1 is used. All VLANs will be "tagged" with its corresponding VLAN. The Native VLAN however is intended for local network communication and is not tagged. Thus anything tagged for the native VLAN will be stripped off. The attacker will insert 2 tags into their frames. The first tag will be for the Native VLAN and the second tag will be for whatever VLAN he is trying to access. Upon receipt the switch will then remove the Native VLAN tag and will leave the second VLAN tag in tact. This method also requires that the attacker and victim be separated by a trunk and a vulnerable switch.
      ```
      switch(config)# vlan dot1q tag native
      switch(config)# interface fastethernet 1/10
      switch(config-if)# switchport mode access
      switch(config-if)# switchport nonegotiate
      switch(config-if)# switchport access vlan 10
      switch(config)# iterface gigabit 0/1
      switch(config-if)# switchport trunk encapsulation dot1q
      switch(config-if)# switchport mode trunk
      switch(config-if)# switchport nonegotiate
      switch(config-if)# switchport trunk native vlan 999
      ```
---
DEMO VLAN Hopping

Scapy Script to demonstrate VLAN Hopping
```
a=Ether()
a.dst="ff:ff:ff:ff:ff:ff"
a.src="01:02:03:aa:bb:cc"
a.type=0x8100           #VLAN Tag will Follow

b=Dot1Q()
b.vlan=1                #Insert the network's Native VLAN number
b.type=0x8100           #Another VLAN Tag will Follow

c=Dot1Q()
c.vlan=20               #Target VLAN
c.type=0x0800           #IPv4 or any other Ethertype that is encapsulated

d=IP()
d.proto=6               #specifies that TCP is encapsulated. Change to 1 for ICMP or 17 for UDP.
d.src="10.10.0.40"      #Any source IP
d.dst="172.16.82.106"   #Target IP

e=TCP()
e.sport=54321
e.dport=80

f="message"

a.show()
b.show()
c.show()
d.show()
e.show()

sendp(a/b/c/d/e/f)
```

References:  
https://networklessons.com/cisco/ccnp-switch/vlan-hopping  


---
### 1.3.8 Describe the address resolution protocol (ARP) 
The Address Resolution Protocol (ARP) is a networking protocol used to map an IP address to a MAC address within a local network segment. ARP operates at the Data Link Layer (Layer 2) of the OSI model and is essential for communication between devices on the same network.

![image](https://github.com/ruppertaj/WOBC/assets/93789685/282501dd-73df-4d95-96b1-d5601b88b671)

The Address Resolution Protocol (ARP) is a Layer 2 protocol of the OSI model. It is used for discovering the Layer 2 or data link layer address (MAC address or even DLCI (Data Link Connection Identifier for a Frame Relay virtual circuit)), associated with a given Layer 3 or network layer address such as an IPv4 address. This mapping is critical in the operation of IPv4. ARP is replaced with ICMPv6 Neighbor Discovery (ND) Protocol suite when using IPv6.

ARP was defined in 1982 by RFC 826 which is Internet Standard STD 37. It has a wide range of various Operation Codes (op) to determine what type of ARP is being utilized. These codes are provided by IANA.

Each device maintains an ARP table (also known as an ARP cache) that stores mappings of IP addresses to MAC addresses. When a device receives an ARP reply, it adds the IP-to-MAC mapping to its ARP table. The ARP table is used to cache ARP mappings to optimize network performance and reduce ARP request/response traffic.
- Structure:
  - Hardware type (HTYPE) This field specifies the network link protocol type.
    - 1 = Ethernet
    - 6 = Token Ring
    - 15 = Frame Relay
  - Protocol type (PTYPE) This field specifies the internetwork protocol for which the ARP request is intended. The permitted PTYPE values share a numbering space with those for EtherType.
    - 0x0800 = IPv4
  - Hardware length (HLEN) Length (in octets) of a hardware address.
    - 6 = Byte size of Ethernet MAC addresses.
  - Protocol length (PLEN) Length (in octets) of addresses used in the upper layer protocol. (The upper layer protocol specified in PTYPE.)
    - 4 = Byte size of IPv4 addresses.
  - Operation Specifies the operation that the sender is performing:
    - 1 = ARP request
    - 2 = ARP reply
    - 3 = RARP request
    - 4 = RARP reply
  - Sender hardware address (SHA) Media address of the sender. In an ARP request this field is used to indicate the address of the host sending the request. In an ARP reply this field is used to indicate the address of the host that the request was looking for. (Not necessarily address of the host replying as in the case of virtual media.) Switches do not pay attention to this field, particularly in learning MAC addresses. The ARP PDU is encapsulated in Ethernet frame, and that is why Layer 2 devices examine it.
    - In a ARP request, this will be the requestor’s MAC address.
    - In a ARP reply, this will be the target’s MAC address.
  - Sender protocol address (SPA) Internetwork address (usually IPv4 Address) of the sender.
    - In a ARP request, this will be the requestor’s IP address.
    - In a ARP reply, this will be the target’s IP address.
  - Target hardware address (THA) Media address of the intended receiver. In an ARP request this field is ignored. In an ARP reply this field is used to indicate the address of the host that originated the ARP request.
    - In a ARP request, this will be blank.
    - In a ARP reply, this will be the requestor’s MAC address.
  - Target protocol address (TPA) Internetwork address (usually IPv4 Address) of the intended receiver.
    - In a ARP request, this will be blank.
    - In a ARP reply, this will be requestor’s IP address.
---
DEMO of ARP Pcap

ARP Pcap <https://www.cloudshark.org/captures/e4d6ea732135>


In Internet Protocol Version 6 (IPv6) networks, the functionality of ARP is provided by the Neighbor Discovery Protocol (NDP) and ARP is not used.

References:  
https://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml  
https://en.wikipedia.org/wiki/Address_Resolution_Protocol  
https://tools.ietf.org/html/rfc826  
https://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml
https://gitlab.com/wireshark/wireshark/-/wikis/AddressResolutionProtocol  


---
#### 1.3.8.1 ARP Types 
- ARP - A request and response in order to resolve the destination L2 (MAC) address when only the destination L3 (IPv4) address is known.
  - ARP Request Operation code = 1
  - ARP Reply Operation code = 2
  - ARP Request:
    - When a device needs to communicate with another device on the same network segment but only knows the destination’s IP address, it broadcasts an ARP request message to the entire network.
    - The ARP request contains the sender’s IP address and MAC address and the IP address of the target device.
  - ARP Reply:
    - The device with the IP address specified in the ARP request responds with an ARP reply.
    - The ARP reply contains the target device’s MAC address.
    - Once the sender receives the ARP reply, it can use the MAC address to address frames destined for the target device.
- RARP - A request and response in order to resolve the destination L3 (IPv4) address when only the destination L2 (MAC) is known. (This protocol has been deprecated since the widespread use of protocols like BOOTP and DHCP.)
  - RARP Request Operation code = 3
  - RARP Reply Operation code = 4
  - When a device boots up and has no configured IP address, it broadcasts a RARP request onto the local network.
  - The RARP request contains the device’s MAC address.
  - RARP servers on the network receive the broadcast request and check their tables for a corresponding IP address entry associated with the MAC address.
- Gratuitous ARP - An ARP reply that was not requested.
  - ARP Reply Operation code = 2
  - A gratuitous ARP messages is an ARP messages sent by a device to announce its own IP-to-MAC address mapping to other devices on the network.
  - Gratuitous ARP messages are commonly used during network initialization or to update ARP caches in other devices.
  - These are commonly used for:
    - Help in detecting IP conflicts
    - Assist in updating other system’s ARP cache
    - To inform switches of the MAC address of the client connected to its port
    - Helps pre-load other systems ARP cache when the local systems IP interface comes up
  - Maliciously used to:
    - Poison a victim’s ARP cache
- Proxy ARP - A device (router) answers the ARP queries for IP address that is on a different network.
  - The ARP proxy sees the ARP request and determines that the target Network address is not on the local network segment and is aware of how to reach the destination network.
  - The proxy will offer its own MAC address in response to the request.
  - Typically this device is the network gateway and is responsible to forward traffic for other networks.
  - Maliciously the ARP requests can be intercepted and a Proxy ARP sent as a response to poision the victim’s ARP Cache.
- ARP Cache - is a collection of Layer 2 to Layer 3 address mappings discovered utilizing the ARP request/response process. When a host needs to send a packet both the L2 and L3 addresses are needed. The host will look in this table to determine if it already knows both the L2 and L3 addresses. If the target is not in the table then a ARP request is initiated. The ARP cache can be populated statically but mostly its done dynamically. This cache can be exploited by attackers with the aim to poison the cache with incorrect information to either perform a DoS or MitM.
```
arp -a
ip neighbor
```
---
DEMO of an ARP BROADCAST STORM

ARP storm PCAP <https://www.cloudshark.org/captures/001ed6092974>

References:  
https://www.cloudshark.org/captures/ed6ca2889d61  


---
### 1.3.9 Explain man-in-the-middle (MitM) with ARP 
- Address Resolution Protocol (ARP) attack using Gratuitous ARPs
When ARP was developed security was not as much of an issue. Over time it was discovered that many protocols could be used in unintended ways. Typically a host will broadcast an ARP request over the network and expects only the intended host to respond. Gratuitous ARP on the other hand is another method that a host can announce itself to the network. All other hosts believe the message and will add this entry into their ARP cache. These are the legitimate uses of ARP but malicious actors can use the open, unencrypted, and unverified nature of the protocol to their own ends.

An attacker can broadcast a gratuitous ARP, announcing itself as the networks default gateway. It will use the legitimate default gateway’s IP address but will use it’s own MAC address. All hosts on the network will assume this information to be true and update their ARP caches. This in essence will poison everyone’s ARP cache. All hosts on the network will now send all traffic to other networks to the attackers computer. The Attacker will forward all traffic to the legitimate gateway but now the attacker is included in the hosts communication.

This process creates a Layer 2 Man in the Middle.

- Proxy ARP and Security Concerns:
Typically a PC will issue an ARP request to get the unknown MAC address of a device when its IP address is known. If the device is on the same network then that device will respond with ARP Reply. If the device happens to be on a different network, the router will respond with its own MAC address. The router responds because it will see that the destination IP address is on a different network and it knows how to get there from its routing tables. The router will respond to the ARP request with its own MAC to tell the host to send all the communication to itself to get to the remote destination. The host will update its ARP cache to reflect the router (default gateway) to be used to reach remote destinations. This is called a Proxy ARP.

An attacker can intercept ARP requests for a gateway and respond with its own MAC address resulting in a Man in the Middle attack.

References:  
Get more information in RFC 826, 5227, 5494  

Resources for further reading:  
https://computernetworkingsimplified.wordpress.com/2013/11/26/components-data-link-layer-llc-mac/  
RFC 826: https://tools.ietf.org/html/rfc826  
RFC 5227: https://tools.ietf.org/html/rfc5227  
RFC 5495: https://tools.ietf.org/html/rfc5494  


---
#### 1.3.9.1 Demonstrate man-in-the-middle (MitM) with ARP  
DEMO ARP MitM attack
```
my_mac = ""             #Insert Your MAC address
victim1_mac = ""        #Insert victim1 MAC address
victim1_ip = ""         #Insert victim1 IP address
victim2_mac = ""        #Insert victim2 MAC address
victim2_ip = ""         #Insert victim2 IP addres

# -- ARP to Poison Victim 1 to pretend to be Victim 2 --
a = Ether()
a.src= my_mac
a.dst= victim1_mac
a.type= 0x0806

b = ARP()
b.op= 2
b.hwsrc= my_mac
b.psrc= victim2_ip    #Who you are pretending to be
b.hwdst= victim1_mac  #Who's ARP cache you are trying to poison
b.pdst= victim1_ip    #Who's ARP cache you are trying to poison

# -- ARP to Poison Victim 2 to pretend to be Victim 1 --
c = Ether()
c.src= my_mac
c.dst= victim2_mac
c.type= 0x0806

d = ARP()
d.op= 2
d.hwsrc= my_mac
d.psrc= victim1_ip    #Who you are pretending to be
d.hwdst= victim2_mac  #Who's ARP cache you are trying to poison
d.pdst= victim2_ip    #Who's ARP cache you are trying to poison

a.show()
b.show()
c.show()
d.show()

sendp(a/b); sendp(c/d)
```

References:  
https://computernetworkingsimplified.wordpress.com/2013/11/26/components-data-link-layer-llc-mac/  
https://tools.ietf.org/html/rfc826  
https://tools.ietf.org/html/rfc5227  
https://tools.ietf.org/html/rfc5494  


---
### 1.3.10 Explain VTP with its vulnerabilities 

![image](https://github.com/ruppertaj/WOBC/assets/93789685/864830e1-81f0-478a-a17c-ff470d5461cd)
Figure 19. Virtual Trunking Protocol

VLAN Trunking Protocol (VTP) is a Cisco proprietary protocol that propagates the definition of Virtual Local Area Networks (VLAN) on the whole local area network. VLAN Trunk Protocol (VTP) was developed to help reduce the administration of creating VLANs on all switches within a switched network. To do this, VTP sends VLAN information to all the switches in a VTP domain.
- Server - can create, modify or delete VLANs. Can create and forward VTP messages.
- Client - can only adopt VLAN information in VTP messages. Can forward VTP messages.
- Transparent - only forwards VTP messages but does not adopt any of the information.

VTP advertisements are sent over all trunk links. VTP messages advertise the following on its trunk ports:
- Management domain
- Configuration revision number
- Known VLANs and their specific parameters

There are three versions of VTP, version 1, version 2, version 3.


---
#### 1.3.10.1 VTP Issue
VTP uses the configuration revision number to determine what is the most "up-to-date" VLAN information. Each time the server makes an update it will send a VTP message with a higher revision number. The other switches will see that the message revision number is higher than what they have recorded so they will adopt the information in the message believing it to be more current.

The concern is that if you add a new switch to the current VTP domain that has a higher VTP revision number. This could be because it was previously on another VTP domain and was not properly erased. Once connected, that switch will not accept any VTP messages from the server since its revision number is higher. But when that switch sends its own VTP message advertising what it believes the current revision number is, all the other switches will see that it has a higher revision number and will cause all switches to dump all their information and request the information from the new switch. This in effect will bring down your entire VLAN infrastructure.

Additionally, an attacker can use this same process to perform a Denial of Service on your VTP-switched network. The attacker can craft their own VTP message and send it over the network. This will cause all the switches in the VTP domain to flush all their VLAN information. This however does not change the VLANs assigned to the ports. The ports will stay assigned to the programmed VLANs. The switch however will no longer be forwarding traffic for those VLANS so the hosts will be isolated until the VLANs are re-introduced to the switch.


---
### 1.3.11 Explain DTP with its vulnerabilities 

![image](https://github.com/ruppertaj/WOBC/assets/93789685/cd987e2b-4eeb-4477-9316-6c8c5c537445)
Figure 20. Dynamic Trunking Protocol

The Dynamic Trunking Protocol (DTP) is a Cisco proprietary Layer 2 protocol. Its purpose is to dynamically negotiate trunking on a link between two switches running VLANS. It can also negotiate the type of trunking protocol to be used on the link (802.1q or ISL). DTP works by exchanging small DTP frames between two supporting devices to negotiate the link parameters.

Most switches will have DTP enabled by default in either "Dynamic-Auto" or "Dynamic-Desirable" modes.

References:  
https://en.wikipedia.org/wiki/Dynamic_Trunking_Protocol  


---
#### 1.3.11.1 DTP Attack (Switch Spoofing) 
DTP attacks relate to the VLAN hopping attack discussed earlier. Attackers can craft their own DTP frames in order to negotiate a trunk link between their device and the switchport. This trunking connection would allow the attacker to communicate with all VLANs on the switch and to inject traffic into whatever VLAN they desire. Typically the trunk link will not be "pruned" or allowed VLANs specified so this connection will allow the attacker access to all VLANs on that switch. This attack is sometimes called "Switch Spoofing".

This attack can be mitigated by using the switchport nonegotiate interface command to disable DTP. Additionally you should manually assign switchports to either Access (switchport mode access) or Trunk (switchport mode trunk).

References:  
https://www.manageengine.com/products/oputils/tech-topics/switch-spoofing.html  
https://www.exploit-db.com/docs/45050  


---
### 1.3.12 Explain CDP, FDP and LLDP and the security vulnerabilities  
- Cisco Discovery Protocol (CDP) is a Layer 2, Cisco proprietary protocol used to share information with other directly connected Cisco devices. CDP is protocol and media independent and runs on all Cisco routers, switches, and other devices.
  - CDP Shares information such as:
  1. Type of device
  2. Hostname
  3. Number and type of interface
  4. IP address
  5. IOS software version
  - CDP can be used as a Network Discovery tool as well as assist in network design decisions and troubleshooting.
- Foundry Discovery Protocol (FDP) is a proprietary data link layer protocol, originally developed by Foundry Networks, which was bought by Brocade. Similar to CDP, FDP enables Brocade devices to advertise to other directly connect Brocade devices on the network.
- Link Layer Discovery Protocol (LLDP) was designed by IEEE 802.1AB to be a vendor-neutral neighbor discovery protocol similar to CDP. LLDP also operates at layer 2 and shares similar information as does CDP with directly connected devices that support LLDP.
---
DEMO of CDP and LLDP

Demonstration of CDP and LLDP messages from www.cloudshark.org. <https://www.cloudshark.org/captures/001ed6092974>

References:  
https://www.cloudshark.org/captures/001ed6092974  


---
#### 1.3.12.1 Cisco Discovery Protocol (CDP) Attack 
Due to the nature of how CDP works, it can be easily used by malicious actors to map out your network infrastructure. It also shares alot of device information that an attacker can use in preparation of an attack; information like IP addresses, router models, software versions and so on can be sensitive for your organization. All information is sent in clear text and unauthenticated. Any attacker sniffing the network is able to see this information and is possible to impersonate (spoof) another device.

It is recommended to disable CDP/LLDP if not needed in your organization. It is however required for many VOIP phones to operate. Cisco VOIP send CDP messages to the switch. This is how switches know to place the phones on the "voice" vlan and not the "data" vlan.
- Disable Globally with no cdp run
- Disable on an interface with no cdp enable


---
### 1.3.13 Explain STP with its vulnerabilities 

![image](https://github.com/ruppertaj/WOBC/assets/93789685/6379845d-8180-40e6-bcf8-ff2b13c14b87)
Figure 21. Spanning-Tree Protocol

We previously mentioned that there is no TTL at Layer 2 to eventually kill a frame that never reaches its destination. This will result in frames endlessly circulating a L2 infrastructure and eventually bringing down the network. This can be caused by simply adding redundant links in your network architecture that could allow frames to potentially circulate.

Spanning Tree Protocol (STP) (802.1D) was developed to resolve this issue. STP is a Layer 2 protocol that builds a loop-free logical topology for Ethernet networks in a network that physically has loops. The basic function of STP is to prevent switching loops and the broadcast storms that can result. Spanning tree allows a network design to include physical "backup links" to provide fault tolerance if the active link fails.

STP works by creating "tree" within a network of connected layer-2 switches, and disable any links that are not part of this tree. The root of the tree determined by electing a Root Bridge and all the other switches are the branches. This essentially leaves only a single active path between any two network switches. STP is based on the algorithm invented by Radia Perlman.

STP operates by flooding Bridge Protocol Data Units (BPDUs) to all other switches in the network. BPDUs consist of:
- Switches priority value (default 32768. Lower numbers are preferred.)
- MAC address (lowest one on the switch. Lower MAC address are preferred.)

These BPDUs are used to:
1. Elect the Root Bridge
2. Identify the Root port on each non-root bridge
3. Identify the Designated port for each segment

After the election of the Root Bridge, all BPDUs will come from the root only and each switch will forward these BPDUs out their Trunk ports. This ensures that all switches know that the root is still active.

IEEE introduced Rapid Spanning Tree Protocol (RSTP) as 802.1w in 2001. RSTP allowed ports to transition from blocking to forwarding in about 10 seconds.

In 2005, the IEEE introduced 802.1s, alternatively referred to as Multiple Spanning Tree Protocol (MSTP), extending the foundational Spanning Tree Protocol (STP) delineated by IEEE 802.1D. MSTP enriches STP by enabling the mapping of multiple VLANs to a solitary spanning tree instance, thereby aiding in the optimization of network assets and the acceleration of convergence time.

Versions of Spanning Tree Protocol (STP)
- Open Standards-Based Versions:
  - STP (802.1D):
    - Open standard defined by the IEEE 802.1D specification.
    - Basic version of the Spanning Tree Protocol, widely supported by networking equipment from various vendors.
    - Defines the original spanning tree algorithm for loop prevention in Ethernet networks.
    - Convergence Time: 30 to 50 seconds.
  - RSTP (802.1w):
    - Open standard defined by the IEEE 802.1w specification.
    - Improves upon the original STP by providing faster convergence and better performance.
    - Offers faster link failover times and better utilization of redundant links compared to STP.
    - Widely supported across networking equipment from multiple vendors.
    - Convergence Time: 6 seconds or less.
  - MSTP (802.1s):
    - Open standard defined by the IEEE 802.1s specification.
    - Extends RSTP to support multiple spanning tree instances, each of which can encompass multiple VLANs.
    - Helps reduce the number of spanning tree instances needed in large networks with multiple VLANs, improving scalability and manageability.
    - Convergence Time: Similar to RSTP (6 seconds or less).
- Cisco Proprietary Versions:
  - Per-VLAN Spanning Tree (PVST) and PVST+ (Per-VLAN Spanning Tree Plus):
    - Proprietary spanning tree protocol developed by Cisco.
    - PVST and PVST+ extend the functionality of STP by creating a separate spanning tree instance for each VLAN.
    - Allows for finer control over spanning tree behavior on a per-VLAN basis, optimizing network performance and stability.
    - Convergence Time: Typically similar to STP (30 to 50 seconds).
  - Rapid Per-VLAN Spanning Tree (Rapid PVST):
    - Cisco’s proprietary version of RSTP, tailored for use with PVST+.
    - Offers faster convergence and better performance compared to traditional PVST+.
    - Provides rapid failover times for individual VLANs, enhancing network resilience and uptime.
    - Convergence Time: Typically similar to RSTP (6 seconds or less).
  - Cisco Multiple Spanning Tree Protocol (MSTP) Implementation:
    - Cisco offers its implementation of MSTP, which is compatible with the IEEE 802.1s standard.
    - Allows Cisco devices to participate in MSTP environments alongside equipment from other vendors.
    - Offers enhanced features and integration with other Cisco networking technologies.
    - Convergence Time: Typically similar to RSTP (6 seconds or less).
---
DEMO PVST+

Demo PVST+ in a pcap from www.cloudshark.org <https://www.cloudshark.org/captures/002d421b5466>

References:  
https://www.cloudshark.org/captures/002d421b5466  
https://en.wikipedia.org/wiki/Spanning_Tree_Protocol  
https://en.wikipedia.org/wiki/Bridge_Protocol_Data_Unit  
https://www.ieee802.org/1/pages/802.1s.html


---
#### 1.3.13.1 STP Bridge Protocol Data Units (BPDU)
Spanning Tree Protocol (STP) uses Bridge Protocol Data Units (BPDUs) to exchange information between switches and determine the topology of the network. BPDUs contain vital information necessary for STP operation, including bridge IDs, port IDs, path costs, and other parameters.
- Contents of a BPDU:
  - Bridge ID (BID):
    - The BID uniquely identifies each bridge (switch) in the network and consists of two components: bridge priority and bridge MAC address.
    - The bridge priority is a numerical value (default is 32768) used to determine the root bridge.
    - The bridge MAC address is the MAC address of the bridge.
  - Port ID:
    - The Port ID uniquely identifies each port on a bridge.
    - It consists of two components: port priority and port number.
    - The port priority is a numerical value (default is 128) used to determine the designated port.
    - The port number is the identifier of the port on the bridge.
  - Path Cost:
    - The path cost represents the cumulative cost of the path from the sending bridge to the root bridge.
    - Each port calculates its path cost based on the speed of the link. For example, a higher speed link (e.g., Gigabit Ethernet) has a lower path cost than a lower speed link (e.g., Fast Ethernet).
  - Root Bridge ID:
    - The Root Bridge ID (RID) is the bridge ID of the root bridge, which is initially set to the bridge ID of the sending bridge.
    - As BPDUs propagate through the network, switches update the RID in the received BPDUs to reflect the bridge ID of the root bridge.
  - Message Type:
    - BPDUs can be either Configuration BPDUs or Topology Change Notification (TCN) BPDUs.
    - Configuration BPDUs are used for regular STP operations, such as root bridge election, topology discovery, and path selection.
    - TCN BPDUs are used to notify other switches of changes in the network topology, such as link failures or port state changes.
- BPDU Exchange Process:
  - Transmission:
    - Each switch sends BPDUs out of all its designated ports at regular intervals (hello time), usually every 2 seconds by default.
    - BPDUs are sent as multicast frames to the well-known address 01:80:C2:00:00:00.
  - Reception:
    - Switches receive BPDUs from neighboring switches on their designated ports.
    - Upon receiving a BPDU, a switch compares the information in the BPDU with its own information to determine the best path to the root bridge.
  - Processing:
    - Switches process incoming BPDUs to update their internal spanning tree information, including root bridge selection, port roles (root, designated, or blocked), and path costs.
    - After the root bridge election, only the root will transmit BPDUs and non-root switches will process the BPDUs sent by the root.
  - Decision Making:
    - Based on the information in received BPDUs, switches make decisions about the state of their ports (forwarding, blocking, or listening/learning) and adjust their forwarding tables accordingly.
    - Switches use BPDUs to decide the root bridge in a STP environment. They determine the root as the one with the lowest priority. If there is a tie for priority then the lowest MAC address is used.


---
#### 1.3.13.1 Spanning-Tree Attack 
**Spanning Tree Denial of Service attack.**

Its goal is to disrupt the switch’s spanning-tree process, destabilize their CAM tables and hold the network in a repetitive state of re-electing the root bridge. This is possible because there is no authentication mechanism built into the STP and its BPDU frames.

This is done by repeatedly sending (crafted) Topology Change Notification (TCN) messages that will disrupt the system’s current understanding of the network. This will force renegotiation of the Root Bridge, resulting in a DoS attack because of the 50 second time period it takes to recalculate.


**Root Bridge Election Manipulation**

Another option is for the attacker to try to become the root bridge. Depending on the location of the attacker’s system, this can have a dramatic effect on the traffic flow throughout the L2 network. This can potentially cause traffic to traverse towards or thru the attacker’s device.

This attack can be done by sending specially crafted BPDUs by giving itself a more preferred BPDU. Typically specifying a lower priority value. Once this is accomplished it is possible for the attacker to see packets that are sent through them. This requires the attacker to stay connected to two switches, running bridging software, so that they can continue to send the BPDU to advertise themselves as the root bridge.



Both attacks require that the attacker be physically connected to the network.

The industry standard of 802.1D there is only 1 spanning tree instance no matter how many vlans are running on the network. So to attack STP will affect every vlan in the network. However Cisco’s proprietary STP called PVST and PVST+, there is a spanning tree instance for each vlan in the network. So to attack one will not affect the others. Each vlan spanning tree instance would need to be attacked for a full network DoS.

To mitigate STP attack you can:
- Enable portfast to have a port immediately come up to the forwarding state.
  - Globally by using spanning-tree portfast default
  - By interface using spanning-tree portfast
- Enable BPDU guard to prevent BPDUs from beign allowed on a switchport.
  - On each access port interface use spanning-tree bpduguard enable
  - Must not use this command on any trunk or switch to switch connections.
---
Without Spanning-Tree

![image](https://github.com/ruppertaj/WOBC/assets/93789685/7ff445bf-8d1b-40f6-84ac-089fa67ebdfb)
Figure 22. Broadcast Storm

Ethernet frames do not have a time to live (TTL) field as the IPv4 and IPv6 packet headers do. Because of this there is no mechanism to block continued propagation of frames on a Layer 2 switched network. It is possible for frames to propagate between switches endlessly. This can result in MAC database instability and can cause broadcast frames to forward endlessly causing broadcast storms and will bring down any network.

Many networks today operate without using STP with careful planning. It is possible to provide redundancy without needing to create a series of redundant links.
---
**Issues in a switched network**

In a switched network with physical loops, Spanning-Tree is crucial or else your whole network can be brought down with broadcasts. Without any configured physical loops in your network, spanning-tree can be safely disabled to conserve a little bandwidth and CPU processing of the BPDU messages. However, if a redundant link were to ever be connected the network will quickly shutdown.


---
### 1.3.14 Explain Port Security with its vulnerabilities
**Port Security**

The purpose of configuring port security technologies is to limit, restrict, and protect network access. Configuring port security can be done on active access ports to limit the number of users or MAC addresses allowed to access onto the network. This will help to alleviate attacks such as DoS, MAC Address Flooding, and most unauthorized access.
- MAC Address Limit:
  - Port security allows administrators to specify the maximum number of MAC addresses allowed on a switch port.
  - When enabled, the switch monitors the MAC addresses of devices connected to the port and takes action if the number of MAC addresses exceeds the configured limit.
- MAC Address Learning:
  - When a device sends traffic through a switch port, the switch learns the device’s MAC address and associates it with the port.
  - The switch maintains a table, known as the MAC address table or CAM table, which maps MAC addresses to switch ports.
- Violation Actions:
  - Administrators can define violation actions to be taken when port security violations occur.
  - Common violation actions include shutting down the port, sending an SNMP trap, or logging a message.
  - These actions help alert administrators to potential security breaches and mitigate unauthorized access attempts.
  - The following are the possible modes:
    - protect - Drops any frames with an unknown source addresses.
    - restrict - Same as protect except it additionally creates a violation counter report.
    - shutdown - Places the interface into an "error-disabled" state immediately and sends an SNMP trap notification. This is typically the default mode.

> When port security violations occur, administrators need to investigate as to why and not simply clear the fault.

Port security’s effectiveness has seemingly diminished over the years. In the past the MAC address were "burned-in" or set in the firmware of the NIC and could not be changed. Today this is managed in software and can easily be changed. Port Security is still an effective tool in the Defense-in-Depth strategy.

Port security can help to:
- Restrict the possible allowed MAC addresses to a port to (1).
- Protect against CAM Table Overflow attack. This is were an attacker can flood a switch with hundreds of bogus MAC addresses in effort to fill its CAM tables. Once full, the switch will operate much like a Layer 1 Hub.

References:  
https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst4500/12-2/25ew/configuration/guide/conf/port_sec.html  
https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst6500/ios/12-2SX/configuration/guide/book/port_sec.pdf  
https://www.ciscopress.com/articles/article.asp?p=1181682&seqNum=12  
https://packetpushers.net/do-we-really-need-layer-2-security/  
https://packetpushers.net/yes-we-really-need-port-security/  


---
### 1.3.15 Layer 2 Attack mitigation techniques 
The following are some mechanisms that can be be configured to better secure your switched network:
- Shutdown unused ports - Bare minimum to secure access ports is to simply shut down any and all inactive ports.
```
interface fastethernet 0/1
shutdown
```

- Switchport Port Security - Can be used to limit the number of MAC addresses that can be dynamically learned on a port or static MAC addresses can be assigned to one. Violation modes of shut down can be used to secure the port should a violation occur.
```
switchport port-security
switchport port-security maximum 1
switchport port-security mac-address sticky
switchport port-security violation shutdown
```

- IP Source Guard - Mitigates the effects of IP address spoofing attacks on the Ethernet LAN. With IP source guard enabled, the source IP address in the packet sent from an untrusted access interface is validated against the DHCP snooping database. If the packet cannot be validated, it is discarded.
```
interface fastethernet 0/1
ip verify source
ip source binding 0100.0230.0002 vlan 11 10.10.0.40 interface fastethernet 0/1
```

- Manually assign STP Root - Manually assign the Spanning Tree Protocol (STP) root bridge allows for a deterministic root bridge election rather than the bridge with the lowest bridge priority. This allows the central most switch to be the root that will best allow traffic to flow in an efficent manner.
```
spanning-tree vlan <vlan-id> priority 0
```

- BPDU Guard - BPDU Guard is a feature used in network switches to enhance network security by protecting against unintentional loops and rogue devices. It works by automatically shutting down a port if it receives Bridge Protocol Data Units (BPDUs), which are indicative of spanning tree protocol (STP) activity.
```
interface fastethernet 0/1
spanning-tree bpduguard enable
```

- DHCP Snooping - DHCP Snooping is a security feature commonly found in network switches that helps prevent rogue or unauthorized DHCP servers from distributing incorrect or malicious IP configuration information to network clients. It operates by monitoring and controlling DHCP messages exchanged between DHCP clients and servers. Configuration is done on ports that are connected to (or leading to) the DHCP server.
```
ip dhcp snooping
interface fastethernet 0/1
 ip dhcp snooping trust
 ip dhcp snooping vlan <vlan-id>
```

- 802.1x - The 802.1x standard defines a client-server-based access control and authentication protocol that prevents unauthorized clients from connecting to a LAN through ports until they are properly authenticated. The authentication server authenticates each client connected to a switchport before making available any services offered by the switch or the LAN.
```
aaa new-model
aaa authentication dot1x default group radius
dot1x system-auth-control
identity profile default
interface fastethernet 0/1
access-session port-control auto
dot1x pae authenticator
```

- Dynamic ARP inspection (DAI) - Prevents Address Resolution Protocol (ARP) spoofing or “man-in-the-middle” attacks. ARP requests and replies are compared against entries in the DHCP snooping database, and filtering decisions are made on the basis of the results of those comparisons.
```
ip arp inspection vlan {vlan-id> | <vlan-range>}
interface fastethernet 0/1
ip arp inspection [ trust | untrust ]
ip arp inspecion filter <arp-acl-name> vlan {vlan-id> | <vlan-range>} [static]
```

- Static CAM entries - Static CAM (Content Addressable Memory) entries refer to manually configured entries in the CAM table of Ethernet switches. These entries map specific MAC addresses to specific switch ports and are used to optimize network performance and facilitate specific network configurations.
```
mac-address-table static 1234:abcd:5678 vlan 1 interface fastethernet 0/1
```

- Static ARP entries - Static ARP (Address Resolution Protocol) entries are manually configured mappings between IP addresses and MAC addresses in the ARP table of network devices. These entries are used to ensure stable communication between specific devices on the network.
```
Linux:
sudo ip neighbor add 10.10.0.50 lladdr 11:22:33:44:55:66 nud permanent dev eth0
sudo ip neighbor delete 10.10.0.50 lladdr 11:22:33:44:55:66 nud permanent dev eth0
Windows:
arp -s 10.10.0.50 11:22:33:44:55:66
```

- Disable DTP negotiations - To disable Dynamic Trunking Protocol (DTP) negotiations on a Cisco switch interface, you need to manually configure the interface as an access port or set it to operate in a specific trunking mode, such as "trunk" or "nonegotiate."
```
interface fastethernet 0/1
 switchport mode trunk
 switchport nonegotiate
interface fastethernet 0/2
 switchport mode access
 switchport nonegotiate
```

- Manually assign Access/Trunk ports - By default, switch ports can be either a trunk or access port depending on the device connected to the port and dynamic negotiations that take place. Manually assigning ports as either trunk or access ports provides greater control and ensures that the network operates as intended.
```
interface fastethernet 0/1
 switchport mode trunk
 switchport nonegotiate
interface fastethernet 0/2
 switchport mode access
 switchport nonegotiate
```

References:  
https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst4500/12-2/25ew/configuration/guide/conf/port_sec.html  
https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_usr_8021x/configuration/xe-3se/3850/sec-user-8021x-xe-3se-3850-book/config-ieee-802x-pba.html  
https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst4500/12-2/25ew/configuration/guide/conf/dynarp.html  
https://www.cisco.com/en/US/docs/switches/lan/catalyst3850/software/release/3.2_0_se/multibook/configuration_guide/b_consolidated_config_guide_3850_chapter_0110110.html  
https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst4500/12-2/25ew/configuration/guide/conf/dhcp.html  
