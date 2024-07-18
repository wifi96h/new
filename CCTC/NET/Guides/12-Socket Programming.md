# 12.0 Outcomes
- Understand socket types for network functions
- Differentiate user space/kernel space sockets
- Understand socket creation behavior based on privilege level
- Implement Network Programming with Python3
- Perform packet creation applying RFC implementation

---
## 12.1 Understanding socket types for network functions
- Stream socket - Normally used with TCP, SCTP, and Bluetooth. A stream socket provides a connection-oriented and sequenced flow of data which has methods for establishment and teardown of connections as well as error detection.
- Datagram socket - Normally used with UDP. A datagram socket is connection-less by nature. Sockets built this way can send and receive data, but there is no mechanism to retransmit data if a packet is dropped.
- Raw socket - A raw socket allows for the direct sending and receiving of IP packets without automatic protocol-specific transport layer formatting, meaning that all headers are typically included in the packet and not removed when moving up the network stack.
- Raw sockets are used in user applications such as nmap, tcpdump, and wireshark when using elevated privilege levels. Nmap needs to open raw sockets when attempting to set specific flags for performing certain scans. Tcpdump requires raw sockets in order to receive each packet, in its entirety, for total packet analysis.


---
# 12.2 Differentiate user space/kernel space sockets

![image](https://github.com/ruppertaj/WOBC/assets/93789685/48479e58-9334-428b-9039-d9fc1c3d1bc2)
User vs. Kernel Space

- System memory can be divided into two regions: kernel space and user space. Kernel space is where the operating system runs and provides its services. User space is a portion of system memory where a user’s processes can run. For a user space process to access or execute functions that require interaction with the OS software or the host’s hardware, a system call to the kernel is made on behalf of the user space process. This segregation of privilege is important to maintaining system stability and security. OSes generally use a number of API’s and libraries in order to manage the functions that span user to kernel space.
- Sockets can be created by programs that reside in user space, however, in order to function with/through the device hardware, a corresponding kernel socket must be created and linked. If a program is seeking access to or through a device (hardware) such as a NIC, privileges are needed in order to access or link to kernel space sockets.
- Stream and Datagram sockets are considered user space sockets and are typically the most common. These sockets do not need elevated privileges to perform the actions the user level applications are attempting.
- Raw sockets are considered kernel space sockets since they are attempting to access hardware interfaces directly to prevent encapsulation/decapsulation or to create packets from scratch.


---
### 12.2.1 User space Applications and Sockets
- Using tcpdump or wireshark to read a file
- Using nmap with no switches
- Using netcat to connect to a listener
- Using netcat to create a listener above the well known port range (1024+)
- Using /dev/tcp or /dev/udp to transmit data


---
### 12.2.2 Kernel space Applications and Sockets
- Using tcpdump or wireshark to capture packets on the wire
- Using nmap for OS identification or to set specific flags when scanning
- Using netcat to create a listener in the well known port range (0 - 1023)
- Using Scapy to craft or modify a packet for transmission


---
## 12.3 Understanding socket creation behavior based on privilege level
*Where does the OS or tools being used come in?*

- Software, applications, etc, that require access to or utilization of communications rely on the kernel’s networking functions. Both the POSIX specification (for nix-systems) and Winsock (for Microsoft windows) use handles known as sockets for identifying an endpoint that is communicating. This may be a process (such as with inter-process communications) or it may be a NIC and service on an operating system looking to communication over a network. Berkeley sockets (known as BSD for Berkeley Software Distribution) provide an API for both domain sockets used during IPC’s and Internet sockets used for communications over the network. Sockets that traverse a NIC are classified as either datagram (UDP) or stream (SCTP/TCP) sockets within the INET (Internet socket) family.

*What about things that don’t ride over transport layers?*

- While normal network communications operate over TCP or UDP, with INET socket functions specific to those protocols, not all communications over a network operate over the transport layer. Many network specific protocols such as OSPF, IGMP, ICMP etc, use raw sockets to send and receive information. BSD supports the use of raw sockets.

*How can raw sockets be used?*

- The INET family sockets for TCP or UDP expect payload information without lower layer headers (MAC, IP), having been de-encapsulated. A raw socket on the other hand will see/handle all of this information. Following Windows XP, Winsock limited raw socket support due to security concerns, however most nix-like systems fully support raw sockets. Raw sockets not only see this information, but they can be used to allow applications to write information into structures for transmission. TCPDump uses a raw socket to capture information, while NMAP uses them to transmit crafted packets for scanning and OS detection among other things.


---
## 12.4 Implement Network Programming with Python3

---
### 12.4.1 Understanding Python Libraries
- Libraries - The Python standard library is only one of many libraries created for Python programming. There are "third-party" created libraries available for public use. Each of these libraries contains its own modules and functions. To get an idea of some other libraries you can reference this link of [20 Python libraries you can’t live without](https://yasoob.me/2013/07/30/20-python-libraries-you-cant-live-without/).
- Additional 3rd party libraries can be found at https://pypi.org/.
- Python comes pre-loaded with its own standard library that can be referenced [here](https://docs.python.org/3/library/).
  - The Python library can contain:
    - [Modules](https://docs.python.org/3/library/index.html) - is a file consisting of Python code. A module can define functions, classes and variables. Some popular modules are:
      - [struct](https://docs.python.org/3/library/struct.html)
      - [socket](https://docs.python.org/3/library/socket.html)
      - [sys](https://docs.python.org/3/library/sys.html)
    - Function - A function is a block of organized, reusable code that is used to perform a single, related action. Functions provide better modularity for your application and a high degree of code reusing. A function is a block of code within a module which only runs when it is called. You can pass data, known as parameters, into a function. A function can return data as a result. Some popular functions include:
      - struct.pack
      - socket.socket
      - or other "user-defined"
      - [Built-In Examples](https://docs.python.org/3/library/functions.html):
        - int()
        - len()
        - str()
        - sum()
        - print()
    - Methods - is a piece of code or function that “belongs to” an object. Generally its a very basic function that performs a task within the function but does not usually return data.
      - The method is implicitly used for an object for which it is called.
      - The method is accessible to data that is contained within the function/class.
      - Can create methods within the function or can call a 'built-in' method
      - does not normally return data
      - cannot be called to perform a task without calling the Class/Object it’s associated with.
      - can be simple such as changing the case or printing test.
      - You can have methods to perform mathematical tasks like add, sub, multiply, or divide.
      - [Built-In Examples](https://docs.python.org/3/library/stdtypes.html#methods):
        - my_string.upper()
        - my_string.lower()
        - my_list.strip()
        - my_string.split()
        - my_list.replace()
        - my_list.count()
        - my_list.clear()
        - my_list.append()
        - my_list.insert()
    - [Exceptions](https://docs.python.org/3/library/exceptions.html) - An exception is a special condition encountered during program execution that is unexpected or anomalous. This will typically break your code with some sort of error. Typically you hear exception handling to manage issues such as:
      - Attempting to execute without proper permissions
      - Using Ctrl + C to perform a non-graceful exit of the program
      - Attempting to access a file that does not exist
    - [Constants](https://docs.python.org/3/library/constants.html) - A constant is a term used to describe data or a value that does not change in a specified amount of time, unlike a variable. Some examples include:
      - AF_INET - always represents ipv4 address family
      - AF_INET6 - always represents ipv6 address family
      - SOCK_STREAM - always represents a stream socket
      - SOCK_DGRAM - always represents a datagram socket
      - SOCK_RAW - always represents a raw socket
    - Objects - a section of code used in object-oriented programming that can be used by other object modules or the program being created. Some objects in the socket function are:
      - socket.bind(address)
      - socket.connect(address)
      - socket.send(bytes[,flags])
      - socket.close()
    - Python Collections (Arrays) - There are four collection data types in the Python programming language:
      - [List](https://docs.python.org/3/library/stdtypes.html#lists) data structure in Python that is a mutable, or changeable, ordered sequence of elements. Each element or value that is inside of a list is called an item. Just as strings are defined as characters between quotes, lists are defined by having values between square brackets [ ] . thislist = ["apple", "banana", "cherry"] print(thislist) print(thislist[1]) print(thislist[-1])
      - [Tuple](https://docs.python.org/3/library/stdtypes.html#tuples) immutable sequence of Python objects. Tuples are sequences, just like lists. The differences between tuples and lists are, the tuples cannot be changed unlike lists and tuples use parentheses, whereas lists use square brackets. Creating a tuple is as simple as putting different comma-separated values and having the values between ( ).
        ```
        thistuple = ("apple", "banana", "cherry")
        print(thistuple)
        ```

      - [Set](https://docs.python.org/3/library/stdtypes.html#set) is a collection which is unordered and unindexed. No duplicate members.
        ```
        thisset = {"apple", "banana", "cherry"}
        print(thisset)
        ```

      - [Dictionary](https://docs.python.org/3/library/stdtypes.html#dict) is a collection which is unordered, changeable, and indexed. No duplicate members.
        ```
        thisdict = {
          "brand": "Ford",
          "model": "Mustang",
          "year": 1964
        }
        print(thisdict)
        ```

    - [Data Types](https://docs.python.org/3/library/stdtypes.html) - describes what the format required by the data such as "string" or "integer" or "float" etc.
      - Numeric Type:
        - [integer (int)](https://docs.python.org/3/library/functions.html#int) - decimal or binary numbers.
        - [floating-point number (float)](https://docs.python.org/3/library/functions.html#float) - decimal integer. It can have anywhere from 1+ decimal digits.
        - [complex numbers (complex)](https://docs.python.org/3/library/functions.html#complex) - integer w/ variable.
      - Text Type:
        - [strings (str)](https://docs.python.org/3/library/stdtypes.html#text-sequence-type-str) - Textual data in Python is handled with str objects, or strings. Strings are immutable sequences of Unicode code points. String literals are written in a variety of ways:
        ```
        Single quotes: 'allows embedded "double" quotes'
        Double quotes: "allows embedded 'single' quotes".
        Triple quoted: '''Three single quotes''', """Three double quotes"""
        ```

        - string methods:
        ```
        str.capitalize()
        str.casefold()
        str.center(width[, fillchar])
        str.count(sub[, start[, end]])
        ```

      - Sequence Type:
        - [list](https://docs.python.org/3/library/stdtypes.html#list) - Lists are mutable sequences, typically used to store collections of homogeneous items (where the precise degree of similarity will vary by application).
        ```
        List1 = [10, 20, 30]
        print(List)
        List2 = ["CCTC", "Students", "AIT", "BOLC"]
        print(List2[0])     # CCTC
        print(List2[1])     # Students
        print(List2[2])     # AIT
        print(List2[3])     # BOLC
        ```

        - [tuple](https://docs.python.org/3/library/stdtypes.html#tuples) - Tuples are immutable (cannot change) sequences, typically used to store collections of heterogeneous data (such as the 2-tuples produced by the enumerate() built-in). Tuples are also used for cases where an immutable sequence of homogeneous data is needed (such as allowing storage in a set or dict instance).
        ```
        thistuple = ("10.10.0.40", 4444)
        print(thistuple)
        ```

        - [range](https://docs.python.org/3/library/stdtypes.html#ranges) - represents an immutable sequence of numbers and is commonly used for looping a specific number of times in for loops.
      - Mapping Type:
        - [dict](https://docs.python.org/3/library/stdtypes.html#mapping-types-dict) - A mapping object maps hashable values to arbitrary objects. Mappings are mutable objects. There is currently only one standard mapping type, the dictionary. (For other containers see the built-in list, set, and tuple classes, and the collections module.) A dictionary’s keys are almost arbitrary values. Values that are not hashable, that is, values containing lists, dictionaries or other mutable types (that are compared by value rather than by object identity) may not be used as keys. Numeric types used for keys obey the normal rules for numeric comparison: if two numbers compare equal (such as 1 and 1.0) then they can be used interchangeably to index the same dictionary entry. (Note however, that since computers store floating-point numbers as approximations it is usually unwise to use them as dictionary keys.)
      - Set Type:
        - [set](https://docs.python.org/3/library/stdtypes.html#set) - Return a new set or frozenset object whose elements are taken from iterable. The elements of a set must be hashable.
        - [frozenset](https://docs.python.org/3/library/stdtypes.html#frozenset) - To represent sets of sets, the inner sets must be frozenset objects. If iterable is not specified, a new empty set is returned.
      - Boolean Type:
        - [bool](https://docs.python.org/3/library/stdtypes.html#boolean-values) - Boolean values are the two constant objects False and True. They are used to represent truth values (although other values can also be considered false or true). In numeric contexts (for example when used as the argument to an arithmetic operator), they behave like the integers 0 and 1, respectively. The built-in function bool() can be used to convert any value to a Boolean, if the value can be interpreted as a truth value (see section Truth Value Testing above). They are written as False and True, respectively.
      - Binary Type:
        - [bytes](https://docs.python.org/3/library/stdtypes.html#bytes) - Bytes objects are immutable sequences of single bytes. Since many major binary protocols are based on the ASCII text encoding, bytes objects offer several methods that are only valid when working with ASCII compatible data and are closely related to string objects in a variety of other ways.
        - [bytearray](https://docs.python.org/3/library/stdtypes.html?highlight=bytearray#bytearray) - Objects are a mutable counterpart to bytes objects. There is no dedicated literal syntax for bytearray objects, instead they are always created by calling the constructor.
        - [memoryview](https://docs.python.org/3/library/stdtypes.html#memoryview) - object exposes the C level buffer interface as a Python object which can then be passed around like any other object.
    - [Built-Ins](https://docs.python.org/3/library/functions.html#built-in-functions) - functions, and types built into python that is always available and does not need to be imported.


---
### 12.4.2 How Imports Work
The import statements do a lot under the hood to import a file or module. First, they look for your module or package in sys.modules, where Python stores your previously imported code. If Python cannot find the module there, it will then search through the Python Standard Library for it. If Python still cannot find the module, it will go through your entire storage space, starting with the current directory and the ones listed in your system.path. If the module is found in these places, it will add the module to your program, otherwise, it will give a ModuleNotFoundError.

- import {module} - this will import the entire module or package. To call it you must use the proper syntax of module.function each time. (i.e. socket.AF_INET)
- from {module} as {name} - same as above but can be used to call the module under a different user defined name. This can be useful if your module/function conflicts with user defined variables. Also to call using a more "friendly" naming.
- from {module} import {function} - this will import only that function from the specified module. It can now be called by specifying the function name only and not needing to use the module.function .
- from {module} import * - same as above but imports all functions under that module. This allows you to call all functions with out needing to use the module.function convention. Care should be used as the function names could interfere with variable names.
- from {module} import {function} as {name} - this will import only that function from the specified module under a different user defined name.

References:  
https://stackabuse.com/relative-vs-absolute-imports-in-python/  
https://www.tutorialspoint.com/python/index.htm  
Python coding best Practices: https://pep8.org/#imports  


---
### 12.4.3 Using python3 to create sockets
In order to program sockets with python3, you need to understand some of the libraries and functions that go along with it. The first library we will discuss is the socket module.

- Inside the socket module we will first look at the functions that are tied to the socket function - "socket.socket". Here is an example:
```
import socket

s = socket.socket(socket.FAMILY, socket.TYPE, socket.PROTOCOL)
```

- Here we import the socket module which provides access to the functions in the socket module.
- Then we create a variable s to link to the socket function in the socket library.
- Inside the socket.socket function, you have these arguments in order: socket.socket([family[,type[,proto]]]).
  - Possible values for the socket objects:
    - family constants should be: AF_INET (default), AF_INET6, AF_UNIX
    - type constants should be: SOCK_STREAM (default), SOCK_DGRAM, SOCK_RAW
    - proto constants should be: 0 (default), IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMP, IPPROTO_RAW

References:  
https://docs.python.org/3/library/socket.html  


---
### 12.4.4 Understanding Socket API Functions
Before we start to create our own sockets lets take a moment to understand the componnents and the order that a socket is established.

- Components. Many are required for every TCP/UDP connection. Some are optional.
  - [socket()](https://docs.python.org/3/library/socket.html#socket.socket) creates a new socket of a certain type, identified by an integer number, and allocates system resources to it.
  - [bind()](https://docs.python.org/3/library/socket.html#socket.socket.bind) is typically used on the server-side, and associates a socket with a socket address structure, i.e. a specified local IP address and a port number.
  - [listen()](https://docs.python.org/3/library/socket.html#socket.socket.listen) is used on the server-side, and causes a bound TCP socket to enter listening state.
  - [connect()](https://docs.python.org/3/library/socket.html#socket.socket.connect) is used on the client-side, and assigns a free local port number to a socket. In the case of a TCP socket, it causes an attempt to establish a new TCP connection.
  - [accept()](https://docs.python.org/3/library/socket.html#socket.socket.accept) is used on the server-side. It accepts a received incoming attempt to create a new TCP connection from the remote client, and creates a new socket associated with the socket address pair of this connection.
  - [send()](https://docs.python.org/3/library/socket.html#socket.socket.send), [sendall()](https://docs.python.org/3/library/socket.html#socket.socket.sendall), [recv()](https://docs.python.org/3/library/socket.html#socket.socket.recv), [sendto()](https://docs.python.org/3/library/socket.html#socket.socket.sendto), and [recvfrom()](https://docs.python.org/3/library/socket.html#socket.socket.recvfrom) are used for sending and receiving data. The standard functions write() and read() may also be used.
  - [close()](https://docs.python.org/3/library/socket.html#socket.close) causes the system to release resources allocated to a socket. In case of TCP, the connection is terminated.
  - [gethostbyname()](https://docs.python.org/3/library/socket.html#socket.gethostname) and [gethostbyaddr()](https://docs.python.org/3/library/socket.html#socket.gethostbyaddr) are used to resolve hostnames and addresses. IPv4 only.
  - [select()](https://docs.python.org/3/library/select.html#select.select) is used to suspend, waiting for one or more of a provided list of sockets to be ready to read, ready to write, or that have errors.
  - [poll()](https://docs.python.org/3/library/select.html#select.poll) is used to check on the state of a socket in a set of sockets. The set can be tested to see if any socket can be written to, read from or if an error occurred.
  - [getsockopt()](https://docs.python.org/3/library/socket.html#socket.socket.getsockopt) is used to retrieve the current value of a particular socket option for the specified socket.
  - [setsockopt()](https://docs.python.org/3/library/socket.html#socket.socket.setsockopt) is used to set a particular socket option for the specified socket.

---
- Typical TCP connection:

![image](https://github.com/ruppertaj/WOBC/assets/93789685/8f9e70cb-f782-4ce7-9956-d4fcec972561)
tcp socket

```
Client Socket                                                   Server Socket
[socket](https://docs.python.org/3/library/socket.html#socket.socket)(family, type, proto)   [socket](https://docs.python.org/3/library/socket.html#socket.socket)(family, type, `proto)
                                                                [setsockopt](https://docs.python.org/3/library/socket.html#socket.socket.setsockopt)(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                                                                [bind](https://docs.python.org/3/library/socket.html#socket.socket.bind)(('', port))
                                                                [listen](https://docs.python.org/3/library/socket.html#socket.socket.listen)(1) - Enable a server to accept TCP connections
[connect](https://docs.python.org/3/library/socket.html#socket.socket.connect)((`ip`, `port`)) - TCP only   →   [accept](https://docs.python.org/3/library/socket.html#socket.socket.accept)() - TCP only
[sendto](https://docs.python.org/3/library/socket.html#socket.socket.sendto)() - send to unestablished socket [send](https://docs.python.org/3/library/socket.html#socket.socket.send)() - send to established socket [sendall](https://docs.python.org/3/library/socket.html#socket.socket.sendall)()-repeats 'send' until all data sent  →  [recv](https://docs.python.org/3/library/socket.html#socket.socket.recv)() - recv data from socket [recvfrom](https://docs.python.org/3/library/socket.html#socket.socket.recvfrom)() - recv data and socket info
[recv](https://docs.python.org/3/library/socket.html#socket.socket.recv)() - recv data from socket [recvfrom](https://docs.python.org/3/library/socket.html#socket.socket.recvfrom)() - recv data and socket info   →   [sendto](https://docs.python.org/3/library/socket.html#socket.socket.sendto)() - send to unestablished socket [send](https://docs.python.org/3/library/socket.html#socket.socket.send)() - send to established socket [sendall](https://docs.python.org/3/library/socket.html#socket.socket.sendall)()-repeats 'send' until all data sent
[close](https://docs.python.org/3/library/socket.html#socket.close)() - Close a socket file descriptor  ←→  [close](https://docs.python.org/3/library/socket.html#socket.close)() - Close a socket file descriptor
```


---
#### 12.4.4.1 Socket ([socket.socket()](https://docs.python.org/3/library/socket.html#socket.socket))
The function socket() creates an endpoint for communication and returns a [file descriptor](https://en.wikipedia.org/wiki/File_descriptor) for the socket. It uses three arguments:

- domain, which specifies the protocol family of the created socket. For example:
  - AF_INET for network protocol IPv4 (IPv4-only)
  - AF_INET6 for IPv6 (and in some cases, backward compatible with IPv4)
  - AF_UNIX for local socket (using a file)
- type, one of: protocol specifying the actual transport protocol to use. These protocols are specified in file netinet/in.h. The value 0 may be used to select a default protocol from the selected domain and type.
  - SOCK_STREAM (reliable stream-oriented service or Stream Sockets)
  - SOCK_DGRAM (datagram service or Datagram Sockets)
  - SOCK_SEQPACKET (reliable sequenced packet service)
  - SOCK_RAW (raw protocols atop the network layer)


---
#### 12.4.4.2 Protocol ([man ip(7)](https://man7.org/linux/man-pages/man7/ip.7.html)):
- 0 or IPPROTO_TCP for STREAM ([man tcp(7)](https://man7.org/linux/man-pages/man7/tcp.7.html)) and 0 or IPPROTO_UDP for DGRAM ([man udp(7)](https://man7.org/linux/man-pages/man7/udp.7.html)). For SOCK_RAW you may specify a valid [IANA IP protocol](https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml) defined in RFC 1700 assigned numbers.
- IPPROTO_IP creates a socket that sends/receives raw data for IPv4-based protocols (TCP, UDP, etc). It will handle the IP headers for you, but you are responsible for processing/creating additional protocol data inside the IP payload.
- IPPROTO_RAW creates a socket that sends/receives raw data for any kind of protocol. It will not handle any headers for you, you are responsible for processing/creating all payload data, including IP and additional headers. ([man raw(7)](https://man7.org/linux/man-pages/man7/raw.7.html))
  - The function returns -1 if an error occurred. Otherwise, it returns an integer representing the newly assigned descriptor.


---
#### 12.4.4.3 bind ([socket.bind()](https://docs.python.org/3/library/socket.html#socket.socket.bind))
- bind() associates a socket with an address. When a socket is created with socket(), it is only given a protocol family, but not assigned an address. This association must be performed before the socket can accept connections from other hosts. The function has three arguments:
```
sockfd, a descriptor representing the socket
my_addr, a pointer to a sockaddr structure representing the address to bind to.
addrlen, a field of type socklen_t specifying the size of the sockaddr structure.
```

- Bind() returns 0 on success and -1 if an error occurs.


---
#### 12.4.4.4 listen ([socket.listen()](https://docs.python.org/3/library/socket.html#socket.socket.listen))
- After a socket has been associated with an address, listen() prepares it for incoming connections. However, this is only necessary for the stream-oriented (connection-oriented) data modes, i.e., for socket types (SOCK_STREAM, SOCK_SEQPACKET). listen() requires two arguments:
```
sockfd, a valid socket descriptor.
backlog, an integer representing the number of pending connections that can be queued up at any one time. The operating system usually places a cap on this value.
```

- Once a connection is accepted, it is dequeued. On success, 0 is returned. If an error occurs, -1 is returned.


---
#### 12.4.4.5 accept ([socket.accept()](https://docs.python.org/3/library/socket.html#socket.socket.accept))
- When an application is listening for stream-oriented connections from other hosts, it is notified of such events (cf. select() function) and must initialize the connection using function accept(). It creates a new socket for each connection and removes the connection from the listening queue. The function has the following arguments:
  - sockfd, the descriptor of the listening socket that has the connection queued.
  - cliaddr, a pointer to a sockaddr structure to receive the client’s address information.
  - addrlen, a pointer to a socklen_t location that specifies the size of the client address structure passed to accept(). When accept() returns, this location contains the size (in bytes) of the structure.
- accept() returns the new socket descriptor for the accepted connection, or the value -1 if an error occurs. All further communication with the remote host now occurs via this new socket.
- Datagram sockets do not require processing by accept() since the receiver may immediately respond to the request using the listening socket.


---
#### 12.4.4.6 connect ([socket.connect()](https://docs.python.org/3/library/socket.html#socket.socket.connect))
- connect() establishes a direct communication link to a specific remote host identified by its address via a socket, identified by its file descriptor.
- When using a connection-oriented protocol, this establishes a connection. Certain types of protocols are connectionless, most notably the User Datagram Protocol. When used with connectionless protocols, connect defines the remote address for sending and receiving data, allowing the use of functions such as send and recv. In these cases, the connect function prevents the reception of datagrams from other sources.
- connect() returns an integer representing the error code: 0 represents success, while –1 represents an error. Historically, in BSD-derived systems, the state of a socket descriptor is undefined if the call to connect fails (as it is specified in the Single Unix Specification), thus, portable applications should close the socket descriptor immediately and obtain a new descriptor with socket(), in the case the call to connect() fails.


---
## 12.5 Demonstration of creating STREAM and DGRAM Sockets

---
### 12.5.1 TCP Stream Client
Here is an example of creating an IPv4 Stream socket. Note that proto field is unnecessary since it keeps the default value of zero.
```
#! /usr/bin/python3
import socket

# This can also be accomplished by using s = socket.socket() due to AF_INET and SOCK_STREAM being defaults
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

ipaddr = '127.0.0.1'
port = 1111

s.connect((ipaddr, port))

# To send a string as a bytes-like object, add the prefix b to the string. \n is used to go to the next line (hit enter)
s.send(b'Message\n')

# It is recommended that the buffersize used with recvfrom is a power of 2 and not a very large number of bits
data, conn = s.recvfrom(1024)

# In order to receive a message that is sent as a bytes-like-object you must decode into utf-8 (default)
print(data.decode('utf-8'))

s.close()
```

- In the above, we are creating a socket with address family = AF_INET (IPv4) and type = SOCK_STREAM (TCP).
- We then define an ip address and port pair.
- Next we call the socket object [connect(address)](https://docs.python.org/3/library/socket.html#socket.socket.connect) tied to IPv4 and TCP we mapped to the variable s which will connect to the remote address and port we provide over IPv4 and TCP.
- Continuing on, we will add to this connection by attempting to send a message through the connection and wait for a response.
- When we call the socket object [send(data)](https://docs.python.org/3/library/socket.html#socket.socket.send) which is also tied to s, it sends whatever we put in for data across the connection. By typing b’Message\n', the string 'Message\n' is converted to a [bytes-like object (b)](https://docs.python.org/3/glossary.html#term-bytes-like-object) which is required before sending.
- After sending the message, we will attempt to receive data from the socket by using the socket object [recvfrom(buffersize)](https://docs.python.org/3/library/socket.html#socket.socket.recvfrom) tied to the variable s. The socket object recvfrom receives data in a pair (bytes, address) where bytes is the data received as a bytes-like object and address is the socket address. We split recvfrom into the two variables response and conn so we can print only the data portion.
- Next we want to print the data received, but we need to [decode](https://docs.python.org/3/library/stdtypes.html#bytes.decode) response into utf-8 (default) from the bytes-like object or it will maintain the prefix b from the message sent across.
- Lastly, we will [close](https://docs.python.org/3/library/socket.html#socket.close) the socket tied to the variable s to clean up when we are finished.
- To test, simply echo a message into a netcat listener session on the same machine you run this script on.
```
echo "I got your message" | nc -l -p 54321
```

- Then run the script on another terminal.
```
python3 fg_stream_socket_example_p3.py
```

- The result will be the message "Hello" is sent to the listener and the message "I got your message" is sent to the terminal that ran the script.
- You can change the ipaddr variable to 10.3.0.2 and port to 1234 to get an automated response. If you do this, watch the connection with tcpdump -X or wireshark to see exactly what is sent across the wire and what is received.


---
### 12.5.2 TCP Stream Server (OPTIONAL)
```
#!/usr/bin/python3
import socket
import os
port = 1111
message = b"Connected to TCP Server on port %i\n" % port

# Create TCP stream socket using IPv4

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)

# This prevents the bind from being stuck in TIME_WAIT state. The SO_REUSEADDR flag tells the kernel to reuse a local socket in TIME_WAIT state, without waiting for its natural timeout to expire. Will not work if the socket is to the same destination.

s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

# Bind the socket to address.  The socket must not already be bound.
# '' Ties the socket to any IPv4 address on this device

s.bind(('', port))

# Enable a server to accept connections. Listens for 1 request to connect

s.listen(1)

# Execute the command (a string) in a subshell.

os.system("clear")

print ("Waiting for TCP connections\n")

#Listens for connections until stopped
while 1:
    conn, addr = s.accept()
    # This accepts connections from clients and creates a new socket.
    # The return value is a pair (conn, address)
    # conn = a new socket object usable to send and receive data on the connection (local)
    # address = the address bound to the socket on the other end of the connection (remote)

    connect = conn.recv(1024)
    # Waits for a message to be sent across and breaks out the address
    # Receive data from the socket.
    # The return value is a bytes object representing the data received.
    # The maximum amount of data to be received at once is specified by buffsize

    # connect = data recieved from remote to your local socket.

    address, port = addr
    # splits addr into 2 variables that is contained within it. Remote IP and remote port.
    # Prints the message

    print ("Message Received - '%s'" % connect.decode())  # Attempts to decode the message sent into utf-8 by default

    print ("Sent by -", address, "port -", port, "\n")   # Extracts the address and port that sent the message

    # Sends our message in response. Used when there is a remote connection (TCP)
    conn.sendall(message)

    # Closes the local connection from remote
    conn.close()
```

```
 #!/usr/bin/python3
 import socket
 import os
 port = 1111
 message = b"Connected to TCP Server on port %i\n" % port
```

- % is to assign a interpolation placeholder for information to be supplied ([Python 3 string formatting](https://docs.python.org/3/library/stdtypes.html#printf-style-string-formatting)).
- Paired with the string converstion type. Some examples include:
  - i = Signed integer decimal
  - c = Single character
  - s = String
- Further informaiton on interpolation can be found [here](https://stackabuse.com/python-string-interpolation-with-the-percent-operator/).
- [PEP 461](https://www.python.org/dev/peps/pep-0461/) — Adding % formatting to bytes and bytearray

```
 # Create TCP stream socket using IPv4
 s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)

 # This prevents the bind from being stuck in TIME_WAIT state. The SO_REUSEADDR flag tells the kernel to reuse a local socket in TIME_WAIT state, without waiting for its natural timeout to expire. Will not work if the socket is to the same destination.

 s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
```

- socket.SOL_SOCKET
  - Reference from the [setsockopt](https://docs.python.org/3/library/socket.html#socket.socket.setsockopt) python page.
  - From [setcoskopt(2)](https://manpages.debian.org/buster/manpages-dev/setsockopt.2.en.html) man page:
    - When manipulating socket options, the level at which the option resides and the name of the option must be specified. To manipulate options at the sockets API level, level is specified as SOL_SOCKET. To manipulate options at any other level the protocol number of the appropriate protocol controlling the option is supplied. For example, to indicate that an option is to be interpreted by the TCP protocol, level should be set to the protocol number of TCP.
- socket.SO_REUSEADDR
  - Running an example several times with too small delay between executions, could lead to this error:
```
OSError: [Errno 98] Address already in use
```

  - This is because the previous execution has left the socket in a TIME_WAIT state, and can’t be immediately reused.
  - There is a socket flag to set, in order to prevent this, socket.SO_REUSEADDR:
    - `s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)`
    - `s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)`
    - `s.bindHOST, PORT`
  - The SO_REUSEADDR flag tells the kernel to reuse a local socket in TIME_WAIT state, without waiting for its natural timeout to expire.

```
 # Bind the socket to address.  The socket must not already be bound.
 # '' Ties the socket to any IPv4 address on this device

 s.[bind](https://docs.python.org/3/library/socket.html#socket.socket.bind)(('', PORT))
```

- Reference from the bind python page.
- socket.bind using the tuple of the arguments `self`, `address`.
  - The specification of `self` is made by the `''`.
  - `address` is the port number or variable to listen on.

```
 # Enable a server to accept connections. Listens for 1 request to connect

 s.listen(1)

```
- Reference on [socket.listen](https://docs.python.org/3/library/socket.html#socket.socket.listen) python page.
  - Enable a server to accept connections. If backlog is specified, it must be at least 0 (if it is lower, it is set to 0); it specifies the number of unaccepted connections that the system will allow before refusing new connections. If not specified, a default reasonable value is chosen.
    - `s.listen(1)` will listen for only `1` connection at a time.

```
 # Execute the command (a string) in a subshell.
 os.system("clear")
```

- Reference from the [os.system](https://docs.python.org/3/library/os.html#os.system) python page.
  - Execute the command (a string) in a subshell. This is implemented by calling the Standard C function system(), and has the same limitations. Changes to sys.stdin, etc. are not reflected in the environment of the executed command. If command generates any output, it will be sent to the interpreter standard output stream.
    - `os.system("clear")` will run the linux command `clear` to clear the screen.

```
 print ("Waiting for TCP connections\n")

 #Listens for connections until stopped
 while 1:
    conn, addr = s.accept()
    # This accepts connections from clients and creates a new socket.
    # The return value is a pair (conn, address)
    # conn = a new socket object usable to send and receive data on the connection (local)
    # address = the address bound to the socket on the other end of the connection (remote)

    connect = conn.recv(1024)
    # Waits for a message to be sent across and breaks out the address
    # Receive data from the socket.
    # The return value is a bytes object representing the data received.
    # The maximum amount of data to be received at once is specified by buffsize

    # connect = data recieved from remote to your local socket.

    address, port = addr
    # splits addr into 2 variables that is contained within it. Remote IP and remote port.
    # Prints the message

    print ("Message Received - '%s'" % connect.decode())  # Attempts to decode the message sent into utf-8 by default

    print ("Sent by -", address, "port -", port, "\n")   # Extracts the address and port that sent the message

    # Sends our message in response. Used when there is a remote connection (TCP)
    conn.sendall(message)

    # Closes the local connection from remote
    conn.close()
```

- while 1: Creates a continuous loop to always listen for incoming connections.
- Reference from the [socket.accept](https://docs.python.org/3/library/socket.html#socket.socket.accept) python page.
  - Accept a connection. The socket must be bound to an address and listening for connections. The return value is a pair (conn, address) where conn is a new socket object usable to send and receive data on the connection, and address is the address bound to the socket on the other end of the connection.
    - `conn` is assigned the tuple socket (ip/port) of the local connection.
    - `addr` is assigned the tuple socket (ip/port) of the remote connection.
      - `address, port = addr` pulls the ip(`address`) and the port(`port`) variables from the `addr` tuple.
- Reference from the [socket.recv](https://docs.python.org/3/library/socket.html#socket.socket.recv) python page.
  - Receive data from the socket. The return value is a bytes object representing the data received. The maximum amount of data to be received at once is specified by bufsize. See the Unix manual page [recv(2)](https://manpages.debian.org/buster/manpages-dev/recv.2.en.html) for the meaning of the optional argument flags; it defaults to zero.
    - `conn.recv(1024)` where `conn` is the variable to specify the local socket and `1024` is the amount of memory (in bytes) assigned to receive the data.
- Reference from the [socket.sendall](https://docs.python.org/3/library/socket.html#socket.socket.sendall) python page.
  - Send data to the socket. The socket must be connected to a remote socket. The optional flags argument has the same meaning as for [recv()](https://docs.python.org/3/library/socket.html#socket.socket.recv) above. Unlike [send()](https://docs.python.org/3/library/socket.html#socket.socket.send), this method continues to send data from bytes until either all data has been sent or an error occurs. None is returned on success. On error, an exception is raised, and there is no way to determine how much data, if any, was successfully sent.
    - `conn.sendall(message)` where `conn` is the variable to specify the local socket and `sendall` will continuously send the message until complete.
- Reference from the [socket.close](https://docs.python.org/3/library/socket.html#socket.close) python page.
  - Close a socket file descriptor. This is like [os.close()](https://docs.python.org/3/library/os.html#os.close), but for sockets. On some platforms (most noticeable Windows) os.close() does not work for socket file descriptors.
    - `conn.close()` where `conn` is the variable to specify the *local* socket to close.


---
### 12.5.3 UDP Dgram Client
Now that we have built a stream socket, we will build a datagram socket to closely mirror the stream socket. Here is an example:
```
import socket

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

ipaddr = '127.0.0.1'
port = 2222

# To send a string as a bytes-like object, add the prefix b to the string. \n is used to go to the next line (hit enter)
s.sendto(b'Message\n', (ipaddr,port))

# It is recommended that the buffersize used with recvfrom is a power of 2 and not a very large number of bits
response, conn = s.recvfrom(1024)

# In order to receive a message that is sent as a bytes-like-object you must decode into utf-8 (default)
print(response.decode())
```

- Notice one of the changes here is that we had to use socket.SOCK_DGRAM instead to indicate that the protocol is UDP instead of TCP.
- Additionally we removed the [connect()](https://docs.python.org/3/library/socket.html#socket.socket.connect) and used [sendto()](https://docs.python.org/3/library/socket.html#socket.socket.sendto) rather than [send()](https://docs.python.org/3/library/socket.html#socket.socket.send) since we do not connect with UDP. With sendto we need to provide the socket tuple (address, port) with it.
- To test, simply echo a message into a netcat listener session on the same machine you run this script on but with the -u option to indicate UDP.
```
echo "I got your message" | nc -l -p 2222 -u
```

- Then run the script on another terminal.
```
python3 fg_dgram_socket_example_p3.py
```

- The result will be the message "Hello" is sent to the listener and the message "I got your message" is sent to the terminal that ran the script.


---
### 12.5.4 UDP Dgram Server (OPTIONAL)
```
#!/usr/bin/python3

import socket
import os

PORT = 2222

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

 s.bind(('', PORT))
# the '' means to bind to any ip address on system

# Execute the command (a string) in a subshell.
os.system("clear")

print ("Awaiting UDP Messages")

# Receive data until canceled
while True:

    # Waits for a message to be sent across and breaks out the address
    # Receive data from the socket.
    # The return value is a bytes object representing the data received.
    # The maximum amount of data to be received at once is specified by bufsize
    # Waiting for data up to 1024 bytes.
    # The return value is a pair (bytes, address)
    # bytes is a bytes object representing the data received
    # address is the address of the socket sending the data

    data, addr = s.recvfrom(1024)

    address, port = addr

    # splits addr into 2 variables that is contained within it. Remote IP and remote port.

    print ("\nMessage Received: '%s'" % data.decode())
    print ("Sent by -", address, "port", port)

    # Send data to the socket. The socket must be connected to a remote socket.
    s.sendto(b"Message received by the UDP Message Server!", addr)
```

```
#!/usr/bin/python3

import socket
import os

PORT = 2222

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

 s.[bind](https://docs.python.org/3/library/socket.html#socket.socket.bind)(('', PORT))
# the '' means to bind to any ip address on system
```

- Reference from the bind python page.
- socket.bind using the tuple of the arguments `self`, `address`.
  - The specification of `self` is made by the `''`.
  - `address` is the port number or variable to listen on.

```
# Execute the command (a string) in a subshell.
[os.system](https://docs.python.org/3/library/os.html#os.system)("clear")
```

- Reference from the os.system python page.
  - Execute the command (a string) in a subshell. This is implemented by calling the Standard C function system(), and has the same limitations. Changes to sys.stdin, etc. are not reflected in the environment of the executed command. If command generates any output, it will be sent to the interpreter standard output stream.
    - `os.system("clear")` will run the linux command `clear` to clear the screen.

```
print ("Awaiting UDP Messages")

# Receive data until canceled
while True:

    # Waits for a message to be sent across and breaks out the address
    # Receive data from the socket.
    # The return value is a bytes object representing the data received.
    # The maximum amount of data to be received at once is specified by bufsize
    # Waiting for data up to 1024 bytes.
    # The return value is a pair (bytes, address)
    # bytes is a bytes object representing the data received
    # address is the address of the socket sending the data

    data, addr = s.recvfrom(1024)

    address, port = addr

    # splits addr into 2 variables that is contained within it. Remote IP and remote port.

    print ("\nMessage Received: '%s'" % data.decode())
    print ("Sent by -", address, "port", port)

    # Send data to the socket. The socket must be connected to a remote socket.
    s.sendto(b"Message received by the UDP Message Server!", addr)
```

- Reference from the [socket.recvfrom](https://docs.python.org/3/library/socket.html#socket.socket.recvfrom) python page.
  - Receive data from the socket. The return value is a pair (bytes, address) where bytes is a bytes object representing the data received and address is the address of the socket sending the data. See the Unix manual page [recv(2)](https://manpages.debian.org/buster/manpages-dev/recv.2.en.html) for the meaning of the optional argument flags; it defaults to zero. (The format of address depends on the address family — see above.)
    - `data, addr = s.recvfrom(1024)` where `data` is the variable to specifiy the data bytes received and `addr` is the variable to reference the remote socket tuple that sent the data. `1024` is the amount of memory (in bytes) assigned to receive the data.
    - `address, port = addr` pulls the ip(`address`) and the port(`port`) variables from the `addr` tuple.
- Reference from the [socket.sendto](https://docs.python.org/3/library/socket.html#socket.socket.sendto) python page.
  - Send data to the socket. The socket should not be connected to a remote socket, since the destination socket is specified by address. The optional flags argument has the same meaning as for [recv()](https://docs.python.org/3/library/socket.html#socket.socket.recv) above. Return the number of bytes sent.
  - `s.sendto` specifies that the system is to send the data into the socket (`addr`) and that it is not currently connected.


---
## 12.6 Encoding and Decoding
- Encoding = The process of taking bits and converting them using the specified cipher, such as ASCII, UTF-8, etc.
  - Most commonly used encoding today is UTF-8 which is compatible with unicode.
- Decoding = The changing of the cipher used to change how the bits are displayed.
  - Documents that display improperly is typically the symptom of incorrect decoding selected by the program.
- Encoding vs Encryption:
  - Encoding - is the process to transform data in such a format that it can be easily used by different types of systems.
    - Transforms data into another format using a scheme that is publicly available so that it can easily be reversed.
    - For maintaining data usability and uses schemes that are publicly available.
    - Examples: HTML Encoding, URL Encoding, Unicode Encoding, Base64 Encoding Hex Encoding, ASCII Encoding, base64 Encoding.
  - Encryption - is a process used to convert simple readable data known as plain text to unreadable data known as ciphertext which can only be converted to plain text if the user knows the encryption key.
    - Transforms data into another format in such a way that only specific individual(s) can reverse the transformation.
    - Uses publicly available methods but requires private "keys" to perform the transformation
    - For maintaining data confidentiality and thus the ability to reverse the transformation (keys) are limited to certain people.
    - Examples: Blowfish (symmetrical) RSA (asymmetrical),AES (symmetrical),ECC (namely ed25519) (asymmetric),Chacha/Salsa (symmetric).
    - Note (Asymmetric is slow but good for establishing a trusted connection. Symmetric has a shared key and is faster.
    - Protocols often use asymmetric to transfer symmetric key.

---
- Examples of character encoding schemes:
  - ASCII (American Standard Code for Information Interchange): One of the oldest and most basic character encoding standards. It uses 7 bits to represent characters, allowing for 128 unique characters, including letters, numbers, punctuation, and control characters.
  - Unicode: A character encoding standard that aims to represent every character from every language. Unicode assigns a unique number, called a code point, to each character. It supports various encoding schemes, including UTF-8, UTF-16, and UTF-32.
    - UTF-8: Variable-width encoding scheme where each character is represented by 1 to 4 bytes. It’s widely used on the internet because it’s backward compatible with ASCII.
    - UTF-7: A variable-width character encoding that’s designed to be more compact than UTF-8 for encoding Unicode text in environments that may restrict the use of 8-bit characters.
    - UTF-16: Fixed-width encoding scheme where each character is represented by either 2 or 4 bytes. It’s commonly used in programming languages and operating systems.
    - UTF-32: Fixed-width encoding scheme where each character is represented by exactly 4 bytes. It’s less commonly used due to its higher memory usage.
  - ISO-8859: A series of character encoding standards developed by the International Organization for Standardization (ISO). Each part of the ISO-8859 series is designed to support specific languages or groups of languages. For example, ISO-8859-1 is designed for Western European languages.
  - ISO-8859-15 (Latin-9): An extension of ISO-8859-1 that adds support for additional characters used in Western European languages, such as the Euro sign (€) and French and Finnish letters.
  - ISO-2022-JP: An extension of ISO-2022 that defines methods for encoding Japanese text specifically for the Japanese market.
  - ISO-8859-7 (Latin/Greek): A character encoding standard for the Greek alphabet, based on ISO-8859-1 but with Greek letters replacing certain Latin letters.
  - ISO-8859-8 (Latin/Hebrew): A character encoding standard for the Hebrew alphabet, based on ISO-8859-1 but with Hebrew letters replacing certain Latin letters.
  - ISO-8859-5 (Latin/Cyrillic): A character encoding standard for the Cyrillic alphabet, based on ISO-8859-1 but with Cyrillic letters replacing certain Latin letters.
  - ISO-8859-9 (Latin-5): A character encoding standard for the Turkish alphabet, based on ISO-8859-1 but with Turkish-specific letters replacing certain Latin letters.
  - ISO-8859-11 (Latin/Thai): A character encoding standard for the Thai alphabet, based on ISO-8859-1 but with Thai letters replacing certain Latin letters.
  - ISO-8859-16 (Latin-10): An extension of ISO-8859-1 that adds support for additional characters used in various European languages, including Romanian and Albanian.
  - TIS-620: A character encoding standard for the Thai alphabet, primarily used in Thailand.
  - ISCII (Indian Script Code for Information Interchange): A character encoding standard for representing various Indic scripts used in languages of India.
  - EBCDIC (Extended Binary Coded Decimal Interchange Code): A character encoding standard primarily used on IBM mainframe computers. It’s different from ASCII and Unicode and was historically used in IBM systems.
  - Morse Code: A method of encoding text characters as sequences of two different signal durations, called dots and dashes or dits and dahs. It’s mainly used in telecommunication.
  - Windows-1252 (CP-1252): An extension of ASCII used by Microsoft Windows to support additional characters for Western European languages. It’s similar to ISO-8859-1 but includes additional characters in the 0x80 to 0x9F range.
  - Shift JIS: A character encoding used for Japanese text. It’s a variable-width encoding where most characters are represented by two bytes, but some characters require three bytes.
  - BIG5: A character encoding used for traditional Chinese characters, primarily in Taiwan, Hong Kong, and Macau. It’s a variable-width encoding with most characters represented by two bytes.
  - GB2312 and GBK: Character encodings used for simplified Chinese characters. GB2312 is an older standard, while GBK is an extension that includes additional characters. Both are widely used in mainland China.
  - KOI8-R and KOI8-U: Character encodings used for Russian text. KOI8-R is for Russian, while KOI8-U extends it to support Ukrainian characters.
  - ISO-2022: A character encoding standard that defines methods for encoding character sets into bit sequences. It’s often used for encoding Japanese text.
  - Latin-1 (ISO-8859-1): A character encoding standard for Western European languages. It’s a single-byte encoding and is part of the ISO/IEC 8859 series.
  - IBM Code Page 437: An extended ASCII character set used by early IBM PCs and compatible systems. It includes special characters, symbols, and box-drawing characters.
  - MacRoman: A character encoding used on older Macintosh computers. It’s similar to ISO-8859-1 but includes additional characters in the 0x80 to 0x9F range.

References:  
https://en.wikipedia.org/wiki/Character_encoding  


---
### 12.6.1 HEX Encoding/Decoding
- xxd: creates a hex dump of a given file or standard input. It can also convert a hex dump back to its original binary form.
  - xxd - https://linux.die.net/man/1/xxd, https://www.howtoforge.com/linux-xxd-command/, https://www.tutorialspoint.com/unix_commands/xxd.htm
```
Encode text to Hex
    echo "Message" | xxd
Endode file to Hex
    xxd {options} infile (outfile)
    xxd file.txt file-encoded.txt
Reverts Hex file to ASCII
    xxd -r file-encoded.txt file-decoded.txt
```

- HEX encoding using Python
```
import binascii
```

```
message = b'Message'
hidden_msg = binascii.hexlify(message)
```

- HEX decoding using Python
new_msg = binascii.unhexlify(hidden_msg)

References:  
https://docs.python.org/3.12/library/binascii.html


---
### 12.6.2 BASE64 Encoding/Decoding
- base64: tool can encode and decode file or input to/from base64 character encoding.
  - base64 - https://linux.die.net/man/1/base64
```
Displays text in base64
    echo "convert me" | base64
    Y29udmVydCBtZQo=
```

```Displays the base64 in ASCII
    echo "Y29udmVydCBtZQo=" | base64 --decode
    convert me
```

```
Coverts content to base64 then save to file
    base64 file.txt > file-encoded.txt
```

```
Converts content from base64 back to origional format
    base64 -d file-encoded.txt > file-decoded.txt
```

- BASE64 encoding using Python
```
import base64
```

```
message = b'Message'
hidden_msg = base64.b64encode(message)
```

- BASE64 decoding using Python
```
new_msg = base64.b64decode(hidden_msg)
```

References:  
https://docs.python.org/3.12/library/base64.html


---
### 12.6.3 Tools
- Web browsers – most modern web browsers feature automatic character encoding detection.
- [iconv](https://linux.die.net/man/1/iconv) – program and standardized API to convert encodings
- [luit](https://linux.die.net/man/1/luit) – program that converts encoding of input and output to programs running interactively convert_encoding.py – Python based utility to convert text files between arbitrary encodings and line endings
- [chardet](https://pypi.org/project/chardet/) – This is a translation of the Mozilla automatic-encoding-detection code into the Python computer language. The newer versions of the Unix file command attempt to do a basic detection of character encoding (also available on Cygwin).


---
## 12.7 Demonstration of creating Raw Sockets
We will now bring the discussion to IPv4 raw sockets. As previously stated, raw sockets usually include headers for each layer that we are attempting to send unlike the stream and datagram sockets, which rely on encapsulation and decapsulation to provide only what is necessary. This means that we will be building out each of the headers and including data as needed.

---
### 12.7.1 IP RAW Client
[IPv4 RAW CODE](https://git.cybbh.space/net/public/-/raw/master/modules/networking/activities/resources/ipraw.adoc)
**For class questions, scenario will tell you what to enter for everything, if not, then 0**
In order to properly set up a raw socket and set the packet structure out, we should consult the RFC for the header we are going to be looking at.

- RFCs, or Requests for Comments, contain technical and organizational documents about the Internet, including specifications and policy documents. RFCs cover many aspects of computer networking, including protocols, procedures, and concepts.

Since we will need to build so much out for raw sockets, it is recommended to perform exception handling. To do so, we will need to discuss error / exception handling little bit. Reference - https://docs.python.org/3/tutorial/errors.html and https://docs.python.org/3/library/exceptions.html

- Errors are considered exceptions in python, and can either break the program, or just make it not work as intended. This can happen if you have a user input a number, but they instead provide a character or string.
- The way we will try to avoid those errors is by handling exceptions using try and except for the type of error. Here is an example of error handling for an IPv4 raw socket:
```
# For building the socket
import socket

# For system level commands
import sys

# For establishing the packet structure (Used later on), this will allow direct access to the methods and functions in the struct module
from struct import *

# Create a raw socket.
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
except socket.error as msg:
    print(msg)
    sys.exit()
```

- The above will attempt to build a socket with s as the variable, using AF_INET as the family, SOCK_RAW as the type, and IPPROTO_RAW as the proto arguments. Note - this will not actually attempt to do anything until we provide more information later on.
  - 0 or IPPROTO_TCP for STREAM ([man tcp(7)](https://man7.org/linux/man-pages/man7/tcp.7.html)) and 0 or IPPROTO_UDP for DGRAM ([man udp(7)](https://man7.org/linux/man-pages/man7/udp.7.html)). For SOCK_RAW you may specify a valid [IANA IP protocol](https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml) defined in RFC 1700 assigned numbers.
  - IPPROTO_IP creates a socket that sends/receives raw data for IPv4-based protocols (TCP, UDP, etc). It will handle the IP headers for you, but you are responsible for processing/creating additional protocol data inside the IP payload.
  - IPPROTO_RAW creates a socket that sends/receives raw data for any kind of protocol. It will not handle any headers for you, you are responsible for processing/creating all payload data, including IP and additional headers. ([man raw(7)](https://man7.org/linux/man-pages/man7/raw.7.html))
- If the socket fails to build, the [error](https://docs.python.org/3/library/socket.html#socket.error) will be placed in the variable msg, and prints it to the screen.
- When the print finishes, [sys.exit()](https://docs.python.org/3/library/sys.html#sys.exit) will exit the program without needing to manually exit.

Now that the socket is getting created with exception handling, we will go ahead and lay out the packet structure using our knowledge of headers and eventually the struct module. Reference - https://docs.python.org/3/library/struct.html

- First, we need to build out the empty packet and lay out the fields in the IPv4 header. Try to keep values at a minimum of 1 byte due to sizing in the struct library.
- To do this, you should refer to the RFC, Section 3 - Specification, (https://tools.ietf.org/html/rfc791) for the IPv4 header to properly lay out the format.

Here is an example:
```
packet = ''

src_ip = "127.0.0.1"
dst_ip = "127.0.0.1"

# Lets add the IPv4 header information
ip_ver_ihl = 69  # This is putting the decimal conversion of 0x45 for Version and Internet Header Length
ip_tos = 0           # This combines the DSCP and ECN feilds
ip_len = 0           # The kernel will fill in the actually length of the packet
ip_id = 12345        # This sets the IP Identification for the packet
ip_frag = 0          # This sets fragmentation to off
ip_ttl = 64          # This determines the TTL of the packet when leaving the machine
ip_proto = 16        # This sets the IP protocol to 16 (Chaos). If this was 6 (TCP) or 17 (UDP) additional headers would be required
ip_check = 0         # The kernel will fill in the checksum for the packet
ip_srcadd = socket.inet_aton(src_ip)  # inet_aton(string) will convert an IP address to a 32 bit binary number
ip_dstadd = socket.inet_aton(dst_ip)  # inet_aton(string) will convert an IP address to a 32 bit binary number
```

- Here we defined each of the ipv4 header fields and their values.
- We defined scr_ip and dst_ip variables but they are currently stored as string values. To convert them to 32-bit binary numbers we use the [inet_aton()](https://docs.python.org/3/library/socket.html#socket.inet_aton) function.
- Now that we have layed out the header fields, we are going to use the function [pack(format, var1, var2, …​)](https://docs.python.org/3/library/struct.html#struct.pack) from the struct module. This will allow us to format the packet in the correct order for field alignment. Format will start with "[!](https://docs.python.org/3/library/struct.html#byte-order-size-and-alignment)" for network ([big-endian](https://thebittheories.com/little-endian-vs-big-endian-b4046c63e1f2)), and will be followed by byte sizes in quotes which corresponds with the fields we apply as variables in order. Here is an example of packing the header:
```
ip_header = pack('!BBHHHBBH4s4s' , ip_ver_ihl, ip_tos, ip_len, ip_id, ip_frag, ip_ttl, ip_proto, ip_check, ip_srcadd, ip_dstadd)
```

- To determine the format sizes, refer to https://docs.python.org/3/library/struct.html#format-characters. Notice that the smallest size allocated in this way is 1 byte, which is why we combined the two nibbles Version and IHL. Here is a quick reference:
  - B = 1 byte (Byte)
  - H = 2 bytes (Half Word)
  - 4s = 4 bytes (Word - Converted from string to binary)
- Next we will add a message to go with the packet, and send it. Here is an example:
```
message = b'This is a message'
packet = ip_header + message

# Send the packet
s.sendto(packet, (dst_ip, 0))
```

- Above you see that the bytes-like object message is added to the ip_header variable.
- Finally, we call the socket object [sendto([bytes,[address(hostaddr, port)](https://docs.python.org/3/library/socket.html#socket.socket.sendto)])] (since we did not establish a connection prior) where bytes is the combination of ip_header and message variables, and address is the tuple for host address and port. Since we aren’t going to a specific port, that is going to stay 0.

Now you can watch wireshark or tcpdump -X to see your packet go across with your message appended. You should get an icmp response saying that port is not open.


---
### 12.7.2 TCP Raw Client
[TCP RAW CODE](https://git.cybbh.space/net/public/-/raw/master/modules/networking/activities/resources/tcpraw.adoc)

Raw sockets can tie in additional headers, such as TCP or UDP, which requires setting up those headers in a similar way as the IP header. For this, we start out the raw socket just like we did previously:
```
# For building the socket
import socket

# For system level commands
import sys

# For doing an array in the TCP checksum
import array

# For establishing the packet structure (Used later on), this will allow direct access to the methods and functions in the struct module
from struct import *

# Create a raw socket.
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
except socket.error as msg:
    print(msg)
    sys.exit()

packet = ''

src_ip = "10.10.0.40"
dst_ip = "172.16.82.106"

# Lets add the IPv4 header information
ip_ver_ihl = 69                       # This is putting the decimal conversion of 0x45 for Version and Internet Header Length
ip_tos = 0                            # This combines the DSCP and ECN feilds
ip_len = 0                            # The kernel will fill in the actually length of the packet
ip_id = 12345                         # This sets the IP Identification for the packet
ip_frag = 0                           # This sets fragmentation to off
ip_ttl = 64                           # This determines the TTL of the packet when leaving the machine
ip_proto = 6                          # This sets the IP protocol to 6 (TCP) so additional headers are required
ip_check = 0                          # The kernel will fill in the checksum for the packet
ip_srcadd = socket.inet_aton(src_ip)  # inet_aton(string) will convert an IP address to a 32 bit binary number
ip_dstadd = socket.inet_aton(dst_ip)  # inet_aton(string) will convert an IP address to a 32 bit binary number

ip_header = pack('!BBHHHBBH4s4s' , ip_ver_ihl, ip_tos, ip_len, ip_id, ip_frag, ip_ttl, ip_proto, ip_check, ip_srcadd, ip_dstadd)
```

- Here we just change the IP protocol to 6 making it TCP, making the tcp header a requirement.
- Then we will move the packet sending portion to the bottom and add our tcp headers by following the RFC, Section 3.1 Header format (https://tools.ietf.org/html/rfc793). Here is an example:
```
# Tcp header fields
tcp_src = 54321                       # source port
tcp_dst = 7777                        # destination port
tcp_seq = 454                         # sequence number
tcp_ack_seq = 0                       # tcp ack sequence number
tcp_data_off = 5                      # data offset specifying the size of tcp header * 4 which is 20
tcp_reserve = 0                       # the 3 reserve bits + ns flag in reserve field
tcp_flags = 0                         # tcp flags field before the bits are turned on
tcp_win = 65535                       # maximum allowed window size reordered to network order
tcp_chk = 0                           # tcp checksum which will be calculated later on
tcp_urg_ptr = 0                       # urgent pointer only if urg flag is set

# Combine the left shifted 4 bit tcp offset and the reserve field
tcp_off_res = (tcp_data_off << 4) + tcp_reserve
```

- As with the IPv4 header, we need to create the fields necessary to build the TCP header.
- The tcp_data_off and tcp_reserve variables are separated at first but combined by putting the value of the field starting 4 bits over. This means instead of the binary values looking like "128 64 32 16 8 4 2 1", you now have binary values "8 4 2 1" starting at the 4th bit from right to left, just like hex. This process is completely optional. We could use tcp_off_res = 80 to avoid the combining of the 2 fields. This would limit our capabilities to adjust these variables independently.
- The tcp_flags variable is set to 0 here because we will be using that variable later and it needs to start with a value.
- Now we will define the tcp flags by bit location and combine them. Here is an example:
```
# Tcp flags by bit starting from right to left
tcp_fin = 0                           # Finished
tcp_syn = 1                           # Synchronization
tcp_rst = 0                           # Reset
tcp_psh = 0                           # Push
tcp_ack = 0                           # Acknowledgment
tcp_urg = 0                           # Urgent
tcp_ece = 0                           # Explicit Congestion Notification Echo
tcp_cwr = 0                           # Congestion Window Reduced

# Combine the tcp flags by left shifting the bit locations and adding the bits together
tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh << 3) + (tcp_ack << 4) + (tcp_urg << 5) + (tcp_ece << 6) + (tcp_cwr << 7)
```

- As you can see, we again left shifted the bit locations from right to left for the tcp flags in order to have the bits combine if they are on. This process is optional. We could use tcp_flags = 2 to get our value to avoid combining all the field individually. This would limit our capabilities to adjust these variables independently.
- The next thing we have to do is pack the tcp header with the struct module.
```
# The ! in the pack format string means network order
tcp_hdr = pack('!HHLLBBHHH', tcp_src, tcp_dst, tcp_seq, tcp_ack_seq, tcp_off_res, tcp_flags, tcp_win, tcp_chk, tcp_urg_ptr)
```

- To determine the format sizes, refer to https://docs.python.org/3/library/struct.html#format-characters. Here is a quick reference:
  - B = 1 byte (Byte)
  - H = 2 bytes (Half Word)
  - L = 4 bytes (32 bit Word as an integer)
- Now you can add a variable for user text. Here is an example:
```
user_data = b'Hello! Is this hidden?'
```

- Now that we have all of the fields created and packed, we need to build a checksum mechanism in order to properly calculate the checksum.
- To do this, we have to understand how a tcp checksum is calculated. Reference - http://www.tcpipguide.com/free/t_TCPChecksumCalculationandtheTCPPseudoHeader-2.htm
  - To calculate the TCP segment header’s checksum field, a 12-byte TCP pseudo header is constructed and placed before the TCP segment.
    - The TCP pseudo header consists of source address (4 bytes from IP header), destination address (4 bytes from IP header), reserved (1 byte), protocol (1 byte from IP header), tcp segment length (2 bytes computed from tcp header and data)
  - Once this 96-bit header has been formed, it is placed in a buffer, following which the TCP segment itself is placed. Then, the checksum is computed over the entire set of data (pseudo header plus TCP segment). The value of the checksum is placed into the Checksum field of the TCP header, and the pseudo header is discarded—it is not an actual part of the TCP segment and is not transmitted.
- Now that we have an idea of how the tcp checksum is run, we need to build the pseudo header. Here is an example:
```
# Pseudo header fields
src_address = socket.inet_aton(src_ip)
dst_address = socket.inet_aton(dst_ip)
reserved = 0
protocol = socket.IPPROTO_TCP
tcp_length = len(tcp_hdr) + len(user_data)
```

- After the variables are created for the pseudo header, we need to pack the header in the proper format using the order and byte values previously stated. Here is an example:
```
# Pack the pseudo header and combine with user data
ps_hdr = pack('!4s4sBBH', src_address, dst_address, reserved, protocol, tcp_length)
ps_hdr = ps_hdr + tcp_hdr + user_data
```

- As you can see, pack from the struct module is setting the format to network order with ! and is matching the byte sizes we stated above before putting the variables in order.
- Now that the pseudo header fields have been packed, we will have to create a function to calculate the checksum before we can call on it. Here is an example:
```
def checksum(data):
        if len(data) % 2 != 0:
                data += b'\0'
        res = sum(array.array("H", data))
        res = (res >> 16) + (res & 0xffff)
        res += res >> 16
        return (~res) & 0xffff
```

- The checksum is evaluating on each part of the combined pseudo header, tcp header, and user data after it is converted into binary.
  - Every 32 bit word is split into 16 bits and the binary values are added together.
  - Once this is complete, you have to invert the binary value to get the ones complement.
- Next we will call the checksum function with the combined pseudo header as the object and repack the header with . Here is an example:
```
tcp_chk = checksum(ps_hdr)

# Pack the tcp header to fill in the correct checksum - remember checksum is NOT in network byte order
tcp_hdr = pack('!HHLLBBH', tcp_src, tcp_dst, tcp_seq, tcp_ack_seq, tcp_off_res, tcp_flags, tcp_win) + pack('H', tcp_chk) + pack('!H', tcp_urg_ptr)
```

- Then you can combine the headers with user data and send the packet to the destination as we have previously.
```
# Combine all of the headers and the user data
packet = ip_header + tcp_hdr + user_data

# Send the packet
s.sendto(packet, (dst_ip, 0))
```

- Finally, we call the socket object [sendto([bytes,[address(hostaddr, port)](https://docs.python.org/3/library/socket.html#socket.socket.sendto)])] where bytes is the combination of ip_header , tcp_hdr and user_data variables, and address is the tuple for host address and port. Since we aren’t telling it to go to a specific port, but to rely on the packet information attached, the third variable in the tuple will stay 0.

Now you can watch wireshark or tcpdump -vX to see your packet go across with your message appended and the correct checksum. You should see the three-way handshake start with syn, then syn-ack, but close with a reset since we are not attempting to fully establish a connection.
