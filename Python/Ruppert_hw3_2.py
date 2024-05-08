#!/usr/bin/env python3

'''
Author: WO1 Tony Ruppert
Class: 24-002 WOBC
Created Date: 26Apr24
'''


'''
addresses = (
'192.168.254.1',
'867.53.0.9',
'192.168.254.1',
'255.255.255.257',
'10.10.100.1',
'172.16.0.1',
'192.168.254.1',
'10.10.100.2'
)

Write a program that uses the above tuple of IP addresses to:

* Print a dictionary with each IP address as the key and the count of occurences of each IP address in the tuple as its value.
Evalute each IP address for validity.
* Print a list of all valid IP address occurences in order of appearance.
* Print a set of all unique valid IP addresses.
* Print a sorted set of all unique valid IP addresses. 
'''

addresses = (
'192.168.254.1',
'867.53.0.9',
'192.168.254.1',
'255.255.255.257',
'10.10.100.1',
'172.16.0.1',
'192.168.254.1',
'10.10.100.2'
)


''' Print a dictionary with each IP address as the key and the count of occurences of each IP address in the tuple as its value. '''
ip_dict = {}
for address in addresses:
    ip_dict.update({address: addresses.count(address)})
print(ip_dict)


''' Evalute each IP address for validity. '''
valid_ips = []

# place addresses in list
for address in addresses:
    addr = address.split('.')
    if addr > ['0', '0', '0', '0'] and addr <= ['255', '255', '255', '255']:
        valid_ips.append(address)


''' Print a list of all valid IP address occurences in order of appearance. '''
print(valid_ips)

''' Print a set of all unique valid IP addresses. '''
unique_ips = []

for ip in valid_ips:
    if ip not in unique_ips:
        unique_ips.append(ip)

print(unique_ips)

''' Print a sorted set of all unique valid IP addresses. '''
print(sorted(unique_ips))
