#!/usr/bin/env python3

'''
Author: WO1 Tony Ruppert
Class: 24-002 WOBC
Py_Version: 3.8
Created_Date: 1May24
'''

'''
Write a python program that takes a file name as a command line argument that will:

1. Counts the number of lines ending in a '?'. You will print that value, followed by all of the sentences.
2. Find all phone numbers and print them to the screen. Format for phone numbers should all be 706-123-4567.
3. Find all ".com" email addresses in the file. Print their username and the email domain. Format should be: kirk.carter uses gmail.com
'''

from sys import argv
import re

'''
open dictated file and extract contents to string and list
'''
with open(argv[1]) as file:
    text = file.read()
    
text_list_by_line = text.split('\n')

'''
1. Counts the number of lines ending in a '?'. Print that value, followed by all of the sentences.
'''
char_freq = list(filter(re.compile(r'.*\?$').match, text_list_by_line))

print(f'There are {len(char_freq)} sentances ending with a \'?\'.\n')
print('\n'.join(char_freq))

'''
2. Find all phone numbers and print them to the screen. Format for phone numbers should all be 706-123-4567.
'''
phone_list = list(filter(re.compile(r'\d\d\d-\d\d\d-\d\d\d\d$').match, text_list_by_line))

print('\n')
print('\n'.join(phone_list))

'''
3. Find all ".com" email addresses in the file. Print their username and the email domain. Format should be: kirk.carter uses gmail.com
'''
user_domain = dict([item.split("@") for item in ','.join(list(filter(re.compile(r'.*\.com$').match, text_list_by_line))).split(",")])

print('\n')
for k,v in user_domain.items():
    print(f'{k} uses {v}')
