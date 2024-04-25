#!/usr/bin/env python3

'''
Author: WO1 Tony Ruppert
Class: 24-002 WOBC
Created Date: 25Apr24
'''

import sys

def check_special(password):
    special_characters = "!@#$%^&*()-+?_=,<>/"
    if any(c in special_characters for c in password):
            return True
    
def check_num(password):
     return any(char.isdigit() for char in inputString)

def password_checker():
    try:
        password = input('Enter your password: ')
        if password.count() < 14:
            print('Password must be at least 14 characters long. Please try again.')
            continue
        
    except KeyboardInterrupt as e:
        sys.exit(1)    
        
        
