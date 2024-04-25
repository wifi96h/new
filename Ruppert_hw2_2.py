#!/usr/bin/env python3

'''
Author: WO1 Tony Ruppert
Class: 24-002 WOBC
Created Date: 25Apr24
'''

import sys

missing_chars = []
special_char = False
digit = False
uppercase = False
lowercase = False
    

print('Passwords are great, but you should be safe with them.\nPlease make sure your password includes special characters, digits, uppercase letters, and lowercase letters.')
while True:
    try:
        user_input = input('Enter your password, or type Q to quit: ')
        for char in user_input:
            if not char.isalnum():
                special_char = True
            elif char.isdigit():
                digit = True
            elif char.isupper():
                uppercase = True
            elif char.islower():
                lowercase = True
        validation = special_char and digit and uppercase and lowercase
        
        if user_input.lower() == 'q':
            sys.exit(1)
        
        elif len(user_input) < 14:
            print('\nYour password must be at least 14 characters long.')
            sys.exit(1)
        
        elif validation:
            break
        
        else:
            if not special_char:
                missing_chars.append('special character')
            if not digit:
                missing_chars.append('digit')
            if not uppercase:
                missing_chars.append('uppercase letter')
            if not lowercase:
                missing_chars.append('lowercase letter')
            print(f"You are missing {len(missing_chars)} character sets. Please add a {', '.join(missing_chars)} to your password.")
            sys.exit(1)
            
    except KeyboardInterrupt as e:
        sys.exit(1)
            
            
print(f'Your password, \'{user_input}\', is secure.')
sys.exit(1)        