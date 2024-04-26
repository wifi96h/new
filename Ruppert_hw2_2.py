#!/usr/bin/env python3

'''
Author: WO1 Tony Ruppert
Class: 24-002 WOBC
Created Date: 25Apr24
'''

import sys

# Global variables

    
# Script intro
print('Passwords are great, but you should be safe with them.\nPlease make sure your password includes special characters, digits, uppercase letters, and lowercase letters.')

# Begin while loop to try for error handling.
while True:
    try:
        missing_chars = []
        special_char = False
        digit = False
        uppercase = False
        lowercase = False
        # User input
        user_input = input('Enter your password, or type Q to quit: ')
        
        # Look for character's characteristics to see if they validate
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
        
        # Verify if user wants to quit
        if user_input.lower() == 'q':
            sys.exit(1)
        
        # Verify if password is long enough
        elif len(user_input) < 14:
            print('\nYour password must be at least 14 characters long.')
            continue
        
        # Pull validation to see if its True; if True, break to end
        elif validation:
            break
        
        # Look through and build list of missing character sets; notify user of missing sets
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
            continue
    
    # input handling        
    except KeyboardInterrupt as e:
        sys.exit(1)
            
# When successful, notify user and exit            
print(f'Your password, \'{user_input}\', is secure.')
sys.exit(1)        
