#!/usr/bin/env python3

'''
Author: WO1 Tony Ruppert
Class: 24-002 WOBC
Created Date: 25Apr24
'''

import sys

def check_special(password):
    # Check entered password for any special characters and return either True or False
    special_characters = "!@#$%^&*()-+?_=,<>/"
    return any(c in special_characters for c in password)
    
def check_num(password):
    # Check entered password for any digits and return either True or False
    return any(char.isdigit() for char in password)

def check_upper(password):
    # Check entered password for any uppercase characters and return either True or False
    return any(char.isupper() for char in password)

def check_lower(password):
    # Check entered password for any lowercase characters and return either True or False
    return any(char.islower() for char in password)

def check_fail():
    # Take results of check_lower, check_special, check_upper, check_num and place into a list
    failed = []
    checklist = [check_upper(), check_lower(), check_num(), check_special()]
    validate = all(checklist)
    return validate


    # Check for any False returns and append them to empty list named "failed"
    for check in checklist:
        if not check:
            failed = failed.append(check)
    
    # Count the number of elements in failed list
    num_of_failed = failed.count()
    return num_of_failed 
        

def password_checker():
    # Create while loop for the script to perform functions
    while True:
        try:
            # User submits password
            password = input('Enter your password, or type Q to quit: ')
            
            # If user wants to exit, exits cordially
            if password.lower() == 'q':
                sys.exit(1)
                
            # Validate password is meets length requirements.
            elif password.count() < 14:
                print('Password must be at least 14 characters long. Please try again.')
                continue
            
            # Conducts validation for special characters, numbers, uppercase, and lowercase requirements; breaks out of loop if True
            elif check_fail().validate:
                break
            
            # Returns number of missing character sets for user to try a new password
            else:
                print(f"You are missing {num_of_failed} character sets. Please try again.")
                continue
        
        # Conducts keyboard interruption of script
        except KeyboardInterrupt as e:
            sys.exit(1)
    
    # Returns accepted password to user and exits script        
    print(f'Your password, \'{password}\', is secure.')
    sys.exit(1)


# Runs password checker
password_checker()