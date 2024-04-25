#!/usr/bin/env python3

'''
Author: WO1 Tony Ruppert
Class: 24-002 WOBC
Created Date: 24Apr24
'''
import datetime

# Gather user information and conduct data validation and error handling
while True:
    try:
        age = int(input("Please enter your age: "))
        if age < 0:
            print('The age provided is not an acceptable age. Please try again.')
            continue
        else:
            break
    except ValueError:
        print('Oops! That was not a valid number. Please try again.')
    except KeyboardInterrupt:
        quit()

while True:
    try:
        f_name = input("Please enter your first name: ").lower()
        if f_name == '':
            print('No name was detected. Please try again.')
            continue
        else:
            break
    except KeyboardInterrupt:
        quit()

while True:
    try:
        l_name = input("Please enter your last name: ").lower()
        if l_name == '':
            print('No name was detected. Please try again.')
            continue
        else:
            break
    except KeyboardInterrupt:
        quit()


'''
1. A sentence that states the user's birthyear.
2. 3 possible username formats based on their first name and last name.
3. 2 possible years the user might have graduated high school.
4. 3 possible "@gmail.com" email addresses based on the previous identified username formats.
5. Percentage of life completed based on life expectancy of 73.4.
'''

# Get year script ran
today = datetime.date.today()
year = today.year

# Get user's (likely) birthyears
b_year =  year - age
b_year2 = b_year - 1

# Get user's possible username formats based on first name and last name

username1 = f_name + '.' + l_name
username2 = f_name[0] + '.' + l_name
username3 = f_name + '.' + l_name[0]

# Get 2 possible years the user may have graduated from high school
# Use age 18 and 17 as possible ages to graduate high school
graduation1 = b_year + 17
graduation2 = b_year + 18

# Get 3 possible "@gmail.com" email addresses based on username formats
email = "@gmail.com"
email1 = username1 + email
email2 = username2 + email
email3 = username3 + email

# Percentage of life completed based on life expectancy of 73.4
life_completed = age / 73.4

print(
    f'Your first name is {f_name.title()}.\n',
    f'Your last name is {l_name.title()}.\n',
    f'Your are {age} year(s) old.\n',
    f'Your birth year is {b_year} or {b_year2}.\n',
    f'Possible usernames are: {username1}, {username2}, {username3}.\n',
    f'You graduated in {graduation1} or {graduation2}.\n',
    f'Your possible email addresses are {email1}, {email2}, or {email3}.\n',
    f'You\'ve lived {life_completed:.2%} of your life.',
)
