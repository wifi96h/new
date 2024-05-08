# Data types and variables
# Note: variables are case sensitive
var = 'string'
Var = 12
print(var, Var)

# Strings ar enclosed with single or double quotes
# Bool evaluates to true or false
# Float evaluates to a decimal place
# Int is any whole number

# Note: adding a float and an int will return a float
print(3.0+2) # -> 5.0

# # -----------------------------------------------

# # String manipulation (immutable)
s = 'this is a string'
print(s.capitalize())
print(s)

# Changing the string
s = s.upper()
print(s)

# Index returns an error if char not found,
# find returns -1
print(s.find('z'))

# is will evaluate to true or false
print(s.isalnum())

# String slicing
# start stop step
print(s[::-1])

# replace
# replace(old, new)
print(s.replace(" ", "-"))


# # ----------------------------------------------

# List
# Converts a string to a list using split()
new_string = 'Convert this to a string'
now_list = new_string.split()
print(now_list)

# appending to a list
now_list.append('or')
now_list.insert(6, "list?")
print(now_list)
now_list.pop(1)
print(now_list)

# Convert back to a string
print(' '.join(now_list))

# # -----------------------------------------

# Dictionaries

di = {'key1' : 'values', 'key2' : 'not', 'key3' : 'unique'}

for keys, values in di.items():
    print(keys, values)

pitem = di.popitem()
print(pitem)

di.update({"key3" : "Unique"})
print(di)

# # -----------------------------------------

# Sets
li = [1,1,1,1,2,2,2,3,3,3]
print(list(set(li)))

# # ----------------------------------------

# if elif else

# will evaluate if a condition is true
# you can have 0 or more elif and else statements

user = int(input('enter a number: '))
if type(user) is str:
    print('string')
elif type(user) is int:
    print('int')
elif type(user) is float:
    print('float')
else:
    print('bool')

# for loops
# range inclusive, exclusive
# range optional step
for i in range(1, 11):
    print(i, end=' ')

# start is defaulted to 0
# enumerate(iterable, start)
s = 'This is a string'
for i in enumerate(s):
    print(i)

count = 1
while count <= 10:
    print(count)
    count += 1

# # ---------------------------------------

# File I/O
# With closes a file automatically
with open('file.txt', 'w') as file:
    file.write('hello world')

# # -------------------------------------

# Functions
def function_1(para):
    print(para)
function_1(para=[2,1.0,'string'])

def function_2(para):
    return para
function_2(para=[1,2.0,'string'])

# # -----------------------------------------

# regex

import re
the = re.compile(r'the')
match_the = re.search(the, 'find the the\'s int he sentances')
print(match_the.group())
print(re.findall(the, 'find the the\'s in the sentances'))
