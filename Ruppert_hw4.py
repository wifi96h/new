#!/usr/bin/env python3

'''
Author: WO1 Tony Ruppert
Class: 24-002 WOBC
Py_Version: 3.8
Created_Date: 30Apr24
'''

'''
Create program that:

    Reads a filename from the command line.
    Determines the most common letter in the file that is not the white space characters, and prints what it is and how many times it occurs.  Use the format " is the most common letter. It occurs _ times."  Replace _ with the appropriate letter (uppercase) and number. Case is important.
    Determines what percentage of the number of words in the file is the word "the"; print the integer that is closest to this percentage, rounding down.  Ignore capitalization: "The" and "the" are the same word.
    Writes the first ten words of the file (as determined by whitespace) to a new file named "ten_words.txt".  Assume the file will be written to the same directory where your program is located. 
'''

# sys.argv
import sys
import re

with open(sys.argv[1]) as file:
    text = file.read()

# removes special characters
clean_text = re.sub(r"[^\w\s]", '', text)

# places clean_text into list
text_list = clean_text.split()
word_count = len(text_list)

# count characters in string that is not white space
freq = {}
for char in clean_text:
    if char.isalpha():
        if char in freq:
            freq[char] += 1
        else:
            freq[char] = 1
top_letter = max(freq, key=freq.get)

print(f'{top_letter} is the most common letter. It occurs {clean_text.count(top_letter)} times.')

# counts number of times 'the' occurs in file
the_count = 0
for word in map(str.lower, text_list):
    if word == 'the':
        the_count += 1

# determine the percentage of the words in file == 'the'
the_perct = the_count / word_count

# print times 'the' occurs in text
print(f'\'The\' is {the_count} of {word_count} or {the_perct:.2%}')

# writes first ten words of file to a new file named 'ten_words.txt'
with open('ten_words.txt','w') as ten_words:
    writing = ' '.join(text_list[:10])
    ten_words.write(writing)
