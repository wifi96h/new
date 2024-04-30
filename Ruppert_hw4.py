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



def file_importer():
    # readlines file to put into lists
    with open(sys.argv[-1]) as file:
        file_content = file.readlines()
    
        # strip out '\n' characters and add to modified list
        mod_file_content = []
        for i in file_content:
            mod_file_content.append(i.strip())
        
        #count words in file
        word_count = len(mod_file_content)
        return mod_file_content, word_count

        
def count_char(mod_file_content):

    # count characters in modified list that is not white space characters
    largest_num = 0
    for char in mod_file_content:
        if char.isalnum():
            if mod_file_content.count(char) > largest_num:
                largest_num = mod_file_content.count(char)
        
    # print what most common letter is and how many times it occurs; 
    print(f'{char} is the most common letter. It occurs {largest_num} times.')


def count_the(mod_file_content, word_count):
    # count the number of times 'the' occurs
    the_count = 0
    for word in (mod_file_content):
        if word.lower() == 'the':
            the_count += 1

    # determine the percentage of the words in file == 'the'
    the_perct = the_count / word_count

    # print times 'the' occurs in text
    print(f'\'The\' is {the_count} of {word_count} or {the_perct:.2%}')


def new_file_writer(mod_file_content):
    # write first ten words of the file to a new file named 'ten_words.txt'
    with open('ten_words.txt','w') as ten_words:
        ten_words.write(mod_file_content[0:10])


def __main__():
    mod_file_content, word_count = file_importer()
    count_char(mod_file_content)
    count_the(mod_file_content, word_count)
    new_file_writer(mod_file_content)

__main__()