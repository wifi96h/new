'''
print('I WILL SCORE 100 ON THIS TEST')
'''

'''
def check(s):
    digit = False
    uppercase = False
    lowercase = False

    for char in s:
        if char.isdigit():
            digit = True
        elif char.isupper():
            uppercase = True
        elif char.islower():
            lowercase = True

    if all([digit, uppercase, lowercase]):
        print('Valid string')
    else:
        print('Not valid')
'''


'''
def combo(li): 
    # li = [i, j, k]
    # need to cycle through all three numbers in list where same numbers do not appear in same sequence
    for i in range(3):
        for j in range(3):
            for k in range(3):
                # when [0] != [1] != [2], print the combinations
                if (i!=j and j!=k and i!=k):
                    print(li[i], li[j], li[k])'''

'''
string = 'How many Uppercase Letters are in this String? How many Lowercase Letters are in this String?'
def count(string):
    U = 0
    L = 0
    for i in string:
        if i.isupper():
            U += 1
        if i.islower():
            L += 1
    print(f'Number of lowercase is: {L}')
    print(f'Number of uppercase is: {U}')
'''

'''
string = "This is sentence one. This is sentence two. This is sentence three"
def split_period(string):
    print(string.split('.'))
'''

'''
def types(li):
    string_list = []
    for l in range(len(li)):
        if type(li[l]) == type('string'):
            string_list.append(li[l])

    print(f'String: {string_list}')
'''
