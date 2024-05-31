# What is the domain portion of the following SID: S-1-5-21-1004336348-1177238915-682003330-1000
21-1004336348-1177238915-682003330

# What PowerShell command will allow you to search Active Directory accounts for expired accounts without having to create a filter?
search-adaccount

# Find the expired accounts that aren't disabled. List the last names in Alphabetical Order, separated with a comma, and no space between.
search-adaccount -accountexpired | select-object name, distinguishedname

# Find the unprofessional email addresses. List the email's domain.
Get-ADUser -filter * -properties name, EmailAddress | Select Name, EmailAddress | where-object -notlike '*@mail.mil'

# The flag is the unprofessionally-named file located somewhere on the Warrior Share.
net use * "\\file-server\warrior share"
ls -r z:\

# The flag is the name of the user who is requesting modified access rights.
scp 'z:\Brigade HQ\CMD GRP\lulz.pdf' andy.dwyer@10.8.0.2:c:\users\andy.dwyer\desktop\lulz.pdf
get-aduser -filter * -properties name,telephonenumber | select-object name,telephonenumber | where-object telephonenumber -match '336-6754'

# Find the accounts that contain unprofessional information in the description.
Get-ADUser -filter * -properties name, Description | Select Name, Description

# Find the following three accounts:    two accounts with passwords that never expire NOT andy.dwyer    one account that has its password stored using reversible encryption
Get-ADUser -filter * -properties name, PasswordNeverExpires, AllowReversiblePasswordEncryption | Select Name, PasswordNeverExpires, AllowReversiblePasswordEncryption

# The flag is the name of the file containing PII on the Warrior Share.
ls -r z:\

# Find the short name of the domain in which this server is a part of.
get-addomain

# What is the RID of the krbtgt account.
get-aduser -identity krbtgt

# How many users are members of the Domain Admins group?
get-adgroupmember -identity 'domain admins'

# How many total users are members of the Domain Admins group?
(Get-ADGroupMember -Identity 'Domain Admin' -Recursive).count
