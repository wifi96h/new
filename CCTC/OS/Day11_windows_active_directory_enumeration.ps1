# What is the domain portion of the following SID: S-1-5-21-1004336348-1177238915-682003330-1000
21-1004336348-1177238915-682003330

# What PowerShell command will allow you to search Active Directory accounts for expired accounts without having to create a filter?
search-adaccount

# Find the expired accounts that aren't disabled. List the last names in Alphabetical Order, separated with a comma, and no space between.
search-adaccount -accountexpired | select-object name, distinguishedname

# Find the unprofessional email addresses. List the email's domain.
get-aduser -properties *
