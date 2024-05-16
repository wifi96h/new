# To complete this challenge, find the description of the Lego Land service.
Get-wmiobject win32_service | where-object -name -eq legoland | select *

# In the CTF folder on the CTF User's Desktop, count the number of words in words2.txt.
get-content words2.txt | measure-object -words

# Count the number of files in the Videos folder in the CTF user's home directory.
get-childitem .\Videos | measure-object 

# Find the only line that makes the two files in the CTF user's Downloads folder different.
Compare-Object -ReferenceObject (Get-Content -Path file1.txt) -DifferenceObject (Get-Content -Path file2.txt)

# The password is the 21st line from the top, in ASCII alphabetically-sorted, descending order of the words.txt file.


# Count the number of unique words in words.txt
get-content words.txt | measure-object -words | select-object -unique

# Count the number of times, case-insensitive, gaab is listed in words.txt **Note: File Location - C:\Users\CTF\Desktop\CTF
(select-string -path 'words.txt' -pattern 'gaab'  -allmatches).matches.count

# Count the number of words, case-insensitive, with either a or z in a word, in the words.txt file
(select-string -path 'words.txt' -pattern '[az]'  -allmatches).matches.count

# Count the number of lines, case-insensitive, that az appears in the words.txt file
(select-string -path 'words.txt' -pattern 'az'  -allmatches).matches.count

# Use a PowerShell loop to unzip the Omega file 1,000 times and read what is inside.
for ($i=1000; $i -gt 0; $i--) {expand-archive -path omega$i.zip -destination .}

<# Count the number of words in words.txt that meet the following criteria:

a appears at least twice consecutively
and is followed immediately by any of the letters a through g
Note: File Location - C:\Users\CTF\Desktop\CTF
Example: aac...aaa...
#>
(select-string -path 'words.txt' -pattern 'aa[a-g]'  -allmatches).matches.count
