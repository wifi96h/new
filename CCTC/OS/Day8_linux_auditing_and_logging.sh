# Parse all of the IP addresses from the file using XPATH queries
xpath -q -e //address/@addr /home/garviel/output.xml | md5sum

# Select all of the IP addresses and ports using a single XPATH Union Statement
xpath -q -e '//address/@addr | //port/@portid' /home/garviel/output.xml | md5sum

# Hash the pretty-printed file with md5sum for the flag
jq . conn.log | md5sum
