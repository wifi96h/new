# Parse all of the IP addresses from the file using XPATH queries
xpath -q -e //address/@addr /home/garviel/output.xml | md5sum

# Select all of the IP addresses and ports using a single XPATH Union Statement
xpath -q -e '//address/@addr | //port/@portid' /home/garviel/output.xml | md5sum

# Hash the pretty-printed file with md5sum for the flag
jq . conn.log | md5sum

# Use jq to locate and count the unique originating endpoint IP addresses in the file. Enter the number of unique originating IP addresses as the flag.
jq '."id.orig_h"' conn.log | sort -u | wc -l

# Use jq to locate and count connections where the destination IP sent more than 40 bytes to the source IP.
jq 'select(.resp_ip_bytes > 40 ) ."id.orig_h"' conn.log | wc -l 

