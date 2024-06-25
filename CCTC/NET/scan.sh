#! /bin/bash
echo "Enter network address: "
read net
echo "Enter starting host range: "
read start
echo "Enter ending host range: "
read end
echo "Enter ports space-delimited: "
read ports

for ((i=$start; $i<=$end; i++))

do
    nc -nvzw1 $net.$i $ports 2>&1 | grep -E 'succ|open'
done

# (-v) running verbosely (-v on Linux, -vv on Windows),
# (-n) not resolving names. numeric only IP(no D.S)
# (-z) without sending any data. zero-I/O mode(used for scanning)
# (-w1) waiting no more than 1second for a connection to occur
# (2>&1) redirect STDERR to STDOUT. Results of scan are errors and need to redirect to output to grep
# ( | grep -E 'succ|open') for Debian/Ubuntu to display only open connections
