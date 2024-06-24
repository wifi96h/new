# Allow New and Established traffic to/from via SSH, TELNET, and RDP
sudo iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 23 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 3389 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
sudo iptables -A OUTPUT -p tcp --sport 3389 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
sudo iptables -A OUTPUT -p tcp --sport 23 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
sudo iptables -A OUTPUT -p tcp --sport 22 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT

# Change the Default Policy in the Filter Table for the INPUT, OUTPUT, and FORWARD chains to DROP
sudo iptables -P INPUT DROP
sudo iptables -P OUTPUT DROP
sudo iptables -P FORWARD DROP

# Allow ping (ICMP) requests (and reply) to and from the Pivot.
sudo iptables -A INPUT -p icmp --icmp-type 0 -j ACCEPT
sudo iptables -A INPUT -p icmp --icmp-type 8 -j ACCEPT
sudo iptables -A OUTPUT -p icmp --icmp-type 8 -j ACCEPT
sudo iptables -A OUTPUT -p icmp --icmp-type 0 -j ACCEPT

# Allow ports 6579 and 4444 for both udp and tcp traffic
sudo iptables -A INPUT -p tcp -m multiport --ports 4444,6579 -j ACCEPT
sudo iptables -A OUTPUT -p tcp -m multiport --ports 4444,6579 -j ACCEPT
sudo iptables -A INPUT -p udp -m multiport --ports 4444,6579 -j ACCEPT
sudo iptables -A OUTPUT -p udp -m multiport --ports 4444,6579 -j ACCEPT

# Allow New and Established traffic to/from via HTTP
sudo iptables -A INPUT -p tcp --dport 80 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
sudo iptables -A OUTPUT -p tcp --sport 80 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT

netcat -l -p 9001

--or--
# Allow New and Established traffic to/from via SSH, TELNET, and RDP
sudo iptables -A INPUT -p tcp -m multiport --ports 22,23,80,3389 -m state --state NEW,ESTABLISHED -j ACCEPT
sudo iptables -A OUTPUT -p tcp -m multiport --ports 22,23,80,3389 -m state --state NEW,ESTABLISHED -j ACCEPT

# Change the Default Policy in the Filter Table for the INPUT, OUTPUT, and FORWARD chains to DROP
sudo iptables -P INPUT DROP
sudo iptables -P OUTPUT DROP
sudo iptables -P FORWARD DROP

# Allow ping (ICMP) requests (and reply) to and from the Pivot.
sudo iptables -A INPUT -s 10.10.0.40 -p icmp --icmp-type 0 -j ACCEPT
sudo iptables -A INPUT -s 10.10.0.40 -p icmp --icmp-type 8 -j ACCEPT
sudo iptables -A OUTPUT -d 10.10.0.40 -p icmp --icmp-type 8 -j ACCEPT
sudo iptables -A OUTPUT -d 10.10.0.40 -p icmp --icmp-type 0 -j ACCEPT

# Allow ports 6579 and 4444 for both udp and tcp traffic
sudo iptables -A INPUT -p tcp -m multiport --ports 4444,6579 -j ACCEPT
sudo iptables -A OUTPUT -p tcp -m multiport --ports 4444,6579 -j ACCEPT
sudo iptables -A INPUT -p udp -m multiport --ports 4444,6579 -j ACCEPT
sudo iptables -A OUTPUT -p udp -m multiport --ports 4444,6579 -j ACCEPT

# Allow New and Established traffic to/from via HTTP
# sudo iptables -A INPUT -p tcp --dport 80 -m state --state NEW,ESTABLISHED -j ACCEPT
# sudo iptables -A OUTPUT -p tcp --sport 80 -m state --state NEW,ESTABLISHED -j ACCEPT


nc -l -p 9001
-------------------------------------------------------

# Allow New and Established traffic to/from via SSH, TELNET, and RDP
sudo iptables -A INPUT -p tcp -m multiport --ports 22,23,80,3389 -m state --state NEW,ESTABLISHED -j ACCEPT
sudo iptables -A OUTPUT -p tcp -m multiport --ports 22,23,80,3389 -m state --state NEW,ESTABLISHED -j ACCEPT

# Change the Default Policy in the Filter Table for the INPUT, OUTPUT, and FORWARD chains to DROP
sudo iptables -P INPUT DROP
sudo iptables -P OUTPUT DROP
sudo iptables -P FORWARD DROP

# Allow New and Established traffic to/from via HTTP

---------------------------------------------------

NFT
# Create input and output base chains with:
  # Hooks
  # Priority of 0
  # Policy as Accept

# Allow New and Established traffic to/from via SSH, TELNET, and RDP

# Change your chains to now have a policy of Drop

# Allow ping (ICMP) requests (and reply) to and from the Pivot.

# Allow ports 5050 and 5150 for both udp and tcp traffic to/from

# Allow New and Established traffic to/from via HTTP
