# Allow New and Established traffic to/from via SSH, TELNET, and RDP
sudo iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 23 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 3389 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
sudo iptables -A OUTPUT -p tcp --sport 3389 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
sudo iptables -A OUTPUT -p tcp --sport 23 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
sudo iptables -A OUTPUT -p tcp --sport 22 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT

# Change the Default Policy in the Filter Table for the INPUT, OUTPUT, and FORWARD chains to DROP
sudo iptables -P INPUT DROP

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
