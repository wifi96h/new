# Donovian Database Exploitation (DWDBE)
XX Dec 2026
Start Time: 1300
Duration: 4 hours

Type of Operation: Cyberspace Exploitation (C-E)

Objective: Maneuver through network, identify and gather intelligence from the Donovian Logistics Agency database.

Tools/Techniques: All connections will be established through web browser to donovian-nla. SSH masquerade to Donovian_Webserver with provide credentials. Ports in use will be dependent on target location and are subject to change. Web exploitation techniques are limited to SQLi injections. Network scanning tools/technique usage is at the discretion of student.

Scenario Credentials: FLAG = 5QL1nj3ct5t@rt0F@ct1v1ty

Prior Approvals: SQLi injects through web browser. Creation of database administrator account if directed to. Any connection to donovian-nla other than HTTP/HTTPs is NOT approved.

## Scheme of Maneuver:
>Jump Box
->T1:10.100.28.48

## Target Section:

T1
Hostname: donovian-nla
IP: 10.100.28.48
OS: unknown
Creds:unknown
Last Known SSH Port: unknown
Last Known HTTP Port: 80
PSP: Unknown
Malware: Unknown
Action: Conduct approved SQLi Exploitation techniques to collect intelligence.

categories	id	3.00
categories	name	3.00
categories	description	3.00

members	id	3.00
members	username	3.00
members	password	3.00
members	first_name	3.00
members	last_name	3.00
members	email	3.00
members	permission	3.00

orderlines	id	3.00
orderlines	quantity	3.00
orderlines	product	3.00
orderlines	order	3.00

orders	id	3.00
orders	date	3.00
orders	member	3.00

payments	id	3.00
payments	creditcard_number	3.00
payments	date	3.00
payments	order	3.00

permissions	id	3.00
permissions	level	3.00
permissions	name	3.00
permissions	description	3.00

products	id	3.00
products	name	3.00
products	description	3.00
products	price	3.00
products	qty_left	3.00
products	category	3.00

share4	id	3.00
share4	comment	3.00
share4	mime	3.00
share4	data	3.00

## username, password
Boss	CdOETQHZoOD0hPvReTMr	3.00
Maverick	turn&burn	3.00
phreak	pwd	3.00
Susan	flowers99	3.00
TW	imAPlaya	3.00
1-2-3-4	sayULuvM3	3.00
rich_kid	1M$	3.00
p0pStar	thrilla	3.00
Joe	vato	3.00
	flag:	3.00
