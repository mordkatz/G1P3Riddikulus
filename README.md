Project 3 (Ridikulus Router)
=============================

The following project establishes a simple router with a static routing table which handles Ethernet frames, ARP packets, IPv4 packets, and ICMP packets. It is capable of forwarding as well as creating new frames, the client is able to properly ping all servers with the proper TTLs, and only the correct ARP requests are responded to. The project uses a combination of mininet and vagrant in order to test the connection between the router and client.
We were not able to establish tracerouting as we ran into various problems with the established code.

## Libraries
- Mininet
- Vagrant

## Project Members
- **Mordechai Katz** | 6198722

Set up testing environment, worked on returning ARP replies, forwarding packets, and handeling ICMP process to self. 
- **Andrew Van Ryn** | 2432461

Worked on handeling IPv4 packets, ARP requests, and ARP cache
- **Jonathan Zamora** | 6122352

Helped with the general logic of the code, helped cleanup some of the code, worked together to fix IPv4 problem.
