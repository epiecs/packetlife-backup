# Packetlife backup
## Cheat sheets

- [BGP](cheat_sheets/BGP.pdf)
- [Cisco_IOS_Versions](cheat_sheets/Cisco_IOS_Versions.pdf)
- [EIGRP](cheat_sheets/EIGRP.pdf)
- [First_Hop_Redundancy](cheat_sheets/First_Hop_Redundancy.pdf)
- [Frame_Mode_MPLS](cheat_sheets/Frame_Mode_MPLS.pdf)
- [IEEE_802.11_WLAN](cheat_sheets/IEEE_802.11_WLAN.pdf)
- [IEEE_802.1X](cheat_sheets/IEEE_802.1X.pdf)
- [IOS_IPv4_Access_Lists](cheat_sheets/IOS_IPv4_Access_Lists.pdf)
- [IOS_Interior_Routing_Protocols](cheat_sheets/IOS_Interior_Routing_Protocols.pdf)
- [IOS_Zone-Based_Firewall](cheat_sheets/IOS_Zone-Based_Firewall.pdf)
- [IPsec](cheat_sheets/IPsec.pdf)
- [IPv4_Multicast](cheat_sheets/IPv4_Multicast.pdf)
- [IPv4_Subnetting](cheat_sheets/IPv4_Subnetting.pdf)
- [IPv6](cheat_sheets/IPv6.pdf)
- [IS-IS](cheat_sheets/IS-IS.pdf)
- [Markdown](cheat_sheets/Markdown.pdf)
- [MediaWiki](cheat_sheets/MediaWiki.pdf)
- [NAT](cheat_sheets/NAT.pdf)
- [OSPF](cheat_sheets/OSPF.pdf)
- [PPP](cheat_sheets/PPP.pdf)
- [QoS](cheat_sheets/QoS.pdf)
- [RIP](cheat_sheets/RIP.pdf)
- [Spanning_Tree](cheat_sheets/Spanning_Tree.pdf)
- [VLANs](cheat_sheets/VLANs.pdf)
- [VOIP_Basics](cheat_sheets/VOIP_Basics.pdf)
- [Wireshark_Display_Filters](cheat_sheets/Wireshark_Display_Filters.pdf)
- [common_ports](cheat_sheets/common_ports.pdf)
- [physical_terminations](cheat_sheets/physical_terminations.pdf)
- [scapy](cheat_sheets/scapy.pdf)
- [tcpdump](cheat_sheets/tcpdump.pdf)

## Packet captures

### Tags

[AH](#ah) - [ARP](#arp) - [Auto-RP](#auto-rp) - [BGP](#bgp) - [BOOTP](#bootp) - [CDP](#cdp) - [CDPCP](#cdpcp) - [CHAP](#chap) - [DEC_DNA](#dec-dna) - [DHCPV6](#dhcpv6) - [DNS](#dns) - [DTP](#dtp) - [DVMRP](#dvmrp) - [EAP](#eap) - [EAPoL](#eapol) - [EIGRP](#eigrp) - [ESP](#esp) - [Ethernet](#ethernet) - [FC](#fc) - [FCCT](#fcct) - [FCDNS](#fcdns) - [FCELS](#fcels) - [FCOE](#fcoe) - [FIP](#fip) - [Frame Relay](#frame-relay) - [GLBP](#glbp) - [GRE](#gre) - [H225](#h225) - [HDLC](#hdlc) - [HSRP](#hsrp) - [HTTP](#http) - [ICMP](#icmp) - [ICMPv6](#icmpv6) - [IEEE8021AD](#ieee8021ad) - [IGMP](#igmp) - [IP](#ip) - [IPCP](#ipcp) - [IPV6CP](#ipv6cp) - [IPv6](#ipv6) - [ISAKMP](#isakmp) - [ISIS](#isis) - [ISL](#isl) - [L2TP](#l2tp) - [L2TP.L2_SPEC_DEF](#l2tp-l2-spec-def) - [LACP](#lacp) - [LCP](#lcp) - [LDP](#ldp) - [LISP](#lisp) - [LISP-DATA](#lisp-data) - [LLC](#llc) - [LLDP](#lldp) - [LMI](#lmi) - [LOOP](#loop) - [MEDIA](#media) - [MPLS](#mpls) - [MSDP](#msdp) - [NBDGM](#nbdgm) - [NBNS](#nbns) - [NBSS](#nbss) - [NHRP](#nhrp) - [NTP](#ntp) - [OCSP](#ocsp) - [OSPF](#ospf) - [PAGP](#pagp) - [PAP](#pap) - [PIM](#pim) - [PPP](#ppp) - [PPPOED](#pppoed) - [PPPOES](#pppoes) - [PPTP](#pptp) - [Q931](#q931) - [Q933](#q933) - [RADIUS](#radius) - [RIP](#rip) - [SFLOW](#sflow) - [SKINNY](#skinny) - [SLARP](#slarp) - [SMB](#smb) - [SMTP](#smtp) - [SNMP](#snmp) - [SSH](#ssh) - [SSL](#ssl) - [STP](#stp) - [STUN](#stun) - [TACACS+](#tacacs) - [TCP](#tcp) - [TDP](#tdp) - [TEREDO](#teredo) - [TPKT](#tpkt) - [Telnet](#telnet) - [UDLD](#udld) - [UDP](#udp) - [VLAN](#vlan) - [VRRP](#vrrp) - [VTP](#vtp) - [WCCP](#wccp) - [XML](#xml) - 
### Captures

- [3560_CDP.cap](<pcaps/3560_CDP.cap>)

  duration: 120s - packets: 3 - size: 1.2 KB

  tags: [CDP](#cdp) [Ethernet](#ethernet) [LLC](#llc)

  Cisco Discovery Protocol (CDP) advertisements from a Catalyst 3560. Note how much information is offered to a potential attacker.
- [3725_CDP.cap](<pcaps/3725_CDP.cap>)

  duration: n/a - packets: 1 - size: 390 bytes

  tags: [CDP](#cdp) [Ethernet](#ethernet) [LLC](#llc)

  Cisco Discovery Protocol (CDP) from FastEthernet0/0 of a Cisco 3725 router.
- [4-byte_AS_numbers_Full_Support.cap](<pcaps/4-byte_AS_numbers_Full_Support.cap>)

  duration: 56s - packets: 9 - size: 1.2 KB

  tags: [BGP](#bgp) [HDLC](#hdlc) [IP](#ip) [TCP](#tcp)

  Router at 172.16.1.2 (hostname "D", AS 40.1 / 2621441) clears a previous established peering with 172.16.1.1 (hostname "A", AS 10.1 / 655361); They both support 32-bit ASN.
- [4-byte_AS_numbers_Mixed_Scenario.cap](<pcaps/4-byte_AS_numbers_Mixed_Scenario.cap>)

  duration: 60s - packets: 4 - size: 414 bytes

  tags: [BGP](#bgp) [HDLC](#hdlc) [IP](#ip) [TCP](#tcp)

  Router "B" (AS 2) at 172.16.3.2 does not support 4-byte AS numbers, while router "A" (AS 10.1 / 655361) at 172.16.3.1 does.
- [6in4-linklocal-hlimit-less255.pcapng.cap](<pcaps/6in4-linklocal-hlimit-less255.pcapng.cap>)

  duration: n/a - packets: 1 - size: 444 bytes

  tags: [ICMPv6](#icmpv6) [IP](#ip) [IPv6](#ipv6)

  Illegal packet: IPv4 (protocol 41) + IPv6 (hop limit = 100) + ICMPv6 Router Advertisement.  The illegal part is that hop limit of IPv6 neighbor discovery protocol (NDP) packets cannot be less than 255.
- [802.1D_spanning_tree.cap](<pcaps/802.1D_spanning_tree.cap>)

  duration: 26s - packets: 14 - size: 1.1 KB

  tags: [Ethernet](#ethernet) [LLC](#llc) [STP](#stp)

  IEEE 802.1D Spanning Tree Protocol (STP) advertisements sent every two seconds.
- [802.1Q_tunneling.cap](<pcaps/802.1Q_tunneling.cap>)

  duration: 35s - packets: 26 - size: 5.0 KB

  tags: [CDP](#cdp) [Ethernet](#ethernet) [IP](#ip) [LLC](#llc) [VLAN](#vlan)

  CDP
Ethernet
IP
LLC
VLAN
- [802.1X.cap](<pcaps/802.1X.cap>)

  duration: 19s - packets: 7 - size: 498 bytes

  tags: [EAPoL](#eapol) [Ethernet](#ethernet)

  A wired client authenticates to its switch using 802.1x/EAP and MD5 challenge authentication.
- [802.1w_rapid_STP.cap](<pcaps/802.1w_rapid_STP.cap>)

  duration: 56s - packets: 30 - size: 2.2 KB

  tags: [Ethernet](#ethernet) [LLC](#llc) [STP](#stp)

  Rapid Spanning Tree Protocol BPDUs are received from a Catalyst switch after connecting to a port not configured for PortFast. The port transitions through the blocking and learning states before issuing a topology change notification (packet #30) and transitioning to the forwarding state.
- [802_1ad.pcapng.cap](<pcaps/802_1ad.pcapng.cap>)

  duration: n/a - packets: 2 - size: 3.3 KB

  tags: [IEEE8021AD](#ieee8021ad) [IP](#ip) [VLAN](#vlan)

  It's an Packet Capture of a QinQ Packet with an Outer Vlan Ethertype 0x88A4. It is used in Service Provider Bridges
- [Auto-RP.cap](<pcaps/Auto-RP.cap>)

  duration: 239s - packets: 9 - size: 726 bytes

  tags: [Auto-RP](#auto-rp) [Ethernet](#ethernet) [IP](#ip) [UDP](#udp)

  Routers 2 and 3 have been configured as candidate RPs, and multicast RP announcements to 239.0.1.39. Router 1 is the RP. R1 sees the candidate RP announcements from R2 and R3, and designates R3 the RP because it has a higher IP address (3.3.3.3). R1 multicasts the RP mapping to 224.0.1.40. The capture is from the R1-R2 link.
- [BGP_AS_set.cap](<pcaps/BGP_AS_set.cap>)

  duration: 1s - packets: 18 - size: 1.6 KB

  tags: [BGP](#bgp) [Ethernet](#ethernet) [IP](#ip) [TCP](#tcp)

  Packet #15 includes a BGP update containing both an AS sequence and an AS set in its AS path attribute.
- [BGP_MD5.cap](<pcaps/BGP_MD5.cap>)

  duration: 61s - packets: 16 - size: 1.7 KB

  tags: [BGP](#bgp) [Ethernet](#ethernet) [IP](#ip) [TCP](#tcp)

  An EBGP with TCP MD5 authentication enabled
- [BGP_MP_NLRI.cap](<pcaps/BGP_MP_NLRI.cap>)

  duration: 60s - packets: 24 - size: 2.9 KB

  tags: [BGP](#bgp) [Ethernet](#ethernet) [IP](#ip) [IPv6](#ipv6) [TCP](#tcp)

  IPv6 routes are carried as a separate address family inside MP_REACH_NLRI attributes.
- [BGP_hard_reset.cap](<pcaps/BGP_hard_reset.cap>)

  duration: 208s - packets: 32 - size: 3.2 KB

  tags: [BGP](#bgp) [Ethernet](#ethernet) [IP](#ip) [TCP](#tcp)

  A hard reset (clear ip bgp) is performed on R1 for its adjacency with R2. Packet #7 shows R1 sending a packet with the TCP FIN flag set, indicating the connection is to be torn down. The TCP connection is then reestablished and UPDATEs are retransmitted.
- [BGP_notification.cap](<pcaps/BGP_notification.cap>)

  duration: n/a - packets: 9 - size: 764 bytes

  tags: [BGP](#bgp) [Ethernet](#ethernet) [IP](#ip) [TCP](#tcp)

  R1 has been misconfigured to expect R2 to reside in AS 65100. R2 attempts to peer with R1 advertising itself correctly in AS 65200. R1 issues a NOTIFICATION in packet #5 citing a "bad peer AS" error and terminates the TCP connection.
- [BGP_redist.cap](<pcaps/BGP_redist.cap>)

  duration: n/a - packets: 2 - size: 378 bytes

  tags: [BGP](#bgp) [HDLC](#hdlc) [IP](#ip) [MPLS](#mpls) [TCP](#tcp)

  The OSPF metric is preserved and propagated within the MPLS cloud by the MP-BGP MED attribute.
- [BGP_soft_reset.cap](<pcaps/BGP_soft_reset.cap>)

  duration: 180s - packets: 17 - size: 2.0 KB

  tags: [BGP](#bgp) [Ethernet](#ethernet) [IP](#ip) [TCP](#tcp)

  R1 performs a soft bidirectional reset (clear ip bgp soft) on its adjacency with R2. The ROUTE-REFRESH message is visible in packet #7. Note that the TCP connection remains uninterrupted, and neither router views the reset as disruptive.
- [DECnet_Phone.pcap.cap](<pcaps/DECnet_Phone.pcap.cap>)

  duration: 100s - packets: 139 - size: 7.5 KB

  tags: [DEC_DNA](#dec-dna) [Ethernet](#ethernet)

  A DECnet Phone session, using the Linux DECnet stack and a clone/port of the OpenVMS eponymous tool.
- [DHCP.cap](<pcaps/DHCP.cap>)

  duration: 153s - packets: 12 - size: 5.8 KB

  tags: [BOOTP](#bootp) [Ethernet](#ethernet) [IP](#ip) [UDP](#udp)

  R0 is the client and R1 is the DHCP server. Lease time is 1 minute.
- [DHCP_Inter_VLAN.cap](<pcaps/DHCP_Inter_VLAN.cap>)

  duration: n/a - packets: 4 - size: 2.0 KB

  tags: [BOOTP](#bootp) [Ethernet](#ethernet) [IP](#ip) [UDP](#udp)

  R1 is a router-on-a-stick. It receives a DHCP Discover on the trunk interface, it sets the "Relay agent IP address" to the sub-interface's IP address it received the packet on and, finally, it forwards it to the DHCP server. Capture perspective is R1-DHCP server link.
- [DHCP_MessageType 10,11,12 and 13.cap](<pcaps/DHCP_MessageType 10,11,12 and 13.cap>)

  duration: 13s - packets: 6 - size: 1.9 KB

  tags: [BOOTP](#bootp) [Ethernet](#ethernet) [IP](#ip) [UDP](#udp)

  Access Concentrator/router queries lease for particular IP addresses using message type as "DHCP LEASE QUERY" and gets response as DHCP LEASE ACTIVE,LEASE UNASSIGNED and LEASE UNKNOWN.
- [DHCPv6.cap](<pcaps/DHCPv6.cap>)

  duration: 13s - packets: 12 - size: 1.6 KB

  tags: [DHCPV6](#dhcpv6) [ICMPv6](#icmpv6) [IPv6](#ipv6) [UDP](#udp)

  sample dhcpv6 client server transaction solicit(fresh lease)/advertise/request/reply/release/reply.
- [DNS Question & Answer.pcapng.cap](<pcaps/DNS Question & Answer.pcapng.cap>)

  duration: n/a - packets: 2 - size: 1.6 KB

  tags: [DNS](#dns) [IP](#ip) [UDP](#udp)

  DNS Question and Answer
- [DTP.cap](<pcaps/DTP.cap>)

  duration: 120s - packets: 10 - size: 934 bytes

  tags: [DTP](#dtp) [Ethernet](#ethernet) [ISL](#isl) [LLC](#llc)

  Dynamic Trunking Protocol (DTP) emanated from a Catalyst 3560 every 60 seconds, both with and without ISL encapsulation.
- [EBGP_adjacency.cap](<pcaps/EBGP_adjacency.cap>)

  duration: 182s - packets: 24 - size: 2.7 KB

  tags: [BGP](#bgp) [Ethernet](#ethernet) [IP](#ip) [TCP](#tcp)

  The external BGP adjacency between routers 1 and 2 is brought online and routes are exchanged. Keepalives are then exchanged every 60 seconds. Note that the IP TTL (normally 1) has been increased to 2 with ebgp-multihop to facilitate communication between the routers' loopback interfaces.
- [EIGRP_adjacency.cap](<pcaps/EIGRP_adjacency.cap>)

  duration: 104s - packets: 53 - size: 5.1 KB

  tags: [EIGRP](#eigrp) [Ethernet](#ethernet) [IP](#ip)

  Formation of an EIGRP adjacency between routers R1 and R2. Capture point is R1's 10.0.0.1 interface.
- [EIGRP_goodbye.cap](<pcaps/EIGRP_goodbye.cap>)

  duration: 43s - packets: 15 - size: 1.3 KB

  tags: [EIGRP](#eigrp) [Ethernet](#ethernet) [IP](#ip)

  R2 designates its interface facing R1 as passive. The final hello message from R2 (packet #9) has all its K values set to 255, designating the message as a "goodbye." Capture perspective is from R1's 10.0.0.1 interface.
- [EIGRP_subnet_down.cap](<pcaps/EIGRP_subnet_down.cap>)

  duration: 23s - packets: 21 - size: 1.8 KB

  tags: [EIGRP](#eigrp) [Ethernet](#ethernet) [IP](#ip)

  R4's interface to 192.168.4.0/24 goes down and the route is advertised as unreachable. Queries are issued by all routers to find a new path to the subnet but none exists, and the route is removed from the topology. Capture perspective is from R1's 10.0.0.1 interface.
- [EIGRP_subnet_up.cap](<pcaps/EIGRP_subnet_up.cap>)

  duration: 18s - packets: 15 - size: 1.3 KB

  tags: [EIGRP](#eigrp) [Ethernet](#ethernet) [IP](#ip)

  R4's 192.168.4.0/24 subnet is brought online. R1 receives updates from both R2 and R3 (only R2's update is shown in the capture). The poison-reverse in packet #9 informs R2 not to use R1 as a path to 192.168.4.0/24. The capture perspective is from R1's 10.0.0.1 interface.
- [EIGRPv2_adjacency.cap](<pcaps/EIGRPv2_adjacency.cap>)

  duration: 52s - packets: 31 - size: 4.1 KB

  tags: [EIGRP](#eigrp) [Ethernet](#ethernet) [IPv6](#ipv6)

  Routers 1 and 2 form an EIGRPv2 adjacency and exchange IPv6 routes.
- [EIGRPv2_subnet_transition.cap](<pcaps/EIGRPv2_subnet_transition.cap>)

  duration: 65s - packets: 49 - size: 5.3 KB

  tags: [EIGRP](#eigrp) [Ethernet](#ethernet) [IPv6](#ipv6)

  R4's 2001:db8:0:400::/64 subnet goes down, then comes back up roughly thirty seconds later. Capture perspective from R1's 2001:db8:0:12::1 interface.
- [EoMPLS.cap](<pcaps/EoMPLS.cap>)

  duration: 32s - packets: 56 - size: 7.0 KB

  tags: [Ethernet](#ethernet) [IP](#ip) [LOOP](#loop) [MPLS](#mpls) [TCP](#tcp) [UDP](#udp)

  Routers at 1.1.2.1 and 1.1.2.2 are PEs in a MPLS cloud. LDP starts at packet 8 and they build up a pseudo-wire VC (last FEC in packets 11 and 13). At packet 15 we already have STP running between CE1 and CE2 (two routers with ESW), encapsulated in 2 MPLS headers. All the ethernet stuff follows: CDP, ARP, ICMP between two hosts on the same subnet.
- [EoMPLS_802.1q.pcap.cap](<pcaps/EoMPLS_802.1q.pcap.cap>)

  duration: 1s - packets: 10 - size: 1.6 KB

  tags: [Ethernet](#ethernet) [MPLS](#mpls)

  ICMP over EoMPLS with 802.1q tagging
- [Ethernet_keepalives.cap](<pcaps/Ethernet_keepalives.cap>)

  duration: 120s - packets: 13 - size: 1012 bytes

  tags: [Ethernet](#ethernet) [LOOP](#loop)

  Loopback keepalives transmitted by an Ethernet interface.
- [FCoE_Flogi_FDisc_Negotiation.cap](<pcaps/FCoE_Flogi_FDisc_Negotiation.cap>)

  duration: 17s - packets: 41 - size: 6.7 KB

  tags: [FC](#fc) [FCCT](#fcct) [FCDNS](#fcdns) [FCELS](#fcels) [FCOE](#fcoe) [FIP](#fip)

  FCoE negotiation between Client and Fabric
- [Frame-Relay over MPLS.pcap.cap](<pcaps/Frame-Relay over MPLS.pcap.cap>)

  duration: 1s - packets: 10 - size: 1.4 KB

  tags: [Ethernet](#ethernet) [MPLS](#mpls)

  ICMP on a Frame-relay over MPLS link. If Wireshark doesn't understand it's FR, right click on a packet, select "Decode as" from the menu and select "Frame Relay DLCI PW" on the "MPLS" tab.
- [GLBP_election.cap](<pcaps/GLBP_election.cap>)

  duration: 68s - packets: 80 - size: 8.4 KB

  tags: [Ethernet](#ethernet) [GLBP](#glbp) [IP](#ip) [UDP](#udp)

  Routers 1, 2, and 3 participate in a GLBP election. R1 becomes the AVG due to having the highest priority (200), and R3 becomes the standby GLBP. All three routers become AVFs.
- [GRE.cap](<pcaps/GRE.cap>)

  duration: n/a - packets: 10 - size: 1.5 KB

  tags: [Ethernet](#ethernet) [GRE](#gre) [IP](#ip)

  ICMP is encapsulated into a Generic Routing Encapsulation (GRE) tunnel.
- [HDLC.cap](<pcaps/HDLC.cap>)

  duration: 111s - packets: 38 - size: 3.4 KB

  tags: [CDP](#cdp) [HDLC](#hdlc) [ICMP](#icmp) [IP](#ip) [SLARP](#slarp)

  ICMP across an HDLC serial link.
- [HSRP_coup.cap](<pcaps/HSRP_coup.cap>)

  duration: 49s - packets: 51 - size: 3.9 KB

  tags: [Ethernet](#ethernet) [HSRP](#hsrp) [IP](#ip) [UDP](#udp)

  Initially only routers 3 (active) and 2 (standby) are online. R1 comes online with a priority higher than R3's. R1 takes over as the active router (the coup occurs in packet #22) almost immediately. R2 is bumped down to passive and R3 becomes the standby router.
- [HSRP_election.cap](<pcaps/HSRP_election.cap>)

  duration: 57s - packets: 49 - size: 3.7 KB

  tags: [Ethernet](#ethernet) [HSRP](#hsrp) [IP](#ip) [UDP](#udp)

  The Ethernet link shared by routers 1, 2, and 3 comes online. R1 wins the HSRP election because it has a priority of 200 (versus the default of 100 held by the other two routers). R3 becomes the standby router.
- [HSRP_failover.cap](<pcaps/HSRP_failover.cap>)

  duration: 47s - packets: 39 - size: 3.0 KB

  tags: [Ethernet](#ethernet) [HSRP](#hsrp) [IP](#ip) [UDP](#udp)

  R1 is the active router, R3 is the standby, and R2 is passive. R1 goes offline and R3 takes over as active after ten seconds. R2 is then promoted to the standby state.
- [HTTP.cap](<pcaps/HTTP.cap>)

  duration: n/a - packets: 40 - size: 24.9 KB

  tags: [Ethernet](#ethernet) [HTTP](#http) [IP](#ip) [TCP](#tcp)

  Simple HTTP transfer of a PNG image using wget
- [IBGP_adjacency.cap](<pcaps/IBGP_adjacency.cap>)

  duration: 63s - packets: 17 - size: 2.3 KB

  tags: [BGP](#bgp) [Ethernet](#ethernet) [IP](#ip) [TCP](#tcp)

  Routers 3 and 4 form an internal BGP relationship. This is evidenced by the OPEN messages in packets #4 and #5, which show both routers belong to the same AS (65300). Also note that IBGP packets are not subject to a limited TTL as are EBGP packets.
- [ICMP_across_dot1q.cap](<pcaps/ICMP_across_dot1q.cap>)

  duration: 35s - packets: 15 - size: 1.7 KB

  tags: [ARP](#arp) [Ethernet](#ethernet) [ICMP](#icmp) [IP](#ip) [VLAN](#vlan)

  A ping issued from 192.168.123.2 to 192.168.123.1 is encapsulated with an IEEE 802.1Q header, placing it in VLAN 123.
- [ICMP_across_frame_relay.cap](<pcaps/ICMP_across_frame_relay.cap>)

  duration: n/a - packets: 10 - size: 1.2 KB

  tags: [Frame Relay](#frame-relay) [ICMP](#icmp) [IP](#ip)

  A Cisco 3725 pinging its neighbor across a point-to-point frame relay connection.
- [ICMP_over_L2TPv3_Pseudowire.pcap.cap](<pcaps/ICMP_over_L2TPv3_Pseudowire.pcap.cap>)

  duration: 30s - packets: 38 - size: 5.3 KB

  tags: [Ethernet](#ethernet) [IP](#ip) [L2TP](#l2tp) [LOOP](#loop) [OSPF](#ospf)

  ICMP pings from a CE to a second CE via a L2TPv3 pseudowire.
- [ICMPv6_echos.cap](<pcaps/ICMPv6_echos.cap>)

  duration: n/a - packets: 10 - size: 1.3 KB

  tags: [Ethernet](#ethernet) [ICMPv6](#icmpv6) [IPv6](#ipv6)

  Five ICMPv6 echo requests and their subsequent replies between routers 1 and 2.
- [IGMP_V1.cap](<pcaps/IGMP_V1.cap>)

  duration: 259s - packets: 27 - size: 2.0 KB

  tags: [IGMP](#igmp) [IP](#ip)

  All IGMP V1 requests : Query General, Join specific group
- [IGMP_V2.cap](<pcaps/IGMP_V2.cap>)

  duration: 133s - packets: 18 - size: 1.3 KB

  tags: [IGMP](#igmp) [IP](#ip)

  All IGMP V2 requests : Query General, Query specfic group, Join specific group, leave specific group
- [IGMPv2_query_and_report.cap](<pcaps/IGMPv2_query_and_report.cap>)

  duration: 126s - packets: 6 - size: 438 bytes

  tags: [Ethernet](#ethernet) [IGMP](#igmp) [IP](#ip)

  R1 issues IGMPv2 general membership queries to the 172.16.40.0/24 segment every 60 seconds. A host replies to each query reporting it belongs to the multicast group 239.255.255.250.
- [IP_in_IP.cap](<pcaps/IP_in_IP.cap>)

  duration: n/a - packets: 10 - size: 1.5 KB

  tags: [Ethernet](#ethernet) [ICMP](#icmp) [IP](#ip)

  Direct IP-in-IP tunnel encapsulation (configured in Cisco IOS with tunnel mode ipip).
- [IPsec_ESP-AH_tunnel_mode.cap](<pcaps/IPsec_ESP-AH_tunnel_mode.cap>)

  duration: n/a - packets: 10 - size: 2.1 KB

  tags: [AH](#ah) [ESP](#esp) [Ethernet](#ethernet) [IP](#ip)

  Encrypted ICMP across an IPsec tunnel. AH and ESP headers are present.
- [IPv6-ESP.pcapng.cap](<pcaps/IPv6-ESP.pcapng.cap>)

  duration: n/a - packets: 1 - size: 364 bytes

  tags: [ESP](#esp) [IPv6](#ipv6)

  IPv6 IPsec - ESP (Encapsulating Security Protocol)
- [IPv6_NDP.cap](<pcaps/IPv6_NDP.cap>)

  duration: 41s - packets: 20 - size: 2.1 KB

  tags: [Ethernet](#ethernet) [ICMPv6](#icmpv6) [IPv6](#ipv6)

  Neighbor Discovery Protocol (NDP) uses ICMPv6 to perform duplicate address detection and address resolution. Also includes multicast listener reports.
- [IPv6_RTSP.cap](<pcaps/IPv6_RTSP.cap>)

  duration: 3s - packets: 17 - size: 15.5 KB

  tags: [IP](#ip) [UDP](#udp)

  This capture contains IPv6_RTSP packets. Accessed IPv6 enabled RTSP server using 6in4 tunnel.
- [IPv6_in_IP.cap](<pcaps/IPv6_in_IP.cap>)

  duration: n/a - packets: 10 - size: 1.5 KB

  tags: [Ethernet](#ethernet) [ICMPv6](#icmpv6) [IP](#ip) [IPv6](#ipv6)

  ICMPv6 echos across an IPv6-in-IP tunnel.
- [ISAKMP_sa_setup.cap](<pcaps/ISAKMP_sa_setup.cap>)

  duration: n/a - packets: 9 - size: 2.0 KB

  tags: [Ethernet](#ethernet) [IP](#ip) [ISAKMP](#isakmp) [UDP](#udp)

  An ISAKMP session is established prior to setting up an IPsec tunnel. Phase one occurs in main mode, and phase two occurs in quick mode.
- [ISIS_external_lsp.cap](<pcaps/ISIS_external_lsp.cap>)

  duration: 23s - packets: 15 - size: 17.0 KB

  tags: [Ethernet](#ethernet) [ISIS](#isis) [LLC](#llc)

  R2 floods the external routes redistributed from RIP into area 10. Packet #9 includes the IP external reachability TLV. Capture perspective from R3's 10.0.10.1 interface.
- [ISIS_level1_adjacency.cap](<pcaps/ISIS_level1_adjacency.cap>)

  duration: 58s - packets: 22 - size: 27.4 KB

  tags: [Ethernet](#ethernet) [ISIS](#isis) [LLC](#llc)

  Routers 2 and 3 form an IS-IS level 2 adjacency.
- [ISIS_level2_adjacency.cap](<pcaps/ISIS_level2_adjacency.cap>)

  duration: 85s - packets: 43 - size: 51.8 KB

  tags: [Ethernet](#ethernet) [ISIS](#isis) [LLC](#llc)

  Routers 3 and 4 form an IS-IS level 2 adjacency.
- [ISIS_p2p_adjacency.cap](<pcaps/ISIS_p2p_adjacency.cap>)

  duration: 113s - packets: 26 - size: 21.7 KB

  tags: [HDLC](#hdlc) [ISIS](#isis)

  Routers 1 and 2 form a L1/L2 adjacency over a point-to-point serial link. Note that both levels of adjacency are managed with a point-to-point (P2P) hello.
- [LACP.cap](<pcaps/LACP.cap>)

  duration: 112s - packets: 20 - size: 2.8 KB

  tags: [Ethernet](#ethernet) [LACP](#lacp)

  Ethernet
LACP
- [LDP_Ethernet_FrameRelay.pcap.cap](<pcaps/LDP_Ethernet_FrameRelay.pcap.cap>)

  duration: 7s - packets: 14 - size: 2.1 KB

  tags: [Ethernet](#ethernet) [IP](#ip) [LDP](#ldp) [MPLS](#mpls) [TCP](#tcp) [UDP](#udp)

  LDP with pseudowire FEC elements (Ethernet and Frame-Relay DLCI-to-DLCI)
- [LDP_adjacency.cap](<pcaps/LDP_adjacency.cap>)

  duration: 108s - packets: 61 - size: 5.7 KB

  tags: [Ethernet](#ethernet) [IP](#ip) [LDP](#ldp) [TCP](#tcp) [UDP](#udp)

  PE1 and P1 multicast LDP hellos to 224.0.0.2 on UDP port 646. They then establish an adjacency on TCP port 646 and exchange labels.
- [LLDP_and_CDP.cap](<pcaps/LLDP_and_CDP.cap>)

  duration: 98s - packets: 12 - size: 4.0 KB

  tags: [CDP](#cdp) [Ethernet](#ethernet) [LLC](#llc) [LLDP](#lldp)

  LLDP and CDP advertisements sent between two switches, S1 and S2.
- [MPLS_encapsulation.cap](<pcaps/MPLS_encapsulation.cap>)

  duration: n/a - packets: 10 - size: 1.3 KB

  tags: [Ethernet](#ethernet) [ICMP](#icmp) [IP](#ip) [MPLS](#mpls)

  Capture taken from the PE1-P1 link. ICMP traffic between CE1 and CE2 is encapsulated outbound with MPLS label 18. Note that returning traffic is not labeled, due to penultimate hop popping (PHP).
- [MSDP.cap](<pcaps/MSDP.cap>)

  duration: 391s - packets: 35 - size: 4.1 KB

  tags: [Ethernet](#ethernet) [IP](#ip) [MSDP](#msdp) [TCP](#tcp)

  R2 and R3 become MSDP peers and exchange keepalives. A multicast source 172.16.40.10 begins sending traffic to group 239.123.123.123, and R2 begins sending periodic source active messages to R3. Capture perspective is the R2-R3 link.
- [MSTP_Intra-Region_BPDUs.cap](<pcaps/MSTP_Intra-Region_BPDUs.cap>)

  duration: 10s - packets: 10 - size: 1.7 KB

  tags: [LLC](#llc) [STP](#stp) [VLAN](#vlan)

  MSTP BPDUs captured on an intra-region root port.
- [NHRP_registration.cap](<pcaps/NHRP_registration.cap>)

  duration: n/a - packets: 4 - size: 648 bytes

  tags: [Ethernet](#ethernet) [GRE](#gre) [IP](#ip) [NHRP](#nhrp)

  R2 registers a multipoint GRE tunnel with R1. Capture perspective from the R1-R5 link.
- [OCSP-Good.cap](<pcaps/OCSP-Good.cap>)

  duration: 1s - packets: 14 - size: 3.5 KB

  tags: [DNS](#dns) [HTTP](#http) [IP](#ip) [OCSP](#ocsp) [TCP](#tcp) [UDP](#udp)

  OCSP_Good (CRL HTTPS CA Verisign)
- [OCSP-Not_Implemted.cap](<pcaps/OCSP-Not_Implemted.cap>)

  duration: n/a - packets: 10 - size: 1.1 KB

  tags: [HTTP](#http) [IP](#ip) [OCSP](#ocsp) [TCP](#tcp)

  OCSP-Not_Implemted
- [OCSP-Revoked.cap](<pcaps/OCSP-Revoked.cap>)

  duration: n/a - packets: 10 - size: 1.8 KB

  tags: [HTTP](#http) [IP](#ip) [OCSP](#ocsp) [TCP](#tcp)

  OCSP (Comodo - FAKE crt Addons-mozilla-org)
- [OSPF_Down-Bit.cap](<pcaps/OSPF_Down-Bit.cap>)

  duration: 203s - packets: 98 - size: 8.9 KB

  tags: [CDP](#cdp) [HDLC](#hdlc) [IP](#ip) [OSPF](#ospf) [SLARP](#slarp)

  LSA Update with down bit set. 
Router R5 56.0.0.5 PE is receiving an update from the MPLS VPN, which is advertised to CE 56.0.0.6 ospf routing table. In order for for the packet(LSA) not to be re-advertised back into the MPLS cloud through another PE(2) router, PE sets the Down-bit to 1.
filter: ospf.v2.options.dn == 1
- [OSPF_LSA_types.cap](<pcaps/OSPF_LSA_types.cap>)

  duration: 63s - packets: 30 - size: 4.0 KB

  tags: [Ethernet](#ethernet) [IP](#ip) [OSPF](#ospf)

  Capture of adjacency formation between OSPF routers 4 and 5 in area 20. Packet #12 contains LSAs of types 1, 2, 3, 4, and 5.
- [OSPF_NBMA_adjacencies.cap](<pcaps/OSPF_NBMA_adjacencies.cap>)

  duration: 66s - packets: 99 - size: 11.7 KB

  tags: [Frame Relay](#frame-relay) [IP](#ip) [OSPF](#ospf)

  Formation of OSPF adjacencies across a Non-broadcast Multiaccess (NBMA) frame relay topology. Neighbors have been manually specified on all routers, with R1 configured to become the DR. No BDR is present. Capture perspective from R1.
- [OSPF_broadcast_adjacencies.cap](<pcaps/OSPF_broadcast_adjacencies.cap>)

  duration: 95s - packets: 74 - size: 8.4 KB

  tags: [Ethernet](#ethernet) [IP](#ip) [OSPF](#ospf)

  Three routers form OSPF adjacencies across a broadcast segment. All interface priorities are left default, so R3 (with the highest router ID) becomes the DR, and R2 (with the next-highest router ID) becomes the BDR. Capture perspective from R1.
- [OSPF_multipoint_adjacencies.cap](<pcaps/OSPF_multipoint_adjacencies.cap>)

  duration: 277s - packets: 196 - size: 16.3 KB

  tags: [ARP](#arp) [Frame Relay](#frame-relay) [IP](#ip) [LMI](#lmi) [OSPF](#ospf) [Q933](#q933)

  Routers 1 through 4 are configured to view the non-broadcast frame relay network as a point-to-multipoint topology. Adjacencies are formed without the need of a DR or BDR. Note that inverse ARP was used to dynamically learn the addresses of neighbors.
- [OSPF_point-to-point_adjacencies.cap](<pcaps/OSPF_point-to-point_adjacencies.cap>)

  duration: 35s - packets: 93 - size: 9.9 KB

  tags: [Frame Relay](#frame-relay) [IP](#ip) [OSPF](#ospf)

  The frame relay network between four routers is configured with point-to-point subinterfaces. No DR/BDR is required as all adjacencies are point-to-point. Capture perspective from R1.
- [OSPF_type7_LSA.cap](<pcaps/OSPF_type7_LSA.cap>)

  duration: 32s - packets: 25 - size: 3.6 KB

  tags: [Ethernet](#ethernet) [IP](#ip) [OSPF](#ospf)

  Area 10 is configured as a not-so-stubby area (NSSA). The capture records the adjacency formed between routers 2 and 3. The link state update in packet #11 includes several type 7 LSAs from R2. Capture perspective from R3's 10.0.10.1 interface.
- [OSPF_with_MD5_auth.cap](<pcaps/OSPF_with_MD5_auth.cap>)

  duration: 63s - packets: 34 - size: 4.6 KB

  tags: [Ethernet](#ethernet) [IP](#ip) [OSPF](#ospf)

  An OSPF adjacency is formed between two routers configured to use MD5 authentication.
- [OSPFv3_NBMA_adjacencies.cap](<pcaps/OSPFv3_NBMA_adjacencies.cap>)

  duration: 90s - packets: 86 - size: 12.9 KB

  tags: [Frame Relay](#frame-relay) [IPv6](#ipv6) [OSPF](#ospf)

  Router 3 forms OSPFv3 adjacencies with routers 1 and two across the non-broadcast multi-access (NBMA) frame relay link.
- [OSPFv3_broadcast_adjacency.cap](<pcaps/OSPFv3_broadcast_adjacency.cap>)

  duration: 70s - packets: 38 - size: 5.4 KB

  tags: [Ethernet](#ethernet) [IPv6](#ipv6) [OSPF](#ospf)

  Routers 1 and 2 form an OSPFv3 adjacency across their common Ethernet link (2001:db8:0:12::/64).
- [OSPFv3_multipoint_adjacencies.cap](<pcaps/OSPFv3_multipoint_adjacencies.cap>)

  duration: 35s - packets: 73 - size: 11.5 KB

  tags: [Frame Relay](#frame-relay) [IPv6](#ipv6) [OSPF](#ospf)

  The frame relay link connecting routers 1, 2, and 3 has been configured as a point-to-multipoint network with broadcast capability. Router 3 forms OSPFv3 adjacencies with routers 1 and 2, but no DR or BDR is elected.
- [OSPFv3_with_AH.cap](<pcaps/OSPFv3_with_AH.cap>)

  duration: 170s - packets: 61 - size: 10.7 KB

  tags: [Ethernet](#ethernet) [IPv6](#ipv6) [OSPF](#ospf)

  The adjacency between R1 and R2 in the 2001:db8:0:12::/64 subnet is configured with IPsec AH authentication. Note the inclusion of an IPsec AH header immediately following the IPv6 header of each OSPF packet.
- [Open Network Connection.pcapng.cap](<pcaps/Open Network Connection.pcapng.cap>)

  duration: 387s - packets: 116 - size: 26.8 KB

  tags: [ARP](#arp) [DNS](#dns) [HTTP](#http) [IP](#ip) [MEDIA](#media) [NBDGM](#nbdgm) [NBNS](#nbns) [NTP](#ntp) [SMB](#smb) [TCP](#tcp) [UDP](#udp) [XML](#xml)

  Open Network Connection
- [PAGP.cap](<pcaps/PAGP.cap>)

  duration: 95s - packets: 25 - size: 2.5 KB

  tags: [Ethernet](#ethernet) [LLC](#llc) [PAGP](#pagp)

  Ethernet
LLC
PAGP
- [PIM-DM_pruning.cap](<pcaps/PIM-DM_pruning.cap>)

  duration: 415s - packets: 38 - size: 10.2 KB

  tags: [Ethernet](#ethernet) [IP](#ip) [PIM](#pim) [UDP](#udp)

  The multicast source at 172.16.40.10 begins sending traffic to the group 239.123.123.123, and PIM-DM floods the traffic down the tree. R4 has no group members, and prunes itself from the tree. R2 and R3 then realize they have no members, and each prunes itself from the tree. The capture shows R2 receiving the multicast traffic flooded from R1 and subsequently pruning itself every three minutes.
- [PIM-SM_join_prune.cap](<pcaps/PIM-SM_join_prune.cap>)

  duration: 473s - packets: 47 - size: 3.8 KB

  tags: [Ethernet](#ethernet) [IGMP](#igmp) [IP](#ip) [PIM](#pim)

  A host on R4's 172.16.20.0/24 subnet requests to join the 239.123.123.123 group. R4 sends a PIMv2 join message up to the RP (R1). Subsequent join messages are sent every 30 seconds, until R4 determines it no longer has any interested hosts and sends a prune request (packet #45). PIMv1 RP-Reachable messages for the group are also visible from R1.
- [PIM_register_register-stop.cap](<pcaps/PIM_register_register-stop.cap>)

  duration: n/a - packets: 2 - size: 258 bytes

  tags: [Ethernet](#ethernet) [IP](#ip) [PIM](#pim)

  Switch at 192.168.0.6 receives an IGMP request for the group 239.1.2.3, encapsulates the original IGMP packet in a PIM Register and sends it to the RP at 192.168.1.254. In packet #2 RP sends a Register-Stop to the switch.
- [PIMv2_bootstrap.cap](<pcaps/PIMv2_bootstrap.cap>)

  duration: 184s - packets: 8 - size: 712 bytes

  tags: [Ethernet](#ethernet) [IP](#ip) [PIM](#pim)

  Router 1 is the BSR and routers 2 and 3 are candidate RPs with the default priority of 0. R1 collects the RP advertisement unicasts from R2 and R3 and combines them in a bootstrap multicast to all PIM routers. Capture perspective is the R1-R3 link.
- [PIMv2_hellos.cap](<pcaps/PIMv2_hellos.cap>)

  duration: 63s - packets: 6 - size: 528 bytes

  tags: [Ethernet](#ethernet) [IP](#ip) [PIM](#pim)

  Routers 1 and 2 exchange PIMv2 hello packets.
- [PPP.cap](<pcaps/PPP.cap>)

  duration: 83s - packets: 50 - size: 3.6 KB

  tags: [CDP](#cdp) [ICMP](#icmp) [IP](#ip) [LCP](#lcp) [PPP](#ppp)

  ICMP across a PPP serial link.
- [PPP_EAP.cap](<pcaps/PPP_EAP.cap>)

  duration: 52s - packets: 52 - size: 2.5 KB

  tags: [CDP](#cdp) [CDPCP](#cdpcp) [EAP](#eap) [IPCP](#ipcp) [LCP](#lcp) [PPP](#ppp)

  PPP link negotiation employing EAP MD5 authentication
- [PPP_TCP_compression.cap](<pcaps/PPP_TCP_compression.cap>)

  duration: 3s - packets: 43 - size: 1.5 KB

  tags: [IP](#ip) [LCP](#lcp) [PPP](#ppp) [TCP](#tcp)

  A telnet session is established to 191.1.13.3 across a PPP link performing TCP header compression. The user at 191.1.13.1 logs in with the password "cisco" and terminates the connection.
- [PPP_negotiation.cap](<pcaps/PPP_negotiation.cap>)

  duration: 67s - packets: 63 - size: 4.6 KB

  tags: [CDP](#cdp) [CDPCP](#cdpcp) [CHAP](#chap) [ICMP](#icmp) [IP](#ip) [IPCP](#ipcp) [LCP](#lcp) [PPP](#ppp)

  CDP
CDPCP
CHAP
ICMP
IP
IPCP
LCP
PPP
- [PPPoE_Dual-Stack_IPv4_IPv6-with_DHCPv6.cap](<pcaps/PPPoE_Dual-Stack_IPv4_IPv6-with_DHCPv6.cap>)

  duration: 46s - packets: 65 - size: 6.1 KB

  tags: [Ethernet](#ethernet) [IPCP](#ipcp) [IPV6CP](#ipv6cp) [IPv6](#ipv6) [LCP](#lcp) [PAP](#pap) [PPP](#ppp) [PPPOED](#pppoed) [PPPOES](#pppoes)

  Dual-stack PPPoE: IP (IPv4) and IPv6 with DHCPv6
- [PPTP_negotiation.cap](<pcaps/PPTP_negotiation.cap>)

  duration: 71s - packets: 28 - size: 2.7 KB

  tags: [ARP](#arp) [GRE](#gre) [IP](#ip) [IPCP](#ipcp) [LCP](#lcp) [PAP](#pap) [PPP](#ppp) [PPTP](#pptp) [TCP](#tcp)

  PPTP negotiation between PNS and PAC
PPTP RFC: https://www.ietf.org/rfc/rfc2637.txt
- [QinQ.pcap.cap](<pcaps/QinQ.pcap.cap>)

  duration: 2s - packets: 2 - size: 184 bytes

  tags: [ARP](#arp) [Ethernet](#ethernet) [VLAN](#vlan)

  ARP requests having two vlan IDs attached (QinQ)
- [RADIUS.cap](<pcaps/RADIUS.cap>)

  duration: n/a - packets: 4 - size: 775 bytes

  tags: [Ethernet](#ethernet) [IP](#ip) [RADIUS](#radius) [UDP](#udp)

  A RADIUS authentication request is issued from a switch at 10.0.0.1 on behalf of an EAP client. The user authenticates via MD5 challenge with the username "John.McGuirk" and the password "S0cc3r".
- [RIPv1.cap](<pcaps/RIPv1.cap>)

  duration: 65s - packets: 6 - size: 876 bytes

  tags: [Ethernet](#ethernet) [IP](#ip) [RIP](#rip) [UDP](#udp)

  A RIPv1 router periodically flooding its database. Capture perspective from R1's 10.0.1.1 interface.
- [RIPv1_subnet_down.cap](<pcaps/RIPv1_subnet_down.cap>)

  duration: 58s - packets: 8 - size: 1.0 KB

  tags: [Ethernet](#ethernet) [IP](#ip) [RIP](#rip) [UDP](#udp)

  RIPv1 routes are being flooded on the R1-R2 link. R2's connection to 192.168.2.0/24 goes down, and the route is advertised as unreachable (metric 16) in packet #5. Capture perspective from R1's 10.0.1.1 interface.
- [RIPv2.cap](<pcaps/RIPv2.cap>)

  duration: 141s - packets: 12 - size: 1.7 KB

  tags: [Ethernet](#ethernet) [IP](#ip) [RIP](#rip) [UDP](#udp)

  A RIPv2 router periodically flooding its database. Capture perspective from R1's 10.0.0.1 interface.
- [RIPv2_subnet_down.cap](<pcaps/RIPv2_subnet_down.cap>)

  duration: 86s - packets: 10 - size: 1.3 KB

  tags: [Ethernet](#ethernet) [IP](#ip) [RIP](#rip) [UDP](#udp)

  RIPv2 routes are being flooded on the R1-R2 link. R2's connection to 192.168.2.0/24 goes down, and the route is advertised as unreachable (metric 16) in packet #7. Capture perspective from R1's 10.0.0.1 interface.
- [SNMPv2c_get_requests.cap](<pcaps/SNMPv2c_get_requests.cap>)

  duration: n/a - packets: 8 - size: 894 bytes

  tags: [Ethernet](#ethernet) [IP](#ip) [SNMP](#snmp) [UDP](#udp)

  SNMPv2c get requests are issued from a manager to an SNMP agent in order to monitor the bandwidth utilization of an interface.
- [SNMPv3.cap](<pcaps/SNMPv3.cap>)

  duration: 10s - packets: 8 - size: 1.3 KB

  tags: [IP](#ip) [SNMP](#snmp) [UDP](#udp)

  This is a SNMPv3 (IPv4) Captures.Where SNMP manager is requesting to SNMP agent using SNMPv3.
- [SSHv2.cap](<pcaps/SSHv2.cap>)

  duration: 7s - packets: 90 - size: 11.4 KB

  tags: [Ethernet](#ethernet) [IP](#ip) [SSH](#ssh) [TCP](#tcp)

  An SSH version 2 session between two routers. All communication is securely encrypted.
- [STP-TCN-TCAck.pcapng.cap](<pcaps/STP-TCN-TCAck.pcapng.cap>)

  duration: 5s - packets: 5 - size: 692 bytes

  tags: [LLC](#llc) [STP](#stp)

  Spanning Tree 8021.D Topology Change Notification and Topology Change Ack.
- [Spanning Tree - MST.pcapng.cap](<pcaps/Spanning Tree - MST.pcapng.cap>)

  duration: 36s - packets: 19 - size: 3.4 KB

  tags: [LLC](#llc) [STP](#stp)

  Example of Multiple Spanning Tree with IEEE 802.3 + 802.2 LLC without SNAP encapsulation.
- [TACACS+_encrypted.cap](<pcaps/TACACS+_encrypted.cap>)

  duration: 7s - packets: 34 - size: 2.8 KB

  tags: [Ethernet](#ethernet) [IP](#ip) [TACACS+](#tacacs) [TCP](#tcp)

  TACACS+ authentication and authorization requests as made by a Cisco IOS router upon a user logging in via Telnet.
- [TCP_SACK.cap](<pcaps/TCP_SACK.cap>)

  duration: n/a - packets: 39 - size: 27.5 KB

  tags: [Ethernet](#ethernet) [HTTP](#http) [IP](#ip) [TCP](#tcp)

  A TCP SACK option is included in packets #31, #33, #35, and #37. The missing segment is retransmitted in packet #38.
- [TDP.cap](<pcaps/TDP.cap>)

  duration: 47s - packets: 33 - size: 2.8 KB

  tags: [Ethernet](#ethernet) [IP](#ip) [TCP](#tcp) [TDP](#tdp) [UDP](#udp)

  P2 and PE2 exchange Tag Distribution Protocol hellos and form an adjacency over TCP port 711.
- [UDLD.cap](<pcaps/UDLD.cap>)

  duration: 93s - packets: 29 - size: 3.3 KB

  tags: [Ethernet](#ethernet) [LLC](#llc) [UDLD](#udld)

  Unidirectional Link Detection (UDLD) is used to monitor the status of a link between a Catalyst 2960 and a Catalyst 3560. Note that echos are initially sent at very small intervals, gradually throttling back to the configured interval of 15 seconds.
- [VRRP_Malformed_DoS.cap](<pcaps/VRRP_Malformed_DoS.cap>)

  duration: n/a - packets: 1 - size: 74 bytes

  tags: [IP](#ip)

  IP
- [VRRP_failover.cap](<pcaps/VRRP_failover.cap>)

  duration: 33s - packets: 32 - size: 2.4 KB

  tags: [Ethernet](#ethernet) [IP](#ip) [VRRP](#vrrp)

  The master router (R1) goes offline. After the down interval passes (roughly 3 seconds), R3 takes over as the master router in packet #12. R2 also offers to take over but R3 wins because it has the higher IP address.
- [VRRP_preempt.cap](<pcaps/VRRP_preempt.cap>)

  duration: 14s - packets: 16 - size: 1.2 KB

  tags: [Ethernet](#ethernet) [IP](#ip) [VRRP](#vrrp)

  Initially R3 is the master, R2 is backup, and R1 is offline. R1 comes back online with a priority of 200, preempting R3 to become the master router.
- [WCCPv2.pcap.cap](<pcaps/WCCPv2.pcap.cap>)

  duration: 27s - packets: 15 - size: 2.8 KB

  tags: [Ethernet](#ethernet) [IP](#ip) [UDP](#udp) [WCCP](#wccp)

  WCCP communication captures between 7200 Router and a WCCP capable optimization device (In my case it is Riverbed's Stealhead 2050)
- [address withdrawal ldp.pcapng.cap](<pcaps/address withdrawal ldp.pcapng.cap>)

  duration: n/a - packets: 1 - size: 716 bytes

  tags: [IP](#ip) [LDP](#ldp) [TCP](#tcp)

  Label address withdrawal message. An LSR sends the label address withdrawal message to a peer when it wants to withdraw previously advertised labels to address mappings. See RFC 3036 for more details.
- [arp_l2tpv3.cap](<pcaps/arp_l2tpv3.cap>)

  duration: 2s - packets: 3 - size: 414 bytes

  tags: [IP](#ip) [L2TP](#l2tp) [L2TP.L2_SPEC_DEF](#l2tp-l2-spec-def) [UDP](#udp)

  ARP request packet encapsulated in L2TPv3 over Ethernet Pseudowire.
- [arp_pcap.pcapng.cap](<pcaps/arp_pcap.pcapng.cap>)

  duration: 50s - packets: 16 - size: 2.2 KB

  tags: [ARP](#arp) [CDP](#cdp) [LLC](#llc) [LOOP](#loop)

  ARP Request reply packet captures
- [bgp as confed sequence.pcapng.cap](<pcaps/bgp as confed sequence.pcapng.cap>)

  duration: n/a - packets: 1 - size: 432 bytes

  tags: [BGP](#bgp) [IP](#ip) [TCP](#tcp)

  AS confederation sequence set in the BGP updates. Confederations are used to minimize IBGP mesh between BGP speakers but IBGP rules apply between EBGP sub confederation peers. AS confederation sequence are an ordered list of Autonomous systems passed within confederations.
- [bgp med.pcapng.cap](<pcaps/bgp med.pcapng.cap>)

  duration: n/a - packets: 1 - size: 364 bytes

  tags: [BGP](#bgp) [IP](#ip) [TCP](#tcp)

  BGP metric value set to 242( just a random value), used as a suggestion for peer in neighboring AS to influence incoming traffic.
- [bgp orf capabilty negotitation.pcapng.cap](<pcaps/bgp orf capabilty negotitation.pcapng.cap>)

  duration: n/a - packets: 1 - size: 328 bytes

  tags: [BGP](#bgp) [IP](#ip) [TCP](#tcp)

  BGP outbound route filtering capabilities negotiation between BGP speakers, sent during route [ Cisco PrefixList ORF-Type (128)].
- [bgp orf prefix advertisement.pcapng.cap](<pcaps/bgp orf prefix advertisement.pcapng.cap>)

  duration: n/a - packets: 1 - size: 336 bytes

  tags: [BGP](#bgp) [IP](#ip) [TCP](#tcp)

  BGP prefix list sent during route refresh when outbound route filtering is configured.
here we clearly see whether the prefix list is add or delete and permit or deny.
Also we can see the actual network/mask sent.
- [bgp-add-path.cap](<pcaps/bgp-add-path.cap>)

  duration: 54s - packets: 9 - size: 1.1 KB

  tags: [BGP](#bgp) [IP](#ip) [TCP](#tcp)

  BGP additional path feature.
https://tools.ietf.org/html/draft-ietf-idr-add-paths-10
- [bgplu.cap](<pcaps/bgplu.cap>)

  duration: 4s - packets: 22 - size: 2.1 KB

  tags: [BGP](#bgp) [IP](#ip) [TCP](#tcp)

  BGP Labeled Unicast
- [cflow.cap](<pcaps/cflow.cap>)

  duration: n/a - packets: 1 - size: 782 bytes

  tags: [IP](#ip) [UDP](#udp)

  Netflow v9 packet containing template as well as data set
- [cm4116_telnet.cap](<pcaps/cm4116_telnet.cap>)

  duration: 14s - packets: 113 - size: 9.4 KB

  tags: [Ethernet](#ethernet) [IP](#ip) [TCP](#tcp) [Telnet](#telnet)

  Short Telnet session with an Opengear CM4116 used to demonstrate the urgent flag and pointer
- [connection termination.cap](<pcaps/connection termination.cap>)

  duration: n/a - packets: 4 - size: 316 bytes

  tags: [IP](#ip) [TCP](#tcp)

  This is a connection termination packet in which both the server and client sends fin & ack to each other.For details of how connection is been teared down by both client and server see the link below.http://www.firewall.cx/networking-topics/protocols/tcp/136-tcp-flag-options.html
- [dhcp-auth.cap](<pcaps/dhcp-auth.cap>)

  duration: n/a - packets: 1 - size: 458 bytes

  tags: [BOOTP](#bootp) [IP](#ip) [UDP](#udp)

  Dhcp v4 Offer with Auth using Options 53,1,54,51,3,6,66,120,61,90,82
- [dns-zone-transfer-axfr.cap](<pcaps/dns-zone-transfer-axfr.cap>)

  duration: n/a - packets: 9 - size: 915 bytes

  tags: [DNS](#dns) [IP](#ip) [TCP](#tcp)

  DNS zone transfer AXFR
- [dns-zone-transfer-ixfr.cap](<pcaps/dns-zone-transfer-ixfr.cap>)

  duration: n/a - packets: 2 - size: 442 bytes

  tags: [DNS](#dns) [IP](#ip) [UDP](#udp)

  DNS Zone transfer, both AXFR and IXFR
- [dtls_null.cap](<pcaps/dtls_null.cap>)

  duration: 7s - packets: 7 - size: 2.2 KB

  tags: [IP](#ip) [UDP](#udp)

  DTLS handshake with one application data packet.
- [gmail.pcapng.cap](<pcaps/gmail.pcapng.cap>)

  duration: 32s - packets: 793 - size: 508.6 KB

  tags: [ARP](#arp) [DHCPV6](#dhcpv6) [DNS](#dns) [HTTP](#http) [IP](#ip) [IPv6](#ipv6) [NBNS](#nbns) [SSL](#ssl) [TCP](#tcp) [TEREDO](#teredo) [UDP](#udp)

  Sample packet capture I created during an attempt to view login details.
- [gratuitous arp hsrp.cap](<pcaps/gratuitous arp hsrp.cap>)

  duration: 6s - packets: 6 - size: 480 bytes

  tags: [ARP](#arp)

  When router take the role of active in hsrp it sends a gratuitous arp in which source mac is 00:00:0c:07:ac:01, the switches update their mac table for the newly learned mac and starts forwarding to that port.
- [gre_and_4over6.cap](<pcaps/gre_and_4over6.cap>)

  duration: n/a - packets: 2 - size: 521 bytes

  tags: [GRE](#gre) [IP](#ip) [IPv6](#ipv6) [VLAN](#vlan)

  Ipv4-over-IPv6, GRE protocol.
- [hdlc slarp.pcapng.cap](<pcaps/hdlc slarp.pcapng.cap>)

  duration: 22s - packets: 7 - size: 612 bytes

  tags: [SLARP](#slarp)

  We can have our serial interface automatically assign itself ip address from neighbor router, like DHCP for serial interfaces.which is called as SLARP(serial line address resolution protocol).Here is a packet capture of slarp and the router requesting the addresss and mask from neighbor router.Also the neighboring router responds with its own ip address and mask and this router looks into the mask and assigns itself the next available ip address from the subnet.
- [icmp fragmented.cap](<pcaps/icmp fragmented.cap>)

  duration: 11s - packets: 77 - size: 106.4 KB

  tags: [ICMP](#icmp) [IP](#ip)

  pinged google.com with -l option in windows which allows us to set the data size of the packet.Data size of 15000 bytes has been chosen and we can see that it is fragmented through the network into a maximum data size 1480 bytes in each packet.We can also see offset and identification field set in the ip header.
- [icmp with record route option set.cap](<pcaps/icmp with record route option set.cap>)

  duration: 2s - packets: 10 - size: 1.2 KB

  tags: [ICMP](#icmp) [IP](#ip)

  ping packet with record route option set and IP addresses of all outgoing and incoming interfaces along the path.In that we can also see position of current pointer.
- [icmp_in_l2tpv3.cap](<pcaps/icmp_in_l2tpv3.cap>)

  duration: 43s - packets: 45 - size: 7.1 KB

  tags: [ARP](#arp) [IP](#ip) [L2TP](#l2tp) [L2TP.L2_SPEC_DEF](#l2tp-l2-spec-def) [UDP](#udp)

  This capture contains icmp packet transported in l2tpv3.
- [iphttps.cap](<pcaps/iphttps.cap>)

  duration: 38s - packets: 83 - size: 12.4 KB

  tags: [ARP](#arp) [DNS](#dns) [Ethernet](#ethernet) [ICMPv6](#icmpv6) [IGMP](#igmp) [IP](#ip) [IPv6](#ipv6) [LLC](#llc) [NBNS](#nbns) [NBSS](#nbss) [SSL](#ssl) [TCP](#tcp) [UDP](#udp)

  IP-HTTPS capture.  This is Microsoft's IPv6 inside HTTPS tunneling for DirectAccess.
- [ipv4-smtp.cap](<pcaps/ipv4-smtp.cap>)

  duration: 9s - packets: 15 - size: 1.5 KB

  tags: [IP](#ip) [SMTP](#smtp) [TCP](#tcp)

  SMTP over IPv4 to Google - GMAIL.
- [ipv6-smtp.pcapng.cap](<pcaps/ipv6-smtp.pcapng.cap>)

  duration: 11s - packets: 17 - size: 6.0 KB

  tags: [IPv6](#ipv6) [SMTP](#smtp) [TCP](#tcp)

  SMTP over IPv6 to Google - GMAIL.
- [ipv6_neighbor_spoofing.cap](<pcaps/ipv6_neighbor_spoofing.cap>)

  duration: 27s - packets: 49 - size: 6.2 KB

  tags: [Ethernet](#ethernet) [ICMPv6](#icmpv6) [IPv6](#ipv6)

  IPv6 neighbor spoofing on the local link using a forged ICMPv6 neighbor advertisement.
- [lispmn_IPv6-RLOC.pcapng.cap](<pcaps/lispmn_IPv6-RLOC.pcapng.cap>)

  duration: 8s - packets: 35 - size: 5.9 KB

  tags: [IP](#ip) [IPv6](#ipv6) [LISP](#lisp) [LISP-DATA](#lisp-data) [UDP](#udp)

  LISP control (map register,request and reply )and Data packets with IPv6 as RLOC and IPv4 as EID.
- [mGRE_ICMP.cap](<pcaps/mGRE_ICMP.cap>)

  duration: 10s - packets: 24 - size: 3.7 KB

  tags: [Ethernet](#ethernet) [GRE](#gre) [IP](#ip) [NHRP](#nhrp)

  R2 begins sending ICMP traffic to R4, but it currently only has a GRE tunnel open to R1. The first two ICMP requests (packets #1 and #4) are routed through R1 while R2 sends an NHRP request to R1 for R4's spoke address. Once a GRE tunnel is dynamically built between spoke routers R2 and R4, R2 begins routing the ICMP traffic directly to R4. Capture perspective from the R2-R5 link.
- [mpls address label mapping.pcapng.cap](<pcaps/mpls address label mapping.pcapng.cap>)

  duration: n/a - packets: 1 - size: 708 bytes

  tags: [IP](#ip) [LDP](#ldp) [TCP](#tcp)

  MPLS address label mappings communication over TCP (here R6 to R5)
In this packet we can see the address bound to that neighbor (R6) in the address list TLV.
Also the address and labels are encoded as TLV(type length value).
We should remember that the transport address of the neighbor should be reachable and not mpls router ID, because the TCP handshake is done via transport address and not MPLS router id.
The address label mapping is exchanged once the TCP handshake is done.
- [mrinfo_query.cap](<pcaps/mrinfo_query.cap>)

  duration: n/a - packets: 2 - size: 182 bytes

  tags: [DVMRP](#dvmrp) [Ethernet](#ethernet) [IGMP](#igmp) [IP](#ip)

  mrinfo 2.2.2.2 is issued on R1. DVMRPv3 is used to query R2 for its multicast interfaces.
- [mtrace.cap](<pcaps/mtrace.cap>)

  duration: n/a - packets: 2 - size: 238 bytes

  tags: [Ethernet](#ethernet) [IGMP](#igmp) [IP](#ip)

  mtrace 172.16.40.1 172.16.20.1 is issued on R1 to trace the RPF path from R4's 172.16.20.0/24 subnet to R1's 172.16.40.0/24 subnet. The capture is taken on the R1-R3 link.
- [nf9-juniper-vmx.pcapng.cap](<pcaps/nf9-juniper-vmx.pcapng.cap>)

  duration: 35s - packets: 5 - size: 912 bytes

  tags: [IP](#ip) [UDP](#udp)

  Juniper vMX NetFlow.
- [no-advertise community.pcapng.cap](<pcaps/no-advertise community.pcapng.cap>)

  duration: n/a - packets: 2 - size: 420 bytes

  tags: [BGP](#bgp) [IP](#ip) [TCP](#tcp)

  BGP update packet with no-advertise community set [Community:NO_ADVERTISE (0xffffff02)]
A BGP router telling its BGP peer not to advertise this route to any other peer whether EBGP or IBGP.
- [ospf over gre tunnel.cap](<pcaps/ospf over gre tunnel.cap>)

  duration: 241s - packets: 63 - size: 8.2 KB

  tags: [GRE](#gre) [IP](#ip) [OSPF](#ospf)

  Configured ospf over GRE tunnel in which packets are double tagged with ip header, useful when there is no direct connection between the 2 routers but still we need to run ospf.
- [ospf simple password authentication.cap](<pcaps/ospf simple password authentication.cap>)

  duration: 60s - packets: 7 - size: 766 bytes

  tags: [IP](#ip) [OSPF](#ospf)

  Simple password authentication in ospf in which we can see password in clear text.
- [packet-c.cap](<pcaps/packet-c.cap>)

  duration: 13s - packets: 926 - size: 675.0 KB

  tags: [BOOTP](#bootp) [DNS](#dns) [HTTP](#http) [IP](#ip) [LLC](#llc) [SKINNY](#skinny) [SSL](#ssl) [STP](#stp) [TCP](#tcp) [UDP](#udp)

  This is a packet capture from a SonicWall. We were troubleshooting DHCP packet flows. The SonicWall saw the DHCP Discover and Sent an Offer. We never saw the DHCP acknowledgement. In the adjacent core stacked switching we were running "debug ip dhcp server packets" we only saw discover packets from IP phones up to the SonicWall. For some reason the SonicWall could not let any other DHCP packets through or out of it INSIDE (LAN) interface. Even if we put an ANY-ANY ALC for that interface. We ended up having to replace the SonicWall and upload the configuration from the old SonicWall to the new one.
- [path_MTU_discovery.cap](<pcaps/path_MTU_discovery.cap>)

  duration: n/a - packets: 8 - size: 6.2 KB

  tags: [Ethernet](#ethernet) [ICMP](#icmp) [IP](#ip) [UDP](#udp)

  Tracepath is used to determine the MTU of the path between hosts 192.168.0.2 and .1.2. Packet #6 contains an ICMP "fragmentation needed" message, indicating the MTU for that hop is 1400 bytes.
- [rpvstp-access.pcap.cap](<pcaps/rpvstp-access.pcap.cap>)

  duration: 77s - packets: 49 - size: 3.7 KB

  tags: [DNS](#dns) [Ethernet](#ethernet) [IP](#ip) [LLC](#llc) [LOOP](#loop) [STP](#stp) [UDP](#udp)

  Rapid per-VLAN spanning tree capture of an access port (without portfast), configured in VLAN 5.
- [rpvstp-trunk-native-vid1.pcap.cap](<pcaps/rpvstp-trunk-native-vid1.pcap.cap>)

  duration: 45s - packets: 81 - size: 6.4 KB

  tags: [DTP](#dtp) [Ethernet](#ethernet) [LLC](#llc) [LOOP](#loop) [STP](#stp) [VLAN](#vlan) [VTP](#vtp)

  Rapid per-VLAN spanning tree capture of a trunk port, configured with native VLAN 1 (default), VLAN 5 is also active over the trunk.
- [rpvstp-trunk-native-vid5.pcap.cap](<pcaps/rpvstp-trunk-native-vid5.pcap.cap>)

  duration: 11s - packets: 22 - size: 1.8 KB

  tags: [DTP](#dtp) [Ethernet](#ethernet) [LLC](#llc) [LOOP](#loop) [STP](#stp) [VLAN](#vlan) [VTP](#vtp)

  Rapid per-VLAN spanning tree capture of a trunk port, configured with native VLAN 5, VLAN 1 is also active over the trunk.
- [sflow.cap](<pcaps/sflow.cap>)

  duration: 109s - packets: 9 - size: 1.8 KB

  tags: [IP](#ip) [SFLOW](#sflow) [UDP](#udp)

  SFLOW capture containing
- counter sample packets
- flow sample packet
- [snmp-ipv4.cap](<pcaps/snmp-ipv4.cap>)

  duration: 2s - packets: 2100 - size: 447.8 KB

  tags: [IP](#ip) [SNMP](#snmp) [UDP](#udp)

  SNMPv3 over IPv4.
- [snmp-ipv6.cap](<pcaps/snmp-ipv6.cap>)

  duration: 1s - packets: 1650 - size: 383.5 KB

  tags: [IPv6](#ipv6) [SNMP](#snmp) [UDP](#udp)

  SNMPv3 over IPv6
- [snoop-working-ccm7.cap](<pcaps/snoop-working-ccm7.cap>)

  duration: 1081s - packets: 191 - size: 203.0 KB

  tags: [H225](#h225) [IP](#ip) [Q931](#q931) [TCP](#tcp) [TPKT](#tpkt) [UDP](#udp)

  H323 Phone registering!!!
- [stun2.cap](<pcaps/stun2.cap>)

  duration: n/a - packets: 1 - size: 102 bytes

  tags: [IP](#ip) [STUN](#stun) [UDP](#udp)

  Stun (2) Protocol. UDP Holepunching technique.
- [telnet.cap](<pcaps/telnet.cap>)

  duration: 10s - packets: 74 - size: 9.4 KB

  tags: [Ethernet](#ethernet) [IP](#ip) [TCP](#tcp) [Telnet](#telnet)

  Telnetting from one router to another. Note that all communication is visible in clear text.
- [traceroute_MPLS.cap](<pcaps/traceroute_MPLS.cap>)

  duration: 3s - packets: 29 - size: 3.3 KB

  tags: [ICMP](#icmp) [IP](#ip) [UDP](#udp)

  ICMP
IP
UDP
### Grouped by tag

#### AH

- [IPsec_ESP-AH_tunnel_mode.cap](<pcaps/IPsec_ESP-AH_tunnel_mode.cap>)

#### ARP

- [ICMP_across_dot1q.cap](<pcaps/ICMP_across_dot1q.cap>)
- [OSPF_multipoint_adjacencies.cap](<pcaps/OSPF_multipoint_adjacencies.cap>)
- [Open Network Connection.pcapng.cap](<pcaps/Open Network Connection.pcapng.cap>)
- [PPTP_negotiation.cap](<pcaps/PPTP_negotiation.cap>)
- [QinQ.pcap.cap](<pcaps/QinQ.pcap.cap>)
- [arp_pcap.pcapng.cap](<pcaps/arp_pcap.pcapng.cap>)
- [gmail.pcapng.cap](<pcaps/gmail.pcapng.cap>)
- [gratuitous arp hsrp.cap](<pcaps/gratuitous arp hsrp.cap>)
- [icmp_in_l2tpv3.cap](<pcaps/icmp_in_l2tpv3.cap>)
- [iphttps.cap](<pcaps/iphttps.cap>)

#### Auto-RP

- [Auto-RP.cap](<pcaps/Auto-RP.cap>)

#### BGP

- [4-byte_AS_numbers_Full_Support.cap](<pcaps/4-byte_AS_numbers_Full_Support.cap>)
- [4-byte_AS_numbers_Mixed_Scenario.cap](<pcaps/4-byte_AS_numbers_Mixed_Scenario.cap>)
- [BGP_AS_set.cap](<pcaps/BGP_AS_set.cap>)
- [BGP_MD5.cap](<pcaps/BGP_MD5.cap>)
- [BGP_MP_NLRI.cap](<pcaps/BGP_MP_NLRI.cap>)
- [BGP_hard_reset.cap](<pcaps/BGP_hard_reset.cap>)
- [BGP_notification.cap](<pcaps/BGP_notification.cap>)
- [BGP_redist.cap](<pcaps/BGP_redist.cap>)
- [BGP_soft_reset.cap](<pcaps/BGP_soft_reset.cap>)
- [EBGP_adjacency.cap](<pcaps/EBGP_adjacency.cap>)
- [IBGP_adjacency.cap](<pcaps/IBGP_adjacency.cap>)
- [bgp as confed sequence.pcapng.cap](<pcaps/bgp as confed sequence.pcapng.cap>)
- [bgp med.pcapng.cap](<pcaps/bgp med.pcapng.cap>)
- [bgp orf capabilty negotitation.pcapng.cap](<pcaps/bgp orf capabilty negotitation.pcapng.cap>)
- [bgp orf prefix advertisement.pcapng.cap](<pcaps/bgp orf prefix advertisement.pcapng.cap>)
- [bgp-add-path.cap](<pcaps/bgp-add-path.cap>)
- [bgplu.cap](<pcaps/bgplu.cap>)
- [no-advertise community.pcapng.cap](<pcaps/no-advertise community.pcapng.cap>)

#### BOOTP

- [DHCP.cap](<pcaps/DHCP.cap>)
- [DHCP_Inter_VLAN.cap](<pcaps/DHCP_Inter_VLAN.cap>)
- [DHCP_MessageType 10,11,12 and 13.cap](<pcaps/DHCP_MessageType 10,11,12 and 13.cap>)
- [dhcp-auth.cap](<pcaps/dhcp-auth.cap>)
- [packet-c.cap](<pcaps/packet-c.cap>)

#### CDP

- [3560_CDP.cap](<pcaps/3560_CDP.cap>)
- [3725_CDP.cap](<pcaps/3725_CDP.cap>)
- [802.1Q_tunneling.cap](<pcaps/802.1Q_tunneling.cap>)
- [HDLC.cap](<pcaps/HDLC.cap>)
- [LLDP_and_CDP.cap](<pcaps/LLDP_and_CDP.cap>)
- [OSPF_Down-Bit.cap](<pcaps/OSPF_Down-Bit.cap>)
- [PPP.cap](<pcaps/PPP.cap>)
- [PPP_EAP.cap](<pcaps/PPP_EAP.cap>)
- [PPP_negotiation.cap](<pcaps/PPP_negotiation.cap>)
- [arp_pcap.pcapng.cap](<pcaps/arp_pcap.pcapng.cap>)

#### CDPCP

- [PPP_EAP.cap](<pcaps/PPP_EAP.cap>)
- [PPP_negotiation.cap](<pcaps/PPP_negotiation.cap>)

#### CHAP

- [PPP_negotiation.cap](<pcaps/PPP_negotiation.cap>)

#### DEC_DNA

- [DECnet_Phone.pcap.cap](<pcaps/DECnet_Phone.pcap.cap>)

#### DHCPV6

- [DHCPv6.cap](<pcaps/DHCPv6.cap>)
- [gmail.pcapng.cap](<pcaps/gmail.pcapng.cap>)

#### DNS

- [DNS Question & Answer.pcapng.cap](<pcaps/DNS Question & Answer.pcapng.cap>)
- [OCSP-Good.cap](<pcaps/OCSP-Good.cap>)
- [Open Network Connection.pcapng.cap](<pcaps/Open Network Connection.pcapng.cap>)
- [dns-zone-transfer-axfr.cap](<pcaps/dns-zone-transfer-axfr.cap>)
- [dns-zone-transfer-ixfr.cap](<pcaps/dns-zone-transfer-ixfr.cap>)
- [gmail.pcapng.cap](<pcaps/gmail.pcapng.cap>)
- [iphttps.cap](<pcaps/iphttps.cap>)
- [packet-c.cap](<pcaps/packet-c.cap>)
- [rpvstp-access.pcap.cap](<pcaps/rpvstp-access.pcap.cap>)

#### DTP

- [DTP.cap](<pcaps/DTP.cap>)
- [rpvstp-trunk-native-vid1.pcap.cap](<pcaps/rpvstp-trunk-native-vid1.pcap.cap>)
- [rpvstp-trunk-native-vid5.pcap.cap](<pcaps/rpvstp-trunk-native-vid5.pcap.cap>)

#### DVMRP

- [mrinfo_query.cap](<pcaps/mrinfo_query.cap>)

#### EAP

- [PPP_EAP.cap](<pcaps/PPP_EAP.cap>)

#### EAPoL

- [802.1X.cap](<pcaps/802.1X.cap>)

#### EIGRP

- [EIGRP_adjacency.cap](<pcaps/EIGRP_adjacency.cap>)
- [EIGRP_goodbye.cap](<pcaps/EIGRP_goodbye.cap>)
- [EIGRP_subnet_down.cap](<pcaps/EIGRP_subnet_down.cap>)
- [EIGRP_subnet_up.cap](<pcaps/EIGRP_subnet_up.cap>)
- [EIGRPv2_adjacency.cap](<pcaps/EIGRPv2_adjacency.cap>)
- [EIGRPv2_subnet_transition.cap](<pcaps/EIGRPv2_subnet_transition.cap>)

#### ESP

- [IPsec_ESP-AH_tunnel_mode.cap](<pcaps/IPsec_ESP-AH_tunnel_mode.cap>)
- [IPv6-ESP.pcapng.cap](<pcaps/IPv6-ESP.pcapng.cap>)

#### Ethernet

- [3560_CDP.cap](<pcaps/3560_CDP.cap>)
- [3725_CDP.cap](<pcaps/3725_CDP.cap>)
- [802.1D_spanning_tree.cap](<pcaps/802.1D_spanning_tree.cap>)
- [802.1Q_tunneling.cap](<pcaps/802.1Q_tunneling.cap>)
- [802.1X.cap](<pcaps/802.1X.cap>)
- [802.1w_rapid_STP.cap](<pcaps/802.1w_rapid_STP.cap>)
- [Auto-RP.cap](<pcaps/Auto-RP.cap>)
- [BGP_AS_set.cap](<pcaps/BGP_AS_set.cap>)
- [BGP_MD5.cap](<pcaps/BGP_MD5.cap>)
- [BGP_MP_NLRI.cap](<pcaps/BGP_MP_NLRI.cap>)
- [BGP_hard_reset.cap](<pcaps/BGP_hard_reset.cap>)
- [BGP_notification.cap](<pcaps/BGP_notification.cap>)
- [BGP_soft_reset.cap](<pcaps/BGP_soft_reset.cap>)
- [DECnet_Phone.pcap.cap](<pcaps/DECnet_Phone.pcap.cap>)
- [DHCP.cap](<pcaps/DHCP.cap>)
- [DHCP_Inter_VLAN.cap](<pcaps/DHCP_Inter_VLAN.cap>)
- [DHCP_MessageType 10,11,12 and 13.cap](<pcaps/DHCP_MessageType 10,11,12 and 13.cap>)
- [DTP.cap](<pcaps/DTP.cap>)
- [EBGP_adjacency.cap](<pcaps/EBGP_adjacency.cap>)
- [EIGRP_adjacency.cap](<pcaps/EIGRP_adjacency.cap>)
- [EIGRP_goodbye.cap](<pcaps/EIGRP_goodbye.cap>)
- [EIGRP_subnet_down.cap](<pcaps/EIGRP_subnet_down.cap>)
- [EIGRP_subnet_up.cap](<pcaps/EIGRP_subnet_up.cap>)
- [EIGRPv2_adjacency.cap](<pcaps/EIGRPv2_adjacency.cap>)
- [EIGRPv2_subnet_transition.cap](<pcaps/EIGRPv2_subnet_transition.cap>)
- [EoMPLS.cap](<pcaps/EoMPLS.cap>)
- [EoMPLS_802.1q.pcap.cap](<pcaps/EoMPLS_802.1q.pcap.cap>)
- [Ethernet_keepalives.cap](<pcaps/Ethernet_keepalives.cap>)
- [Frame-Relay over MPLS.pcap.cap](<pcaps/Frame-Relay over MPLS.pcap.cap>)
- [GLBP_election.cap](<pcaps/GLBP_election.cap>)
- [GRE.cap](<pcaps/GRE.cap>)
- [HSRP_coup.cap](<pcaps/HSRP_coup.cap>)
- [HSRP_election.cap](<pcaps/HSRP_election.cap>)
- [HSRP_failover.cap](<pcaps/HSRP_failover.cap>)
- [HTTP.cap](<pcaps/HTTP.cap>)
- [IBGP_adjacency.cap](<pcaps/IBGP_adjacency.cap>)
- [ICMP_across_dot1q.cap](<pcaps/ICMP_across_dot1q.cap>)
- [ICMP_over_L2TPv3_Pseudowire.pcap.cap](<pcaps/ICMP_over_L2TPv3_Pseudowire.pcap.cap>)
- [ICMPv6_echos.cap](<pcaps/ICMPv6_echos.cap>)
- [IGMPv2_query_and_report.cap](<pcaps/IGMPv2_query_and_report.cap>)
- [IP_in_IP.cap](<pcaps/IP_in_IP.cap>)
- [IPsec_ESP-AH_tunnel_mode.cap](<pcaps/IPsec_ESP-AH_tunnel_mode.cap>)
- [IPv6_NDP.cap](<pcaps/IPv6_NDP.cap>)
- [IPv6_in_IP.cap](<pcaps/IPv6_in_IP.cap>)
- [ISAKMP_sa_setup.cap](<pcaps/ISAKMP_sa_setup.cap>)
- [ISIS_external_lsp.cap](<pcaps/ISIS_external_lsp.cap>)
- [ISIS_level1_adjacency.cap](<pcaps/ISIS_level1_adjacency.cap>)
- [ISIS_level2_adjacency.cap](<pcaps/ISIS_level2_adjacency.cap>)
- [LACP.cap](<pcaps/LACP.cap>)
- [LDP_Ethernet_FrameRelay.pcap.cap](<pcaps/LDP_Ethernet_FrameRelay.pcap.cap>)
- [LDP_adjacency.cap](<pcaps/LDP_adjacency.cap>)
- [LLDP_and_CDP.cap](<pcaps/LLDP_and_CDP.cap>)
- [MPLS_encapsulation.cap](<pcaps/MPLS_encapsulation.cap>)
- [MSDP.cap](<pcaps/MSDP.cap>)
- [NHRP_registration.cap](<pcaps/NHRP_registration.cap>)
- [OSPF_LSA_types.cap](<pcaps/OSPF_LSA_types.cap>)
- [OSPF_broadcast_adjacencies.cap](<pcaps/OSPF_broadcast_adjacencies.cap>)
- [OSPF_type7_LSA.cap](<pcaps/OSPF_type7_LSA.cap>)
- [OSPF_with_MD5_auth.cap](<pcaps/OSPF_with_MD5_auth.cap>)
- [OSPFv3_broadcast_adjacency.cap](<pcaps/OSPFv3_broadcast_adjacency.cap>)
- [OSPFv3_with_AH.cap](<pcaps/OSPFv3_with_AH.cap>)
- [PAGP.cap](<pcaps/PAGP.cap>)
- [PIM-DM_pruning.cap](<pcaps/PIM-DM_pruning.cap>)
- [PIM-SM_join_prune.cap](<pcaps/PIM-SM_join_prune.cap>)
- [PIM_register_register-stop.cap](<pcaps/PIM_register_register-stop.cap>)
- [PIMv2_bootstrap.cap](<pcaps/PIMv2_bootstrap.cap>)
- [PIMv2_hellos.cap](<pcaps/PIMv2_hellos.cap>)
- [PPPoE_Dual-Stack_IPv4_IPv6-with_DHCPv6.cap](<pcaps/PPPoE_Dual-Stack_IPv4_IPv6-with_DHCPv6.cap>)
- [QinQ.pcap.cap](<pcaps/QinQ.pcap.cap>)
- [RADIUS.cap](<pcaps/RADIUS.cap>)
- [RIPv1.cap](<pcaps/RIPv1.cap>)
- [RIPv1_subnet_down.cap](<pcaps/RIPv1_subnet_down.cap>)
- [RIPv2.cap](<pcaps/RIPv2.cap>)
- [RIPv2_subnet_down.cap](<pcaps/RIPv2_subnet_down.cap>)
- [SNMPv2c_get_requests.cap](<pcaps/SNMPv2c_get_requests.cap>)
- [SSHv2.cap](<pcaps/SSHv2.cap>)
- [TACACS+_encrypted.cap](<pcaps/TACACS+_encrypted.cap>)
- [TCP_SACK.cap](<pcaps/TCP_SACK.cap>)
- [TDP.cap](<pcaps/TDP.cap>)
- [UDLD.cap](<pcaps/UDLD.cap>)
- [VRRP_failover.cap](<pcaps/VRRP_failover.cap>)
- [VRRP_preempt.cap](<pcaps/VRRP_preempt.cap>)
- [WCCPv2.pcap.cap](<pcaps/WCCPv2.pcap.cap>)
- [cm4116_telnet.cap](<pcaps/cm4116_telnet.cap>)
- [iphttps.cap](<pcaps/iphttps.cap>)
- [ipv6_neighbor_spoofing.cap](<pcaps/ipv6_neighbor_spoofing.cap>)
- [mGRE_ICMP.cap](<pcaps/mGRE_ICMP.cap>)
- [mrinfo_query.cap](<pcaps/mrinfo_query.cap>)
- [mtrace.cap](<pcaps/mtrace.cap>)
- [path_MTU_discovery.cap](<pcaps/path_MTU_discovery.cap>)
- [rpvstp-access.pcap.cap](<pcaps/rpvstp-access.pcap.cap>)
- [rpvstp-trunk-native-vid1.pcap.cap](<pcaps/rpvstp-trunk-native-vid1.pcap.cap>)
- [rpvstp-trunk-native-vid5.pcap.cap](<pcaps/rpvstp-trunk-native-vid5.pcap.cap>)
- [telnet.cap](<pcaps/telnet.cap>)

#### FC

- [FCoE_Flogi_FDisc_Negotiation.cap](<pcaps/FCoE_Flogi_FDisc_Negotiation.cap>)

#### FCCT

- [FCoE_Flogi_FDisc_Negotiation.cap](<pcaps/FCoE_Flogi_FDisc_Negotiation.cap>)

#### FCDNS

- [FCoE_Flogi_FDisc_Negotiation.cap](<pcaps/FCoE_Flogi_FDisc_Negotiation.cap>)

#### FCELS

- [FCoE_Flogi_FDisc_Negotiation.cap](<pcaps/FCoE_Flogi_FDisc_Negotiation.cap>)

#### FCOE

- [FCoE_Flogi_FDisc_Negotiation.cap](<pcaps/FCoE_Flogi_FDisc_Negotiation.cap>)

#### FIP

- [FCoE_Flogi_FDisc_Negotiation.cap](<pcaps/FCoE_Flogi_FDisc_Negotiation.cap>)

#### Frame Relay

- [ICMP_across_frame_relay.cap](<pcaps/ICMP_across_frame_relay.cap>)
- [OSPF_NBMA_adjacencies.cap](<pcaps/OSPF_NBMA_adjacencies.cap>)
- [OSPF_multipoint_adjacencies.cap](<pcaps/OSPF_multipoint_adjacencies.cap>)
- [OSPF_point-to-point_adjacencies.cap](<pcaps/OSPF_point-to-point_adjacencies.cap>)
- [OSPFv3_NBMA_adjacencies.cap](<pcaps/OSPFv3_NBMA_adjacencies.cap>)
- [OSPFv3_multipoint_adjacencies.cap](<pcaps/OSPFv3_multipoint_adjacencies.cap>)

#### GLBP

- [GLBP_election.cap](<pcaps/GLBP_election.cap>)

#### GRE

- [GRE.cap](<pcaps/GRE.cap>)
- [NHRP_registration.cap](<pcaps/NHRP_registration.cap>)
- [PPTP_negotiation.cap](<pcaps/PPTP_negotiation.cap>)
- [gre_and_4over6.cap](<pcaps/gre_and_4over6.cap>)
- [mGRE_ICMP.cap](<pcaps/mGRE_ICMP.cap>)
- [ospf over gre tunnel.cap](<pcaps/ospf over gre tunnel.cap>)

#### H225

- [snoop-working-ccm7.cap](<pcaps/snoop-working-ccm7.cap>)

#### HDLC

- [4-byte_AS_numbers_Full_Support.cap](<pcaps/4-byte_AS_numbers_Full_Support.cap>)
- [4-byte_AS_numbers_Mixed_Scenario.cap](<pcaps/4-byte_AS_numbers_Mixed_Scenario.cap>)
- [BGP_redist.cap](<pcaps/BGP_redist.cap>)
- [HDLC.cap](<pcaps/HDLC.cap>)
- [ISIS_p2p_adjacency.cap](<pcaps/ISIS_p2p_adjacency.cap>)
- [OSPF_Down-Bit.cap](<pcaps/OSPF_Down-Bit.cap>)

#### HSRP

- [HSRP_coup.cap](<pcaps/HSRP_coup.cap>)
- [HSRP_election.cap](<pcaps/HSRP_election.cap>)
- [HSRP_failover.cap](<pcaps/HSRP_failover.cap>)

#### HTTP

- [HTTP.cap](<pcaps/HTTP.cap>)
- [OCSP-Good.cap](<pcaps/OCSP-Good.cap>)
- [OCSP-Not_Implemted.cap](<pcaps/OCSP-Not_Implemted.cap>)
- [OCSP-Revoked.cap](<pcaps/OCSP-Revoked.cap>)
- [Open Network Connection.pcapng.cap](<pcaps/Open Network Connection.pcapng.cap>)
- [TCP_SACK.cap](<pcaps/TCP_SACK.cap>)
- [gmail.pcapng.cap](<pcaps/gmail.pcapng.cap>)
- [packet-c.cap](<pcaps/packet-c.cap>)

#### ICMP

- [HDLC.cap](<pcaps/HDLC.cap>)
- [ICMP_across_dot1q.cap](<pcaps/ICMP_across_dot1q.cap>)
- [ICMP_across_frame_relay.cap](<pcaps/ICMP_across_frame_relay.cap>)
- [IP_in_IP.cap](<pcaps/IP_in_IP.cap>)
- [MPLS_encapsulation.cap](<pcaps/MPLS_encapsulation.cap>)
- [PPP.cap](<pcaps/PPP.cap>)
- [PPP_negotiation.cap](<pcaps/PPP_negotiation.cap>)
- [icmp fragmented.cap](<pcaps/icmp fragmented.cap>)
- [icmp with record route option set.cap](<pcaps/icmp with record route option set.cap>)
- [path_MTU_discovery.cap](<pcaps/path_MTU_discovery.cap>)
- [traceroute_MPLS.cap](<pcaps/traceroute_MPLS.cap>)

#### ICMPv6

- [6in4-linklocal-hlimit-less255.pcapng.cap](<pcaps/6in4-linklocal-hlimit-less255.pcapng.cap>)
- [DHCPv6.cap](<pcaps/DHCPv6.cap>)
- [ICMPv6_echos.cap](<pcaps/ICMPv6_echos.cap>)
- [IPv6_NDP.cap](<pcaps/IPv6_NDP.cap>)
- [IPv6_in_IP.cap](<pcaps/IPv6_in_IP.cap>)
- [iphttps.cap](<pcaps/iphttps.cap>)
- [ipv6_neighbor_spoofing.cap](<pcaps/ipv6_neighbor_spoofing.cap>)

#### IEEE8021AD

- [802_1ad.pcapng.cap](<pcaps/802_1ad.pcapng.cap>)

#### IGMP

- [IGMP_V1.cap](<pcaps/IGMP_V1.cap>)
- [IGMP_V2.cap](<pcaps/IGMP_V2.cap>)
- [IGMPv2_query_and_report.cap](<pcaps/IGMPv2_query_and_report.cap>)
- [PIM-SM_join_prune.cap](<pcaps/PIM-SM_join_prune.cap>)
- [iphttps.cap](<pcaps/iphttps.cap>)
- [mrinfo_query.cap](<pcaps/mrinfo_query.cap>)
- [mtrace.cap](<pcaps/mtrace.cap>)

#### IP

- [4-byte_AS_numbers_Full_Support.cap](<pcaps/4-byte_AS_numbers_Full_Support.cap>)
- [4-byte_AS_numbers_Mixed_Scenario.cap](<pcaps/4-byte_AS_numbers_Mixed_Scenario.cap>)
- [6in4-linklocal-hlimit-less255.pcapng.cap](<pcaps/6in4-linklocal-hlimit-less255.pcapng.cap>)
- [802.1Q_tunneling.cap](<pcaps/802.1Q_tunneling.cap>)
- [802_1ad.pcapng.cap](<pcaps/802_1ad.pcapng.cap>)
- [Auto-RP.cap](<pcaps/Auto-RP.cap>)
- [BGP_AS_set.cap](<pcaps/BGP_AS_set.cap>)
- [BGP_MD5.cap](<pcaps/BGP_MD5.cap>)
- [BGP_MP_NLRI.cap](<pcaps/BGP_MP_NLRI.cap>)
- [BGP_hard_reset.cap](<pcaps/BGP_hard_reset.cap>)
- [BGP_notification.cap](<pcaps/BGP_notification.cap>)
- [BGP_redist.cap](<pcaps/BGP_redist.cap>)
- [BGP_soft_reset.cap](<pcaps/BGP_soft_reset.cap>)
- [DHCP.cap](<pcaps/DHCP.cap>)
- [DHCP_Inter_VLAN.cap](<pcaps/DHCP_Inter_VLAN.cap>)
- [DHCP_MessageType 10,11,12 and 13.cap](<pcaps/DHCP_MessageType 10,11,12 and 13.cap>)
- [DNS Question & Answer.pcapng.cap](<pcaps/DNS Question & Answer.pcapng.cap>)
- [EBGP_adjacency.cap](<pcaps/EBGP_adjacency.cap>)
- [EIGRP_adjacency.cap](<pcaps/EIGRP_adjacency.cap>)
- [EIGRP_goodbye.cap](<pcaps/EIGRP_goodbye.cap>)
- [EIGRP_subnet_down.cap](<pcaps/EIGRP_subnet_down.cap>)
- [EIGRP_subnet_up.cap](<pcaps/EIGRP_subnet_up.cap>)
- [EoMPLS.cap](<pcaps/EoMPLS.cap>)
- [GLBP_election.cap](<pcaps/GLBP_election.cap>)
- [GRE.cap](<pcaps/GRE.cap>)
- [HDLC.cap](<pcaps/HDLC.cap>)
- [HSRP_coup.cap](<pcaps/HSRP_coup.cap>)
- [HSRP_election.cap](<pcaps/HSRP_election.cap>)
- [HSRP_failover.cap](<pcaps/HSRP_failover.cap>)
- [HTTP.cap](<pcaps/HTTP.cap>)
- [IBGP_adjacency.cap](<pcaps/IBGP_adjacency.cap>)
- [ICMP_across_dot1q.cap](<pcaps/ICMP_across_dot1q.cap>)
- [ICMP_across_frame_relay.cap](<pcaps/ICMP_across_frame_relay.cap>)
- [ICMP_over_L2TPv3_Pseudowire.pcap.cap](<pcaps/ICMP_over_L2TPv3_Pseudowire.pcap.cap>)
- [IGMP_V1.cap](<pcaps/IGMP_V1.cap>)
- [IGMP_V2.cap](<pcaps/IGMP_V2.cap>)
- [IGMPv2_query_and_report.cap](<pcaps/IGMPv2_query_and_report.cap>)
- [IP_in_IP.cap](<pcaps/IP_in_IP.cap>)
- [IPsec_ESP-AH_tunnel_mode.cap](<pcaps/IPsec_ESP-AH_tunnel_mode.cap>)
- [IPv6_RTSP.cap](<pcaps/IPv6_RTSP.cap>)
- [IPv6_in_IP.cap](<pcaps/IPv6_in_IP.cap>)
- [ISAKMP_sa_setup.cap](<pcaps/ISAKMP_sa_setup.cap>)
- [LDP_Ethernet_FrameRelay.pcap.cap](<pcaps/LDP_Ethernet_FrameRelay.pcap.cap>)
- [LDP_adjacency.cap](<pcaps/LDP_adjacency.cap>)
- [MPLS_encapsulation.cap](<pcaps/MPLS_encapsulation.cap>)
- [MSDP.cap](<pcaps/MSDP.cap>)
- [NHRP_registration.cap](<pcaps/NHRP_registration.cap>)
- [OCSP-Good.cap](<pcaps/OCSP-Good.cap>)
- [OCSP-Not_Implemted.cap](<pcaps/OCSP-Not_Implemted.cap>)
- [OCSP-Revoked.cap](<pcaps/OCSP-Revoked.cap>)
- [OSPF_Down-Bit.cap](<pcaps/OSPF_Down-Bit.cap>)
- [OSPF_LSA_types.cap](<pcaps/OSPF_LSA_types.cap>)
- [OSPF_NBMA_adjacencies.cap](<pcaps/OSPF_NBMA_adjacencies.cap>)
- [OSPF_broadcast_adjacencies.cap](<pcaps/OSPF_broadcast_adjacencies.cap>)
- [OSPF_multipoint_adjacencies.cap](<pcaps/OSPF_multipoint_adjacencies.cap>)
- [OSPF_point-to-point_adjacencies.cap](<pcaps/OSPF_point-to-point_adjacencies.cap>)
- [OSPF_type7_LSA.cap](<pcaps/OSPF_type7_LSA.cap>)
- [OSPF_with_MD5_auth.cap](<pcaps/OSPF_with_MD5_auth.cap>)
- [Open Network Connection.pcapng.cap](<pcaps/Open Network Connection.pcapng.cap>)
- [PIM-DM_pruning.cap](<pcaps/PIM-DM_pruning.cap>)
- [PIM-SM_join_prune.cap](<pcaps/PIM-SM_join_prune.cap>)
- [PIM_register_register-stop.cap](<pcaps/PIM_register_register-stop.cap>)
- [PIMv2_bootstrap.cap](<pcaps/PIMv2_bootstrap.cap>)
- [PIMv2_hellos.cap](<pcaps/PIMv2_hellos.cap>)
- [PPP.cap](<pcaps/PPP.cap>)
- [PPP_TCP_compression.cap](<pcaps/PPP_TCP_compression.cap>)
- [PPP_negotiation.cap](<pcaps/PPP_negotiation.cap>)
- [PPTP_negotiation.cap](<pcaps/PPTP_negotiation.cap>)
- [RADIUS.cap](<pcaps/RADIUS.cap>)
- [RIPv1.cap](<pcaps/RIPv1.cap>)
- [RIPv1_subnet_down.cap](<pcaps/RIPv1_subnet_down.cap>)
- [RIPv2.cap](<pcaps/RIPv2.cap>)
- [RIPv2_subnet_down.cap](<pcaps/RIPv2_subnet_down.cap>)
- [SNMPv2c_get_requests.cap](<pcaps/SNMPv2c_get_requests.cap>)
- [SNMPv3.cap](<pcaps/SNMPv3.cap>)
- [SSHv2.cap](<pcaps/SSHv2.cap>)
- [TACACS+_encrypted.cap](<pcaps/TACACS+_encrypted.cap>)
- [TCP_SACK.cap](<pcaps/TCP_SACK.cap>)
- [TDP.cap](<pcaps/TDP.cap>)
- [VRRP_Malformed_DoS.cap](<pcaps/VRRP_Malformed_DoS.cap>)
- [VRRP_failover.cap](<pcaps/VRRP_failover.cap>)
- [VRRP_preempt.cap](<pcaps/VRRP_preempt.cap>)
- [WCCPv2.pcap.cap](<pcaps/WCCPv2.pcap.cap>)
- [address withdrawal ldp.pcapng.cap](<pcaps/address withdrawal ldp.pcapng.cap>)
- [arp_l2tpv3.cap](<pcaps/arp_l2tpv3.cap>)
- [bgp as confed sequence.pcapng.cap](<pcaps/bgp as confed sequence.pcapng.cap>)
- [bgp med.pcapng.cap](<pcaps/bgp med.pcapng.cap>)
- [bgp orf capabilty negotitation.pcapng.cap](<pcaps/bgp orf capabilty negotitation.pcapng.cap>)
- [bgp orf prefix advertisement.pcapng.cap](<pcaps/bgp orf prefix advertisement.pcapng.cap>)
- [bgp-add-path.cap](<pcaps/bgp-add-path.cap>)
- [bgplu.cap](<pcaps/bgplu.cap>)
- [cflow.cap](<pcaps/cflow.cap>)
- [cm4116_telnet.cap](<pcaps/cm4116_telnet.cap>)
- [connection termination.cap](<pcaps/connection termination.cap>)
- [dhcp-auth.cap](<pcaps/dhcp-auth.cap>)
- [dns-zone-transfer-axfr.cap](<pcaps/dns-zone-transfer-axfr.cap>)
- [dns-zone-transfer-ixfr.cap](<pcaps/dns-zone-transfer-ixfr.cap>)
- [dtls_null.cap](<pcaps/dtls_null.cap>)
- [gmail.pcapng.cap](<pcaps/gmail.pcapng.cap>)
- [gre_and_4over6.cap](<pcaps/gre_and_4over6.cap>)
- [icmp fragmented.cap](<pcaps/icmp fragmented.cap>)
- [icmp with record route option set.cap](<pcaps/icmp with record route option set.cap>)
- [icmp_in_l2tpv3.cap](<pcaps/icmp_in_l2tpv3.cap>)
- [iphttps.cap](<pcaps/iphttps.cap>)
- [ipv4-smtp.cap](<pcaps/ipv4-smtp.cap>)
- [lispmn_IPv6-RLOC.pcapng.cap](<pcaps/lispmn_IPv6-RLOC.pcapng.cap>)
- [mGRE_ICMP.cap](<pcaps/mGRE_ICMP.cap>)
- [mpls address label mapping.pcapng.cap](<pcaps/mpls address label mapping.pcapng.cap>)
- [mrinfo_query.cap](<pcaps/mrinfo_query.cap>)
- [mtrace.cap](<pcaps/mtrace.cap>)
- [nf9-juniper-vmx.pcapng.cap](<pcaps/nf9-juniper-vmx.pcapng.cap>)
- [no-advertise community.pcapng.cap](<pcaps/no-advertise community.pcapng.cap>)
- [ospf over gre tunnel.cap](<pcaps/ospf over gre tunnel.cap>)
- [ospf simple password authentication.cap](<pcaps/ospf simple password authentication.cap>)
- [packet-c.cap](<pcaps/packet-c.cap>)
- [path_MTU_discovery.cap](<pcaps/path_MTU_discovery.cap>)
- [rpvstp-access.pcap.cap](<pcaps/rpvstp-access.pcap.cap>)
- [sflow.cap](<pcaps/sflow.cap>)
- [snmp-ipv4.cap](<pcaps/snmp-ipv4.cap>)
- [snoop-working-ccm7.cap](<pcaps/snoop-working-ccm7.cap>)
- [stun2.cap](<pcaps/stun2.cap>)
- [telnet.cap](<pcaps/telnet.cap>)
- [traceroute_MPLS.cap](<pcaps/traceroute_MPLS.cap>)

#### IPCP

- [PPP_EAP.cap](<pcaps/PPP_EAP.cap>)
- [PPP_negotiation.cap](<pcaps/PPP_negotiation.cap>)
- [PPPoE_Dual-Stack_IPv4_IPv6-with_DHCPv6.cap](<pcaps/PPPoE_Dual-Stack_IPv4_IPv6-with_DHCPv6.cap>)
- [PPTP_negotiation.cap](<pcaps/PPTP_negotiation.cap>)

#### IPV6CP

- [PPPoE_Dual-Stack_IPv4_IPv6-with_DHCPv6.cap](<pcaps/PPPoE_Dual-Stack_IPv4_IPv6-with_DHCPv6.cap>)

#### IPv6

- [6in4-linklocal-hlimit-less255.pcapng.cap](<pcaps/6in4-linklocal-hlimit-less255.pcapng.cap>)
- [BGP_MP_NLRI.cap](<pcaps/BGP_MP_NLRI.cap>)
- [DHCPv6.cap](<pcaps/DHCPv6.cap>)
- [EIGRPv2_adjacency.cap](<pcaps/EIGRPv2_adjacency.cap>)
- [EIGRPv2_subnet_transition.cap](<pcaps/EIGRPv2_subnet_transition.cap>)
- [ICMPv6_echos.cap](<pcaps/ICMPv6_echos.cap>)
- [IPv6-ESP.pcapng.cap](<pcaps/IPv6-ESP.pcapng.cap>)
- [IPv6_NDP.cap](<pcaps/IPv6_NDP.cap>)
- [IPv6_in_IP.cap](<pcaps/IPv6_in_IP.cap>)
- [OSPFv3_NBMA_adjacencies.cap](<pcaps/OSPFv3_NBMA_adjacencies.cap>)
- [OSPFv3_broadcast_adjacency.cap](<pcaps/OSPFv3_broadcast_adjacency.cap>)
- [OSPFv3_multipoint_adjacencies.cap](<pcaps/OSPFv3_multipoint_adjacencies.cap>)
- [OSPFv3_with_AH.cap](<pcaps/OSPFv3_with_AH.cap>)
- [PPPoE_Dual-Stack_IPv4_IPv6-with_DHCPv6.cap](<pcaps/PPPoE_Dual-Stack_IPv4_IPv6-with_DHCPv6.cap>)
- [gmail.pcapng.cap](<pcaps/gmail.pcapng.cap>)
- [gre_and_4over6.cap](<pcaps/gre_and_4over6.cap>)
- [iphttps.cap](<pcaps/iphttps.cap>)
- [ipv6-smtp.pcapng.cap](<pcaps/ipv6-smtp.pcapng.cap>)
- [ipv6_neighbor_spoofing.cap](<pcaps/ipv6_neighbor_spoofing.cap>)
- [lispmn_IPv6-RLOC.pcapng.cap](<pcaps/lispmn_IPv6-RLOC.pcapng.cap>)
- [snmp-ipv6.cap](<pcaps/snmp-ipv6.cap>)

#### ISAKMP

- [ISAKMP_sa_setup.cap](<pcaps/ISAKMP_sa_setup.cap>)

#### ISIS

- [ISIS_external_lsp.cap](<pcaps/ISIS_external_lsp.cap>)
- [ISIS_level1_adjacency.cap](<pcaps/ISIS_level1_adjacency.cap>)
- [ISIS_level2_adjacency.cap](<pcaps/ISIS_level2_adjacency.cap>)
- [ISIS_p2p_adjacency.cap](<pcaps/ISIS_p2p_adjacency.cap>)

#### ISL

- [DTP.cap](<pcaps/DTP.cap>)

#### L2TP

- [ICMP_over_L2TPv3_Pseudowire.pcap.cap](<pcaps/ICMP_over_L2TPv3_Pseudowire.pcap.cap>)
- [arp_l2tpv3.cap](<pcaps/arp_l2tpv3.cap>)
- [icmp_in_l2tpv3.cap](<pcaps/icmp_in_l2tpv3.cap>)

#### L2TP.L2_SPEC_DEF

- [arp_l2tpv3.cap](<pcaps/arp_l2tpv3.cap>)
- [icmp_in_l2tpv3.cap](<pcaps/icmp_in_l2tpv3.cap>)

#### LACP

- [LACP.cap](<pcaps/LACP.cap>)

#### LCP

- [PPP.cap](<pcaps/PPP.cap>)
- [PPP_EAP.cap](<pcaps/PPP_EAP.cap>)
- [PPP_TCP_compression.cap](<pcaps/PPP_TCP_compression.cap>)
- [PPP_negotiation.cap](<pcaps/PPP_negotiation.cap>)
- [PPPoE_Dual-Stack_IPv4_IPv6-with_DHCPv6.cap](<pcaps/PPPoE_Dual-Stack_IPv4_IPv6-with_DHCPv6.cap>)
- [PPTP_negotiation.cap](<pcaps/PPTP_negotiation.cap>)

#### LDP

- [LDP_Ethernet_FrameRelay.pcap.cap](<pcaps/LDP_Ethernet_FrameRelay.pcap.cap>)
- [LDP_adjacency.cap](<pcaps/LDP_adjacency.cap>)
- [address withdrawal ldp.pcapng.cap](<pcaps/address withdrawal ldp.pcapng.cap>)
- [mpls address label mapping.pcapng.cap](<pcaps/mpls address label mapping.pcapng.cap>)

#### LISP

- [lispmn_IPv6-RLOC.pcapng.cap](<pcaps/lispmn_IPv6-RLOC.pcapng.cap>)

#### LISP-DATA

- [lispmn_IPv6-RLOC.pcapng.cap](<pcaps/lispmn_IPv6-RLOC.pcapng.cap>)

#### LLC

- [3560_CDP.cap](<pcaps/3560_CDP.cap>)
- [3725_CDP.cap](<pcaps/3725_CDP.cap>)
- [802.1D_spanning_tree.cap](<pcaps/802.1D_spanning_tree.cap>)
- [802.1Q_tunneling.cap](<pcaps/802.1Q_tunneling.cap>)
- [802.1w_rapid_STP.cap](<pcaps/802.1w_rapid_STP.cap>)
- [DTP.cap](<pcaps/DTP.cap>)
- [ISIS_external_lsp.cap](<pcaps/ISIS_external_lsp.cap>)
- [ISIS_level1_adjacency.cap](<pcaps/ISIS_level1_adjacency.cap>)
- [ISIS_level2_adjacency.cap](<pcaps/ISIS_level2_adjacency.cap>)
- [LLDP_and_CDP.cap](<pcaps/LLDP_and_CDP.cap>)
- [MSTP_Intra-Region_BPDUs.cap](<pcaps/MSTP_Intra-Region_BPDUs.cap>)
- [PAGP.cap](<pcaps/PAGP.cap>)
- [STP-TCN-TCAck.pcapng.cap](<pcaps/STP-TCN-TCAck.pcapng.cap>)
- [Spanning Tree - MST.pcapng.cap](<pcaps/Spanning Tree - MST.pcapng.cap>)
- [UDLD.cap](<pcaps/UDLD.cap>)
- [arp_pcap.pcapng.cap](<pcaps/arp_pcap.pcapng.cap>)
- [iphttps.cap](<pcaps/iphttps.cap>)
- [packet-c.cap](<pcaps/packet-c.cap>)
- [rpvstp-access.pcap.cap](<pcaps/rpvstp-access.pcap.cap>)
- [rpvstp-trunk-native-vid1.pcap.cap](<pcaps/rpvstp-trunk-native-vid1.pcap.cap>)
- [rpvstp-trunk-native-vid5.pcap.cap](<pcaps/rpvstp-trunk-native-vid5.pcap.cap>)

#### LLDP

- [LLDP_and_CDP.cap](<pcaps/LLDP_and_CDP.cap>)

#### LMI

- [OSPF_multipoint_adjacencies.cap](<pcaps/OSPF_multipoint_adjacencies.cap>)

#### LOOP

- [EoMPLS.cap](<pcaps/EoMPLS.cap>)
- [Ethernet_keepalives.cap](<pcaps/Ethernet_keepalives.cap>)
- [ICMP_over_L2TPv3_Pseudowire.pcap.cap](<pcaps/ICMP_over_L2TPv3_Pseudowire.pcap.cap>)
- [arp_pcap.pcapng.cap](<pcaps/arp_pcap.pcapng.cap>)
- [rpvstp-access.pcap.cap](<pcaps/rpvstp-access.pcap.cap>)
- [rpvstp-trunk-native-vid1.pcap.cap](<pcaps/rpvstp-trunk-native-vid1.pcap.cap>)
- [rpvstp-trunk-native-vid5.pcap.cap](<pcaps/rpvstp-trunk-native-vid5.pcap.cap>)

#### MEDIA

- [Open Network Connection.pcapng.cap](<pcaps/Open Network Connection.pcapng.cap>)

#### MPLS

- [BGP_redist.cap](<pcaps/BGP_redist.cap>)
- [EoMPLS.cap](<pcaps/EoMPLS.cap>)
- [EoMPLS_802.1q.pcap.cap](<pcaps/EoMPLS_802.1q.pcap.cap>)
- [Frame-Relay over MPLS.pcap.cap](<pcaps/Frame-Relay over MPLS.pcap.cap>)
- [LDP_Ethernet_FrameRelay.pcap.cap](<pcaps/LDP_Ethernet_FrameRelay.pcap.cap>)
- [MPLS_encapsulation.cap](<pcaps/MPLS_encapsulation.cap>)

#### MSDP

- [MSDP.cap](<pcaps/MSDP.cap>)

#### NBDGM

- [Open Network Connection.pcapng.cap](<pcaps/Open Network Connection.pcapng.cap>)

#### NBNS

- [Open Network Connection.pcapng.cap](<pcaps/Open Network Connection.pcapng.cap>)
- [gmail.pcapng.cap](<pcaps/gmail.pcapng.cap>)
- [iphttps.cap](<pcaps/iphttps.cap>)

#### NBSS

- [iphttps.cap](<pcaps/iphttps.cap>)

#### NHRP

- [NHRP_registration.cap](<pcaps/NHRP_registration.cap>)
- [mGRE_ICMP.cap](<pcaps/mGRE_ICMP.cap>)

#### NTP

- [Open Network Connection.pcapng.cap](<pcaps/Open Network Connection.pcapng.cap>)

#### OCSP

- [OCSP-Good.cap](<pcaps/OCSP-Good.cap>)
- [OCSP-Not_Implemted.cap](<pcaps/OCSP-Not_Implemted.cap>)
- [OCSP-Revoked.cap](<pcaps/OCSP-Revoked.cap>)

#### OSPF

- [ICMP_over_L2TPv3_Pseudowire.pcap.cap](<pcaps/ICMP_over_L2TPv3_Pseudowire.pcap.cap>)
- [OSPF_Down-Bit.cap](<pcaps/OSPF_Down-Bit.cap>)
- [OSPF_LSA_types.cap](<pcaps/OSPF_LSA_types.cap>)
- [OSPF_NBMA_adjacencies.cap](<pcaps/OSPF_NBMA_adjacencies.cap>)
- [OSPF_broadcast_adjacencies.cap](<pcaps/OSPF_broadcast_adjacencies.cap>)
- [OSPF_multipoint_adjacencies.cap](<pcaps/OSPF_multipoint_adjacencies.cap>)
- [OSPF_point-to-point_adjacencies.cap](<pcaps/OSPF_point-to-point_adjacencies.cap>)
- [OSPF_type7_LSA.cap](<pcaps/OSPF_type7_LSA.cap>)
- [OSPF_with_MD5_auth.cap](<pcaps/OSPF_with_MD5_auth.cap>)
- [OSPFv3_NBMA_adjacencies.cap](<pcaps/OSPFv3_NBMA_adjacencies.cap>)
- [OSPFv3_broadcast_adjacency.cap](<pcaps/OSPFv3_broadcast_adjacency.cap>)
- [OSPFv3_multipoint_adjacencies.cap](<pcaps/OSPFv3_multipoint_adjacencies.cap>)
- [OSPFv3_with_AH.cap](<pcaps/OSPFv3_with_AH.cap>)
- [ospf over gre tunnel.cap](<pcaps/ospf over gre tunnel.cap>)
- [ospf simple password authentication.cap](<pcaps/ospf simple password authentication.cap>)

#### PAGP

- [PAGP.cap](<pcaps/PAGP.cap>)

#### PAP

- [PPPoE_Dual-Stack_IPv4_IPv6-with_DHCPv6.cap](<pcaps/PPPoE_Dual-Stack_IPv4_IPv6-with_DHCPv6.cap>)
- [PPTP_negotiation.cap](<pcaps/PPTP_negotiation.cap>)

#### PIM

- [PIM-DM_pruning.cap](<pcaps/PIM-DM_pruning.cap>)
- [PIM-SM_join_prune.cap](<pcaps/PIM-SM_join_prune.cap>)
- [PIM_register_register-stop.cap](<pcaps/PIM_register_register-stop.cap>)
- [PIMv2_bootstrap.cap](<pcaps/PIMv2_bootstrap.cap>)
- [PIMv2_hellos.cap](<pcaps/PIMv2_hellos.cap>)

#### PPP

- [PPP.cap](<pcaps/PPP.cap>)
- [PPP_EAP.cap](<pcaps/PPP_EAP.cap>)
- [PPP_TCP_compression.cap](<pcaps/PPP_TCP_compression.cap>)
- [PPP_negotiation.cap](<pcaps/PPP_negotiation.cap>)
- [PPPoE_Dual-Stack_IPv4_IPv6-with_DHCPv6.cap](<pcaps/PPPoE_Dual-Stack_IPv4_IPv6-with_DHCPv6.cap>)
- [PPTP_negotiation.cap](<pcaps/PPTP_negotiation.cap>)

#### PPPOED

- [PPPoE_Dual-Stack_IPv4_IPv6-with_DHCPv6.cap](<pcaps/PPPoE_Dual-Stack_IPv4_IPv6-with_DHCPv6.cap>)

#### PPPOES

- [PPPoE_Dual-Stack_IPv4_IPv6-with_DHCPv6.cap](<pcaps/PPPoE_Dual-Stack_IPv4_IPv6-with_DHCPv6.cap>)

#### PPTP

- [PPTP_negotiation.cap](<pcaps/PPTP_negotiation.cap>)

#### Q931

- [snoop-working-ccm7.cap](<pcaps/snoop-working-ccm7.cap>)

#### Q933

- [OSPF_multipoint_adjacencies.cap](<pcaps/OSPF_multipoint_adjacencies.cap>)

#### RADIUS

- [RADIUS.cap](<pcaps/RADIUS.cap>)

#### RIP

- [RIPv1.cap](<pcaps/RIPv1.cap>)
- [RIPv1_subnet_down.cap](<pcaps/RIPv1_subnet_down.cap>)
- [RIPv2.cap](<pcaps/RIPv2.cap>)
- [RIPv2_subnet_down.cap](<pcaps/RIPv2_subnet_down.cap>)

#### SFLOW

- [sflow.cap](<pcaps/sflow.cap>)

#### SKINNY

- [packet-c.cap](<pcaps/packet-c.cap>)

#### SLARP

- [HDLC.cap](<pcaps/HDLC.cap>)
- [OSPF_Down-Bit.cap](<pcaps/OSPF_Down-Bit.cap>)
- [hdlc slarp.pcapng.cap](<pcaps/hdlc slarp.pcapng.cap>)

#### SMB

- [Open Network Connection.pcapng.cap](<pcaps/Open Network Connection.pcapng.cap>)

#### SMTP

- [ipv4-smtp.cap](<pcaps/ipv4-smtp.cap>)
- [ipv6-smtp.pcapng.cap](<pcaps/ipv6-smtp.pcapng.cap>)

#### SNMP

- [SNMPv2c_get_requests.cap](<pcaps/SNMPv2c_get_requests.cap>)
- [SNMPv3.cap](<pcaps/SNMPv3.cap>)
- [snmp-ipv4.cap](<pcaps/snmp-ipv4.cap>)
- [snmp-ipv6.cap](<pcaps/snmp-ipv6.cap>)

#### SSH

- [SSHv2.cap](<pcaps/SSHv2.cap>)

#### SSL

- [gmail.pcapng.cap](<pcaps/gmail.pcapng.cap>)
- [iphttps.cap](<pcaps/iphttps.cap>)
- [packet-c.cap](<pcaps/packet-c.cap>)

#### STP

- [802.1D_spanning_tree.cap](<pcaps/802.1D_spanning_tree.cap>)
- [802.1w_rapid_STP.cap](<pcaps/802.1w_rapid_STP.cap>)
- [MSTP_Intra-Region_BPDUs.cap](<pcaps/MSTP_Intra-Region_BPDUs.cap>)
- [STP-TCN-TCAck.pcapng.cap](<pcaps/STP-TCN-TCAck.pcapng.cap>)
- [Spanning Tree - MST.pcapng.cap](<pcaps/Spanning Tree - MST.pcapng.cap>)
- [packet-c.cap](<pcaps/packet-c.cap>)
- [rpvstp-access.pcap.cap](<pcaps/rpvstp-access.pcap.cap>)
- [rpvstp-trunk-native-vid1.pcap.cap](<pcaps/rpvstp-trunk-native-vid1.pcap.cap>)
- [rpvstp-trunk-native-vid5.pcap.cap](<pcaps/rpvstp-trunk-native-vid5.pcap.cap>)

#### STUN

- [stun2.cap](<pcaps/stun2.cap>)

#### TACACS+

- [TACACS+_encrypted.cap](<pcaps/TACACS+_encrypted.cap>)

#### TCP

- [4-byte_AS_numbers_Full_Support.cap](<pcaps/4-byte_AS_numbers_Full_Support.cap>)
- [4-byte_AS_numbers_Mixed_Scenario.cap](<pcaps/4-byte_AS_numbers_Mixed_Scenario.cap>)
- [BGP_AS_set.cap](<pcaps/BGP_AS_set.cap>)
- [BGP_MD5.cap](<pcaps/BGP_MD5.cap>)
- [BGP_MP_NLRI.cap](<pcaps/BGP_MP_NLRI.cap>)
- [BGP_hard_reset.cap](<pcaps/BGP_hard_reset.cap>)
- [BGP_notification.cap](<pcaps/BGP_notification.cap>)
- [BGP_redist.cap](<pcaps/BGP_redist.cap>)
- [BGP_soft_reset.cap](<pcaps/BGP_soft_reset.cap>)
- [EBGP_adjacency.cap](<pcaps/EBGP_adjacency.cap>)
- [EoMPLS.cap](<pcaps/EoMPLS.cap>)
- [HTTP.cap](<pcaps/HTTP.cap>)
- [IBGP_adjacency.cap](<pcaps/IBGP_adjacency.cap>)
- [LDP_Ethernet_FrameRelay.pcap.cap](<pcaps/LDP_Ethernet_FrameRelay.pcap.cap>)
- [LDP_adjacency.cap](<pcaps/LDP_adjacency.cap>)
- [MSDP.cap](<pcaps/MSDP.cap>)
- [OCSP-Good.cap](<pcaps/OCSP-Good.cap>)
- [OCSP-Not_Implemted.cap](<pcaps/OCSP-Not_Implemted.cap>)
- [OCSP-Revoked.cap](<pcaps/OCSP-Revoked.cap>)
- [Open Network Connection.pcapng.cap](<pcaps/Open Network Connection.pcapng.cap>)
- [PPP_TCP_compression.cap](<pcaps/PPP_TCP_compression.cap>)
- [PPTP_negotiation.cap](<pcaps/PPTP_negotiation.cap>)
- [SSHv2.cap](<pcaps/SSHv2.cap>)
- [TACACS+_encrypted.cap](<pcaps/TACACS+_encrypted.cap>)
- [TCP_SACK.cap](<pcaps/TCP_SACK.cap>)
- [TDP.cap](<pcaps/TDP.cap>)
- [address withdrawal ldp.pcapng.cap](<pcaps/address withdrawal ldp.pcapng.cap>)
- [bgp as confed sequence.pcapng.cap](<pcaps/bgp as confed sequence.pcapng.cap>)
- [bgp med.pcapng.cap](<pcaps/bgp med.pcapng.cap>)
- [bgp orf capabilty negotitation.pcapng.cap](<pcaps/bgp orf capabilty negotitation.pcapng.cap>)
- [bgp orf prefix advertisement.pcapng.cap](<pcaps/bgp orf prefix advertisement.pcapng.cap>)
- [bgp-add-path.cap](<pcaps/bgp-add-path.cap>)
- [bgplu.cap](<pcaps/bgplu.cap>)
- [cm4116_telnet.cap](<pcaps/cm4116_telnet.cap>)
- [connection termination.cap](<pcaps/connection termination.cap>)
- [dns-zone-transfer-axfr.cap](<pcaps/dns-zone-transfer-axfr.cap>)
- [gmail.pcapng.cap](<pcaps/gmail.pcapng.cap>)
- [iphttps.cap](<pcaps/iphttps.cap>)
- [ipv4-smtp.cap](<pcaps/ipv4-smtp.cap>)
- [ipv6-smtp.pcapng.cap](<pcaps/ipv6-smtp.pcapng.cap>)
- [mpls address label mapping.pcapng.cap](<pcaps/mpls address label mapping.pcapng.cap>)
- [no-advertise community.pcapng.cap](<pcaps/no-advertise community.pcapng.cap>)
- [packet-c.cap](<pcaps/packet-c.cap>)
- [snoop-working-ccm7.cap](<pcaps/snoop-working-ccm7.cap>)
- [telnet.cap](<pcaps/telnet.cap>)

#### TDP

- [TDP.cap](<pcaps/TDP.cap>)

#### TEREDO

- [gmail.pcapng.cap](<pcaps/gmail.pcapng.cap>)

#### TPKT

- [snoop-working-ccm7.cap](<pcaps/snoop-working-ccm7.cap>)

#### Telnet

- [cm4116_telnet.cap](<pcaps/cm4116_telnet.cap>)
- [telnet.cap](<pcaps/telnet.cap>)

#### UDLD

- [UDLD.cap](<pcaps/UDLD.cap>)

#### UDP

- [Auto-RP.cap](<pcaps/Auto-RP.cap>)
- [DHCP.cap](<pcaps/DHCP.cap>)
- [DHCP_Inter_VLAN.cap](<pcaps/DHCP_Inter_VLAN.cap>)
- [DHCP_MessageType 10,11,12 and 13.cap](<pcaps/DHCP_MessageType 10,11,12 and 13.cap>)
- [DHCPv6.cap](<pcaps/DHCPv6.cap>)
- [DNS Question & Answer.pcapng.cap](<pcaps/DNS Question & Answer.pcapng.cap>)
- [EoMPLS.cap](<pcaps/EoMPLS.cap>)
- [GLBP_election.cap](<pcaps/GLBP_election.cap>)
- [HSRP_coup.cap](<pcaps/HSRP_coup.cap>)
- [HSRP_election.cap](<pcaps/HSRP_election.cap>)
- [HSRP_failover.cap](<pcaps/HSRP_failover.cap>)
- [IPv6_RTSP.cap](<pcaps/IPv6_RTSP.cap>)
- [ISAKMP_sa_setup.cap](<pcaps/ISAKMP_sa_setup.cap>)
- [LDP_Ethernet_FrameRelay.pcap.cap](<pcaps/LDP_Ethernet_FrameRelay.pcap.cap>)
- [LDP_adjacency.cap](<pcaps/LDP_adjacency.cap>)
- [OCSP-Good.cap](<pcaps/OCSP-Good.cap>)
- [Open Network Connection.pcapng.cap](<pcaps/Open Network Connection.pcapng.cap>)
- [PIM-DM_pruning.cap](<pcaps/PIM-DM_pruning.cap>)
- [RADIUS.cap](<pcaps/RADIUS.cap>)
- [RIPv1.cap](<pcaps/RIPv1.cap>)
- [RIPv1_subnet_down.cap](<pcaps/RIPv1_subnet_down.cap>)
- [RIPv2.cap](<pcaps/RIPv2.cap>)
- [RIPv2_subnet_down.cap](<pcaps/RIPv2_subnet_down.cap>)
- [SNMPv2c_get_requests.cap](<pcaps/SNMPv2c_get_requests.cap>)
- [SNMPv3.cap](<pcaps/SNMPv3.cap>)
- [TDP.cap](<pcaps/TDP.cap>)
- [WCCPv2.pcap.cap](<pcaps/WCCPv2.pcap.cap>)
- [arp_l2tpv3.cap](<pcaps/arp_l2tpv3.cap>)
- [cflow.cap](<pcaps/cflow.cap>)
- [dhcp-auth.cap](<pcaps/dhcp-auth.cap>)
- [dns-zone-transfer-ixfr.cap](<pcaps/dns-zone-transfer-ixfr.cap>)
- [dtls_null.cap](<pcaps/dtls_null.cap>)
- [gmail.pcapng.cap](<pcaps/gmail.pcapng.cap>)
- [icmp_in_l2tpv3.cap](<pcaps/icmp_in_l2tpv3.cap>)
- [iphttps.cap](<pcaps/iphttps.cap>)
- [lispmn_IPv6-RLOC.pcapng.cap](<pcaps/lispmn_IPv6-RLOC.pcapng.cap>)
- [nf9-juniper-vmx.pcapng.cap](<pcaps/nf9-juniper-vmx.pcapng.cap>)
- [packet-c.cap](<pcaps/packet-c.cap>)
- [path_MTU_discovery.cap](<pcaps/path_MTU_discovery.cap>)
- [rpvstp-access.pcap.cap](<pcaps/rpvstp-access.pcap.cap>)
- [sflow.cap](<pcaps/sflow.cap>)
- [snmp-ipv4.cap](<pcaps/snmp-ipv4.cap>)
- [snmp-ipv6.cap](<pcaps/snmp-ipv6.cap>)
- [snoop-working-ccm7.cap](<pcaps/snoop-working-ccm7.cap>)
- [stun2.cap](<pcaps/stun2.cap>)
- [traceroute_MPLS.cap](<pcaps/traceroute_MPLS.cap>)

#### VLAN

- [802.1Q_tunneling.cap](<pcaps/802.1Q_tunneling.cap>)
- [802_1ad.pcapng.cap](<pcaps/802_1ad.pcapng.cap>)
- [ICMP_across_dot1q.cap](<pcaps/ICMP_across_dot1q.cap>)
- [MSTP_Intra-Region_BPDUs.cap](<pcaps/MSTP_Intra-Region_BPDUs.cap>)
- [QinQ.pcap.cap](<pcaps/QinQ.pcap.cap>)
- [gre_and_4over6.cap](<pcaps/gre_and_4over6.cap>)
- [rpvstp-trunk-native-vid1.pcap.cap](<pcaps/rpvstp-trunk-native-vid1.pcap.cap>)
- [rpvstp-trunk-native-vid5.pcap.cap](<pcaps/rpvstp-trunk-native-vid5.pcap.cap>)

#### VRRP

- [VRRP_failover.cap](<pcaps/VRRP_failover.cap>)
- [VRRP_preempt.cap](<pcaps/VRRP_preempt.cap>)

#### VTP

- [rpvstp-trunk-native-vid1.pcap.cap](<pcaps/rpvstp-trunk-native-vid1.pcap.cap>)
- [rpvstp-trunk-native-vid5.pcap.cap](<pcaps/rpvstp-trunk-native-vid5.pcap.cap>)

#### WCCP

- [WCCPv2.pcap.cap](<pcaps/WCCPv2.pcap.cap>)

#### XML

- [Open Network Connection.pcapng.cap](<pcaps/Open Network Connection.pcapng.cap>)

