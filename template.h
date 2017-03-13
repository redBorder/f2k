/*
  Copyright (C) 2016 Eneo Tecnologia S.L.
  Author: Eugenio Perez <eupm90@gmail.com>
  Based on Luca Deri nprobe 6.22 collector

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU Affero General Public License as
  published by the Free Software Foundation, either version 3 of the
  License, or (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU Affero General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */


#pragma once

#include <stdint.h>

struct flow_ver9_ipfix_template_elementids;
const char* getStandardFieldId(size_t id);

#define NTOP_BASE_ID 57472

/* 1024 custom ntop elements for v9 should be enough */
#define NTOP_BASE_NETFLOW_ID  NTOP_BASE_ID+1024
// Netflow ID for not-netflow elements, like *_name
#define PRIVATE_ENTITY_ID NTOP_BASE_NETFLOW_ID+__COUNTER__

/* Last used identified is NTOP_BASE_ID+351 */
/// @TODO #define REDBORDER_BASE_ID NTOP_BASE_ID+351

/// Special macro that protects comma, making it looks like only one parameter
#define C(...) __VA_ARGS__

#ifdef HAVE_GEOIP
#define X_GEO_IP \
	/* no normalize direction */ \
	X(STANDARD_ENTERPRISE_ID, SRC_IP_COUNTRY, PRIVATE_ENTITY_ID, QUOTE_OUTPUT, "SRC_IP_COUNTRY", "src_country_code", "", "Country where the src IP is located",print_country_code,NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, DST_IP_COUNTRY, PRIVATE_ENTITY_ID, QUOTE_OUTPUT, "DST_IP_COUNTRY", "dst_country_code", "", "Country where the dst IP is located",print_country_code,NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, IPV4_SRC_ASNUM_NAME,PRIVATE_ENTITY_ID, QUOTE_OUTPUT, "IPV4_SRC_ASNUM_NAME", "src_as_name", "sourceIPv4Address", "IPv4 source address Autonomous system name",print_AS_ipv4_name, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, IPV4_DST_ASNUM_NAME, PRIVATE_ENTITY_ID, QUOTE_OUTPUT, "IPV4_DST_ASNUM_NAME", "dst_as_name", "destinationIPv4AddressAsNumber", "IPv4 destination address Autonomous System name",print_AS_ipv4_name, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, IPV6_SRC_IP_COUNTRY, PRIVATE_ENTITY_ID, QUOTE_OUTPUT, "IPV6_SRC_IP_COUNTRY", "src_country_code", "", "Country where the src IP is located (IPv6)",print_country6_code, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, IPV6_DST_IP_COUNTRY, PRIVATE_ENTITY_ID, QUOTE_OUTPUT, "IPV6_DST_IP_COUNTRY", "dst_country_code", "", "Country where the dst IP is located (IPv6)",print_country6_code, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, IPV6_SRC_AS_NAME, PRIVATE_ENTITY_ID, QUOTE_OUTPUT, "IPV6_SRC_AS_NAME", "src_as_name", "SourceAsNumber", "Source IP AS", print_AS6_name, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, IPV6_DST_AS_NAME, PRIVATE_ENTITY_ID, QUOTE_OUTPUT, "IPV6_DST_AS_NAME", "dst_as_name", "DestinationAsNumber", "Destination IP AS", print_AS6_name, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, STA_IPV4_ADDRESS_IP_COUNTRY, PRIVATE_ENTITY_ID, QUOTE_OUTPUT, "STA_IPV4_ADDRESS_IP_COUNTRY", "lan_ip_country_code", "", "Country where the lan IP is located",print_country_code,NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, STA_IPV4_ADDRESS_AS_NAME,PRIVATE_ENTITY_ID, QUOTE_OUTPUT, "STA_IPV4_ADDRESS_AS_NAME", "lan_ip_as_name", "sourceIPv4Address", "IPv4 source address Autonomous system name",print_AS_ipv4_name, NO_CHILDS)\
	/* Normalize direction */ \
	X(STANDARD_ENTERPRISE_ID, LAN_IP_COUNTRY, PRIVATE_ENTITY_ID, QUOTE_OUTPUT, "LAN_IP_COUNTRY", "lan_ip_country_code", "", "Country where the lan IP is located",print_lan_country_code,NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, WAN_IP_COUNTRY, PRIVATE_ENTITY_ID, QUOTE_OUTPUT, "WAN_IP_COUNTRY", "wan_ip_country_code", "", "Country where the wan IP is located",print_wan_country_code,NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, LAN_IP_AS_NAME, PRIVATE_ENTITY_ID, QUOTE_OUTPUT, "LAN_IP_AS_NAME", "lan_ip_as_name", "sourceIPv4Address", "LAN Autonomous system name",print_lan_AS_name, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, WAN_IP_AS_NAME, PRIVATE_ENTITY_ID, QUOTE_OUTPUT, "WAN_IP_AS_NAME", "wan_ip_as_name", "destinationIPv4AddressAsNumber", "WAN destination address Autonomous System name",print_wan_AS_name, NO_CHILDS)\

#define IPV4_SRC_IP_GEO_CHILDS C(SRC_IP_COUNTRY, IPV4_SRC_ASNUM_NAME)
#define IPV4_DST_IP_GEO_CHILDS C(DST_IP_COUNTRY, IPV4_DST_ASNUM_NAME)
#define IPV6_SRC_IP_GEO_CHILDS C(IPV6_SRC_IP_COUNTRY, IPV6_SRC_AS_NAME)
#define IPV6_DST_IP_GEO_CHILDS C(IPV6_DST_IP_COUNTRY, IPV6_DST_AS_NAME)
#define STA_IPV4_ADDRESS_GEO_CHILDS C(STA_IPV4_ADDRESS_IP_COUNTRY, \
		STA_IPV4_ADDRESS_AS_NAME)
#define LAN_IP_GEO_CHILDS C(LAN_IP_COUNTRY, LAN_IP_AS_NAME)
#define WAN_IP_GEO_CHILDS C(WAN_IP_COUNTRY, WAN_IP_AS_NAME)
#else
#define X_GEO_IP
#define IPV4_SRC_IP_GEO_CHILDS
#define IPV4_DST_IP_GEO_CHILDS
#define IPV6_SRC_IP_GEO_CHILDS
#define IPV6_DST_IP_GEO_CHILDS
#define STA_IPV4_ADDRESS_GEO_CHILDS
#endif

#ifdef SECONDS_PRECISION
#define X_SECONDS_PRECISION
	X(STANDARD_ENTERPRISE_ID, CISCO_SECONDS_PRECISION, PRIVATE_ENTITY_ID, DONT_QUOTE_OUTPUT, "CISCO_SECONDS", "second", "flowEndSysUpTime", "SysUptime (msec) of the last flow pkt",NO_FN, NO_CHILDS)
#else
#define X_SECONDS_PRECISION
#endif

#define X_CISCO_URL \
	X(CISCO_ENTERPRISE_ID, CISCO_URL, 12235, QUOTE_OUTPUT, "CISCO_URL", "", "", "CISCO HTTP.",NO_FN,C(CISCO_HTTP_URL,CISCO_HTTP_HOST,CISCO_HTTP_USER_AGENT,CISCO_HTTP_REFERER,CISCO_HTTPS_COMMON_NAME))\
	X(CISCO_ENTERPRISE_ID, CISCO_HTTP_URL, PRIVATE_ENTITY_ID, QUOTE_OUTPUT, "HTTP_URL", "http_url", "", "CISCO HTTP_URL information.",print_http_url,NO_CHILDS)\
	X(CISCO_ENTERPRISE_ID, CISCO_HTTP_HOST, PRIVATE_ENTITY_ID, QUOTE_OUTPUT, "HTTP_HOST", "http_host", "", "CISCO HTTP_HOST information.",print_http_host, CISCO_HTTP_HOST_L2)\
	X(CISCO_ENTERPRISE_ID, CISCO_HTTP_HOST_L2, PRIVATE_ENTITY_ID, QUOTE_OUTPUT, "HTTP_HOST_L2", "http_host_l2", "", "CISCO HTTP_HOST level 2 domain information.",print_http_host_l2,NO_CHILDS)\
	X(CISCO_ENTERPRISE_ID, CISCO_HTTP_USER_AGENT, PRIVATE_ENTITY_ID, QUOTE_OUTPUT, "HTTP_USER_AGENT", "http_user_agent", "", "CISCO HTTP_USER_AGENT information.",print_http_user_agent,NO_CHILDS)\
	X(CISCO_ENTERPRISE_ID, CISCO_HTTP_USER_AGENT_OS, PRIVATE_ENTITY_ID, QUOTE_OUTPUT, "HTTP_USER_AGENT_OS", "http_user_agent_os", "", "CISCO HTTP_USER_AGENT OS information.",NO_FN,NO_CHILDS)\
	X(CISCO_ENTERPRISE_ID, CISCO_HTTP_REFERER, PRIVATE_ENTITY_ID, QUOTE_OUTPUT, "HTTP_REFERER", "http_referer", "", "CISCO HTTP_REFERER information.", print_http_referer,CISCO_HTTP_REFERER_L2)\
	X(CISCO_ENTERPRISE_ID, CISCO_HTTP_REFERER_L2, PRIVATE_ENTITY_ID, QUOTE_OUTPUT, "HTTP_REFERER_L2", "http_referer_l2", "", "CISCO HTTP_REFERER level 2 domain.",NO_FN,NO_CHILDS)\
	X(CISCO_ENTERPRISE_ID, CISCO_HTTPS_COMMON_NAME, PRIVATE_ENTITY_ID, QUOTE_OUTPUT, "HTTPS_COMMON_NAME", "https_common_name", "", "CISCO HTTPS certificate common name.",print_https_common_name,NO_CHILDS)\
	X(CISCO_ENTERPRISE_ID, HOST, PRIVATE_ENTITY_ID, QUOTE_OUTPUT, "HOST", "host", "", "HTTP_HOST ? : SSL_COMMON_NAME.", print_host, C(HOST_L2))\
	X(CISCO_ENTERPRISE_ID, HOST_L2, PRIVATE_ENTITY_ID, QUOTE_OUTPUT, "HOST_L2", "host_l2_domain", "", "host level 2 domain information.", print_host_l2, NO_CHILDS)\
	X(CISCO_ENTERPRISE_ID, REFERER, PRIVATE_ENTITY_ID, QUOTE_OUTPUT, "REFERER", "referer", "", "REFERER ? : SSL_COMMON_NAME.",print_referer,C(REFERER_L2))\
	X(CISCO_ENTERPRISE_ID, REFERER_L2, PRIVATE_ENTITY_ID, QUOTE_OUTPUT, "REFERER_L2", "referer_l2", "", "referer level 2 domain information.",print_referer_l2,NO_CHILDS)\
	X(CISCO_ENTERPRISE_ID, CISCO_HTTP_SOCIAL_USER_FB, PRIVATE_ENTITY_ID, QUOTE_OUTPUT, "HTTP_SOCIAL_USER_FB", "http_social_user", "", "Social media id (based on CISCO HTTP_URL information.)",NO_FN,NO_CHILDS)\
	X(CISCO_ENTERPRISE_ID, CISCO_HTTP_SOCIAL_MEDIA_IG, PRIVATE_ENTITY_ID, QUOTE_OUTPUT, "HTTP_SOCIAL_MEDIA_IG", "http_social_media", "", "Social media id (based on CISCO HTTP_URL information.)",NO_FN,NO_CHILDS)\
	X(CISCO_ENTERPRISE_ID, CISCO_HTTP_SOCIAL_MEDIA_YT, PRIVATE_ENTITY_ID, QUOTE_OUTPUT, "HTTP_SOCIAL_MEDIA_YT", "http_social_media", "", "Social media id (based on CISCO HTTP_URL information.)",NO_FN,NO_CHILDS)\
	X(CISCO_ENTERPRISE_ID, CISCO_HTTP_SOCIAL_MEDIA_TT, PRIVATE_ENTITY_ID, QUOTE_OUTPUT, "HTTP_SOCIAL_MEDIA_TT", "http_social_media", "", "Social media id (based on CISCO HTTP_URL information.)",NO_FN,NO_CHILDS)\
	X(CISCO_ENTERPRISE_ID, CISCO_HTTP_SOCIAL_USER_TT, PRIVATE_ENTITY_ID, QUOTE_OUTPUT, "HTTP_SOCIAL_USER", "http_social_user", "", "Social media id (based on CISCO HTTP_URL information.)",NO_FN,NO_CHILDS)\
	X(CISCO_ENTERPRISE_ID, CISCO_HTTP_SOCIAL_USER_YT, PRIVATE_ENTITY_ID, QUOTE_OUTPUT, "HTTP_SOCIAL_USER_YT", "http_social_user", "", "Social media id (based on CISCO HTTP_URL information.)",NO_FN,NO_CHILDS)\
	X(CISCO_ENTERPRISE_ID, CISCO_HTTP_SOCIAL_USER_YT_REFERER, PRIVATE_ENTITY_ID, QUOTE_OUTPUT, "HTTP_SOCIAL_USER_YT_REFERER", "http_social_user", "", "Social media id (based on CISCO HTTP_URL information.)",NO_FN,NO_CHILDS)\
	X(CISCO_ENTERPRISE_ID, CISCO_HTTP_SOCIAL_USER_DROPBOX, PRIVATE_ENTITY_ID, QUOTE_OUTPUT, "HTTP_SOCIAL_USER_DROPBOX", "http_social_user", "", "Social media id (based on CISCO HTTP_URL information.)",NO_FN,NO_CHILDS)


#ifdef HAVE_UDNS
#define X_UDNS \
	X(STANDARD_ENTERPRISE_ID, DNS_CLIENT_NAME, PRIVATE_ENTITY_ID, QUOTE_OUTPUT, "DNS_CLIENT_NAME", "lan_ip_name", "lan_ip_name", "Client name obtained via reversed DNS" ,print_client_name, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, DNS_TARGET_NAME, PRIVATE_ENTITY_ID, QUOTE_OUTPUT, "DNS_TARGET_NAME", "wan_ip_name", "wan_ip_name", "Target name obtained via reversed DNS" ,print_target_name, NO_CHILDS)
#else
#define X_UDNS
#endif

#define NO_CHILDS
#define NO_FN NULL

/** V9/IPFIX entities (ENTERPRISE ID, ID_STR, ID, JSON_QUOTE, NAME,
    JSON_NAME, IPFIX_NAME, DESCRIPTION, FUNCTION, CHILDS)
    */
#define X_TEMPLATE_ENTITIES \
	X(STANDARD_ENTERPRISE_ID, IN_BYTES, 1, DONT_QUOTE_OUTPUT, "IN_BYTES", "bytes", "octetDeltaCount", "Incoming flow bytes (src->dst)", save_flow_bytes, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, PRINT_IN_BYTES, PRIVATE_ENTITY_ID, DONT_QUOTE_OUTPUT, "IN_BYTES", "bytes", "octetDeltaCount", "Incoming flow bytes (src->dst)", print_number, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, IN_PKTS,2, DONT_QUOTE_OUTPUT, "IN_PKTS", "pkts", "packetDeltaCount", "Incoming flow packets (src->dst)", save_flow_pkts, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, PRINT_IN_PKTS, PRIVATE_ENTITY_ID, DONT_QUOTE_OUTPUT, "IN_PKTS", "pkts", "packetDeltaCount", "Incoming flow packets (src->dst)", print_number, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, FLOWS,3, DONT_QUOTE_OUTPUT, "FLOWS", "flows", "<reserved>", "Number of flows", NO_FN, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, PROTOCOL,4, DONT_QUOTE_OUTPUT, "PROTOCOL", "l4_proto", "protocolIdentifier", "IP protocol byte",print_number , NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, SRC_TOS, 5, DONT_QUOTE_OUTPUT, "SRC_TOS", "tos", "ipClassOfService", "Type of service byte", print_number, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, TCP_FLAGS, 6, QUOTE_OUTPUT, "TCP_FLAGS", "tcp_flags", "tcpControlBits", "Cumulative of all flow TCP flags", print_tcp_flags, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, L4_SRC_PORT, 7, DONT_QUOTE_OUTPUT, "L4_SRC_PORT", "src_port", "src_port", "IPv4 source port", process_src_port, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, IPV4_SRC_ADDR, 8, QUOTE_OUTPUT, "IPV4_SRC_ADDR", "src", "sourceIPv4Address", "IPv4 source address" , print_ipv4_src_addr, C(IPV4_SRC_NET, IPV4_SRC_IP_GEO_CHILDS))\
	X(STANDARD_ENTERPRISE_ID, IPV4_SRC_NET, PRIVATE_ENTITY_ID, QUOTE_OUTPUT, "IPV4_SRC_NET", "src_net", "sourceIPv4Net", "IPv4 source net name",print_net,C(IPV4_SRC_NET_NAME))\
	X(STANDARD_ENTERPRISE_ID, IPV4_SRC_NET_NAME, PRIVATE_ENTITY_ID, QUOTE_OUTPUT, "IPV4_SRC_NET_NAME", "src_net_name", "sourceIPv4NetName", "IPv4 source net name",print_net_name, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, IPV4_SRC_MASK, 9, QUOTE_OUTPUT, "IPV4_SRC_MASK", "ipv4_src_mask", "sourceIPv4PrefixLength", "IPv4 source subnet mask (/<bits>)", NO_FN, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, INPUT_SNMP, 10, DONT_QUOTE_OUTPUT, "INPUT_SNMP", "input_snmp", "ingressInterface", "Input interface SNMP idx",process_input_snmp, C(INPUT_SNMP_NAME, INPUT_SNMP_DESCRIPTION))\
	X(STANDARD_ENTERPRISE_ID, INPUT_SNMP_NAME, PRIVATE_ENTITY_ID, QUOTE_OUTPUT, "INPUT_SNMP_NAME", "input_snmp_name", "ingressInterfaceName", "Input interface SNMP name",print_interface_name, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, INPUT_SNMP_DESCRIPTION, PRIVATE_ENTITY_ID, QUOTE_OUTPUT, "INPUT_SNMP_DESCRIPTION", "input_snmp_description", "ingressInterfaceDescription", "Input interface SNMP description",print_interface_description, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, L4_DST_PORT, 11, DONT_QUOTE_OUTPUT, "L4_DST_PORT", "dst_port", "destinationTransportPort", "IPv4 destination port", process_dst_port, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, IPV4_DST_ADDR, 12, QUOTE_OUTPUT, "IPV4_DST_ADDR", "dst", "destinationIPv4Address", "IPv4 destination address", print_ipv4_dst_addr, C(IPV4_DST_NET, IPV4_DST_IP_GEO_CHILDS))\
	X(STANDARD_ENTERPRISE_ID, IPV4_DST_NET, PRIVATE_ENTITY_ID, QUOTE_OUTPUT, "IPV4_DST_NET", "dst_net", "destinationIPv4Net", "IPv4 destination net name",print_net ,C(IPV4_DST_NET_NAME))\
	X(STANDARD_ENTERPRISE_ID, IPV4_DST_NET_NAME, PRIVATE_ENTITY_ID, QUOTE_OUTPUT, "IPV4_DST_NET_NAME", "dst_net_name", "destinationIPv4NetName", "IPv4 destination net name", print_net_name, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, IPV4_DST_MASK, 13, QUOTE_OUTPUT, "IPV4_DST_MASK", "ipv4_dst_mask", "destinationIPv4PrefixLength", "IPv4 dest subnet mask (/<bits>)", NO_FN, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, OUTPUT_SNMP, 14, DONT_QUOTE_OUTPUT, "OUTPUT_SNMP", "output_snmp", "egressInterface", "Output interface SNMP idx",process_output_snmp, C(OUTPUT_SNMP_NAME, OUTPUT_SNMP_DESCRIPTION))\
	X(STANDARD_ENTERPRISE_ID, OUTPUT_SNMP_NAME, PRIVATE_ENTITY_ID, QUOTE_OUTPUT, "OUTPUT_SNMP_NAME", "output_snmp_name", "egressInterfaceName", "Output interface SNMP name",print_interface_name, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, OUTPUT_SNMP_DESCRIPTION, PRIVATE_ENTITY_ID, QUOTE_OUTPUT, "OUTPUT_SNMP_DESCRIPTION", "output_snmp_description", "egressInterfaceDescription", "Output interface SNMP description",print_interface_description, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, IPV4_NEXT_HOP, 15, QUOTE_OUTPUT, "IPV4_NEXT_HOP", "ipv4_next_hop", "ipNextHopIPv4Address", "IPv4 next hop address", NO_FN, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, SRC_AS, 16, DONT_QUOTE_OUTPUT, "SRC_AS", "prev_as", "bgpSourceAsNumber", "Source BGP AS",print_number, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, DST_AS, 17, DONT_QUOTE_OUTPUT, "DST_AS", "next_as", "bgpDestinationAsNumber", "Destination BGP AS",print_number, NO_CHILDS)\
	/*X(STANDARD_ENTERPRISE_ID, BGP_IPV4_NEXT_HOP, 18, DONT_QUOTE_OUTPUT, "BGP_IPV4_NEXT_HOP", "bgp_ipv4_next_hop", "bgpNexthopIPv4Address", "")*/\
	/*X(STANDARD_ENTERPRISE_ID, MUL_DST_PKTS, 19, DONT_QUOTE_OUTPUT, "MUL_DST_PKTS", "mul_dst_pkts", "postMCastPacketDeltaCount", "")*/\
	/*X(STANDARD_ENTERPRISE_ID, MUL_DST_BYTES, 20, DONT_QUOTE_OUTPUT, "MUL_DST_BYTES", "mul_dst_bytes", "postMCastOctetDeltaCount", "")*/\
	X(STANDARD_ENTERPRISE_ID, LAST_SWITCHED, 21, DONT_QUOTE_OUTPUT, "LAST_SWITCHED", "timestamp", "flowEndSysUpTime", "SysUptime (msec) of the last flow pkt", save_last_switched, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, PRINT_LAST_SWITCHED, PRIVATE_ENTITY_ID, DONT_QUOTE_OUTPUT, "LAST_SWITCHED", "timestamp", "flowEndSysUpTime", "SysUptime (msec) of the last flow pkt", print_number, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, FIRST_SWITCHED, 22, DONT_QUOTE_OUTPUT, "FIRST_SWITCHED", "first_switched", "flowStartSysUpTime", "SysUptime (msec) of the first flow pkt", save_first_switched, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, PRINT_FIRST_SWITCHED, PRIVATE_ENTITY_ID, DONT_QUOTE_OUTPUT, "FIRST_SWITCHED", "first_switched", "flowStartSysUpTime", "SysUptime (msec) of the first flow pkt", print_number, NO_CHILDS)\
	X_SECONDS_PRECISION \
	X(STANDARD_ENTERPRISE_ID, OUT_BYTES, 23, DONT_QUOTE_OUTPUT, "OUT_BYTES", "out_bytes", "postOctetDeltaCount", "Outgoing flow bytes (dst->src)",NO_FN, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, OUT_PKTS, 24, DONT_QUOTE_OUTPUT, "OUT_PKTS", "out_pkts", "postPacketDeltaCount", "Outgoing flow packets (dst->src)",NO_FN, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, IPV6_SRC_ADDR, 27, QUOTE_OUTPUT, "IPV6_SRC_ADDR", "src", "sourceIPv6Address", "IPv6 source address" ,print_ipv6_src_addr, C(IPV6_SRC_NET, IPV6_SRC_IP_GEO_CHILDS))\
	X(STANDARD_ENTERPRISE_ID, IPV6_DST_ADDR, 28, QUOTE_OUTPUT, "IPV6_DST_ADDR", "dst", "destinationIPv6Address", "IPv6 destination address" ,print_ipv6_dst_addr, C(IPV6_DST_NET, IPV6_DST_IP_GEO_CHILDS))\
	X(STANDARD_ENTERPRISE_ID, IPV6_SRC_MASK, 29, DONT_QUOTE_OUTPUT, "IPV6_SRC_MASK", "ipv6_src_mask", "sourceIPv6PrefixLength", "IPv6 source mask",NO_FN, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, IPV6_DST_MASK, 30, DONT_QUOTE_OUTPUT, "IPV6_DST_MASK", "ipv6_dst_mask", "destinationIPv6PrefixLength", "IPv6 destination mask",NO_FN, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, IPV6_SRC_NAME, PRIVATE_ENTITY_ID, QUOTE_OUTPUT, "IPV6_SRC_NAME", "src_name", "sourceIPv6Name", "IPv6 source name",NO_FN, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, IPV6_SRC_NET_NAME, PRIVATE_ENTITY_ID, QUOTE_OUTPUT, "IPV6_SRC_NET_NAME", "src_net_name", "sourceIPv6NetName", "IPv6 source net name",print_net_name_v6, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, IPV6_SRC_NET, PRIVATE_ENTITY_ID, QUOTE_OUTPUT, "IPV6_SRC_NET", "src_net", "sourceIPv6Net", "IPv6 source net name",print_net_v6, IPV6_SRC_NET_NAME)\
	X(STANDARD_ENTERPRISE_ID, IPV6_DST_NAME, PRIVATE_ENTITY_ID, QUOTE_OUTPUT, "IPV6_DST_NAME", "dst_name", "destinationIPv6Address", "IPv6 destination name",NO_FN, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, IPV6_DST_NET_NAME, PRIVATE_ENTITY_ID, QUOTE_OUTPUT, "IPV6_DST_NET_NAME", "dst_net_name", "destinationIPv6NetName", "IPv6 destination net name",print_net_name_v6, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, IPV6_DST_NET, PRIVATE_ENTITY_ID, QUOTE_OUTPUT, "IPV6_DST_NET", "dst_net", "destinationIPv6Net", "IPv6 destination net name",print_net_v6, IPV6_DST_NET_NAME)\
	X(STANDARD_ENTERPRISE_ID, ICMP_TYPE, 32, DONT_QUOTE_OUTPUT, "ICMP_TYPE", "icmp_type", "icmpTypeCodeIPv4", "ICMP Type * 256 + ICMP code",NO_FN, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, SAMPLING_INTERVAL, 34, DONT_QUOTE_OUTPUT, "SAMPLING_INTERVAL", "sampling_interval", "<reserved>", "Sampling rate",NO_FN, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, SAMPLING_ALGORITHM, 35, DONT_QUOTE_OUTPUT, "SAMPLING_ALGORITHM", "sampling_algorithm", "<reserved>", "Sampling type (deterministic/random)",NO_FN, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, FLOW_ACTIVE_TIMEOUT, 36, DONT_QUOTE_OUTPUT, "FLOW_ACTIVE_TIMEOUT", "flow_active_timeout", "flowActiveTimeout", "Activity timeout of flow cache entries",NO_FN, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, FLOW_INACTIVE_TIMEOUT, 37, DONT_QUOTE_OUTPUT, "FLOW_INACTIVE_TIMEOUT", "flow_inactive_timeout", "flowIdleTimeout", "Inactivity timeout of flow cache entries",NO_FN, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, ENGINE_TYPE, 38, DONT_QUOTE_OUTPUT, "ENGINE_TYPE", "engine_type", "<reserved>", "Flow switching engine",print_number, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, ENGINE_ID, 39, DONT_QUOTE_OUTPUT, "ENGINE_ID", "engine_id", "<reserved>", "Id of the flow switching engine",NO_FN,ENGINE_ID_NAME)\
	X(STANDARD_ENTERPRISE_ID, ENGINE_ID_NAME, PRIVATE_ENTITY_ID, QUOTE_OUTPUT, "ENGINE_ID_NAME", "engine_id_name", "<reserved>", "Id of the flow switching engine",print_engine_id_name, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, TOTAL_BYTES_EXP, 40, DONT_QUOTE_OUTPUT, "TOTAL_BYTES_EXP", "total_bytes_exp", "exportedOctetTotalCount", "Total bytes exported",NO_FN, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, TOTAL_PKTS_EXP, 41, DONT_QUOTE_OUTPUT, "TOTAL_PKTS_EXP", "total_pkts_exp", "exportedMessageTotalCount", "Total flow packets exported",NO_FN, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, TOTAL_FLOWS_EXP, 42, DONT_QUOTE_OUTPUT, "TOTAL_FLOWS_EXP", "total_flows_exp", "exportedFlowRecordTotalCount", "Total number of exported flows",NO_FN, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, FLOW_SAMPLER_ID, 48, DONT_QUOTE_OUTPUT, "FLOW_SAMPLER_ID", "flow_sampler_id", "flowSamplerId", "Flow sampler ID", NO_FN, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, MIN_TTL, 52, DONT_QUOTE_OUTPUT, "MIN_TTL", "min_ttl", "minimumTTL", "Min flow TTL",NO_FN, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, MAX_TTL, 53, DONT_QUOTE_OUTPUT, "MAX_TTL", "max_ttl", "maximumTTL", "Max flow TTL",NO_FN, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, IN_SRC_MAC, 56, QUOTE_OUTPUT, "IN_SRC_MAC", "src_mac", "sourceMacAddress", "Source MAC Address", process_src_mac, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, OUT_SRC_MAC, 81, QUOTE_OUTPUT, "OUT_SRC_MAC", "post_dst_mac", "sourceMacAddress", "Source MAC Address after observation point", process_post_src_mac, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, IN_SRC_MAC_MAP, PRIVATE_ENTITY_ID, QUOTE_OUTPUT, "IN_SRC_MAC_MAP", "in_src_mac_name", "sourceMacAddress", "Name of Source MAC Address",NO_FN, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, OUT_SRC_MAC_MAP, PRIVATE_ENTITY_ID, QUOTE_OUTPUT, "OUT_SRC_MAC_MAP", "out_src_mac_name", "sourceMacAddress", "Name of Source MAC Address after observation point",NO_FN, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, SRC_VLAN, 58, DONT_QUOTE_OUTPUT, "CISCO_SRC_VLAN", "cisco_src_vlan", "preVlanId", "Source VLAN", print_number, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, DST_VLAN, 59, DONT_QUOTE_OUTPUT, "CISCO_DST_VLAN", "cisco_dst_vlan", "postVlanId", "Destination VLAN", print_number, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, DOT_1Q_VLANID, 243, DONT_QUOTE_OUTPUT, "SRC_VLAN", "src_vlan", "preVlanId", "Source VLAN", print_number, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, POST_DOT_1Q_VLANID, 254, DONT_QUOTE_OUTPUT, "DST_VLAN", "dst_vlan", "postVlanId", "Destination VLAN", print_number, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, DOT_1Q_VLANID_MAP, PRIVATE_ENTITY_ID, QUOTE_OUTPUT, "SRC_VLAN_MAP", "src_vlan_name", "preVlanId_map", "Source VLAN name",NO_FN, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, POST_DOT_1Q_VLANID_MAP, PRIVATE_ENTITY_ID, QUOTE_OUTPUT, "DST_VLAN_MAP", "dst_vlan_name", "postVlanId_map", "Destination VLAN name",NO_FN, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, IP_PROTOCOL_VERSION, 60, DONT_QUOTE_OUTPUT, "IP_PROTOCOL_VERSION", "ip_protocol_version", "ipVersion", "[4=IPv4][6=IPv6]", print_number, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, DIRECTION, 61, QUOTE_OUTPUT, "DIRECTION", "direction", "direction", "Flow direction", process_direction, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, PRINT_DIRECTION, PRIVATE_ENTITY_ID, QUOTE_OUTPUT, "DIRECTION", "direction", "flowDirection", "Indicates flow direction", print_flow_cache_direction,NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, IPV6_NEXT_HOP, 62, QUOTE_OUTPUT, "IPV6_NEXT_HOP", "ipv6_next_hop", "ipNextHopIPv6Address", "IPv6 next hop address",NO_FN, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, MPLS_LABEL_1, 70, DONT_QUOTE_OUTPUT, "MPLS_LABEL_1", "mpls_label_1", "mplsTopLabelStackSection", "MPLS label at position 1",NO_FN, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, MPLS_LABEL_2, 71, DONT_QUOTE_OUTPUT, "MPLS_LABEL_2", "mpls_label_2", "mplsLabelStackSection2", "MPLS label at position 2",NO_FN, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, MPLS_LABEL_3, 72, DONT_QUOTE_OUTPUT, "MPLS_LABEL_3", "mpls_label_3", "mplsLabelStackSection3", "MPLS label at position 3",NO_FN, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, MPLS_LABEL_4, 73, DONT_QUOTE_OUTPUT, "MPLS_LABEL_4", "mpls_label_4", "mplsLabelStackSection4", "MPLS label at position 4",NO_FN, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, MPLS_LABEL_5, 74, DONT_QUOTE_OUTPUT, "MPLS_LABEL_5", "mpls_label_5", "mplsLabelStackSection5", "MPLS label at position 5",NO_FN, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, MPLS_LABEL_6, 75, DONT_QUOTE_OUTPUT, "MPLS_LABEL_6", "mpls_label_6", "mplsLabelStackSection6", "MPLS label at position 6",NO_FN, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, MPLS_LABEL_7, 76, DONT_QUOTE_OUTPUT, "MPLS_LABEL_7", "mpls_label_7", "mplsLabelStackSection7", "MPLS label at position 7",NO_FN, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, MPLS_LABEL_8, 77, DONT_QUOTE_OUTPUT, "MPLS_LABEL_8", "mpls_label_8", "mplsLabelStackSection8", "MPLS label at position 8",NO_FN, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, MPLS_LABEL_9, 78, DONT_QUOTE_OUTPUT, "MPLS_LABEL_9", "mpls_label_9", "mplsLabelStackSection9", "MPLS label at position 9",NO_FN, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, MPLS_LABEL_10, 79, DONT_QUOTE_OUTPUT, "MPLS_LABEL_10", "mpls_label_10", "mplsLabelStackSection10", "MPLS label at position 10",NO_FN, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, IN_DST_MAC, 80, QUOTE_OUTPUT, "IN_DST_MAC", "dst_mac", "destinationMacAddress", "Destination MAC Address", process_dst_mac, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, IF_NAME, 82, QUOTE_OUTPUT, "IF_NAME", NULL, NULL, "Interface name",NO_FN, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, IF_DESCRIPTION, 83, QUOTE_OUTPUT, "IF_NAME", NULL, NULL, "Interface description",NO_FN, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, IN_DST_MAC_MAP, PRIVATE_ENTITY_ID, QUOTE_OUTPUT, "IN_DST_MAC_MAP", "in_dst_mac_name", "destinationMacAddress", "Name Destination MAC Address",NO_FN, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, OUT_DST_MAC, 57, QUOTE_OUTPUT, "OUT_DST_MAC", "post_dst_mac", "PostdestinationMacAddress", "Destination MAC Address after observation point", process_post_dst_mac, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, OUT_DST_MAC_MAP, PRIVATE_ENTITY_ID, QUOTE_OUTPUT, "OUT_DST_MAC_MAP", "out_dst_mac_name", "PostdestinationMacAddress", "Name Destination MAC Address after observation point",NO_FN, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, APPLICATION_ID, 95, QUOTE_OUTPUT, "APPLICATION_ID", "application_id",  "application_id", "Cisco NBAR Application Id",NO_FN, C(APPLICATION_NAME, ENGINE_ID))\
	X(STANDARD_ENTERPRISE_ID, APPLICATION_NAME, 96, QUOTE_OUTPUT, "APPLICATION_NAME", "application_id_name",  "application_name", "Cisco NBAR Application Name",print_application_id_name, NO_CHILDS)\
	/* Use selector_id and engine_id */\
	/*X(STANDARD_ENTERPRISE_ID, APPLICATION_ID_MAJOR, DONT_QUOTE_OUTPUT, "APPLICATION_ID_MAJOR", "application_id_major",  "application_id_major", "Cisco NBAR Application Id (major number)")*/\
	/*X(STANDARD_ENTERPRISE_ID, APPLICATION_ID_MINOR, DONT_QUOTE_OUTPUT, "APPLICATION_ID_MINOR", "application_id_minor",  "application_id_minor", "Cisco NBAR Application Id (minor number)")*/\
	/* */ \
	X(STANDARD_ENTERPRISE_ID, PACKET_SECTION_OFFSET, 102, DONT_QUOTE_OUTPUT, "PACKET_SECTION_OFFSET", "packet_section_offset", "<reserved>", "Packet section offset",NO_FN, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, SAMPLED_PACKET_SIZE, 103, DONT_QUOTE_OUTPUT, "SAMPLED_PACKET_SIZE", "sampled_packet_size", "<reserved>", "Sampled packet size",NO_FN, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, SAMPLED_PACKET_ID, 104, DONT_QUOTE_OUTPUT, "SAMPLED_PACKET_ID", "sampled_packet_id",  "<reserved>", "Sampled packet id",NO_FN, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, DROPPED_BYTES_TOTAL, 134, DONT_QUOTE_OUTPUT, "DROPPED_BYTES_TOTAL", "dropped_bytes_total",  "dropped_bytes_total", "number of octets dropped", print_number, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, DROPPED_PACKETS_TOTAL, 135, DONT_QUOTE_OUTPUT, "DROPPED_PACKETS_TOTAL", "dropped_pkts_total",  "dropped_pkts_total", "number of packets dropped", print_number, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, FLOW_END_REASON, 136, QUOTE_OUTPUT, "FLOW_END_REASON", "flow_end_reason",  "flowEndReason", "Exporter IPv6 Address", print_flow_end_reason, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, EXPORTING_PROCESS_ID, 144, DONT_QUOTE_OUTPUT, "EXPORTING_PROCESS_ID", "exporting_process_id", "exporting_process_id", "Exporting Process Identifier", print_number, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, FLOW_ID, 148, DONT_QUOTE_OUTPUT, "FLOW_ID", "flow_id", "flowId", "Serial Flow Identifier", NO_FN, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, FLOW_START_SEC, 150, DONT_QUOTE_OUTPUT, "FLOW_START_SEC", "flow_start_sec", "flowStartSeconds", "Seconds (epoch) of the first flow packet",save_first_second, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, FLOW_END_SEC, 151, DONT_QUOTE_OUTPUT, "FLOW_END_SEC", "flow_end_sec",  "flowEndSeconds",  "Seconds (epoch) of the last flow packet",save_last_second, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, FLOW_START_MILLISECONDS, 152, DONT_QUOTE_OUTPUT, "FLOW_START_MILLISECONDS", "flow_start_milliseconds", "flowStartMilliseconds", "Msec (epoch) of the first flow packet",save_first_msecond, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, FLOW_END_MILLISECONDS, 153, DONT_QUOTE_OUTPUT, "FLOW_END_MILLISECONDS", "flow_end_milliseconds",  "flowEndMilliseconds",  "Msec (epoch) of the last flow packet",save_last_msecond, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, PADDING_OCTETS, 210, DONT_QUOTE_OUTPUT, "PADDING_OCTETS", "padding", "padding", "Padding", NO_FN, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, INGRESS_VRFID, 234, DONT_QUOTE_OUTPUT, "INGRESS_VRFID", "input_vrf", "ingressVRFID", "Ingress Virtual Routing&Forwarding Interface ID",print_number, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, EGRESS_VRFID, 235, DONT_QUOTE_OUTPUT, "EGRESS_VRFID", "output_vrf", "egressVRFID", "Egress Virtual Routing&Forwarding Interface ID",print_number, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, BIFLOW_DIRECTION, 239, QUOTE_OUTPUT, "BIFLOW_DIRECTION", "biflow_direction",  "biflow_direction",  "1=initiator, 2=reverseInitiator", print_biflow_direction, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, OBSERVATION_POINT_TYPE, 277, DONT_QUOTE_OUTPUT, "OBSERVATION_POINT_TYPE", "observation_point_type", "<reserved>", "Observation point type",NO_FN, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, TRANSACTION_ID, 280, DONT_QUOTE_OUTPUT, "TRANSACTION_ID", "transaction_id", "<reserved>", "Transaction id", print_number, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, OBSERVATION_POINT_ID, 300, DONT_QUOTE_OUTPUT, "OBSERVATION_POINT_ID", "observation_point_id", "<reserved>", "Observation point id",NO_FN,NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, SELECTOR_ID, 302, DONT_QUOTE_OUTPUT, "SELECTOR_ID", "selector_id", "<reserved>", "Selector id", print_number, SELECTOR_NAME)\
	X(STANDARD_ENTERPRISE_ID, IPFIX_SAMPLING_ALGORITHM, 304, DONT_QUOTE_OUTPUT, "IPFIX_SAMPLING_ALGORITHM", "ipfix_sampling_algorithm", "<reserved>", "Sampling algorithm",NO_FN,NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, SAMPLING_SIZE, 309, DONT_QUOTE_OUTPUT, "SAMPLING_SIZE", "sampling_size", "<reserved>", "Number of packets to sample",NO_FN,NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, SAMPLING_POPULATION, 310, DONT_QUOTE_OUTPUT, "SAMPLING_POPULATION", "sampling_population", "<reserved>", "Sampling population",NO_FN,NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, FRAME_LENGTH, 312, DONT_QUOTE_OUTPUT, "FRAME_LENGTH", "frame_length", "<reserved>", "Original L2 frame length",NO_FN,NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, PACKETS_OBSERVED, 318, DONT_QUOTE_OUTPUT, "PACKETS_OBSERVED", "packets_observed", "<reserved>", "Tot number of packets seen",NO_FN,NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, PACKETS_SELECTED, 319, DONT_QUOTE_OUTPUT, "PACKETS_SELECTED", "packets_selected", "<reserved>", "Number of pkts selected for sampling",NO_FN,NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, SELECTOR_NAME, 335, QUOTE_OUTPUT, "SELECTOR_NAME", "selector_name", "<reserved>", "Sampler name", print_selector_name ,NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, USERNAME, 371, QUOTE_OUTPUT, "USERNAME", "user", "User Name", "User name", print_string, NO_CHILDS)\
	X(NTOP_ENTERPRISE_ID, FRAGMENTS, NTOP_BASE_ID+80, DONT_QUOTE_OUTPUT, "FRAGMENTS", "fragments", "", "Number of fragmented flow packets",NO_FN,NO_CHILDS)\
	X(NTOP_ENTERPRISE_ID, CLIENT_NW_DELAY_SEC, NTOP_BASE_ID+82, DONT_QUOTE_OUTPUT, "CLIENT_NW_DELAY_SEC", "client_nw_delay_sec", "", "Network latency client <-> nprobe (sec) [deprecated]",NO_FN,NO_CHILDS)\
	X(NTOP_ENTERPRISE_ID, CLIENT_NW_DELAY_USEC, NTOP_BASE_ID+83, DONT_QUOTE_OUTPUT, "CLIENT_NW_DELAY_USEC", "client_nw_delay_usec", "", "Network latency client <-> nprobe (residual usec) [deprecated]",NO_FN,NO_CHILDS)\
	X(NTOP_ENTERPRISE_ID, CLIENT_NW_DELAY_MS, NTOP_BASE_ID+123, DONT_QUOTE_OUTPUT, "CLIENT_NW_DELAY_MS", "client_nw_delay_ms", "", "Network latency client <-> nprobe (msec)",NO_FN,NO_CHILDS)\
	X(NTOP_ENTERPRISE_ID, SERVER_NW_DELAY_SEC, NTOP_BASE_ID+84, DONT_QUOTE_OUTPUT, "SERVER_NW_DELAY_SEC", "server_nw_delay_sec", "", "Network latency nprobe <-> server (sec) [deprecated]",NO_FN,NO_CHILDS)\
	X(NTOP_ENTERPRISE_ID, SERVER_NW_DELAY_USEC, NTOP_BASE_ID+85, DONT_QUOTE_OUTPUT, "SERVER_NW_DELAY_USEC", "server_nw_delay_usec", "", "Network latency nprobe <-> server (residual usec) [deprecated]",NO_FN,NO_CHILDS)\
	X(NTOP_ENTERPRISE_ID, SERVER_NW_DELAY_MS, NTOP_BASE_ID+124, DONT_QUOTE_OUTPUT, "SERVER_NW_DELAY_MS", "server_nw_delay_ms", "", "Network latency nprobe <-> server (residual msec)",NO_FN,NO_CHILDS)\
	X(NTOP_ENTERPRISE_ID, APPL_LATENCY_SEC, NTOP_BASE_ID+86, DONT_QUOTE_OUTPUT, "APPL_LATENCY_SEC", "appl_latency_sec", "", "Application latency (sec) [deprecated]",NO_FN,NO_CHILDS)\
	X(NTOP_ENTERPRISE_ID, APPL_LATENCY_USEC, NTOP_BASE_ID+87, DONT_QUOTE_OUTPUT, "APPL_LATENCY_USEC", "appl_latency_usec", "", "Application latency (residual usec) [deprecated]",NO_FN,NO_CHILDS)\
	X(NTOP_ENTERPRISE_ID, APPL_LATENCY_MS, NTOP_BASE_ID+125, DONT_QUOTE_OUTPUT, "APPL_LATENCY_MS", "appl_latency_ms", "", "Application latency (msec)",NO_FN,NO_CHILDS)\
	X(NTOP_ENTERPRISE_ID, NUM_PKTS_UP_TO_128_BYTES, NTOP_BASE_ID+88, DONT_QUOTE_OUTPUT, "NUM_PKTS_UP_TO_128_BYTES", "num_pkts_up_to_128_bytes", "", "# packets whose size <= 128",NO_FN,NO_CHILDS)\
	X(NTOP_ENTERPRISE_ID, NUM_PKTS_128_TO_256_BYTES, NTOP_BASE_ID+89, DONT_QUOTE_OUTPUT, "NUM_PKTS_128_TO_256_BYTES", "num_pkts_128_to_256_bytes", "", "# packets whose size > 128 and <= 256",NO_FN,NO_CHILDS)\
	X(NTOP_ENTERPRISE_ID, NUM_PKTS_256_TO_512_BYTES, NTOP_BASE_ID+90, DONT_QUOTE_OUTPUT, "NUM_PKTS_256_TO_512_BYTES", "num_pkts_256_to_512_bytes", "", "# packets whose size > 256 and < 512",NO_FN,NO_CHILDS)\
	X(NTOP_ENTERPRISE_ID, NUM_PKTS_512_TO_1024_BYTES, NTOP_BASE_ID+91, DONT_QUOTE_OUTPUT, "NUM_PKTS_512_TO_1024_BYTES", "num_pkts_512_to_1024_bytes", "", "# packets whose size > 512 and < 1024",NO_FN,NO_CHILDS)\
	X(NTOP_ENTERPRISE_ID, NUM_PKTS_1024_TO_1514_BYTES, NTOP_BASE_ID+92, DONT_QUOTE_OUTPUT, "NUM_PKTS_1024_TO_1514_BYTES", "num_pkts_1024_to_1514_bytes", "", "# packets whose size > 1024 and <= 1514",NO_FN,NO_CHILDS)\
	X(NTOP_ENTERPRISE_ID, NUM_PKTS_OVER_1514_BYTES, NTOP_BASE_ID+93, DONT_QUOTE_OUTPUT, "NUM_PKTS_OVER_1514_BYTES", "num_pkts_over_1514_bytes", "", "# packets whose size > 1514",NO_FN,NO_CHILDS)\
	X(NTOP_ENTERPRISE_ID, CUMULATIVE_ICMP_TYPE, NTOP_BASE_ID+98, DONT_QUOTE_OUTPUT, "CUMULATIVE_ICMP_TYPE", "cumulative_icmp_type", "", "Cumulative OR of ICMP type packets",NO_FN,NO_CHILDS)\
	X_GEO_IP \
	X(NTOP_ENTERPRISE_ID, FLOW_PROTO_PORT, NTOP_BASE_ID+105, DONT_QUOTE_OUTPUT, "FLOW_PROTO_PORT", "flow_proto_port", "", "L7 port that identifies the flow protocol or 0 if unknown",NO_FN,NO_CHILDS)\
	X(NTOP_ENTERPRISE_ID, UPSTREAM_TUNNEL_ID, NTOP_BASE_ID+106, DONT_QUOTE_OUTPUT, "UPSTREAM_TUNNEL_ID", "upstream_tunnel_id", "", "Upstream tunnel identifier (e.g. GTP TEID) or 0 if unknown",NO_FN,NO_CHILDS)\
	X(NTOP_ENTERPRISE_ID, LONGEST_FLOW_PKT, NTOP_BASE_ID+107, DONT_QUOTE_OUTPUT, "LONGEST_FLOW_PKT", "longest_flow_pkt", "", "Longest packet (bytes) of the flow",NO_FN,NO_CHILDS)\
	X(NTOP_ENTERPRISE_ID, SHORTEST_FLOW_PKT, NTOP_BASE_ID+108, DONT_QUOTE_OUTPUT, "SHORTEST_FLOW_PKT", "shortest_flow_pkt", "", "Shortest packet (bytes) of the flow",NO_FN,NO_CHILDS)\
	X(NTOP_ENTERPRISE_ID, RETRANSMITTED_IN_PKTS, NTOP_BASE_ID+109, DONT_QUOTE_OUTPUT, "RETRANSMITTED_IN_PKTS", "retransmitted_in_pkts", "", "Number of retransmitted TCP flow packets (src->dst)",NO_FN,NO_CHILDS)\
	X(NTOP_ENTERPRISE_ID, RETRANSMITTED_OUT_PKTS, NTOP_BASE_ID+110, DONT_QUOTE_OUTPUT, "RETRANSMITTED_OUT_PKTS", "retransmitted_out_pkts", "", "Number of retransmitted TCP flow packets (dst->src)",NO_FN,NO_CHILDS)\
	X(NTOP_ENTERPRISE_ID, OOORDER_IN_PKTS, NTOP_BASE_ID+111, DONT_QUOTE_OUTPUT, "OOORDER_IN_PKTS", "ooorder_in_pkts", "", "Number of out of order TCP flow packets (dst->src)",NO_FN,NO_CHILDS)\
	X(NTOP_ENTERPRISE_ID, OOORDER_OUT_PKTS, NTOP_BASE_ID+112, DONT_QUOTE_OUTPUT, "OOORDER_OUT_PKTS", "ooorder_out_pkts", "", "Number of out of order TCP flow packets (dst->src)",NO_FN,NO_CHILDS)\
	X(NTOP_ENTERPRISE_ID, UNTUNNELED_PROTOCOL, NTOP_BASE_ID+113, DONT_QUOTE_OUTPUT, "UNTUNNELED_PROTOCOL", "l2_proto", "", "Untunneled IP protocol byte",NO_FN,NO_CHILDS)\
	X(NTOP_ENTERPRISE_ID, UNTUNNELED_IPV4_SRC_ADDR, NTOP_BASE_ID+114, QUOTE_OUTPUT, "UNTUNNELED_IPV4_SRC_ADDR", "untunneled_src", "", "Untunneled IPv4 source address",NO_FN,NO_CHILDS)\
	X(NTOP_ENTERPRISE_ID, UNTUNNELED_L4_SRC_PORT, NTOP_BASE_ID+115, DONT_QUOTE_OUTPUT, "UNTUNNELED_L4_SRC_PORT", "untunneled_srcport", "", "Untunneled IPv4 source port",NO_FN,NO_CHILDS)\
	X(NTOP_ENTERPRISE_ID, UNTUNNELED_IPV4_DST_ADDR, NTOP_BASE_ID+116, QUOTE_OUTPUT, "UNTUNNELED_IPV4_DST_ADDR", "untunneled_dst_str", "", "Untunneled IPv4 destination address",NO_FN,NO_CHILDS)\
	X(NTOP_ENTERPRISE_ID, UNTUNNELED_L4_DST_PORT, NTOP_BASE_ID+117, DONT_QUOTE_OUTPUT, "UNTUNNELED_L4_DST_PORT", "untunneled_dstport", "", "Untunneled IPv4 destination port",NO_FN,NO_CHILDS)\
	X(NTOP_ENTERPRISE_ID, L7_PROTO, NTOP_BASE_ID+118, DONT_QUOTE_OUTPUT, "L7_PROTO", "l7_proto", "", "Layer 7 protocol (numeric)",NO_FN,NO_CHILDS)\
	X(NTOP_ENTERPRISE_ID, L7_PROTO_NAME, NTOP_BASE_ID+119,  QUOTE_OUTPUT, "L7_PROTO_NAME", "l7_proto_name", "", "Layer 7 protocol name",NO_FN,NO_CHILDS)\
	X(NTOP_ENTERPRISE_ID, DOWNSTREAM_TUNNEL_ID, NTOP_BASE_ID+120, DONT_QUOTE_OUTPUT, "DOWNSTREAM_TUNNEL_ID", "downstream_tunnel_id", "", "Downstream tunnel identifier (e.g. GTP TEID) or 0 if unknown",NO_FN,NO_CHILDS)\
	X(NTOP_ENTERPRISE_ID, FLOW_USER_NAME, NTOP_BASE_ID+121, QUOTE_OUTPUT, "FLOW_USER_NAME", "flow_user_name", "", "Flow username of the tunnel (if known)",NO_FN,NO_CHILDS)\
	X(NTOP_ENTERPRISE_ID, FLOW_SERVER_NAME, NTOP_BASE_ID+122, QUOTE_OUTPUT, "FLOW_SERVER_NAME", "flow_server_name", "", "Flow server name (if known)",NO_FN,NO_CHILDS)\
	X(NTOP_ENTERPRISE_ID, PLUGIN_NAME, NTOP_BASE_ID+126, QUOTE_OUTPUT, "PLUGIN_NAME", "plugin_name", "", "Plugin name used by this flow (if any)",NO_FN,NO_CHILDS)\
	X(NTOP_ENTERPRISE_ID, NUM_PKTS_TTL_EQ_1, NTOP_BASE_ID+347, DONT_QUOTE_OUTPUT, "NUM_PKTS_TTL_EQ_1", "num_pkts_ttl_eq_1", "", "# packets with TTL = 1",NO_FN,NO_CHILDS)\
	X(NTOP_ENTERPRISE_ID, NUM_PKTS_TTL_2_5, NTOP_BASE_ID+346, DONT_QUOTE_OUTPUT, "NUM_PKTS_TTL_2_5", "num_pkts_ttl_2_5", "", "# packets with TTL > 1 and TTL <= 5",NO_FN,NO_CHILDS)\
	X(NTOP_ENTERPRISE_ID, NUM_PKTS_TTL_5_32, NTOP_BASE_ID+334, DONT_QUOTE_OUTPUT, "NUM_PKTS_TTL_5_32", "num_pkts_ttl_5_32", "", "# packets with TTL > 5 and TTL <= 32",NO_FN,NO_CHILDS)\
	X(NTOP_ENTERPRISE_ID, NUM_PKTS_TTL_32_64, NTOP_BASE_ID+335, DONT_QUOTE_OUTPUT, "NUM_PKTS_TTL_32_64", "num_pkts_ttl_32_64", "", "# packets with TTL > 32 and <= 64 ",NO_FN,NO_CHILDS)\
	X(NTOP_ENTERPRISE_ID, NUM_PKTS_TTL_64_96, NTOP_BASE_ID+336, DONT_QUOTE_OUTPUT, "NUM_PKTS_TTL_64_96", "num_pkts_ttl_64_96", "", "# packets with TTL > 64 and <= 96",NO_FN,NO_CHILDS)\
	X(NTOP_ENTERPRISE_ID, NUM_PKTS_TTL_96_128, NTOP_BASE_ID+337, DONT_QUOTE_OUTPUT, "NUM_PKTS_TTL_96_128", "num_pkts_ttl_96_128", "", "# packets with TTL > 96 and <= 128",NO_FN,NO_CHILDS)\
	X(NTOP_ENTERPRISE_ID, NUM_PKTS_TTL_128_160, NTOP_BASE_ID+338, DONT_QUOTE_OUTPUT, "NUM_PKTS_TTL_128_160", "num_pkts_ttl_128_160", "", "# packets with TTL > 128 and <= 160",NO_FN,NO_CHILDS)\
	X(NTOP_ENTERPRISE_ID, NUM_PKTS_TTL_160_192, NTOP_BASE_ID+339, DONT_QUOTE_OUTPUT, "NUM_PKTS_TTL_160_192", "num_pkts_ttl_160_192", "", "# packets with TTL > 160 and <= 192",NO_FN,NO_CHILDS)\
	X(NTOP_ENTERPRISE_ID, NUM_PKTS_TTL_192_224, NTOP_BASE_ID+340, DONT_QUOTE_OUTPUT, "NUM_PKTS_TTL_192_224", "num_pkts_ttl_192_224", "", "# packets with TTL > 192 and <= 224",NO_FN,NO_CHILDS)\
	X(NTOP_ENTERPRISE_ID, NUM_PKTS_TTL_224_255, NTOP_BASE_ID+341, DONT_QUOTE_OUTPUT, "NUM_PKTS_TTL_224_255", "num_pkts_ttl_224_255", "", "# packets with TTL > 224 and <= 255",NO_FN,NO_CHILDS)\
	X_CISCO_URL \
	X(CISCO_ENTERPRISE_ID, WLAN_SSID, 147, QUOTE_OUTPUT, "WLAN_SSID", "wireless_id", "wlan_ssid", "SSID of Wireless LAN", print_ssid_name, NO_CHILDS)\
	X(CISCO_ENTERPRISE_ID, STA_MAC_ADDRESS, 365, QUOTE_OUTPUT, "STA_MAC_ADDRESS", "sta_mac", "apMacAddress", "Access Point MAC Address", NO_FN,CLIENT_MAC_ADDRESS)\
	X(CISCO_ENTERPRISE_ID, CLIENT_MAC_ADDRESS, PRIVATE_ENTITY_ID, QUOTE_OUTPUT, "CLIENT_MAC_ADDRESS", "client_mac", "apMacAddress", "Access Point MAC Address", print_client_mac, CLIENT_MAC_VENDOR)\
	X(CISCO_ENTERPRISE_ID, CLIENT_MAC_BASED_ON_DIRECTION, PRIVATE_ENTITY_ID, QUOTE_OUTPUT, "DIRECTION_BASED_CLIENT_MAC_ADDRESS", "client_mac", "apMacAddress", "Access Point MAC Address", print_direction_based_client_mac, DIRECTION_BASED_CLIENT_MAC_VENDOR)\
	X(CISCO_ENTERPRISE_ID, CLIENT_MAC_MAP, PRIVATE_ENTITY_ID, QUOTE_OUTPUT, "CLIENT_MAC_ADDRESS_NAME", "client_mac_name", "apMacAddressName", "Access Point MAC Address Name" , print_mac_map, NO_CHILDS)\
	X(CISCO_ENTERPRISE_ID, CLIENT_MAC_VENDOR, PRIVATE_ENTITY_ID, QUOTE_OUTPUT, "CLIENT_MAC_ADDRESS_VENDOR", "client_mac_vendor", "apMacAddressName", "Access Point MAC Address Name" , print_mac_vendor, NO_CHILDS)\
	X(CISCO_ENTERPRISE_ID, DIRECTION_BASED_CLIENT_MAC_VENDOR, PRIVATE_ENTITY_ID, QUOTE_OUTPUT, "DIRECTION_BASED_CLIENT_MAC_ADDRESS_VENDOR", "client_mac_vendor", "apMacAddressName", "Access Point MAC Address Name" , print_direction_based_client_mac_vendor, NO_CHILDS)\
	X(CISCO_ENTERPRISE_ID, LAN_IP_BASED_ON_DIRECTION, PRIVATE_ENTITY_ID, QUOTE_OUTPUT, "LAN_IP", "lan_ip", "LAN_IP", "LAN IP address", print_lan_addr, C(LAN_IP_NET_BASED_ON_DIRECTION, LAN_IP_GEO_CHILDS))\
	X(CISCO_ENTERPRISE_ID, LAN_IP_NET_BASED_ON_DIRECTION, PRIVATE_ENTITY_ID, QUOTE_OUTPUT, "LAN_IP_NET_BASED_ON_DIRECTION", "lan_ip_net", "LAN_IP", "LAN IP address", print_lan_addr_net, LAN_IP_NET_NAME_BASED_ON_DIRECTION)\
	X(CISCO_ENTERPRISE_ID, LAN_IP_NET_NAME_BASED_ON_DIRECTION, PRIVATE_ENTITY_ID, QUOTE_OUTPUT, "LAN_IP_NET_NAME_BASED_ON_DIRECTION", "lan_ip_net_name", "LAN_IP", "LAN IP address", print_lan_addr_net_name, NO_CHILDS)\
	X(CISCO_ENTERPRISE_ID, WAN_IP_BASED_ON_DIRECTION, PRIVATE_ENTITY_ID, QUOTE_OUTPUT, "WAN_IP", "wan_ip", "IP", "WAN IP address", print_wan_addr, C(WAN_IP_NET_BASED_ON_DIRECTION, WAN_IP_GEO_CHILDS))\
	X(CISCO_ENTERPRISE_ID, WAN_IP_NET_BASED_ON_DIRECTION, PRIVATE_ENTITY_ID, QUOTE_OUTPUT, "WAN_IP_NET_BASED_ON_DIRECTION", "wan_ip_net", "IP", "WAN IP address", print_wan_addr_net, WAN_IP_NET_NAME_BASED_ON_DIRECTION)\
	X(CISCO_ENTERPRISE_ID, WAN_IP_NET_NAME_BASED_ON_DIRECTION, PRIVATE_ENTITY_ID, QUOTE_OUTPUT, "WAN_IP_NET_NAME_BASED_ON_DIRECTION", "wan_ip_net_name", "IP", "WAN IP address", print_wan_addr_net_name, NO_CHILDS)\
	X(CISCO_ENTERPRISE_ID, LAN_PORT, PRIVATE_ENTITY_ID, DONT_QUOTE_OUTPUT, "LAN_PORT_BASED_ON_DIRECTION", "lan_l4_port", "lanPort", "LAN Port number", print_lan_port, NO_CHILDS)\
	X(CISCO_ENTERPRISE_ID, WAN_PORT, PRIVATE_ENTITY_ID, DONT_QUOTE_OUTPUT, "WAN_PORT_BASED_ON_DIRECTION", "wan_l4_port", "wanPort", "WAN Port number", print_wan_port, NO_CHILDS)\
	X(CISCO_ENTERPRISE_ID, LAN_INTERFACE, PRIVATE_ENTITY_ID, DONT_QUOTE_OUTPUT, "LAN_INTERFACE_BASED_ON_DIRECTION", "lan_interface", "lanInterface", "LAN Interface number", print_lan_interface, C(LAN_INTERFACE_NAME, LAN_INTERFACE_DESCRIPTION))\
	X(CISCO_ENTERPRISE_ID, LAN_INTERFACE_NAME, PRIVATE_ENTITY_ID, QUOTE_OUTPUT, "LAN_INTERFACE_NAME_BASED_ON_DIRECTION", "lan_interface_name", "lanInterface", "LAN Interface name", print_lan_interface_name, NO_CHILDS)\
	X(CISCO_ENTERPRISE_ID, LAN_INTERFACE_DESCRIPTION, PRIVATE_ENTITY_ID, QUOTE_OUTPUT, "LAN_INTERFACE_DESCRIPTION_BASED_ON_DIRECTION", "lan_interface_description", "lanInterface", "LAN Interface description", print_lan_interface_description, NO_CHILDS)\
	X(CISCO_ENTERPRISE_ID, WAN_INTERFACE, PRIVATE_ENTITY_ID, DONT_QUOTE_OUTPUT, "WAN_INTERFACE_BASED_ON_DIRECTION", "wan_interface", "wanInterface", "WAN Interface number", print_wan_interface, C(WAN_INTERFACE_NAME, WAN_INTERFACE_DESCRIPTION))\
	X(CISCO_ENTERPRISE_ID, WAN_INTERFACE_NAME, PRIVATE_ENTITY_ID, QUOTE_OUTPUT, "WAN_INTERFACE_NAME_BASED_ON_DIRECTION", "wan_interface_name", "wanInterface", "WAN Interface name", print_wan_interface_name, NO_CHILDS)\
	X(CISCO_ENTERPRISE_ID, WAN_INTERFACE_DESCRIPTION, PRIVATE_ENTITY_ID, QUOTE_OUTPUT, "WAN_INTERFACE_DESCRIPTION_BASED_ON_DIRECTION", "wan_interface_description", "wanInterface", "WAN Interface description", print_wan_interface_description, NO_CHILDS)\
	X(CISCO_ENTERPRISE_ID, STA_IPV4_ADDRESS, 366, QUOTE_OUTPUT, "STA_IPV4_ADDRESS", "lan_ip", "lan_ip", "IPv4 LAN address", print_sta_ipv4_address, C(STA_IPV4_ADDRESS_NET, STA_IPV4_ADDRESS_GEO_CHILDS))\
	X(CISCO_ENTERPRISE_ID, STA_IPV4_ADDRESS_NET, PRIVATE_ENTITY_ID, QUOTE_OUTPUT, "STA_IPV4_NET", "lan_ip_net", "STA_IPV4_NET", "Wireless station IP address", print_net, STA_IPV4_ADDRESS_NET_NAME)\
	X(CISCO_ENTERPRISE_ID, STA_IPV4_ADDRESS_NET_NAME, PRIVATE_ENTITY_ID, QUOTE_OUTPUT, "STA_IPV4_NET_NAME", "lan_ip_net_name", "STA_IPV4_NET", "Wireless station IP address", print_net_name, NO_CHILDS)\
	X(CISCO_ENTERPRISE_ID, WAP_MAC_ADDRESS, 367, QUOTE_OUTPUT, "WAP_MAC_ADDRESS", "wireless_station", "devMacAddr", "Device MAC Address",print_mac, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, REDBORDER_TYPE, PRIVATE_ENTITY_ID, QUOTE_OUTPUT, "REDBORDER_TYPE", "type", "type", "Redborder internal flowtype (currenly, netflow version)" ,print_netflow_type, NO_CHILDS)\
	X(STANDARD_ENTERPRISE_ID, FLOW_SEQUENCE, PRIVATE_ENTITY_ID, QUOTE_OUTPUT, "FLOW_SEQUENCE", "flow_sequence", "flow_sequence", "flow sequence number" ,print_number, NO_CHILDS)\
	X_UDNS \
	X(STANDARD_ENTERPRISE_ID, END_OF_ENTITIES, 0, false, NULL, NULL, NULL, NULL, NULL, NO_CHILDS ) /* That's all folks */

/// Template entities
enum {
#define X(ENTERPRISE_ID, ID_STR, ID, JSON_QUOTE, NAME, JSON_NAME, IPFIX_NAME, \
						DESCRIPTION, FUNCTION, CHILDS) \
								ID_STR = ID,
	X_TEMPLATE_ENTITIES
#undef X
};

struct flowCache;
struct printbuf;
typedef struct flow_ver9_ipfix_template_elementids {
  const uint16_t templateElementId;
  const bool quote; //< Hint if we need quote output or not
  const char *jsonElementName;
  size_t (*export_fn)(struct printbuf *kafka_line_buffer,
    const void *buffer,const size_t real_field_len,
    struct flowCache *flowCache);

  /* Auto-filled fields */
  const struct flow_ver9_ipfix_template_elementids **postTemplate;
} V9V10TemplateElementId;

/// Position of a template in our database. Do not use directly, use TEMPLATE_OF
enum {
#define X(ENTERPRISE_ID, ID_STR, ID, JSON_QUOTE, NAME, JSON_NAME, IPFIX_NAME, \
						DESCRIPTION, FUNCTION, CHILDS) \
								ID_STR##_POS,
	X_TEMPLATE_ENTITIES
#undef X
};

/// All IPFIX/version 9 template ids, names and function to process
extern const V9V10TemplateElementId ver9_templates[];
/// NF5 interesting fields, NULL terminated
extern const V9V10TemplateElementId *v5TemplateFields[];
#define TEMPLATE_OF(entity) &ver9_templates[entity##_POS]

void printTemplateInfo(const V9V10TemplateElementId *templates);
struct flowSetV9Ipfix;
char *serialize_template(const struct flowSetV9Ipfix *new_template,size_t *_new_buffer_size);
struct flowSetV9Ipfix *deserialize_template(const char *buf,size_t bufsize);
const V9V10TemplateElementId *find_template(const int templateElementId);
