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

#include "f2k.h"

#include "rb_netflow_test.h"

#include <setjmp.h>
#include <cmocka.h>

static const NetFlow5Record record1 = {
	.flowHeader = {
		.version = 0x0500,     /* Current version=5*/
		.count = 0x0600,       /* The number of records in PDU. */
		.sys_uptime = 12345,    /* Current time in msecs since router booted */
		.unix_secs = 12345,    /* Current seconds since 0000 UTC 1970 */
		.unix_nsecs = 12345,   /* Residual nanoseconds since 0000 UTC 1970 */
		.flow_sequence = 1050, /* Sequence number of total flows seen */
		.engine_type = 0,      /* Type of flow switching engine (RP,VIP,etc.)*/
		.engine_id  = 0,       /* Slot number of the flow switching engine */
		.sampleRate = 0,       /* Packet capture sample rate */
	},

	.flowRecord = {
		/* FIRST: Can't complete net information */
		[0] = {
			.srcaddr = 0x0101a8c0L,    /* Source IP Address */
			.dstaddr = 0x0201a8c0L,    /* Destination IP Address */
			.nexthop = 0x00000000L,    /* Next hop router's IP Address */
			.input   = 0,              /* Input interface index */
			.output  = 255,            /* Output interface index */
			.dPkts   = 0x0100,              /* Packets sent in Duration (milliseconds between 1st
			                             & last packet in this flow)*/
			.dOctets = 0x4600,             /* Octets sent in Duration (milliseconds between 1st
			                             & last packet in  this flow)*/
			.first   = 0xa8484206,     /* SysUptime at start of flow */
			.last    = 0xa8484206,     /* and of last packet of the flow */
			.srcport = 0xbb01,     /* ntohs(443)  */  /* TCP/UDP source port number (.e.g, FTP, Telnet, etc.,or equivalent) */
			.dstport = 0x7527,   /* ntohs(10101)*/  /* TCP/UDP destination port number (.e.g, FTP, Telnet, etc.,or equivalent) */
			.pad1    = 0,        /* pad to word boundary */
			.tcp_flags = 0,   /* Cumulative OR of tcp flags */
			.proto   = 0,     /* IP protocol, e.g., 6=TCP, 17=UDP, etc... */
			.tos     = 0,     /* IP Type-of-Service */
			.src_as  = 0,     /* source peer/origin Autonomous System */
			.dst_as  = 0,     /* dst peer/origin Autonomous System */
			.src_mask = 0,    /* source route's mask bits */
			.dst_mask = 0,    /* destination route's mask bits */
			.pad2    = 0,       /* pad to word boundary */
		},

		/* Second: Source belongs to home net */
		[1] = {
			.srcaddr = 0x0a1e000aL,    /* Source IP Address */
			.dstaddr = 0x0201a8c0L,    /* Destination IP Address */
			.nexthop = 0x00000000L,    /* Next hop router's IP Address */
			.input   = 0,              /* Input interface index */
			.output  = 255,            /* Output interface index */
			.dPkts   = 0x0100,              /* Packets sent in Duration (milliseconds between 1st
			                             & last packet in this flow)*/
			.dOctets = 0x4600,             /* Octets sent in Duration (milliseconds between 1st
			                             & last packet in  this flow)*/
			.first   = 0xa8484205,     /* SysUptime at start of flow */
			.last    = 0xa8484205,     /* and of last packet of the flow */
			.srcport = 0xbb01,     /* ntohs(443)  */  /* TCP/UDP source port number (.e.g, FTP, Telnet, etc.,or equivalent) */
			.dstport = 0x7527,   /* ntohs(10101)*/  /* TCP/UDP destination port number (.e.g, FTP, Telnet, etc.,or equivalent) */
			.pad1    = 0,        /* pad to word boundary */
			.tcp_flags = 0,   /* Cumulative OR of tcp flags */
			.proto   = 0,     /* IP protocol, e.g., 6=TCP, 17=UDP, etc... */
			.tos     = 0,     /* IP Type-of-Service */
			.src_as  = 0,     /* source peer/origin Autonomous System */
			.dst_as  = 0,     /* dst peer/origin Autonomous System */
			.src_mask = 0,    /* source route's mask bits */
			.dst_mask = 0,    /* destination route's mask bits */
			.pad2    = 0,       /* pad to word boundary */
		},

		/* 3rd: Source belongs to objects net */
		[2] = {
			.srcaddr = 0x08080808L,    /* Source IP Address */
			.dstaddr = 0x0201a8c0L,    /* Destination IP Address */
			.nexthop = 0x00000000L,    /* Next hop router's IP Address */
			.input   = 0,              /* Input interface index */
			.output  = 255,            /* Output interface index */
			.dPkts   = 0x0100,              /* Packets sent in Duration (milliseconds between 1st
			                             & last packet in this flow)*/
			.dOctets = 0x4600,             /* Octets sent in Duration (milliseconds between 1st
			                             & last packet in  this flow)*/
			.first   = 0xa8484205,     /* SysUptime at start of flow */
			.last    = 0xa8484205,     /* and of last packet of the flow */
			.srcport = 0xbb01,     /* ntohs(443)  */  /* TCP/UDP source port number (.e.g, FTP, Telnet, etc.,or equivalent) */
			.dstport = 0x7527,   /* ntohs(10101)*/  /* TCP/UDP destination port number (.e.g, FTP, Telnet, etc.,or equivalent) */
			.pad1    = 0,        /* pad to word boundary */
			.tcp_flags = 0,   /* Cumulative OR of tcp flags */
			.proto   = 0,     /* IP protocol, e.g., 6=TCP, 17=UDP, etc... */
			.tos     = 0,     /* IP Type-of-Service */
			.src_as  = 0,     /* source peer/origin Autonomous System */
			.dst_as  = 0,     /* dst peer/origin Autonomous System */
			.src_mask = 0,    /* source route's mask bits */
			.dst_mask = 0,    /* destination route's mask bits */
			.pad2    = 0,       /* pad to word boundary */
		},

		/* 4th: Destination belongs to home net */
		[3] = {
			.srcaddr = 0x0201a8c0L,    /* Source IP Address */
			.dstaddr = 0x0a1e000aL,    /* Destination IP Address */
			.nexthop = 0x00000000L,    /* Next hop router's IP Address */
			.input   = 0,              /* Input interface index */
			.output  = 255,            /* Output interface index */
			.dPkts   = 0x0100,              /* Packets sent in Duration (milliseconds between 1st
			                             & last packet in this flow)*/
			.dOctets = 0x4600,             /* Octets sent in Duration (milliseconds between 1st
			                             & last packet in  this flow)*/
			.first   = 0xa8484205,     /* SysUptime at start of flow */
			.last    = 0xa8484205,     /* and of last packet of the flow */
			.srcport = 0xbb01,     /* ntohs(443)  */  /* TCP/UDP source port number (.e.g, FTP, Telnet, etc.,or equivalent) */
			.dstport = 0x7527,   /* ntohs(10101)*/  /* TCP/UDP destination port number (.e.g, FTP, Telnet, etc.,or equivalent) */
			.pad1    = 0,        /* pad to word boundary */
			.tcp_flags = 0,   /* Cumulative OR of tcp flags */
			.proto   = 0,     /* IP protocol, e.g., 6=TCP, 17=UDP, etc... */
			.tos     = 0,     /* IP Type-of-Service */
			.src_as  = 0,     /* source peer/origin Autonomous System */
			.dst_as  = 0,     /* dst peer/origin Autonomous System */
			.src_mask = 0,    /* source route's mask bits */
			.dst_mask = 0,    /* destination route's mask bits */
			.pad2    = 0,       /* pad to word boundary */
		},

		/* 5th: Destination belongs to objects net */
		[4] = {
			.srcaddr = 0x0201a8c0L,    /* Source IP Address */
			.dstaddr = 0x08080808L,    /* Destination IP Address */
			.nexthop = 0x00000000L,    /* Next hop router's IP Address */
			.input   = 0,              /* Input interface index */
			.output  = 255,            /* Output interface index */
			.dPkts   = 0x0100,              /* Packets sent in Duration (milliseconds between 1st
			                             & last packet in this flow)*/
			.dOctets = 0x4600,             /* Octets sent in Duration (milliseconds between 1st
			                             & last packet in  this flow)*/
			.first   = 0xa8484205,     /* SysUptime at start of flow */
			.last    = 0xa8484205,     /* and of last packet of the flow */
			.srcport = 0xbb01,     /* ntohs(443)  */  /* TCP/UDP source port number (.e.g, FTP, Telnet, etc.,or equivalent) */
			.dstport = 0x7527,   /* ntohs(10101)*/  /* TCP/UDP destination port number (.e.g, FTP, Telnet, etc.,or equivalent) */
			.pad1    = 0,        /* pad to word boundary */
			.tcp_flags = 0,   /* Cumulative OR of tcp flags */
			.proto   = 0,     /* IP protocol, e.g., 6=TCP, 17=UDP, etc... */
			.tos     = 0,     /* IP Type-of-Service */
			.src_as  = 0,     /* source peer/origin Autonomous System */
			.dst_as  = 0,     /* dst peer/origin Autonomous System */
			.src_mask = 0,    /* source route's mask bits */
			.dst_mask = 0,    /* destination route's mask bits */
			.pad2    = 0,       /* pad to word boundary */
		},

		/* 6th: Source belongs to home net and objects nets. Must priorize home net. */
		[5] = {
			.srcaddr = 0x0a96000aL,    /* Source IP Address */
			.dstaddr = 0x0201a8c0L,    /* Destination IP Address */
			.nexthop = 0x00000000L,    /* Next hop router's IP Address */
			.input   = 0,              /* Input interface index */
			.output  = 255,            /* Output interface index */
			.dPkts   = 0x0100,              /* Packets sent in Duration (milliseconds between 1st
			                             & last packet in this flow)*/
			.dOctets = 0x4600,             /* Octets sent in Duration (milliseconds between 1st
			                             & last packet in  this flow)*/
			.first   = 0xa8484205,     /* SysUptime at start of flow */
			.last    = 0xa8484205,     /* and of last packet of the flow */
			.srcport = 0xbb01,     /* ntohs(443)  */  /* TCP/UDP source port number (.e.g, FTP, Telnet, etc.,or equivalent) */
			.dstport = 0x7527,   /* ntohs(10101)*/  /* TCP/UDP destination port number (.e.g, FTP, Telnet, etc.,or equivalent) */
			.pad1    = 0,        /* pad to word boundary */
			.tcp_flags = 0,   /* Cumulative OR of tcp flags */
			.proto   = 0,     /* IP protocol, e.g., 6=TCP, 17=UDP, etc... */
			.tos     = 0,     /* IP Type-of-Service */
			.src_as  = 0,     /* source peer/origin Autonomous System */
			.dst_as  = 0,     /* dst peer/origin Autonomous System */
			.src_mask = 0,    /* source route's mask bits */
			.dst_mask = 0,    /* destination route's mask bits */
			.pad2    = 0,       /* pad to word boundary */
		},

		/* 7th: Source belongs to home net and objects nets. Must priorize home net. */
		[6] = {
			.srcaddr = 0x0201a8c0L,    /* Source IP Address */
			.dstaddr = 0x0a96000aL,    /* Destination IP Address */
			.nexthop = 0x00000000L,    /* Next hop router's IP Address */
			.input   = 0,              /* Input interface index */
			.output  = 255,            /* Output interface index */
			.dPkts   = 0x0100,              /* Packets sent in Duration (milliseconds between 1st
			                             & last packet in this flow)*/
			.dOctets = 0x4600,             /* Octets sent in Duration (milliseconds between 1st
			                             & last packet in  this flow)*/
			.first   = 0xa8484205,     /* SysUptime at start of flow */
			.last    = 0xa8484205,     /* and of last packet of the flow */
			.srcport = 0xbb01,     /* ntohs(443)  */  /* TCP/UDP source port number (.e.g, FTP, Telnet, etc.,or equivalent) */
			.dstport = 0x7527,   /* ntohs(10101)*/  /* TCP/UDP destination port number (.e.g, FTP, Telnet, etc.,or equivalent) */
			.pad1    = 0,        /* pad to word boundary */
			.tcp_flags = 0,   /* Cumulative OR of tcp flags */
			.proto   = 0,     /* IP protocol, e.g., 6=TCP, 17=UDP, etc... */
			.tos     = 0,     /* IP Type-of-Service */
			.src_as  = 0,     /* source peer/origin Autonomous System */
			.dst_as  = 0,     /* dst peer/origin Autonomous System */
			.src_mask = 0,    /* source route's mask bits */
			.dst_mask = 0,    /* destination route's mask bits */
			.pad2    = 0,       /* pad to word boundary */
		},
	}
};

/* Second record: This sensor does not have any home nets. */
static const NetFlow5Record record2 = {
	.flowHeader = {
		.version = 0x0500,     /* Current version=5*/
		.count = 0x0100,       /* The number of records in PDU. */
		.sys_uptime = 12345,    /* Current time in msecs since router booted */
		.unix_secs = 12345,    /* Current seconds since 0000 UTC 1970 */
		.unix_nsecs = 12345,   /* Residual nanoseconds since 0000 UTC 1970 */
		.flow_sequence = 1050, /* Sequence number of total flows seen */
		.engine_type = 0,      /* Type of flow switching engine (RP,VIP,etc.)*/
		.engine_id  = 0,       /* Slot number of the flow switching engine */
		.sampleRate = 0,       /* Packet capture sample rate */
	},

	.flowRecord = {
		/* Second: Source belongs to home net from ANOTHER sensors */
		[0] = {
			.srcaddr = 0x0a1e000aL,    /* Source IP Address */
			.dstaddr = 0x0201a8c0L,    /* Destination IP Address */
			.nexthop = 0x00000000L,    /* Next hop router's IP Address */
			.input   = 0,              /* Input interface index */
			.output  = 255,            /* Output interface index */
			.dPkts   = 0x0100,              /* Packets sent in Duration (milliseconds between 1st
			                             & last packet in this flow)*/
			.dOctets = 0x4600,             /* Octets sent in Duration (milliseconds between 1st
			                             & last packet in  this flow)*/
			.first   = 0xa8484205,     /* SysUptime at start of flow */
			.last    = 0xa8484205,     /* and of last packet of the flow */
			.srcport = 0xbb01,     /* ntohs(443)  */  /* TCP/UDP source port number (.e.g, FTP, Telnet, etc.,or equivalent) */
			.dstport = 0x7527,   /* ntohs(10101)*/  /* TCP/UDP destination port number (.e.g, FTP, Telnet, etc.,or equivalent) */
			.pad1    = 0,        /* pad to word boundary */
			.tcp_flags = 0,   /* Cumulative OR of tcp flags */
			.proto   = 0,     /* IP protocol, e.g., 6=TCP, 17=UDP, etc... */
			.tos     = 0,     /* IP Type-of-Service */
			.src_as  = 0,     /* source peer/origin Autonomous System */
			.dst_as  = 0,     /* dst peer/origin Autonomous System */
			.src_mask = 0,    /* source route's mask bits */
			.dst_mask = 0,    /* destination route's mask bits */
			.pad2    = 0,       /* pad to word boundary */
		},
	}
};

static int prepare_test_nf5_home_nets_0(void **state,
					const bool normalize_directions,
					const struct checkdata *checkdata_r1,
					const size_t checkdata_r1_size,
					const struct checkdata *checkdata_r2,
					const size_t checkdata_r2_size) {
#define TEST(nf_dev_ip, mrecord, mrecord_size, checks, checks_size, ...) {     \
		.netflow_src_ip = nf_dev_ip,                                   \
		.record = mrecord, .record_size = mrecord_size,                \
		.checkdata = checks, .checkdata_size = checks_size,            \
		__VA_ARGS__}

	struct test_params test_params[] = {
		[0] = TEST(0x04030201,
			&record1, sizeof(record1),
			checkdata_r1, checkdata_r1_size,
			.config_json_path = "./tests/0020-testHomeNetsV5.json",
			.host_list_path = "./tests/0020-data/",
			.normalize_directions = normalize_directions),

		[1] = TEST(0x04030301,
			&record2, sizeof(record2),
			checkdata_r2, checkdata_r2_size,),
	};
#undef TEST

	*state = prepare_tests(test_params, RD_ARRAYSIZE(test_params));
	return *state == NULL;
}

/* Left: SRC/LAN, RIGHT: DST/WAN */
#define CHECKDATA(left_name, left_ip, left_net, left_net_name, \
		  right_name, right_ip, right_net, right_net_name, \
		  direction) {\
	{.key = left_name, .value=left_ip,}, \
	{.key = left_name "_net", .value=left_net,}, \
	{.key = left_name "_net_name", .value=left_net_name,}, \
	{.key = right_name, .value=right_ip,}, \
	{.key = right_name "_net", .value=right_net,}, \
	{.key = right_name "_net_name", .value=right_net_name,}, \
	{.key = "direction", .value=direction,}, \
};

static int prepare_test_nf5_home_nets_normalize(void *state) {
	/* Can't guess direction => src is LAN, dst is WAN */
	static const struct checkdata_value checkdata_values1_0[] =
		CHECKDATA("lan_ip", "192.168.1.1", NULL, NULL,
			  "wan_ip", "192.168.1.2", NULL, NULL, NULL);

	/* src is in lan */
	static const struct checkdata_value checkdata_values1_1[] =
		CHECKDATA("lan_ip", "10.0.30.10", "10.0.30.0/24", "users",
			  "wan_ip", "192.168.1.2", NULL, NULL, "upstream");

	/* src is in net objects, but not in home net => LAN is src,
	WAN is dst*/
	static const struct checkdata_value checkdata_values1_2[] =
		CHECKDATA("lan_ip", "8.8.8.8", "8.8.8.0/24", "google8",
			  "wan_ip", "192.168.1.2", NULL, NULL, NULL);

	/* dst is in home net */
	static const struct checkdata_value checkdata_values1_3[] =
		CHECKDATA("wan_ip", "192.168.1.2", NULL, NULL,
			  "lan_ip", "10.0.30.10", "10.0.30.0/24", "users",
			  "downstream");

	/* dst is in nets, but src/dst are not in home nets */
	static const struct checkdata_value checkdata_values1_4[] =
		CHECKDATA("lan_ip", "192.168.1.2", NULL, NULL,
			  "wan_ip", "8.8.8.8", "8.8.8.0/24", "google8", NULL);

	/* src in home nets & nets objects => prioritize home nets */
	static const struct checkdata_value checkdata_values1_5[] =
		CHECKDATA("lan_ip", "10.0.150.10", "10.0.150.0/24", "lab",
			  "wan_ip", "192.168.1.2", NULL, NULL, "upstream");

	/* Other sensor, with no home nets */
	static const struct checkdata_value checkdata_values2_0[] =
		CHECKDATA("lan_ip", "10.0.30.10", NULL, NULL,
			  "wan_ip", "192.168.1.2", NULL, NULL, NULL);

	static const struct checkdata checkdata1[] = {
		{.size = RD_ARRAYSIZE(checkdata_values1_0), .checks=checkdata_values1_0},
		{.size = RD_ARRAYSIZE(checkdata_values1_1), .checks=checkdata_values1_1},
		{.size = RD_ARRAYSIZE(checkdata_values1_2), .checks=checkdata_values1_2},
		{.size = RD_ARRAYSIZE(checkdata_values1_3), .checks=checkdata_values1_3},
		{.size = RD_ARRAYSIZE(checkdata_values1_4), .checks=checkdata_values1_4},
		{.size = RD_ARRAYSIZE(checkdata_values1_5), .checks=checkdata_values1_5},
	};

	static const struct checkdata checkdata2[] = {
		{.size = RD_ARRAYSIZE(checkdata_values2_0), .checks=checkdata_values2_0},
	};

	return prepare_test_nf5_home_nets_0(state, true,
				checkdata1, RD_ARRAYSIZE(checkdata1),
				checkdata2, RD_ARRAYSIZE(checkdata2));
}

static int prepare_test_nf5_home_nets_dont_normalize(void *state) {
	/* Can't guess direction => src is LAN, dst is WAN */
	static const struct checkdata_value checkdata_values1_0[] =
		CHECKDATA("src", "192.168.1.1", NULL, NULL,
			  "dst", "192.168.1.2", NULL, NULL, NULL);

	/* src is in lan */
	static const struct checkdata_value checkdata_values1_1[] =
		CHECKDATA("src", "10.0.30.10", "10.0.30.0/24", "users",
			  "dst", "192.168.1.2", NULL, NULL, NULL);

	/* src is in net objects, but not in home net => LAN is src,
	WAN is dst*/
	static const struct checkdata_value checkdata_values1_2[] =
		CHECKDATA("src", "8.8.8.8", "8.8.8.0/24", "google8",
			  "dst", "192.168.1.2", NULL, NULL, NULL);

	/* dst is in home net */
	static const struct checkdata_value checkdata_values1_3[] =
		CHECKDATA("src", "192.168.1.2", NULL, NULL,
			  "dst", "10.0.30.10", "10.0.30.0/24", "users", NULL);

	/* dst is in nets, but src/dst are not in home nets */
	static const struct checkdata_value checkdata_values1_4[] =
		CHECKDATA("src", "192.168.1.2", NULL, NULL,
			  "dst", "8.8.8.8", "8.8.8.0/24", "google8", NULL);

	/* src in home nets & nets objects => prioritize home nets */
	static const struct checkdata_value checkdata_values1_5[] =
		CHECKDATA("src", "10.0.150.10", "10.0.150.0/24", "lab",
			  "dst", "192.168.1.2", NULL, NULL, NULL);

	/* Other sensor, with no home nets */
	static const struct checkdata_value checkdata_values2_0[] =
		CHECKDATA("src", "10.0.30.10", NULL, NULL,
			  "dst", "192.168.1.2", NULL, NULL, NULL);

	static const struct checkdata checkdata1[] = {
		{.size = RD_ARRAYSIZE(checkdata_values1_0), .checks=checkdata_values1_0},
		{.size = RD_ARRAYSIZE(checkdata_values1_1), .checks=checkdata_values1_1},
		{.size = RD_ARRAYSIZE(checkdata_values1_2), .checks=checkdata_values1_2},
		{.size = RD_ARRAYSIZE(checkdata_values1_3), .checks=checkdata_values1_3},
		{.size = RD_ARRAYSIZE(checkdata_values1_4), .checks=checkdata_values1_4},
		{.size = RD_ARRAYSIZE(checkdata_values1_5), .checks=checkdata_values1_5},
	};

	static const struct checkdata checkdata2[] = {
		{.size = RD_ARRAYSIZE(checkdata_values2_0), .checks=checkdata_values2_0},
	};

	return prepare_test_nf5_home_nets_0(state, false,
				checkdata1, RD_ARRAYSIZE(checkdata1),
				checkdata2, RD_ARRAYSIZE(checkdata2));
}

int main() {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup(testFlow,
			prepare_test_nf5_home_nets_dont_normalize),
		cmocka_unit_test_setup(testFlow,
			prepare_test_nf5_home_nets_normalize),
	};

	return cmocka_run_group_tests(tests, nf_test_setup, nf_test_teardown);
}
