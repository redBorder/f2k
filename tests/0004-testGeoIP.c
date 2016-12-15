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

#ifdef HAVE_GEOIP

static const char CONFIG_FILE_PATH[] = "./tests/0004-testGeoIp-databases.json";

static const NetFlow5Record record1 = {
	.flowHeader = {
		.version = 0x0500,     /* Current version=5*/
		.count = 0x0300,       /* The number of records in PDU. */
		.sys_uptime = 12345,    /* Current time in msecs since router booted */
		.unix_secs = 12345,    /* Current seconds since 0000 UTC 1970 */
		.unix_nsecs = 12345,   /* Residual nanoseconds since 0000 UTC 1970 */
		.flow_sequence = 1050, /* Sequence number of total flows seen */
		.engine_type = 0,      /* Type of flow switching engine (RP,VIP,etc.)*/
		.engine_id  = 0,       /* Slot number of the flow switching engine */
		.sampleRate = 0,       /* Packet capture sample rate */
	},
	.flowRecord = {
		/* FIRST: No GeoIP information */
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

		/* FIRST: src from US, dst private*/
		[1] = {
			.srcaddr = 0x08080808L,    /* Source IP Address */
			.dstaddr = 0x0201a8c0L,    /* Destination IP Address */
			.nexthop = 0x00000000L,    /* Next hop router's IP Address */
			.input   = 0,              /* Input interface index */
			.output  = 255,            /* Output interface index */
			.dPkts   = 0x0100,              /* Packets sent in Duration (milliseconds between 1st
			                             & last packet in this flow)*/
			.dOctets = 0x4600,             /* Octets sent in Duration (milliseconds between 1st
			                             & last packet in  this flow)*/
			.first   = 0xa8484205, /* SysUptime at start of flow */
			.last    = 0xa8484205, /* and of last packet of the flow */
			.srcport = 0x1010,     /* ntohs(443)  */  /* TCP/UDP source port number (.e.g, FTP, Telnet, etc.,or equivalent) */
			.dstport = 0x7527, /* ntohs(10101)*/  /* TCP/UDP destination port number (.e.g, FTP, Telnet, etc.,or equivalent) */
			.pad1    = 0,      /* pad to word boundary */
			.tcp_flags = 0,    /* Cumulative OR of tcp flags */
			.proto   = 2,      /* IP protocol, e.g., 6=TCP, 17=UDP, etc... */
			.tos     = 0,      /* IP Type-of-Service */
			.src_as  = 0,      /* source peer/origin Autonomous System */
			.dst_as  = 0,      /* dst peer/origin Autonomous System */
			.src_mask = 0,     /* source route's mask bits */
			.dst_mask = 0,     /* destination route's mask bits */
			.pad2    = 0,      /* pad to word boundary */
		},

		/* FIRST: private, dst from ES */
		[2] = {
			.srcaddr = 0x0201a8c0L,    /* Source IP Address */
			.dstaddr = 0xc7283853L,    /* Destination IP Address */
			.nexthop = 0x00000000L,    /* Next hop router's IP Address */
			.input   = 0,              /* Input interface index */
			.output  = 255,            /* Output interface index */
			.dPkts   = 0x0100,              /* Packets sent in Duration (milliseconds between 1st
			                             & last packet in this flow)*/
			.dOctets = 0x4600,             /* Octets sent in Duration (milliseconds between 1st
			                             & last packet in  this flow)*/
			.first   = 0xa8484205, /* SysUptime at start of flow */
			.last    = 0xa8484205, /* and of last packet of the flow */
			.srcport = 0x1010,     /* ntohs(443)  */  /* TCP/UDP source port number (.e.g, FTP, Telnet, etc.,or equivalent) */
			.dstport = 0x7527, /* ntohs(10101)*/  /* TCP/UDP destination port number (.e.g, FTP, Telnet, etc.,or equivalent) */
			.pad1    = 0,      /* pad to word boundary */
			.tcp_flags = 0,    /* Cumulative OR of tcp flags */
			.proto   = 2,      /* IP protocol, e.g., 6=TCP, 17=UDP, etc... */
			.tos     = 0,      /* IP Type-of-Service */
			.src_as  = 0,      /* source peer/origin Autonomous System */
			.dst_as  = 0,      /* dst peer/origin Autonomous System */
			.src_mask = 0,     /* source route's mask bits */
			.dst_mask = 0,     /* destination route's mask bits */
			.pad2    = 0,      /* pad to word boundary */
		},
	}
};

#define NETFLOW_DIRECTION_INGRESS 0
#define NETFLOW_DIRECTION_EGRESS  1

#define IPFIX_BASE_ENTITIES(X, SRC_IP_1, SRC_IP_2, SRC_IP_3, SRC_IP_4, \
			 DST_IP_1, DST_IP_2, DST_IP_3, DST_IP_4, \
			 T_DIRECTION) \
	X(IPV4_SRC_ADDR, 4, 0, SRC_IP_1, SRC_IP_2, SRC_IP_3, SRC_IP_4) \
	X(IPV4_DST_ADDR, 4, 0, DST_IP_1, DST_IP_2, DST_IP_3, DST_IP_4) \
	X(IP_PROTOCOL_VERSION, 1, 0, 4) \
	X(PROTOCOL, 1, 0, 6) \
	X(L4_SRC_PORT, 2, 0, UINT16_TO_UINT8_ARR(54713)) \
	X(L4_DST_PORT, 2, 0, UINT16_TO_UINT8_ARR(443)) \
	X(FLOW_END_REASON, 1, 0, 3) \
	X(DIRECTION, 1, 0, T_DIRECTION) \
	X(FLOW_SAMPLER_ID, 1, 0, 0) \
	X(TRANSACTION_ID, 8, 0, 0x8f, 0x63, 0xf3, 0x40, \
				0x00, 0x01, 0x00, 0x00) \
	X(APPLICATION_ID, 4, 0, FLOW_APPLICATION_ID(13, 459)) \
	X(IN_BYTES, 8, 0, UINT64_TO_UINT8_ARR(7603)) \
	X(IN_PKTS, 4, 0, UINT32_TO_UINT8_ARR(263)) \
	X(FIRST_SWITCHED, 4, 0, 0x0f, 0xed, 0x0a, 0xc0) \
	X(LAST_SWITCHED, 4, 0, 0x0f, 0xee, 0x18, 0x00)

#define TEST_IPFIX_FLOW_HEADER \
	.unix_secs = constexpr_be32toh(1382364130), \
	.flow_sequence = constexpr_be32toh(1080), \
	.observation_id = constexpr_be32toh(256),

#define TEST_IPFIX_TEMPLATE_ID 259

#define GEO_IPFIX_ENTITIES(RT, R) \
	/* no GEOIP information */ \
	IPFIX_BASE_ENTITIES(RT, 192, 168, 1, 1, 192, 168, 1, 2,  \
		NETFLOW_DIRECTION_INGRESS) \
	/* FIRST: src/lan from US, dst/wan private*/ \
	IPFIX_BASE_ENTITIES(R, 8, 8, 8, 8, 192, 168, 1, 2, \
		NETFLOW_DIRECTION_INGRESS) \
	/* FIRST: src/lan private, dst/wan from ES */ \
	IPFIX_BASE_ENTITIES(R, 192, 168, 1, 2,  83, 56, 40, 199,  \
		NETFLOW_DIRECTION_INGRESS)

static const IPFIX_TEMPLATE(v10Template, TEST_IPFIX_FLOW_HEADER,
		TEST_IPFIX_TEMPLATE_ID, GEO_IPFIX_ENTITIES);

static const IPFIX_FLOW(v10Flow, TEST_IPFIX_FLOW_HEADER,
	TEST_IPFIX_TEMPLATE_ID, GEO_IPFIX_ENTITIES);

/*
 * TEST 1: No normalization
 */

/// Test a V5 flow
#define TEST_V5(t_netflow_src_ip, t_record, t_record_size, t_checkdata,        \
						t_checkdata_size, ...) {       \
	.netflow_src_ip = t_netflow_src_ip,                                    \
	.record = t_record, .record_size = t_record_size,                      \
	.checkdata = t_checkdata, .checkdata_size = t_checkdata_size,          \
	__VA_ARGS__}

// Test V9/IPFIX template+flow
#define TEST(t_netflow_src_ip, t_template, t_template_size,                    \
	t_record, t_record_size, t_checkdata, t_checkdata_size, ...)           \
	TEST_V5(t_netflow_src_ip, t_template, t_template_size, NULL, 0,        \
		__VA_ARGS__),                                                  \
	TEST_V5(t_netflow_src_ip, t_record, t_record_size,                     \
		t_checkdata, t_checkdata_size,)                                \

static int prepare_tests_v5_ipfix_record(void **state,
		const struct checkdata *checkdata, size_t checkdata_size,
		bool normalize) {
	struct test_params test_params[] = {
		TEST_V5(0x04030201,
			&record1, sizeof(record1),
			checkdata, checkdata_size,
			.config_json_path = "./tests/0000-testFlowV5.json",
			.geoip_path = CONFIG_FILE_PATH,
			.normalize_directions = normalize),
		TEST(0x04030201, &v10Template, sizeof(v10Template),
			&v10Flow, sizeof(v10Flow),
			checkdata, checkdata_size,),
	};

	*state = prepare_tests(test_params, RD_ARRAYSIZE(test_params));
	return *state == NULL;
}

#define CHECKDATA_IP_COUNTRY_AS(t_key, ip, country_code, as, as_name) \
	{.key= t_key, .value=ip},                                     \
	{.key= t_key "_country_code", .value = country_code},         \
	/* @TODO recover {.key="src_as", .value = as}, */             \
	{.key= t_key "_as_name", .value = as_name}

// Checkdata for flow 1 at src/lan
#define CHECKDATA_1_LEFT(name) \
	CHECKDATA_IP_COUNTRY_AS(name, "192.168.1.1", NULL, NULL, NULL)
#define CHECKDATA_1_RIGHT(name) \
	CHECKDATA_IP_COUNTRY_AS(name, "192.168.1.2", NULL, NULL, NULL)

#define CHECKDATA_2_LEFT(name) \
	CHECKDATA_IP_COUNTRY_AS(name, "8.8.8.8", "US", "15169", "Google Inc.")
#define CHECKDATA_2_RIGHT(name) \
	CHECKDATA_IP_COUNTRY_AS(name, "192.168.1.2", NULL, NULL, NULL)

#define CHECKDATA_3_LEFT(name) \
	CHECKDATA_IP_COUNTRY_AS(name, "192.168.1.2", NULL, NULL, NULL)
#define CHECKDATA_3_RIGHT(name) \
	CHECKDATA_IP_COUNTRY_AS(name, "83.56.40.199", "ES", "3352", \
			"Telefonica De Espana")

static int prepare_test_v5_ipfix_geoip(void **state) {
	static const struct checkdata_value checkdata_values1[] = {
		CHECKDATA_1_LEFT("src"), CHECKDATA_1_RIGHT("dst"),
	};

	static const struct checkdata_value checkdata_values2[] = {
		CHECKDATA_2_LEFT("src"), CHECKDATA_2_RIGHT("dst"),
	};

	static const struct checkdata_value checkdata_values3[] = {
		CHECKDATA_3_LEFT("src"), CHECKDATA_3_RIGHT("dst"),
	};

	static const struct checkdata checkdata[] = {
		{.size=RD_ARRAYSIZE(checkdata_values1), checkdata_values1},
		{.size=RD_ARRAYSIZE(checkdata_values2), checkdata_values2},
		{.size=RD_ARRAYSIZE(checkdata_values3), checkdata_values3},
	};

	return prepare_tests_v5_ipfix_record(state, checkdata,
		RD_ARRAYSIZE(checkdata), false);
}

/*
 * TEST2: WLC NF9 data -> already normalized
 */

#define TEST_V9_FLOW_HEADER \
	.sys_uptime = constexpr_be32toh(12345), \
	.unix_secs = constexpr_be32toh(1382364130), \
	.flow_sequence = constexpr_be32toh(1080), \
	.source_id = constexpr_be32toh(1),

#define TEST_V9_TEMPLATE_ID 259

#define T_WLAN_SSID \
	'l','o','c','a','l','-','w','i', \
	'f','i',0,  0,  0,  0,  0,  0,   \
	0,  0,  0,  0,  0,  0,  0,  0,   \
	0,  0,  0,  0,  0,  0,  0,  0,   \
	0

#define TEST_NF9_BASE_ENTITIES(X, STA_IP_1, STA_IP_2, STA_IP_3, STA_IP_4) \
	X(STA_MAC_ADDRESS, 6, 0, 0x00, 0x05, 0x69, 0x28, 0xb0, 0xc7) \
	X(STA_IPV4_ADDRESS, 4, 0, STA_IP_1, STA_IP_2, STA_IP_3, STA_IP_4) \
	X(APPLICATION_ID, 4, 0, FLOW_APPLICATION_ID(13, 453)) \
	X(WLAN_SSID, 33, 0, T_WLAN_SSID) \
	X(DIRECTION, 1, 0, 0) \
	X(IN_BYTES, 8, 0, UINT64_TO_UINT8_ARR(7603)) \
	X(IN_PKTS, 8, 0,  UINT64_TO_UINT8_ARR(263)) \
	X(98, 1, 0, 0) \
	X(195, 1, 0, 0) \
	X(WAP_MAC_ADDRESS, 6, 0, 0x58, 0xbf, 0xea, 0x01, 0x5b, 0x40) \

#define TEST_NF9_ENTITIES(RT, R) \
	TEST_NF9_BASE_ENTITIES(RT, 192, 168, 1, 1) \
	TEST_NF9_BASE_ENTITIES(R, 8, 8, 8, 8) \
	TEST_NF9_BASE_ENTITIES(R, 192, 168, 1, 2)

// THIS V9 flows are always direction-normalized
static int prepare_tests_v9(void **state, bool normalize_directions) {
	static const NF9_TEMPLATE(v9Template, TEST_V9_FLOW_HEADER,
		TEST_V9_TEMPLATE_ID, TEST_NF9_ENTITIES);

	static const NF9_FLOW(v9Flow, TEST_V9_FLOW_HEADER,
		TEST_V9_TEMPLATE_ID, TEST_NF9_ENTITIES);

	static const struct checkdata_value checkdata_values1[] = {
		CHECKDATA_1_LEFT("lan_ip"),
	};

	static const struct checkdata_value checkdata_values2[] = {
		CHECKDATA_2_LEFT("lan_ip")
	};

	static const struct checkdata_value checkdata_values3[] = {
		CHECKDATA_3_LEFT("lan_ip"),
	};

	static const struct checkdata checkdata[] = {
		{.size=RD_ARRAYSIZE(checkdata_values1), checkdata_values1},
		{.size=RD_ARRAYSIZE(checkdata_values2), checkdata_values2},
		{.size=RD_ARRAYSIZE(checkdata_values3), checkdata_values3},
	};

	struct test_params test_params[] = {
		TEST(0x04030201, &v9Template, sizeof(v9Template),
			&v9Flow, sizeof(v9Flow),
			checkdata, RD_ARRAYSIZE(checkdata),
			.config_json_path = "./tests/0000-testFlowV5.json",
			.geoip_path = CONFIG_FILE_PATH,
			.normalize_directions = normalize_directions),
	};

	*state = prepare_tests(test_params, RD_ARRAYSIZE(test_params));
	return *state == NULL;
}

static int prepare_test_v9_dont_normalize(void **state) {
	return prepare_tests_v9(state, false);
}

static int prepare_test_v9_normalized(void **state) {
	return prepare_tests_v9(state, true);
}

/*
 * TEST3: Normalized NF5/IPFIX
 */

static int prepare_test_v5_ipfix_normalized(void **state) {
	static const struct checkdata_value checkdata_values1[] = {
		CHECKDATA_1_LEFT("lan_ip"), CHECKDATA_1_RIGHT("wan_ip"),
	};

	static const struct checkdata_value checkdata_values2[] = {
		CHECKDATA_2_LEFT("lan_ip"), CHECKDATA_2_RIGHT("wan_ip"),
	};

	static const struct checkdata_value checkdata_values3[] = {
		CHECKDATA_3_LEFT("lan_ip"), CHECKDATA_3_RIGHT("wan_ip"),
	};

	static const struct checkdata checkdata[] = {
		{.size=RD_ARRAYSIZE(checkdata_values1), checkdata_values1},
		{.size=RD_ARRAYSIZE(checkdata_values2), checkdata_values2},
		{.size=RD_ARRAYSIZE(checkdata_values3), checkdata_values3},
	};

	return prepare_tests_v5_ipfix_record(state, checkdata,
		RD_ARRAYSIZE(checkdata), true);
}

#else /* HAVE_GEOIP */
static void skip_test() { skip(); }
#endif

int main() {
	const struct CMUnitTest tests[] = {
#ifdef HAVE_GEOIP
		cmocka_unit_test_setup(testFlow, prepare_test_v5_ipfix_geoip),
		cmocka_unit_test_setup(testFlow,
			prepare_test_v5_ipfix_normalized),
		cmocka_unit_test_setup(testFlow,
			prepare_test_v9_dont_normalize),
		cmocka_unit_test_setup(testFlow, prepare_test_v9_normalized),
#else
		cmocka_unit_test(skip_test),
#endif
	};

	return cmocka_run_group_tests(tests, nf_test_setup, nf_test_teardown);
}
