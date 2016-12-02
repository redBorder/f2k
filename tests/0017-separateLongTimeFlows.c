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

#include "rb_netflow_test.h"

#include "f2k.h"

#include <librd/rd.h>

#include <setjmp.h>
#include <cmocka.h>

/* *********************** FIRST TEST: NF5 split flow *********************** */

#define NF5_RECORD(...) {            \
	.srcaddr = NF5_IP(8, 8, 8, 8),  /* Source IP Address */                \
	.dstaddr = NF5_IP(10,10,10,10),  /* Source IP Address */               \
	.nexthop = NF5_IP(0,0,0,0),  /* Next hop router's IP Address */        \
	.input   = 0,            /* Input interface index */                   \
	.output  = 255,          /* Output interface index */                  \
	.srcport = constexpr_be16toh(443), /* source port number */            \
	.dstport = constexpr_be16toh(10101), /* destination port number */     \
	.tcp_flags = 0,          /* Cumulative OR of tcp flags */              \
	.proto   = 2,           /* IP protocol, e.g., 6=TCP, 17=UDP, etc... */ \
	.tos     = 0,            /* IP Type-of-Service */                      \
	.src_as  = 0,            /* source peer/origin Autonomous System */    \
	.dst_as  = 0,            /* dst peer/origin Autonomous System */       \
	.src_mask = 0,           /* source route's mask bits */                \
	.dst_mask = 0,           /* destination route's mask bits */           \
	__VA_ARGS__ \
}

static const NetFlow5Record record5 = {
	.flowHeader = {
		.version = constexpr_be16toh(5),
		.count = constexpr_be16toh(4),
		.sys_uptime = constexpr_be32toh(600000),
		.unix_secs = constexpr_be32toh(1200),
		.unix_nsecs = constexpr_be32toh(12345),
		.flow_sequence = constexpr_be16toh(1050),
		.engine_type = 0,
		.engine_id  = 0,
		.sampleRate = 0,
	},
	.flowRecord = {
		NF5_RECORD(
			.dPkts   = constexpr_be32toh(20),
			.dOctets = constexpr_be32toh(30),
			.first   = constexpr_be32toh(400000),
			.last    = constexpr_be32toh(400000)),

		NF5_RECORD(
			.dPkts   = constexpr_be32toh(20),
			.dOctets = constexpr_be32toh(30),
			.first   = constexpr_be32toh(400000),
			.last    = constexpr_be32toh(416000)),

		NF5_RECORD(
			.dPkts   = constexpr_be32toh(20),
			.dOctets = constexpr_be32toh(30),
			.first   = constexpr_be32toh(400000),
			.last    = constexpr_be32toh(470000)),

		NF5_RECORD(
			.dPkts   = constexpr_be32toh(20),
			.dOctets = constexpr_be32toh(30),
			.first   = constexpr_be32toh(400000),
			.last    = constexpr_be32toh(540000)),
	}
};

/* ***************************** 2ND: NF9 TESTS ***************************** */

#define TEST_TEMPLATE_ID 1025

#define NF9_HEADER \
	.sys_uptime = constexpr_be32toh(12345), /* CISCO WLC sent this ! */ \
	.unix_secs = constexpr_be32toh(1000), \
	.flow_sequence = constexpr_be32toh(1050), \
	.source_id = constexpr_be32toh(1),

#define NF9_ENTITIES_BASE(X) \
	X(IPV4_SRC_ADDR, 4, 0, 208, 67, 222, 222) \
	X(IPV4_DST_ADDR, 4, 0, 192, 168, 210, 18) \
	X(IN_PKTS, 4, 0, UINT32_TO_UINT8_ARR(20)) \
	X(IN_BYTES, 4, 0, UINT32_TO_UINT8_ARR(30)) \
	X(L4_SRC_PORT, 2, 0, UINT16_TO_UINT8_ARR(53)) \
	X(L4_DST_PORT, 2, 0, UINT16_TO_UINT8_ARR(53549)) \
	X(PROTOCOL, 1, 0, IPPROTO_UDP)

#define NF_WLC_NO_TIME_ENTITIES(RT, R) \
	NF9_ENTITIES_BASE(RT) \

static const NF9_TEMPLATE(nf9_notime_template, NF9_HEADER,
	TEST_TEMPLATE_ID, NF_WLC_NO_TIME_ENTITIES);
static const NF9_FLOW(nf9_notime_flow, NF9_HEADER,
	TEST_TEMPLATE_ID, NF_WLC_NO_TIME_ENTITIES);

/* **************************** 3RD: IPFIX TESTS **************************** */

#define IPFIX_HEADER \
	.unix_secs = constexpr_be32toh(1000), \
	.flow_sequence = constexpr_be32toh(12372811), \
	.observation_id = 0

#define IPFIX_ENTITIES_BASE(X) NF9_ENTITIES_BASE(X)

// IPFIX uptime model
#define IPFIX_UPTIME_ENTITIES(RT, R) \
	IPFIX_ENTITIES_BASE(RT) \
	RT(FIRST_SWITCHED, 4, 0, UINT32_TO_UINT8_ARR(400000)) \
	RT(LAST_SWITCHED,  4, 0, UINT32_TO_UINT8_ARR(400000)) \
	IPFIX_ENTITIES_BASE(R) \
	R(FIRST_SWITCHED, 4, 0, UINT32_TO_UINT8_ARR(400000)) \
	R(LAST_SWITCHED,  4, 0, UINT32_TO_UINT8_ARR(416000)) \
	IPFIX_ENTITIES_BASE(R) \
	R(FIRST_SWITCHED, 4, 0, UINT32_TO_UINT8_ARR(400000)) \
	R(LAST_SWITCHED,  4, 0, UINT32_TO_UINT8_ARR(470000)) \
	IPFIX_ENTITIES_BASE(R) \
	R(FIRST_SWITCHED, 4, 0, UINT32_TO_UINT8_ARR(400000)) \
	R(LAST_SWITCHED,  4, 0, UINT32_TO_UINT8_ARR(540000))

// IPFIX timestamp model
#define IPFIX_TIMESTAMP_ENTITIES(RT, R) \
	IPFIX_ENTITIES_BASE(RT) \
	RT(FLOW_START_SEC, 4, 0, UINT32_TO_UINT8_ARR(1000)) \
	RT(FLOW_END_SEC,  4, 0, UINT32_TO_UINT8_ARR(1000)) \
	IPFIX_ENTITIES_BASE(R) \
	R(FLOW_START_SEC, 4, 0, UINT32_TO_UINT8_ARR(984)) \
	R(FLOW_END_SEC,  4, 0, UINT32_TO_UINT8_ARR(1000)) \
	IPFIX_ENTITIES_BASE(R) \
	R(FLOW_START_SEC, 4, 0, UINT32_TO_UINT8_ARR(930)) \
	R(FLOW_END_SEC,  4, 0, UINT32_TO_UINT8_ARR(1000)) \
	IPFIX_ENTITIES_BASE(R) \
	R(FLOW_START_SEC, 4, 0, UINT32_TO_UINT8_ARR(860)) \
	R(FLOW_END_SEC,  4, 0, UINT32_TO_UINT8_ARR(1000))

static const IPFIX_TEMPLATE(ipfix_uptime_template, IPFIX_HEADER,
	TEST_TEMPLATE_ID, IPFIX_UPTIME_ENTITIES);
static const IPFIX_FLOW(ipfix_uptime_flow, IPFIX_HEADER, TEST_TEMPLATE_ID,
	IPFIX_UPTIME_ENTITIES);

static const IPFIX_TEMPLATE(ipfix_timestamp_template, IPFIX_HEADER,
	TEST_TEMPLATE_ID, IPFIX_TIMESTAMP_ENTITIES);
static const IPFIX_FLOW(ipfix_timestamp_flow, IPFIX_HEADER, TEST_TEMPLATE_ID,
	IPFIX_TIMESTAMP_ENTITIES);

/* ******************************* NF CHECKS ******************************* */
// d = 0
static const struct checkdata_value timestamp_0_chks[] = {
	{.key="timestamp",.value="1000"},
	{.key="bytes",.value="30"},
	{.key="pkts",.value="20"},
};

// d = 16
static const struct checkdata_value timestamp_16_chks[] = {
	{.key="timestamp",.value="1000"},
	{.key="bytes",.value="30"},
	{.key="pkts",.value="20"},
};

// d = 70
static const struct checkdata_value timestamp_70_1_chks[] = {
	{.key="timestamp",.value="1060"},
	{.key="bytes",.value="4"},
	{.key="pkts",.value="2"},
};

static const struct checkdata_value timestamp_70_2_chks[] = {
	{.key="timestamp",.value="1000"},
	{.key="bytes",.value="26"},
	{.key="pkts",.value="18"},
};

// d = 140
static const struct checkdata_value timestamp_140_1_chks[] = {
	{.key="timestamp",.value="1120"},
	{.key="bytes",.value="4"},
	{.key="pkts",.value="2"},
};

static const struct checkdata_value timestamp_140_2_chks[] = {
	{.key="timestamp",.value="1060"},
	{.key="bytes",.value="13"},
	{.key="pkts",.value="9"},
};

static const struct checkdata_value timestamp_140_3_chks[] = {
	{.key="timestamp",.value="1000"},
	{.key="bytes",.value="13"},
	{.key="pkts",.value="9"},
};

/// @todo use C99 to make this smaller and not to use so many definitions!
static const struct checkdata checkdata_split[] = {
	{
		.size = RD_ARRAYSIZE(timestamp_0_chks),
		.checks = timestamp_0_chks,
	},{
		.size = RD_ARRAYSIZE(timestamp_16_chks),
		.checks = timestamp_16_chks,
	},{
		.size = RD_ARRAYSIZE(timestamp_70_1_chks),
		.checks = timestamp_70_1_chks,
	},{
		.size = RD_ARRAYSIZE(timestamp_70_2_chks),
		.checks = timestamp_70_2_chks,
	},{
		.size = RD_ARRAYSIZE(timestamp_140_1_chks),
		.checks = timestamp_140_1_chks,
	},{
		.size = RD_ARRAYSIZE(timestamp_140_2_chks),
		.checks = timestamp_140_2_chks,
	},{
		.size = RD_ARRAYSIZE(timestamp_140_3_chks),
		.checks = timestamp_140_3_chks,
	}
};

// d = 16
static const struct checkdata_value timestamp_16_dontsplit_chks[] = {
	{.key="timestamp",.value="1016"},
	{.key="bytes",.value="30"},
	{.key="pkts",.value="20"},
};

// d = 70
static const struct checkdata_value timestamp_70_dontsplit_chks[] = {
	{.key="timestamp",.value="1070"},
	{.key="bytes",.value="30"},
	{.key="pkts",.value="20"},
};
// d = 140
static const struct checkdata_value timestamp_140_dontsplit_chks[] = {
	{.key="timestamp",.value="1140"},
	{.key="bytes",.value="30"},
	{.key="pkts",.value="20"},
};

/// @todo use C99 to make this smaller and not to use so many definitions!
static const struct checkdata checkdata_dont_split[] = {
	{
		.size = RD_ARRAYSIZE(timestamp_0_chks),
		.checks = timestamp_0_chks,
	},{
		.size = RD_ARRAYSIZE(timestamp_16_dontsplit_chks),
		.checks = timestamp_16_dontsplit_chks,
	},{
		.size = RD_ARRAYSIZE(timestamp_70_dontsplit_chks),
		.checks = timestamp_70_dontsplit_chks,
	},{
		.size = RD_ARRAYSIZE(timestamp_140_dontsplit_chks),
		.checks = timestamp_140_dontsplit_chks,
	},
};

/* **************************** IPFIX checkdata **************************** */
// Uptime split checks
static const struct checkdata_value timestamp_0_nfchks[] = {
	{.key="timestamp",.value="1000"},
	{.key="bytes",.value="30"},
	{.key="pkts",.value="20"},
};

// d = 16
static const struct checkdata_value timestamp_16_nfchks[] = {
	{.key="timestamp",.value="984"},
	{.key="bytes",.value="30"},
	{.key="pkts",.value="20"},
};

// d = 70
static const struct checkdata_value timestamp_70_1_nfchks[] = {
	{.key="timestamp",.value="990"},
	{.key="bytes",.value="4"},
	{.key="pkts",.value="2"},
};

static const struct checkdata_value timestamp_70_2_nfchks[] = {
	{.key="timestamp",.value="930"},
	{.key="bytes",.value="26"},
	{.key="pkts",.value="18"},
};

// d = 140
static const struct checkdata_value timestamp_140_1_nfchks[] = {
	{.key="timestamp",.value="980"},
	{.key="bytes",.value="4"},
	{.key="pkts",.value="2"},
};

static const struct checkdata_value timestamp_140_2_nfchks[] = {
	{.key="timestamp",.value="920"},
	{.key="bytes",.value="13"},
	{.key="pkts",.value="9"},
};

static const struct checkdata_value timestamp_140_3_nfchks[] = {
	{.key="timestamp",.value="860"},
	{.key="bytes",.value="13"},
	{.key="pkts",.value="9"},
};

/// @todo use C99 to make this smaller and not to use so many definitions!
static const struct checkdata ipfix_checkdata_split[] = {
	{
		.size = RD_ARRAYSIZE(timestamp_0_nfchks),
		.checks = timestamp_0_nfchks,
	},{
		.size = RD_ARRAYSIZE(timestamp_16_nfchks),
		.checks = timestamp_16_nfchks,
	},{
		.size = RD_ARRAYSIZE(timestamp_70_1_nfchks),
		.checks = timestamp_70_1_nfchks,
	},{
		.size = RD_ARRAYSIZE(timestamp_70_2_nfchks),
		.checks = timestamp_70_2_nfchks,
	},{
		.size = RD_ARRAYSIZE(timestamp_140_1_nfchks),
		.checks = timestamp_140_1_nfchks,
	},{
		.size = RD_ARRAYSIZE(timestamp_140_2_nfchks),
		.checks = timestamp_140_2_nfchks,
	},{
		.size = RD_ARRAYSIZE(timestamp_140_3_nfchks),
		.checks = timestamp_140_3_nfchks,
	}
};

// no split checks
/// @todo use C99 to make this smaller and not to use so many definitions!
static const struct checkdata ipfix_checkdata_dont_split[] = {
	{
		.size = RD_ARRAYSIZE(timestamp_0_nfchks),
		.checks = timestamp_0_nfchks,
	},{
		.size = RD_ARRAYSIZE(timestamp_0_nfchks),
		.checks = timestamp_0_nfchks,
	},{
		.size = RD_ARRAYSIZE(timestamp_0_nfchks),
		.checks = timestamp_0_nfchks,
	},{
		.size = RD_ARRAYSIZE(timestamp_0_nfchks),
		.checks = timestamp_0_nfchks,
	},
};

/* ************************************************************************* */

static int prepare_test_timestamp_split(void **state,
		const void *flow1, size_t flow1_size,
		const struct checkdata *checkdata1, size_t checkdata1_size,
		const void *flow2, size_t flow2_size,
		const struct checkdata *checkdata2, size_t checkdata2_size,
		bool separate_long_flows) {
	readOnlyGlobals.separate_long_flows = separate_long_flows;

	struct test_params test_params[] = {
		[0] = {
			.config_json_path = "./tests/0000-testFlowV5.json",
			.host_list_path = NULL,
			.netflow_src_ip = 0x04030201,
			.record = flow1, .record_size = flow1_size,
			.checkdata = checkdata1,
			.checkdata_size = checkdata1_size,
		},
		[1] = {
			.config_json_path = NULL,
			.host_list_path = NULL,
			.netflow_src_ip = 0x04030201,
			.record = flow2, .record_size = flow2_size,
			.checkdata = checkdata2,
			.checkdata_size = checkdata2_size,
		},
	};

	*state = prepare_tests(test_params, flow2 ? 2 : 1);
	return *state == NULL;
}

static int prepare_test_nf5_base(void **state,
		const struct checkdata *checkdata, size_t checkdata_size,
		bool slip_flow) {
	return prepare_test_timestamp_split(state, &record5, sizeof(record5),
		checkdata, checkdata_size, NULL, 0, NULL, 0, slip_flow);
}

static int prepare_test_nf5_timestamp_split(void **state) {
	return prepare_test_nf5_base(state,
		checkdata_split, RD_ARRAYSIZE(checkdata_split), true);
}

static int prepare_test_nf5_timestamp_dont_split(void **state) {
	return prepare_test_nf5_base(state, checkdata_dont_split,
		RD_ARRAYSIZE(checkdata_dont_split), false);
}

static int prepare_test_ipfix_uptime_base(void **state,
		const struct checkdata *checkdata, size_t checkdata_size,
		bool split_flow) {
	return prepare_test_timestamp_split(state,
		&ipfix_uptime_template, sizeof(ipfix_uptime_template), NULL, 0,
		&ipfix_uptime_flow, sizeof(ipfix_uptime_flow),
		checkdata, checkdata_size, split_flow);
}

static int prepare_test_ipfix_timestamp_uptime_dont_split(void **state) {
	return prepare_test_ipfix_uptime_base(state, ipfix_checkdata_dont_split,
		RD_ARRAYSIZE(ipfix_checkdata_dont_split), false);
}

static int prepare_test_ipfix_timestamp_uptime_split(void **state) {
	return prepare_test_ipfix_uptime_base(state, ipfix_checkdata_split,
		RD_ARRAYSIZE(ipfix_checkdata_split), true);
}

static int prepare_test_ipfix_timestamp_base(void **state,
		const struct checkdata *checkdata, size_t checkdata_size,
		bool split_flow) {
	return prepare_test_timestamp_split(state,
		&ipfix_timestamp_template, sizeof(ipfix_timestamp_template),
		NULL, 0,
		&ipfix_timestamp_flow, sizeof(ipfix_timestamp_flow),
		checkdata, checkdata_size, split_flow);
}

static int prepare_test_ipfix_timestamp_dont_split(void **state) {
	return prepare_test_ipfix_timestamp_base(state,
		ipfix_checkdata_dont_split,
		RD_ARRAYSIZE(ipfix_checkdata_dont_split), false);
}

static int prepare_test_ipfix_timestamp_split(void **state) {
	return prepare_test_ipfix_timestamp_base(state, ipfix_checkdata_split,
		RD_ARRAYSIZE(ipfix_checkdata_split), true);
}

static int prepare_test_nf9_no_timestamp_base(void **state, bool split) {
	static const struct checkdata checkdata_notime = {
		.size = RD_ARRAYSIZE(timestamp_0_chks),
		.checks = timestamp_0_chks,
	};

	return prepare_test_timestamp_split(state,
		&nf9_notime_template, sizeof(nf9_notime_template),
		NULL, 0,
		&nf9_notime_flow, sizeof(nf9_notime_flow),
		&checkdata_notime, 1, split);
}

static int prepare_test_nf9_no_timestamp_dont_split(void **state) {
	return prepare_test_nf9_no_timestamp_base(state, false);
}

static int prepare_test_nf9_no_timestamp_split(void **state) {
	return prepare_test_nf9_no_timestamp_base(state, true);
}

int main() {
	static const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup(testFlow,
			prepare_test_nf5_timestamp_split),
		cmocka_unit_test_setup(testFlow,
			prepare_test_nf5_timestamp_dont_split),

		cmocka_unit_test_setup(testFlow,
			prepare_test_nf9_no_timestamp_dont_split),
		cmocka_unit_test_setup(testFlow,
			prepare_test_nf9_no_timestamp_split),

		cmocka_unit_test_setup(testFlow,
			prepare_test_ipfix_timestamp_uptime_dont_split),
		cmocka_unit_test_setup(testFlow,
			prepare_test_ipfix_timestamp_uptime_split),
		cmocka_unit_test_setup(testFlow,
			prepare_test_ipfix_timestamp_dont_split),
		cmocka_unit_test_setup(testFlow,
			prepare_test_ipfix_timestamp_split),
	};

	return cmocka_run_group_tests(tests, nf_test_setup, nf_test_teardown);
}
