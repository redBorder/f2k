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

#define NF5_RECORD(mtcp_flags) { \
	.srcaddr = NF5_IP(8, 8, 8, 8),  /* Source IP Address */                       \
	.dstaddr = NF5_IP(10,10,10,10),  /* Source IP Address */                       \
	.nexthop = NF5_IP(0,0,0,0),  /* Next hop router's IP Address */            \
	.input   = 0,            /* Input interface index */                   \
	.output  = 255,          /* Output interface index */                  \
	.dPkts   = constexpr_be16toh(1), /* Packets sent in Duration           \
	                            (milliseconds between 1st & last packet in \
	                            this flow) */                              \
	.dOctets = constexpr_be16toh(70), /* Octets sent in Duration */        \
	.first   = 0xa8484205,   /* SysUptime at start of flow */              \
	.last    = 0xa8484205,   /* and of last packet of the flow */          \
	.srcport = constexpr_be16toh(443), /* source port number */            \
	.dstport = constexpr_be16toh(10101), /* destination port number */     \
	.tcp_flags = mtcp_flags, /* Cumulative OR of tcp flags */              \
	.proto   = 2,           /* IP protocol, e.g., 6=TCP, 17=UDP, etc... */ \
	.tos     = 0,            /* IP Type-of-Service */                      \
	.src_as  = 0,            /* source peer/origin Autonomous System */    \
	.dst_as  = 0,            /* dst peer/origin Autonomous System */       \
	.src_mask = 0,           /* source route's mask bits */                \
	.dst_mask = 0,           /* destination route's mask bits */           \
}

static const NetFlow5Record record5 = {
	.flowHeader = {
		.version = constexpr_be16toh(5),
		.count = constexpr_be16toh(30),
		.sys_uptime = constexpr_be16toh(12345),
		.unix_secs = constexpr_be16toh(12345),
		.unix_nsecs = constexpr_be16toh(12345),
		.flow_sequence = constexpr_be16toh(1050),
		.engine_type = 0,      /* Type of flow switching engine (RP,VIP,etc.)*/
		.engine_id  = 0,       /* Slot number of the flow switching engine */
		.sampleRate = 0,       /* Packet capture sample rate */
	},
	.flowRecord = {
		// Some random records
		NF5_RECORD(0x6c), NF5_RECORD(0xe0), NF5_RECORD(0x80),
		NF5_RECORD(0xee), NF5_RECORD(0x3c), NF5_RECORD(0xe5),
		NF5_RECORD(0x2e), NF5_RECORD(0xc6), NF5_RECORD(0xa8),
		NF5_RECORD(0x76), NF5_RECORD(0x6a), NF5_RECORD(0x9f),
		NF5_RECORD(0xc4), NF5_RECORD(0xa0), NF5_RECORD(0x64),
		NF5_RECORD(0x8a), NF5_RECORD(0xe3), NF5_RECORD(0x0b),
		NF5_RECORD(0x2a), NF5_RECORD(0xdc), NF5_RECORD(0xa5),
		NF5_RECORD(0x35), NF5_RECORD(0x7f), NF5_RECORD(0x1d),
		NF5_RECORD(0x65), NF5_RECORD(0x3b), NF5_RECORD(0x80),
		NF5_RECORD(0xd7), NF5_RECORD(0x8b), NF5_RECORD(0x89),
	}
};

#define ARGS(...) __VA_ARGS__


/** Flow + template definitions
  @param RT Macro to call in each entity that define a template
  @param R Macro to call in each entity that does not define a template
  @varargs Element of TCP entry
  @note R macro arguments are:
    1) -> Template entity
    2) -> Length
    3) -> PEN number (if >0)
    4..) -> value
  */
#define FLOW_TCP_FLAGS_ENTITIES(RT, R, ...) \
	RT(IPV4_SRC_ADDR, 4, 0, 208, 67, 222, 222) \
	RT(IPV4_DST_ADDR, 4, 0, 192, 168, 210, 18) \
	RT(IPV4_NEXT_HOP, 4, 0, 192, 168, 210, 18) \
	RT(INPUT_SNMP, 2, 0, UINT16_TO_UINT8_ARR(2)) \
	RT(OUTPUT_SNMP, 2, 0, UINT16_TO_UINT8_ARR(7)) \
	RT(IN_PKTS, 4, 0, UINT32_TO_UINT8_ARR(1)) \
	RT(IN_BYTES, 4, 0, UINT32_TO_UINT8_ARR(88)) \
	RT(L4_SRC_PORT, 2, 0, UINT16_TO_UINT8_ARR(53)) \
	RT(L4_DST_PORT, 2, 0, UINT16_TO_UINT8_ARR(53549)) \
	RT(__VA_ARGS__) \
	RT(PROTOCOL, 1, 0, IPPROTO_UDP) \
	RT(SRC_TOS, 1, 0, 0) \
	RT(IPV4_SRC_MASK, 1, 0, 16) \
	RT(IPV4_DST_MASK, 1, 0, 23) \
	RT(DIRECTION, 1, 0, 0) \
	RT(FLOW_START_SEC, 4, 0, 0x57, 0x74, 0x00, 0x9d) \
	RT(FLOW_END_SEC, 4, 0, 0x57, 0x74, 0x00, 0x9d) \
	RT(12235, 0xffff, 9, 0)

/// Flow entities for 1byte TCP flags
#define FLOW_ENTITIES_TCP_FLAGS_1B(R, RT) \
	FLOW_TCP_FLAGS_ENTITIES(R, RT, TCP_FLAGS, 1, 0, 0x6e)
#define FLOW_ENTITIES_TCP_FLAGS_2B(R, RT) \
	FLOW_TCP_FLAGS_ENTITIES(R, RT, TCP_FLAGS, 2, 0, 0x00, 0x6e)

#define TEST_TEMPLATE_ID 1025

#define TEST_FLOW_HEADER \
	.unix_secs = constexpr_be32toh(1467220140), \
	.flow_sequence = constexpr_be32toh(12372811), \
	.observation_id = 0

#define BASE_CHECKS(mtcp_flags) { \
	{.key="type",.value="netflowv5"}, \
	{.key="src",.value="8.8.8.8"}, \
	{.key="dst",.value="10.10.10.10"}, \
	{.key="src_port",.value="443"}, \
	{.key="dst_port",.value="10101"}, \
	{.key="input_snmp",.value="0"}, \
	{.key="output_snmp",.value="65280"}, \
	{.key="tos",.value="0"}, \
	{.key="tcp_flags",.value=mtcp_flags}, \
	{.key="l4_proto",.value="2"}, \
	{.key="engine_type",.value="0"}, \
	{.key="sensor_ip",.value="4.3.2.1"} \
}

// @todo this can be improved using c99 array initializers
#define CHECKS_REF(id) checks_##id
#define CHECKS_DEF(id, mtcp_flags) \
	static const struct checkdata_value CHECKS_REF(id)[] = \
		BASE_CHECKS(mtcp_flags)
#define CHECKDATA(id) \
		{.size = 12, .checks=CHECKS_REF(id)}

// end of todo

CHECKS_DEF(0,".EU.PR..");  CHECKS_DEF(1,"CEU.....");  CHECKS_DEF(2,"C.......");
CHECKS_DEF(3,"CEU.PRS.");  CHECKS_DEF(4,"..UAPR..");  CHECKS_DEF(5,"CEU..R.F");
CHECKS_DEF(6,"..U.PRS.");  CHECKS_DEF(7,"CE...RS.");  CHECKS_DEF(8,"C.U.P...");
CHECKS_DEF(9,".EUA.RS.");  CHECKS_DEF(10,".EU.P.S."); CHECKS_DEF(11,"C..APRSF");
CHECKS_DEF(12,"CE...R.."); CHECKS_DEF(13,"C.U....."); CHECKS_DEF(14,".EU..R..");
CHECKS_DEF(15,"C...P.S."); CHECKS_DEF(16,"CEU...SF"); CHECKS_DEF(17,"....P.SF");
CHECKS_DEF(18,"..U.P.S."); CHECKS_DEF(19,"CE.APR.."); CHECKS_DEF(20,"C.U..R.F");
CHECKS_DEF(21,"..UA.R.F"); CHECKS_DEF(22,".EUAPRSF"); CHECKS_DEF(23,"...APR.F");
CHECKS_DEF(24,".EU..R.F"); CHECKS_DEF(25,"..UAP.SF"); CHECKS_DEF(26,"C.......");
CHECKS_DEF(27,"CE.A.RSF"); CHECKS_DEF(28,"C...P.SF"); CHECKS_DEF(29,"C...P..F");

static int prepare_test_nf5_tcpflags(void **state) {
	static const struct checkdata checkdata[] = {
		CHECKDATA(0),  CHECKDATA(1),  CHECKDATA(2),
		CHECKDATA(3),  CHECKDATA(4),  CHECKDATA(5),
		CHECKDATA(6),  CHECKDATA(7),  CHECKDATA(8),
		CHECKDATA(9),  CHECKDATA(10), CHECKDATA(11),
		CHECKDATA(12), CHECKDATA(13), CHECKDATA(14),
		CHECKDATA(15), CHECKDATA(16), CHECKDATA(17),
		CHECKDATA(18), CHECKDATA(19), CHECKDATA(20),
		CHECKDATA(21), CHECKDATA(22), CHECKDATA(23),
		CHECKDATA(24), CHECKDATA(25), CHECKDATA(26),
		CHECKDATA(27), CHECKDATA(28), CHECKDATA(29),
	};

	struct test_params test_params[] = {
		[0] = {
			.config_json_path = "./tests/0000-testFlowV5.json",
			.host_list_path = NULL,
			.netflow_src_ip = 0x04030201,
			.record = &record5,
			.record_size = sizeof(record5),
			.checkdata = checkdata,
			.checkdata_size = RD_ARRAYSIZE(checkdata),
		},
	};

	*state = prepare_tests(test_params, RD_ARRAYSIZE(test_params));
	return *state == NULL;
}

/// Test of IPFIX TCP flag with 1 byte length
static int prepare_test_ipfix_tcpflags(void **state,
		const void *v10_template, size_t v10_template_len,
		const void *v10_flow, size_t v10_flow_len) {

	static const struct checkdata_value ipfix_checks[] = {
		{.key="type",.value="netflowv10"},
		{.key="src",.value="208.67.222.222"},
		{.key="dst",.value="192.168.210.18"},
		{.key="src_port",.value="53"},
		{.key="dst_port",.value="53549"},
		{.key="input_snmp",.value="2"},
		{.key="output_snmp",.value="7"},
		{.key="tcp_flags",.value=".EU.PRS."},
		{.key="l4_proto",.value="17"},
		{.key="sensor_ip",.value="4.3.2.1"},
		{.key="bytes",.value="88"},
		{.key="pkts",.value="1"}
	};

	static const struct checkdata checkdata = {
		.size = RD_ARRAYSIZE(ipfix_checks), .checks=ipfix_checks,
	};

	struct test_params test_params[] = {
		[0] = {
			.config_json_path = "./tests/0000-testFlowV5.json",
			.host_list_path = NULL,
			.netflow_src_ip = 0x04030201,
			.record = v10_template,
			.record_size = v10_template_len,
			.checkdata = NULL,
			.checkdata_size = 0,
		},
		[1] = {
			.config_json_path = NULL,
			.host_list_path = NULL,
			.netflow_src_ip = 0x04030201,
			.record = v10_flow,
			.record_size = v10_flow_len,
			.checkdata = &checkdata,
			.checkdata_size = 1,
		},
	};

	*state = prepare_tests(test_params, RD_ARRAYSIZE(test_params));
	return *state == NULL;
}

static int prepare_test_ipfix_tcpflags_1b(void **state) {
	static const IPFIX_TEMPLATE(template, TEST_FLOW_HEADER,
		TEST_TEMPLATE_ID, FLOW_ENTITIES_TCP_FLAGS_1B);
	static const IPFIX_FLOW(flow, TEST_FLOW_HEADER, TEST_TEMPLATE_ID,
		FLOW_ENTITIES_TCP_FLAGS_1B);
	return prepare_test_ipfix_tcpflags(state,
		&template, sizeof(template), &flow, sizeof(flow));
}

static int prepare_test_ipfix_tcpflags_2b(void **state) {
	static const IPFIX_TEMPLATE(template, TEST_FLOW_HEADER,
		TEST_TEMPLATE_ID, FLOW_ENTITIES_TCP_FLAGS_2B);
	static const IPFIX_FLOW(flow, TEST_FLOW_HEADER, TEST_TEMPLATE_ID,
		FLOW_ENTITIES_TCP_FLAGS_2B);
	return prepare_test_ipfix_tcpflags(state,
		&template, sizeof(template), &flow, sizeof(flow));
}

int main() {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup(testFlow,
				prepare_test_nf5_tcpflags),
		cmocka_unit_test_setup(testFlow,
				prepare_test_ipfix_tcpflags_1b),
		cmocka_unit_test_setup(testFlow,
				prepare_test_ipfix_tcpflags_2b),
	};

	return cmocka_run_group_tests(tests, nf_test_setup, nf_test_teardown);
}
