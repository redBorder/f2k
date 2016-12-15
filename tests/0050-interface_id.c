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

#define WLAN_SSID_CHARS \
	0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x2d, /* WLAN_SSID: "local-wifi" */ \
	0x77, 0x69, 0x66, 0x69, 0x00, 0x00, \
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
	0x00, 0x00, 0x00

#define INTERFACE_FLOW_BASE(X, t_direction, t_input_snmp, t_output_snmp) \
	X(STA_MAC_ADDRESS, 6, 0, 0x00, 0x05, 0x69, 0x28, 0xb0, 0xc7) \
	X(STA_IPV4_ADDRESS, 4, 0, 10, 13, 94, 223) \
	X(INPUT_SNMP, 2, 0, UINT16_TO_UINT8_ARR(t_input_snmp)) \
	X(OUTPUT_SNMP, 2, 0, UINT16_TO_UINT8_ARR(t_output_snmp)) \
	X(WLAN_SSID, 33, 0,  WLAN_SSID_CHARS) \
	X(DIRECTION, 1, 0, t_direction) \
	X(IN_BYTES, 8, 0, UINT64_TO_UINT8_ARR(7603)) \
	X(IN_PKTS, 8, 0, UINT64_TO_UINT8_ARR(263)) \
	X(98, 1, 0, 0) \
	X(195, 1, 0, 0) \
	X(WAP_MAC_ADDRESS, 6, 0, 0x58, 0xbf, 0xea, 0x01, 0x5b, 0x40)

#define INTERFACE_ID_ENTITIES(RT, R) \
	INTERFACE_FLOW_BASE(RT, 0, 1, 2) \
	INTERFACE_FLOW_BASE(R, 1, 2, 4) \
	INTERFACE_FLOW_BASE(R, 1, 3, 1)

#define INTERFACE_NAME(num) \
	'e', 't', 'h', 'e',  'r',  'n',  'e',  't', \
	'0', '/', num, 0x00, 0x00, 0x00, 0x00, 0x00, \
	0x00, 0x00, 0x00, 0x00

#define INTERFACE_DESCRIPTION(num) \
	'e', 't', 'h', 'e',  'r',  'n',  'e',  't', \
	'0', '/', num, 'd', 0x00, 0x00, 0x00, 0x00, \
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00

// @todo merge both option entities
#define OPTIONS_ENTITIES_NF9(SCOPE_CBT, OPTION_CBT, PADDING_CBT, \
		SCOPE_CBR, OPTION_CBR, PADDING_CBR, ...) \
	SCOPE_CBT(1, 4, 0x0a, 0x00, 0x32, 0x28)  \
	OPTION_CBT(INPUT_SNMP, 2, UINT16_TO_UINT8_ARR(0)) \
	OPTION_CBT(IF_NAME, 20, INTERFACE_NAME('0')) \
	OPTION_CBT(IF_DESCRIPTION, 64, INTERFACE_DESCRIPTION('0')) \
	/*****/ \
	SCOPE_CBR(1, 4, 0x0a, 0x00, 0x32, 0x28)  \
	OPTION_CBR(INPUT_SNMP, 2, UINT16_TO_UINT8_ARR(1)) \
	OPTION_CBR(IF_NAME, 20, INTERFACE_NAME('1')) \
	OPTION_CBR(IF_DESCRIPTION, 64, INTERFACE_DESCRIPTION('1')) \
	/*****/ \
	SCOPE_CBR(1, 4, 0x0a, 0x00, 0x32, 0x28)  \
	OPTION_CBR(INPUT_SNMP, 2, UINT16_TO_UINT8_ARR(2)) \
	OPTION_CBR(IF_NAME, 20, INTERFACE_NAME('2')) \
	OPTION_CBR(IF_DESCRIPTION, 64, INTERFACE_DESCRIPTION('2')) \

// IPFIX has no padding here
#define OPTIONS_ENTITIES_IPFIX(SCOPE_CBT, OPTION_CBT, PADDING_CBT, \
		SCOPE_CBR, OPTION_CBR, PADDING_CBR) \
	SCOPE_CBT(INPUT_SNMP, 2, UINT16_TO_UINT8_ARR(0)) \
	OPTION_CBT(IF_NAME, 20, INTERFACE_NAME('0')) \
	OPTION_CBT(IF_DESCRIPTION, 64, INTERFACE_DESCRIPTION('0')) \
	/*****/ \
	SCOPE_CBR(INPUT_SNMP, 2, UINT16_TO_UINT8_ARR(1)) \
	OPTION_CBR(IF_NAME, 20, INTERFACE_NAME('1')) \
	OPTION_CBR(IF_DESCRIPTION, 64, INTERFACE_DESCRIPTION('1')) \
	/*****/ \
	SCOPE_CBR(INPUT_SNMP, 2, UINT16_TO_UINT8_ARR(2)) \
	OPTION_CBR(IF_NAME, 20, INTERFACE_NAME('2')) \
	OPTION_CBR(IF_DESCRIPTION, 64, INTERFACE_DESCRIPTION('2')) \

#define OPTIONS_TEMPLATE_ID 256
#define TEST_TEMPLATE_ID 1025

#define TEST_V9_FLOW_HEADER \
	.unix_secs = constexpr_be32toh(1467220140), \
	.flow_sequence = constexpr_be32toh(12372811), \
	.source_id = constexpr_be32toh(1),

#define TEST_IPFIX_FLOW_HEADER \
	.unix_secs = constexpr_be32toh(1467220140), \
	.flow_sequence = constexpr_be32toh(12372811), \
	.observation_id = constexpr_be32toh(2),

/* *************************** NF9 interfaces id *************************** */
static const NF9_TEMPLATE(v9_template, TEST_V9_FLOW_HEADER,
	TEST_TEMPLATE_ID, INTERFACE_ID_ENTITIES);
static const NF9_FLOW(v9_flow, TEST_V9_FLOW_HEADER, TEST_TEMPLATE_ID,
	INTERFACE_ID_ENTITIES);

static const NF9_OPTION_TEMPLATE(v9_option_template,
	TEST_V9_FLOW_HEADER, OPTIONS_TEMPLATE_ID,
	OPTIONS_ENTITIES_NF9);
static const NF9_OPTION_FLOW(v9_option_flow, TEST_V9_FLOW_HEADER,
	OPTIONS_TEMPLATE_ID, OPTIONS_ENTITIES_NF9);

/* ************************** IPFIX interfaces id ************************** */
static const IPFIX_TEMPLATE(ipfix_template, TEST_IPFIX_FLOW_HEADER,
	TEST_TEMPLATE_ID, INTERFACE_ID_ENTITIES);
static const IPFIX_FLOW(ipfix_flow, TEST_IPFIX_FLOW_HEADER,
	TEST_TEMPLATE_ID, INTERFACE_ID_ENTITIES);

static const IPFIX_OPTION_TEMPLATE(ipfix_option_template,
	TEST_IPFIX_FLOW_HEADER, OPTIONS_TEMPLATE_ID,
	OPTIONS_ENTITIES_IPFIX);
static const IPFIX_OPTION_FLOW(ipfix_option_flow,
	TEST_IPFIX_FLOW_HEADER, OPTIONS_TEMPLATE_ID,
	OPTIONS_ENTITIES_IPFIX);


static int prepare_test_interface_id0(void **state,
		const struct checkdata *pre_checkdata,
		const size_t pre_checkdata_size,
		const struct checkdata *post_checkdata,
		const size_t post_checkdata_size,
		const bool normalize_directions) {
	#define TEST(mrecord, mrecord_size, checks, checks_size, ...) {        \
		.record = mrecord, .record_size = mrecord_size,                \
		.checkdata = checks, .checkdata_size = checks_size,            \
		.netflow_src_ip = 0x04030201, __VA_ARGS__                      \
	}

	struct test_params test_params[] = {
		// 1st test use fallback list
		TEST(&v9_template, sizeof(v9_template), NULL, 0,
			.config_json_path =
				"tests/0010-testAppIdEnrichment.json",
			.host_list_path = "./tests/0010-data/",
			.normalize_directions = normalize_directions),
		TEST(&v9_flow, sizeof(v9_flow),
			pre_checkdata, pre_checkdata_size,),

		// 2nd test use an option template (private ssl)
		TEST(&v9_option_template, sizeof(v9_option_template), NULL, 0,),
		TEST(&v9_option_flow, sizeof(v9_option_flow), NULL, 0,),
		TEST(&v9_flow, sizeof(v9_flow),
			post_checkdata, post_checkdata_size,),

		// Same with IPFIX
		TEST(&ipfix_template, sizeof(ipfix_template), NULL, 0,),
		TEST(&ipfix_flow, sizeof(ipfix_flow),
			pre_checkdata, pre_checkdata_size,),

		TEST(&ipfix_option_template, sizeof(ipfix_option_template),
			NULL, 0,),
		TEST(&ipfix_option_flow, sizeof(ipfix_option_flow), NULL, 0,),
		TEST(&ipfix_flow, sizeof(ipfix_flow),
			post_checkdata, post_checkdata_size,),
	};
#undef TEST

	*state = prepare_tests(test_params, RD_ARRAYSIZE(test_params));
	return *state == NULL;
}

static int prepare_test_interface_id(void **state) {

/* ********************************* CHECKS ********************************* */

#define CHECKDATA(left_name, left_snmp, \
			left_snmp_name, left_snmp_description, \
		  right_name, right_snmp, \
			right_snmp_name, right_snmp_description) \
	{{.key = left_name, .value = left_snmp}, \
	{.key = left_name "_name", .value = left_snmp_name}, \
	{.key = left_name "_description", .value = left_snmp_description}, \
	{.key = right_name, .value = right_snmp}, \
	{.key = right_name "_name", .value = right_snmp_name}, \
	{.key = right_name "_description", .value = right_snmp_description}}

	static const struct checkdata_value checkdata1[] =
		CHECKDATA("input_snmp", "1", "1", "1",
			"output_snmp", "2", "2", "2");
	static const struct checkdata_value checkdata2[] =
		CHECKDATA("input_snmp", "2", "2", "2",
			"output_snmp", "4", "4", "4");
	static const struct checkdata_value checkdata3[] =
		CHECKDATA("input_snmp", "3", "3", "3",
			"output_snmp", "1", "1", "1");

	static const struct checkdata_value checkdata1_name[] =
		CHECKDATA("input_snmp", "1", "ethernet0/1", "ethernet0/1d",
			"output_snmp", "2", "ethernet0/2", "ethernet0/2d");
	static const struct checkdata_value checkdata2_name[] =
		CHECKDATA("input_snmp", "2", "ethernet0/2", "ethernet0/2d",
			"output_snmp", "4", "4", "4");
	static const struct checkdata_value checkdata3_name[] =
		CHECKDATA("input_snmp", "3", "3", "3",
			"output_snmp", "1", "ethernet0/1", "ethernet0/1d");

#define CHECK(checkdata) {.size = RD_ARRAYSIZE(checkdata), .checks = checkdata}

	static const struct checkdata pre_checkdata[] = {
		CHECK(checkdata1),
		CHECK(checkdata2),
		CHECK(checkdata3),
	};

	static const struct checkdata post_checkdata[] = {
		CHECK(checkdata1_name),
		CHECK(checkdata2_name),
		CHECK(checkdata3_name),
	};

	return prepare_test_interface_id0(state,
		pre_checkdata, RD_ARRAYSIZE(pre_checkdata),
		post_checkdata, RD_ARRAYSIZE(post_checkdata),
		false);
}

static int prepare_test_normalized_interface_id(void **state) {

/* ********************************* CHECKS ********************************* */

	static const struct checkdata_value checkdata1[] =
		CHECKDATA("lan_interface", "1", "1", "1",
			"wan_interface", "2", "2", "2");
	static const struct checkdata_value checkdata2[] =
		CHECKDATA("wan_interface", "2", "2", "2",
			"lan_interface", "4", "4", "4");
	static const struct checkdata_value checkdata3[] =
		CHECKDATA("wan_interface", "3", "3", "3",
			"lan_interface", "1", "1", "1");

	static const struct checkdata_value checkdata1_name[] =
		CHECKDATA("lan_interface", "1", "ethernet0/1", "ethernet0/1d",
			"wan_interface", "2", "ethernet0/2", "ethernet0/2d");
	static const struct checkdata_value checkdata2_name[] =
		CHECKDATA("wan_interface", "2", "ethernet0/2", "ethernet0/2d",
			"lan_interface", "4", "4", "4");
	static const struct checkdata_value checkdata3_name[] =
		CHECKDATA("wan_interface", "3", "3", "3",
			"lan_interface", "1", "ethernet0/1", "ethernet0/1d");

	static const struct checkdata pre_checkdata[] = {
		CHECK(checkdata1),
		CHECK(checkdata2),
		CHECK(checkdata3),
	};

	static const struct checkdata post_checkdata[] = {
		CHECK(checkdata1_name),
		CHECK(checkdata2_name),
		CHECK(checkdata3_name),
	};

	return prepare_test_interface_id0(state,
		pre_checkdata, RD_ARRAYSIZE(pre_checkdata),
		post_checkdata, RD_ARRAYSIZE(post_checkdata),
		true);
}

int main() {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup(testFlow, prepare_test_interface_id),
		cmocka_unit_test_setup(testFlow,
		 	prepare_test_normalized_interface_id),
	};

	return cmocka_run_group_tests(tests, nf_test_setup, nf_test_teardown);
}
