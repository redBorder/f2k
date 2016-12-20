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

#define APP_ID_ENTITIES(RT, R) \
	RT(STA_MAC_ADDRESS, 6, 0, 0x00, 0x05, 0x69, 0x28, 0xb0, 0xc7) \
	RT(STA_IPV4_ADDRESS, 4, 0, 10, 13, 94, 223) \
	RT(SELECTOR_ID, 4, 0, UINT32_TO_UINT8_ARR(1)) \
	RT(WLAN_SSID, 33, 0,  WLAN_SSID_CHARS) \
	RT(DIRECTION, 1, 0, 0) \
	RT(IN_BYTES, 8, 0, UINT64_TO_UINT8_ARR(7603)) \
	RT(IN_PKTS, 8, 0, UINT64_TO_UINT8_ARR(263)) \
	RT(98, 1, 0, 0) \
	RT(195, 1, 0, 0) \
	RT(WAP_MAC_ADDRESS, 6, 0, 0x58, 0xbf, 0xea, 0x01, 0x5b, 0x40) \
		/* ****************************** */ \
	R(STA_MAC_ADDRESS, 6, 0, 0x00, 0x05, 0x69, 0x28, 0xb0, 0xc7) \
	R(STA_IPV4_ADDRESS, 4, 0, 10, 13, 94, 223) \
	R(SELECTOR_ID, 4, 0, UINT32_TO_UINT8_ARR(2)) \
	R(WLAN_SSID, 33, 0,  WLAN_SSID_CHARS) \
	R(DIRECTION, 1, 0, 0) \
	R(BYTES, 8, 0, UINT64_TO_UINT8_ARR(7603)) \
	R(PKTS, 8, 0, UINT64_TO_UINT8_ARR(263)) \
	R(98, 1, 0, 0) \
	R(195, 1, 0, 0) \
	R(WAP_MAC_ADDRESS, 6, 0, 0x58, 0xbf, 0xea, 0x01, 0x5b, 0x40) \
		/* ****************************** */ \
	R(STA_MAC_ADDRESS, 6, 0, 0x00, 0x05, 0x69, 0x28, 0xb0, 0xc7) \
	R(STA_IPV4_ADDRESS, 4, 0, 10, 13, 94, 223) \
	R(SELECTOR_ID, 4, 0, UINT32_TO_UINT8_ARR(3)) \
	R(WLAN_SSID, 33, 0,  WLAN_SSID_CHARS) \
	R(DIRECTION, 1, 0, 0) \
	R(BYTES, 8, 0, UINT64_TO_UINT8_ARR(7603)) \
	R(PKTS, 8, 0, UINT64_TO_UINT8_ARR(263)) \
	R(98, 1, 0, 0) \
	R(195, 1, 0, 0) \
	R(WAP_MAC_ADDRESS, 6, 0, 0x58, 0xbf, 0xea, 0x01, 0x5b, 0x40)

// @todo merge both option entities
#define OPTIONS_ENTITIES_NF9(SCOPE_CBT, OPTION_CBT, PADDING_CBT, \
		SCOPE_CBR, OPTION_CBR, PADDING_CBR, ...) \
	SCOPE_CBT(1, 4, 0x0a, 0x00, 0x32, 0x28)  \
	OPTION_CBT(SELECTOR_ID, 4, UINT32_TO_UINT8_ARR(1)) \
	OPTION_CBT(SELECTOR_NAME, 5, 'o', 'n', 'e', 00, 00) \
	PADDING_CBT(0x0, 0x0) \
	/*****/ \
	SCOPE_CBR(1, 4, 0x0a, 0x00, 0x32, 0x28)  \
	OPTION_CBR(SELECTOR_ID, 4, UINT32_TO_UINT8_ARR(2)) \
	OPTION_CBR(SELECTOR_NAME, 5, 't', 'w', 'o', 00, 00) \
	/*****/ \
	SCOPE_CBR(1, 4, 0x0a, 0x00, 0x32, 0x28)  \
	OPTION_CBR(SELECTOR_ID, 4, UINT32_TO_UINT8_ARR(3)) \
	OPTION_CBR(SELECTOR_NAME, 5, 't', 'h', 'r', 'e', 'e') \

// IPFIX has no padding here
#define OPTIONS_ENTITIES_IPFIX(SCOPE_CBT, OPTION_CBT, PADDING_CBT, \
		SCOPE_CBR, OPTION_CBR, PADDING_CBR) \
	SCOPE_CBT(SELECTOR_ID, 4, UINT32_TO_UINT8_ARR(1)) \
	OPTION_CBT(SELECTOR_NAME, 5, 'o', 'n', 'e', 00, 00) \
	/*****/ \
	SCOPE_CBR(SELECTOR_ID, 4, UINT32_TO_UINT8_ARR(2)) \
	OPTION_CBR(SELECTOR_NAME, 5, 't', 'w', 'o', 00, 00) \
	/*****/ \
	SCOPE_CBR(SELECTOR_ID, 4, UINT32_TO_UINT8_ARR(3)) \
	OPTION_CBR(SELECTOR_NAME, 5, 't', 'h', 'r', 'e', 'e') \

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


static int prepare_test_nf9_appid_enrichment(void **state) {

/* *************************** NF9 application id *************************** */
	static const NF9_TEMPLATE(v9_template, TEST_V9_FLOW_HEADER,
		TEST_TEMPLATE_ID, APP_ID_ENTITIES);
	static const NF9_FLOW(v9_flow, TEST_V9_FLOW_HEADER, TEST_TEMPLATE_ID,
		APP_ID_ENTITIES);

	static const NF9_OPTION_TEMPLATE(v9_option_template,
		TEST_V9_FLOW_HEADER, OPTIONS_TEMPLATE_ID,
		OPTIONS_ENTITIES_NF9);
	static const NF9_OPTION_FLOW(v9_option_flow, TEST_V9_FLOW_HEADER,
		OPTIONS_TEMPLATE_ID, OPTIONS_ENTITIES_NF9);

/* ************************** IPFIX application id ************************** */
	static const IPFIX_TEMPLATE(ipfix_template, TEST_IPFIX_FLOW_HEADER,
		TEST_TEMPLATE_ID, APP_ID_ENTITIES);
	static const IPFIX_FLOW(ipfix_flow, TEST_IPFIX_FLOW_HEADER,
		TEST_TEMPLATE_ID, APP_ID_ENTITIES);

	static const IPFIX_OPTION_TEMPLATE(ipfix_option_template,
		TEST_IPFIX_FLOW_HEADER, OPTIONS_TEMPLATE_ID,
		OPTIONS_ENTITIES_IPFIX);
	static const IPFIX_OPTION_FLOW(ipfix_option_flow,
		TEST_IPFIX_FLOW_HEADER, OPTIONS_TEMPLATE_ID,
		OPTIONS_ENTITIES_IPFIX)

/* ********************************* CHECKS ********************************* */

#define CHECKDATA(selector_id, selector_name) { \
	{.key = "selector_id", .value = selector_id}, \
	{.key = "selector_name", .value = selector_name}}

	static const struct checkdata_value checkdata1[] =
		CHECKDATA("1", "1");
	static const struct checkdata_value checkdata2[] =
		CHECKDATA("2", "2");
	static const struct checkdata_value checkdata3[] =
		CHECKDATA("3", "3");

	static const struct checkdata_value checkdata1_name[] =
		CHECKDATA("1", "one");
	static const struct checkdata_value checkdata2_name[] =
		CHECKDATA("2", "two");
	static const struct checkdata_value checkdata3_name[] =
		CHECKDATA("3", "three");
#undef CHECKDATA

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
#undef CHECK

/* ****************************** Actual test ****************************** */

#define TEST(mrecord, mrecord_size, checks, checks_size, ...) {                \
		.record = mrecord, .record_size = mrecord_size,                \
		.checkdata = checks, .checkdata_size = checks_size,            \
		.netflow_src_ip = 0x04030201, __VA_ARGS__                      \
	}

	struct test_params test_params[] = {
		// 1st test use fallback list
		TEST(&v9_template, sizeof(v9_template), NULL, 0,
			.config_json_path =
				"tests/0010-testAppIdEnrichment.json",
			.host_list_path = "./tests/0010-data/"),
		TEST(&v9_flow, sizeof(v9_flow),
			pre_checkdata, RD_ARRAYSIZE(pre_checkdata),),

		// 2nd test use an option template (private ssl)
		TEST(&v9_option_template, sizeof(v9_option_template), NULL, 0,),
		TEST(&v9_option_flow, sizeof(v9_option_flow), NULL, 0,),
		TEST(&v9_flow, sizeof(v9_flow),
			post_checkdata, RD_ARRAYSIZE(post_checkdata),),

		// Same with IPFIX
		TEST(&ipfix_template, sizeof(ipfix_template), NULL, 0,),
		TEST(&ipfix_flow, sizeof(ipfix_flow),
			pre_checkdata, RD_ARRAYSIZE(pre_checkdata),),

		TEST(&ipfix_option_template, sizeof(ipfix_option_template),
			NULL, 0,),
		TEST(&ipfix_option_flow, sizeof(ipfix_option_flow), NULL, 0,),
		TEST(&ipfix_flow, sizeof(ipfix_flow),
			post_checkdata, RD_ARRAYSIZE(post_checkdata),),
	};

	*state = prepare_tests(test_params, RD_ARRAYSIZE(test_params));
	return *state == NULL;
}

/*
 * REGRESION TEST: FLOW END PADDING
 */

#define WEB_SELECTOR_ID   UINT32_TO_UINT8_ARR(10)
#define WEB_SELECTOR_NAME 'w','e','b', 0, 0, 0, 0, 0, \
			0, 0, 0, 0, 0, 0, 0, 0, \
			0, 0, 0, 0, 0, 0, 0, 0, \
			0, 0, 0, 0, 0, 0, 0, 0, \
			0, 0, 0, 0, 0, 0, 0, 0, \
			0, 0, 0, 0, 0, 0, 0, 0, \
			0, 0, 0, 0, 0, 0, 0, 0, \
			0, 0, 0, 0, 0, 0, 0, 0, \
			0, 0, 0, 0, 0, 0, 0, 0, \
			0, 0, 0, 0, 0, 0, 0, 0, \
			0, 0, 0, 0, 0, 0, 0, 0, \
			0, 0, 0, 0, 0, 0, 0, 0, \
			0, 0, 0, 0, 0, 0, 0, 0, \
			0, 0, 0, 0, 0, 0, 0, 0, \
			0, 0, 0, 0, 0, 0, 0, 0, \
			0, 0, 0, 0, 0, 0, 0, 0
#define VOICE_SELECTOR_ID   UINT32_TO_UINT8_ARR(20)
#define VOICE_SELECTOR_NAME 'v','o','i', 'c', 'e', 0, 0, 0, \
			0, 0, 0, 0, 0, 0, 0, 0, \
			0, 0, 0, 0, 0, 0, 0, 0, \
			0, 0, 0, 0, 0, 0, 0, 0, \
			0, 0, 0, 0, 0, 0, 0, 0, \
			0, 0, 0, 0, 0, 0, 0, 0, \
			0, 0, 0, 0, 0, 0, 0, 0, \
			0, 0, 0, 0, 0, 0, 0, 0, \
			0, 0, 0, 0, 0, 0, 0, 0, \
			0, 0, 0, 0, 0, 0, 0, 0, \
			0, 0, 0, 0, 0, 0, 0, 0, \
			0, 0, 0, 0, 0, 0, 0, 0, \
			0, 0, 0, 0, 0, 0, 0, 0, \
			0, 0, 0, 0, 0, 0, 0, 0, \
			0, 0, 0, 0, 0, 0, 0, 0, \
			0, 0, 0, 0, 0, 0, 0, 0
#define OTHER_SELECTOR_ID   UINT32_TO_UINT8_ARR(30)
#define OTHER_SELECTOR_NAME 'o','t','h', 'e', 'r', 'w', 'i', 's', \
			'e', 0, 0, 0, 0, 0, 0, 0, \
			0, 0, 0, 0, 0, 0, 0, 0, \
			0, 0, 0, 0, 0, 0, 0, 0, \
			0, 0, 0, 0, 0, 0, 0, 0, \
			0, 0, 0, 0, 0, 0, 0, 0, \
			0, 0, 0, 0, 0, 0, 0, 0, \
			0, 0, 0, 0, 0, 0, 0, 0, \
			0, 0, 0, 0, 0, 0, 0, 0, \
			0, 0, 0, 0, 0, 0, 0, 0, \
			0, 0, 0, 0, 0, 0, 0, 0, \
			0, 0, 0, 0, 0, 0, 0, 0, \
			0, 0, 0, 0, 0, 0, 0, 0, \
			0, 0, 0, 0, 0, 0, 0, 0, \
			0, 0, 0, 0, 0, 0, 0, 0, \
			0, 0, 0, 0, 0, 0, 0, 0
#define LOCAL_SELECTOR_ID   UINT32_TO_UINT8_ARR(40)
#define LOCAL_SELECTOR_NAME 'l','o','c', 'a', 'l', 0, 0, 0, \
			0, 0, 0, 0, 0, 0, 0, 0, \
			0, 0, 0, 0, 0, 0, 0, 0, \
			0, 0, 0, 0, 0, 0, 0, 0, \
			0, 0, 0, 0, 0, 0, 0, 0, \
			0, 0, 0, 0, 0, 0, 0, 0, \
			0, 0, 0, 0, 0, 0, 0, 0, \
			0, 0, 0, 0, 0, 0, 0, 0, \
			0, 0, 0, 0, 0, 0, 0, 0, \
			0, 0, 0, 0, 0, 0, 0, 0, \
			0, 0, 0, 0, 0, 0, 0, 0, \
			0, 0, 0, 0, 0, 0, 0, 0, \
			0, 0, 0, 0, 0, 0, 0, 0, \
			0, 0, 0, 0, 0, 0, 0, 0, \
			0, 0, 0, 0, 0, 0, 0, 0, \
			0, 0, 0, 0, 0, 0, 0, 0


// Note the padding only in flow. this way, flow alignment is 4
#define PADDING_ENTITIES(SCOPE_CBT, OPTION_CBT, PADDING_CBT, \
		SCOPE_CBR, OPTION_CBR, PADDING_CBR) \
	SCOPE_CBT(SELECTOR_ID, 4, WEB_SELECTOR_ID) \
	OPTION_CBT(SELECTOR_NAME, 128, WEB_SELECTOR_NAME) \
	/*****/ \
	SCOPE_CBR(SELECTOR_ID, 4, VOICE_SELECTOR_ID) \
	OPTION_CBR(SELECTOR_NAME, 128, VOICE_SELECTOR_NAME) \
	/*****/ \
	SCOPE_CBR(SELECTOR_ID, 4, OTHER_SELECTOR_ID) \
	OPTION_CBR(SELECTOR_NAME, 128, OTHER_SELECTOR_NAME) \
	/*****/ \
	SCOPE_CBR(SELECTOR_ID, 4, LOCAL_SELECTOR_ID) \
	OPTION_CBR(SELECTOR_NAME, 128, LOCAL_SELECTOR_NAME) \
	PADDING_CBR(0x0, 0x0)


static int prepare_test_final_padding(void **state) {
	static const NF9_OPTION_TEMPLATE(v9_option_template,
		TEST_V9_FLOW_HEADER, OPTIONS_TEMPLATE_ID,
		PADDING_ENTITIES);
	static const NF9_OPTION_FLOW(v9_option_flow, TEST_V9_FLOW_HEADER,
		OPTIONS_TEMPLATE_ID, PADDING_ENTITIES);

	static const IPFIX_OPTION_TEMPLATE(ipfix_option_template,
		TEST_IPFIX_FLOW_HEADER, OPTIONS_TEMPLATE_ID,
		PADDING_ENTITIES);
	static const IPFIX_OPTION_FLOW(ipfix_option_flow,
		TEST_IPFIX_FLOW_HEADER, OPTIONS_TEMPLATE_ID,
		PADDING_ENTITIES)


	struct test_params test_params[] = {
		TEST(&v9_option_template, sizeof(v9_option_template), NULL, 0,
			.config_json_path =
				"tests/0010-testAppIdEnrichment.json",
			.host_list_path = "./tests/0010-data/"),
		TEST(&v9_option_flow, sizeof(v9_option_flow), NULL, 0,),
		TEST(&ipfix_option_template, sizeof(ipfix_option_template),
					NULL, 0,),
		TEST(&ipfix_option_flow, sizeof(ipfix_option_flow), NULL, 0,),

	};

	*state = prepare_tests(test_params, RD_ARRAYSIZE(test_params));
	return *state == NULL;
}

int main() {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup(testFlow,
					prepare_test_nf9_appid_enrichment),
		cmocka_unit_test_setup(testFlow, prepare_test_final_padding),
	};

	return cmocka_run_group_tests(tests, nf_test_setup, nf_test_teardown);
}
