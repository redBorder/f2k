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
	RT(APPLICATION_ID, 4, 0, UINT32_TO_UINT8_ARR(0)) \
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
	R(APPLICATION_ID, 4, 0, FLOW_APPLICATION_ID(13, 453)) \
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
	R(APPLICATION_ID, 4, 0, FLOW_APPLICATION_ID(3, 53)) \
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
	R(APPLICATION_ID, 4, 0, FLOW_APPLICATION_ID(3, 1990)) \
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
	R(APPLICATION_ID, 4, 0, FLOW_APPLICATION_ID(245, 1990)) \
	R(WLAN_SSID, 33, 0,  WLAN_SSID_CHARS) \
	R(DIRECTION, 1, 0, 0) \
	R(BYTES, 8, 0, UINT64_TO_UINT8_ARR(7603)) \
	R(PKTS, 8, 0, UINT64_TO_UINT8_ARR(263)) \
	R(98, 1, 0, 0) \
	R(195, 1, 0, 0) \
	R(WAP_MAC_ADDRESS, 6, 0, 0x58, 0xbf, 0xea, 0x01, 0x5b, 0x40)

#define SSL_APPLICATION_NAME \
	'p', 's', 's', 'l', 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, \
	00,  00,  00,  00,  00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, \
	00,  00,  00,  00,  00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, \
	00,  00,  00,  00,  00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00

#define FTP_APPLICATION_NAME \
	'f', 't', 'p', 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, \
	00,  00,  00,  00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, \
	00,  00,  00,  00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, \
	00,  00,  00,  00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00

#define DNS_APPLICATION_NAME \
	'd', 'n', 's', 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, \
	00,  00,  00,  00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, \
	00,  00,  00,  00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, \
	00,  00,  00,  00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00

// @todo merge both option entities
#define OPTIONS_ENTITIES_NF9(SCOPE_CBT, OPTION_CBT, PADDING_CBT, \
		SCOPE_CBR, OPTION_CBR, PADDING_CBR, ...) \
	SCOPE_CBT(1, 4, 0x0a, 0x00, 0x32, 0x28)  \
	OPTION_CBT(APPLICATION_ID, 4, FLOW_APPLICATION_ID(13, 453)) \
	OPTION_CBT(APPLICATION_NAME, 64, SSL_APPLICATION_NAME) \
	PADDING_CBT(0x0, 0x0) \
	/*****/ \
	SCOPE_CBR(1, 4, 0x0a, 0x00, 0x32, 0x28)  \
	OPTION_CBR(APPLICATION_ID, 4, FLOW_APPLICATION_ID(3, 21)) \
	OPTION_CBR(APPLICATION_NAME, 64, FTP_APPLICATION_NAME) \
	/*****/ \
	SCOPE_CBR(1, 4, 0x0a, 0x00, 0x32, 0x28)  \
	OPTION_CBR(APPLICATION_ID, 4, FLOW_APPLICATION_ID(3, 53)) \
	OPTION_CBR(APPLICATION_NAME, 64, DNS_APPLICATION_NAME) \

// IPFIX has no padding here
#define OPTIONS_ENTITIES_IPFIX(SCOPE_CBT, OPTION_CBT, PADDING_CBT, \
		SCOPE_CBR, OPTION_CBR, PADDING_CBR) \
	SCOPE_CBT(APPLICATION_ID, 4, FLOW_APPLICATION_ID(13, 453)) \
	OPTION_CBT(APPLICATION_NAME, 64, SSL_APPLICATION_NAME) \
	/*****/ \
	SCOPE_CBR(APPLICATION_ID, 4, FLOW_APPLICATION_ID(3, 21)) \
	OPTION_CBR(APPLICATION_NAME, 64, FTP_APPLICATION_NAME) \
	/*****/ \
	SCOPE_CBR(APPLICATION_ID, 4, FLOW_APPLICATION_ID(3, 53)) \
	OPTION_CBR(APPLICATION_NAME, 64, DNS_APPLICATION_NAME) \

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


#define CHECKDATA_BASE(mapplication_name, mengine_name) { \
	{.key = "application_id_name", .value = mapplication_name}, \
	{.key = "engine_id_name", .value = mengine_name}}

static const struct checkdata_value checkdata1[] = CHECKDATA_BASE(NULL, NULL);
static const struct checkdata_value checkdata2[] = CHECKDATA_BASE("ssl",
								"PANA-L7");

static const struct checkdata_value checkdata3[] = CHECKDATA_BASE("dns",
								"IANA-L4");

static const struct checkdata_value checkdata4[] = CHECKDATA_BASE("pssl",
								"PANA-L7");

static const struct checkdata_value checkdata5[] = CHECKDATA_BASE("IANA-L4:1990",
								"IANA-L4");

static const struct checkdata_value checkdata6[] = CHECKDATA_BASE("245:1990",
								"245");

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

#define CHECK(checkdata) {.size = RD_ARRAYSIZE(checkdata), .checks = checkdata}

	static const struct checkdata pre_checkdata[] = {
		CHECK(checkdata1),
		CHECK(checkdata2),
		CHECK(checkdata3),
		CHECK(checkdata5),
		CHECK(checkdata6),
	};

	static const struct checkdata post_checkdata[] = {
		CHECK(checkdata1),
		CHECK(checkdata4),
		CHECK(checkdata3),
		CHECK(checkdata5),
		CHECK(checkdata6),
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
#undef TEST

	*state = prepare_tests(test_params, RD_ARRAYSIZE(test_params));
	return *state == NULL;
}

int main() {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup(testFlow,
					prepare_test_nf9_appid_enrichment),
	};

	return cmocka_run_group_tests(tests, nf_test_setup, nf_test_teardown);
}
