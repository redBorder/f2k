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

#define TEST_IPFIX_FLOW_HEADER  \
	.unix_secs = 0xdd5d6952, \
	.flow_sequence = 0x38040000, \
	.observationDomainId = 0x00010000,

#define IPFIX_TEMPLATE_ID 0x0200

/// @todo handle case of >255
#define ARGS(...) __VA_ARGS__
#define CISCO_HTTP_LEN(HOST) 6+sizeof((uint8_t[]) {HOST})
#define CISCO_HTTP_FIELD(ID, ...) CISCO_HTTP_LEN(ARGS(__VA_ARGS__)), ID, \
	__VA_ARGS__
#define CISCO_HTTP_EMPTY_FIELD(ID) 0x06, ID

#define CISCO_HTTP_ID 0x03, 0x00, 0x00, 0x50, 0x34
#define CISCO_HTTP_URL_ID CISCO_HTTP_ID, 0x01
#define CISCO_HTTP_HOST_ID CISCO_HTTP_ID, 0x02
#define CISCO_HTTP_UA_ID CISCO_HTTP_ID, 0x03
#define CISCO_HTTP_REFERER_ID CISCO_HTTP_ID, 0x04

#define CISCO_HTTP_URL(...) CISCO_HTTP_FIELD(CISCO_HTTP_URL_ID, __VA_ARGS__)
#define CISCO_HTTP_HOST(...) CISCO_HTTP_FIELD(CISCO_HTTP_HOST_ID, __VA_ARGS__)
#define CISCO_HTTP_UA(...) CISCO_HTTP_FIELD(CISCO_HTTP_UA_ID, __VA_ARGS__)
#define CISCO_HTTP_REFERER(...) \
	CISCO_HTTP_FIELD(CISCO_HTTP_REFERER_ID, __VA_ARGS__)

#define T_CISCO_URL CISCO_HTTP_URL('/', \
		'p',  'r',  'o',  'f',  'i',  'l',  'e',  's', \
		'/',  'p',  'r',  'o',  'f',  'i',  'l',  'e', \
		'_',  '1',  '2',  '3',  '4',  '5',  '6',  '7', \
		'7',  '_',  '7',  '5',  's',  'q',  '_',  '1', \
		'1',  '2',  '3',  '4',  '5',  '6',  '7',  '8', \
		'2',  '.',  'j',  'p',  'g')

#define T_CISCO_HOST CISCO_HTTP_HOST('i', \
		'm', 'a', 'g', 'e', 's', '.', 'a', 'k', \
		'.', 'i', 'n', 's', 't', 'a', 'g', 'r', \
		'a', 'm', '.', 'c', 'o', 'm')

#define CISCO_DOT_L2_HOST CISCO_HTTP_HOST('.', \
		'i', 'n', 's', 't', 'a', 'g', 'r', 'a', \
		'm', '.', 'c', 'o', 'm')

#define CISCO_DOT_L1_HOST CISCO_HTTP_HOST('.', 'c', 'o', 'm')
#define CISCO_L1_HOST CISCO_HTTP_HOST('c', 'o', 'm')

#define CISCO_L2_HOST CISCO_HTTP_HOST('i', \
		'n', 's', 't', 'a', 'g', 'r', 'a', 'm', \
		'.', 'c', 'o', 'm')

#define T_CISCO_UA CISCO_HTTP_UA('I', \
		'n',  's',  't',  'a',  'g',  'r',  'a',  'm', \
		' ',  '4',  '.',  '2',  '.',  '3',  ' ',  '(', \
		'i',  'P',  'h',  'o',  'n',  'e',  '5',  ',', \
		'1',  ';',  ' ',  'i',  'P',  'h',  'o',  'n', \
		'e',  ' ',  'O',  'S',  ' ',  '7',  '_',  '0', \
		'_',  '2',  ';',  ' ',  'e',  'n',  '_',  'U', \
		'S',  ';',  ' ',  'e',  'n',  ')',  ' ',  'A', \
		'p',  'p',  'l',  'e',  'W',  'e',  'b',  'K', \
		'i',  't',  '/',  '4',  '2',  '0',  '+')

#define T_CISCO_REFERER CISCO_HTTP_EMPTY_FIELD(CISCO_HTTP_REFERER_ID)

/*
	Regression test 1:
	Bad h1/h2 domain detection: it detects point in next field as own field
	(buffer overflow)

	Regression test 2:
	Bad l2 identification if only one dot: l2_d.l1_d
 */

#define BASE_ENTITIES_PRE(X) \
	X(IPV4_SRC_ADDR, 4, 0, 10, 13, 122, 44) \
	X(IPV4_DST_ADDR, 4, 0, 66, 220, 152, 19) \
	X(IP_PROTOCOL_VERSION, 1, 0, 4) \
	X(PROTOCOL, 1, 0, 6) \
	X(L4_SRC_PORT, 2, 0, UINT16_TO_UINT8_ARR(54713)) \
	X(L4_DST_PORT, 2, 0, UINT16_TO_UINT8_ARR(443)) \
	X(FLOW_END_REASON, 1, 0, 3) \
	X(BIFLOW_DIRECTION, 1, 0, 1) \
	X(FLOW_SAMPLER_ID, 1, 0, 0) \
	X(TRANSACTION_ID, 8, 0, 0x8f, 0x63, 0xf3, 0x40, \
				 0x00, 0x01, 0x00, 0x00) \
	X(APPLICATION_ID, 4, 0, FLOW_APPLICATION_ID(13, 459))

#define BASE_ENTITIES_POST(X, PKTS, BYTES) \
	X(IN_BYTES, 8, 0, BYTES) \
	X(IN_PKTS, 4, 0, PKTS) \
	X(FIRST_SWITCHED, 4, 0, 0x0f, 0xed, 0x0a, 0xc0) \
	X(LAST_SWITCHED, 4, 0, 0x0f, 0xee, 0x18, 0x00)

#define BASE_PKTS  UINT32_TO_UINT8_ARR(31)
#define BASE_BYTES UINT64_TO_UINT8_ARR(2744)
#define PKTS_AS_DOTS  '.', '.', '.', '.'
#define BYTES_AS_DOTS '.', '.', '.', '.', '.', '.', '.', '.'

#define ENTITIES(RT,R) \
	BASE_ENTITIES_PRE(RT) \
	RT(CISCO_URL, 0xffff, 9, T_CISCO_URL) \
	RT(CISCO_URL, 0xffff, 9, T_CISCO_HOST) \
	RT(CISCO_URL, 0xffff, 9, T_CISCO_UA) \
	RT(CISCO_URL, 0xffff, 9, T_CISCO_REFERER) \
	BASE_ENTITIES_POST(RT, BASE_PKTS, BASE_BYTES) \
	/* Regression test 1 */ \
	BASE_ENTITIES_PRE(R) \
	R(CISCO_URL, 0xffff, 9, T_CISCO_URL) \
	R(CISCO_URL, 0xffff, 9, T_CISCO_UA) \
	R(CISCO_URL, 0xffff, 9, T_CISCO_REFERER) \
	R(CISCO_URL, 0xffff, 9, T_CISCO_HOST) \
	BASE_ENTITIES_POST(R, PKTS_AS_DOTS, BYTES_AS_DOTS) \
	/* Regression test 2 */ \
	BASE_ENTITIES_PRE(R) \
	R(CISCO_URL, 0xffff, 9, T_CISCO_URL) \
	R(CISCO_URL, 0xffff, 9, CISCO_L1_HOST) \
	R(CISCO_URL, 0xffff, 9, T_CISCO_UA) \
	R(CISCO_URL, 0xffff, 9, T_CISCO_REFERER) \
	BASE_ENTITIES_POST(R, BASE_PKTS, BASE_BYTES) \
	/* */ \
	BASE_ENTITIES_PRE(R) \
	R(CISCO_URL, 0xffff, 9, T_CISCO_URL) \
	R(CISCO_URL, 0xffff, 9, CISCO_DOT_L1_HOST) \
	R(CISCO_URL, 0xffff, 9, T_CISCO_UA) \
	R(CISCO_URL, 0xffff, 9, T_CISCO_REFERER) \
	BASE_ENTITIES_POST(R, BASE_PKTS, BASE_BYTES) \
	/* */ \
	BASE_ENTITIES_PRE(R) \
	R(CISCO_URL, 0xffff, 9, T_CISCO_URL) \
	R(CISCO_URL, 0xffff, 9, CISCO_L2_HOST) \
	R(CISCO_URL, 0xffff, 9, T_CISCO_UA) \
	R(CISCO_URL, 0xffff, 9, T_CISCO_REFERER) \
	BASE_ENTITIES_POST(R, BASE_PKTS, BASE_BYTES) \
	/* */ \
	BASE_ENTITIES_PRE(R) \
	R(CISCO_URL, 0xffff, 9, T_CISCO_URL) \
	R(CISCO_URL, 0xffff, 9, CISCO_DOT_L2_HOST) \
	R(CISCO_URL, 0xffff, 9, T_CISCO_UA) \
	R(CISCO_URL, 0xffff, 9, T_CISCO_REFERER) \
	BASE_ENTITIES_POST(R, BASE_PKTS, BASE_BYTES)

#define CHECKDATA_BASE \
	{.key = "type", .value="netflowv10"}, \
	{.key = "http_url", \
		.value="/profiles/profile_12345677_75sq_1123456782.jpg"}

#define CHECKDATA_L2_BASE \
	CHECKDATA_BASE, \
	{.key = "http_host_l1", .value="com"}, \
	{.key = "http_host_l2", .value="instagram.com"}

#define CHECKDATA_L1_BASE \
	CHECKDATA_BASE, \
	{.key = "http_host_l1", .value="com"}, \
	{.key = "http_host_l2", .value="com"}

static const struct checkdata_value checkdata_values_fullhost[] = {
	CHECKDATA_L2_BASE,
	{.key = "http_host", .value="images.ak.instagram.com"},
};

static const struct checkdata_value checkdata_values_l1host[] = {
	CHECKDATA_L1_BASE,
	{.key = "http_host", .value="com"},
};

static const struct checkdata_value checkdata_values_dotl1host[] = {
	CHECKDATA_L1_BASE,
	{.key = "http_host", .value=".com"},
};

static const struct checkdata_value checkdata_values_l2host[] = {
	CHECKDATA_L2_BASE,
	{.key = "http_host", .value="instagram.com"},
};

static const struct checkdata_value checkdata_values_dotl2host[] = {
	CHECKDATA_L2_BASE,
	{.key = "http_host", .value=".instagram.com"},
};

static int prepare_test_nf10_cisco_url(void **state) {
	static const IPFIX_TEMPLATE(v10Template, TEST_IPFIX_FLOW_HEADER,
		IPFIX_TEMPLATE_ID, ENTITIES);
	static const IPFIX_FLOW(v10Flow, TEST_IPFIX_FLOW_HEADER,
		IPFIX_TEMPLATE_ID, ENTITIES);

#define CHECK(checkdata) {.checks = checkdata, .size = RD_ARRAYSIZE(checkdata)}
	static const struct checkdata sl1_checkdata[] = {
		CHECK(checkdata_values_fullhost),
		CHECK(checkdata_values_fullhost),
		CHECK(checkdata_values_l1host),
		CHECK(checkdata_values_dotl1host),
		CHECK(checkdata_values_l2host),
		CHECK(checkdata_values_dotl2host),
	};
#undef CHECK

#define TEST(config_path, mhosts_db_path, mrecord, mrecord_size, checks,       \
								checks_size) { \
		.config_json_path = config_path,                               \
		.host_list_path = mhosts_db_path,                              \
		.netflow_src_ip = 0x04030201, .netflow_dst_port = 2055,        \
		.record = mrecord, .record_size = mrecord_size,                \
		.checkdata = checks, .checkdata_size = checks_size             \
	}

	struct test_params test_params[] = {
		[0] = TEST("./tests/0000-testFlowV5.json", "./tests/0011-data/",
				&v10Template, sizeof(v10Template),
				NULL, 0),

		[1] = TEST(NULL, NULL, &v10Flow, sizeof(v10Flow),
			sl1_checkdata, RD_ARRAYSIZE(sl1_checkdata)),
	};

	*state = prepare_tests(test_params, RD_ARRAYSIZE(test_params));
	return *state == NULL;
}

int main() {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup(testFlow,
				prepare_test_nf10_cisco_url),
	};

	return cmocka_run_group_tests(tests, nf_test_setup, nf_test_teardown);
}
