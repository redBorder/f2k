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
 */

#define ENTITIES(RT,R) \
	RT(IPV4_SRC_ADDR, 4, 0, 10, 13, 122, 44) \
	RT(IPV4_DST_ADDR, 4, 0, 66, 220, 152, 19) \
	RT(IP_PROTOCOL_VERSION, 1, 0, 4) \
	RT(PROTOCOL, 1, 0, 6) \
	RT(L4_SRC_PORT, 2, 0, UINT16_TO_UINT8_ARR(54713)) \
	RT(L4_DST_PORT, 2, 0, UINT16_TO_UINT8_ARR(443)) \
	RT(FLOW_END_REASON, 1, 0, 3) \
	RT(BIFLOW_DIRECTION, 1, 0, 1) \
	RT(FLOW_SAMPLER_ID, 1, 0, 0) \
	RT(TRANSACTION_ID, 8, 0, 0x8f, 0x63, 0xf3, 0x40, \
				 0x00, 0x01, 0x00, 0x00) \
	RT(APPLICATION_ID, 4, 0, FLOW_APPLICATION_ID(13, 459)) \
	RT(CISCO_URL, 0xffff, 9, T_CISCO_URL) \
	RT(CISCO_URL, 0xffff, 9, T_CISCO_HOST) \
	RT(CISCO_URL, 0xffff, 9, T_CISCO_UA) \
	RT(CISCO_URL, 0xffff, 9, T_CISCO_REFERER) \
	RT(IN_BYTES, 8, 0, UINT64_TO_UINT8_ARR(2744)) \
	RT(IN_PKTS, 4, 0, UINT32_TO_UINT8_ARR(31)) \
	RT(FIRST_SWITCHED, 4, 0, 0x0f, 0xed, 0x0a, 0xc0) \
	RT(LAST_SWITCHED, 4, 0, 0x0f, 0xee, 0x18, 0x00) \
	/* Regression test 1 */ \
	R(IPV4_SRC_ADDR, 4, 0, 10, 13, 122, 44) \
	R(IPV4_DST_ADDR, 4, 0, 66, 220, 152, 19) \
	R(IP_PROTOCOL_VERSION, 1, 0, 4) \
	R(PROTOCOL, 1, 0, 6) \
	R(L4_SRC_PORT, 2, 0, UINT16_TO_UINT8_ARR(54713)) \
	R(L4_DST_PORT, 2, 0, UINT16_TO_UINT8_ARR(443)) \
	R(FLOW_END_REASON, 1, 0, 3) \
	R(BIFLOW_DIRECTION, 1, 0, 1) \
	R(FLOW_SAMPLER_ID, 1, 0, 0) \
	R(TRANSACTION_ID, 8, 0, 0x8f, 0x63, 0xf3, 0x40, \
				0x00, 0x01, 0x00, 0x00) \
	R(APPLICATION_ID, 4, 0, FLOW_APPLICATION_ID(13, 459)) \
	R(CISCO_URL, 0xffff, 9, T_CISCO_URL) \
	R(CISCO_URL, 0xffff, 9, T_CISCO_UA) \
	R(CISCO_URL, 0xffff, 9, T_CISCO_REFERER) \
	R(CISCO_URL, 0xffff, 9, T_CISCO_HOST) \
	R(IN_BYTES, 8, 0, '.', '.', '.', '.', '.', '.', '.', '.') \
	R(IN_PKTS, 4, 0, '.', '.', '.', '.') \
	R(FIRST_SWITCHED, 4, 0, 0x0f, 0xed, 0x0a, 0xc0) \
	R(LAST_SWITCHED, 4, 0, 0x0f, 0xee, 0x18, 0x00)

static const struct checkdata_value checkdata_values1[] = {
	{.key = "type", .value="netflowv10"},
	{.key = "http_url", .value="/profiles/profile_12345677_75sq_1123456782.jpg"},
	{.key = "http_host", .value="images.ak.instagram.com"},
	{.key = "http_host_l1", .value="com"},
	{.key = "http_host_l2", .value="instagram.com"},
};

static int prepare_test_nf10_cisco_url(void **state) {
	static const IPFIX_TEMPLATE(v10Template, TEST_IPFIX_FLOW_HEADER,
		IPFIX_TEMPLATE_ID, ENTITIES);
	static const IPFIX_FLOW(v10Flow, TEST_IPFIX_FLOW_HEADER,
		IPFIX_TEMPLATE_ID, ENTITIES);

#define CHECK(checkdata) {.checks = checkdata, .size = RD_ARRAYSIZE(checkdata)}
	static const struct checkdata sl1_checkdata[] = {
		CHECK(checkdata_values1), CHECK(checkdata_values1)
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
