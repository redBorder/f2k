/*
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

/*
	Regression test: IPFIX private enterprise fields of an unknown vendor
	(Fortinet, PEN 12356) whose element id collides with an IANA one
	(1 = IN_BYTES, 2 = IN_PKTS) must not be decoded as the IANA field.
	FortiGate was producing flows with ASCII text as bytes/pkts.
 */


#define TEST_IPFIX_HEADER \
	.unix_secs = constexpr_be32toh(1382637021), \
	.flow_sequence = constexpr_be32toh(1080), \
	.observation_id = constexpr_be32toh(256),

#define TEST_TEMPLATE_ID 269

#define TEST_ENTITIES(RT, R) \
	RT(IPV4_SRC_ADDR, 4, 0, 10, 13, 122, 44) \
	RT(IPV4_DST_ADDR, 4, 0, 66, 220, 152, 19) \
	RT(IN_BYTES, 8, 12356, 0, 'G', 'e', 'n', 'e', 'r', 'a', 'l') \
	RT(IN_PKTS, 4, 12356, 't', 'e', 's', 't') \
	RT(L4_SRC_PORT, 2, 0, UINT16_TO_UINT8_ARR(54713)) \
	RT(L4_DST_PORT, 2, 0, UINT16_TO_UINT8_ARR(443))

static const struct checkdata_value checkdata_values1[] = {
	{.key = "type", .value="netflowv10"},
	{.key = "src", .value="10.13.122.44"},
	{.key = "dst", .value="66.220.152.19"},
	{.key = "src_port", .value="54713"},
	{.key = "dst_port", .value="443"},
	{.key = "bytes", .value="0"},
	{.key = "pkts", .value="0"},
};

static const struct checkdata sl1_checkdata = {
	.checks = checkdata_values1,
	.size = RD_ARRAYSIZE(checkdata_values1)
};

static int prepare_test_ipfix_pen(void **state) {
	static const IPFIX_TEMPLATE_FLOW(pkt, TEST_IPFIX_HEADER,
		TEST_TEMPLATE_ID, TEST_ENTITIES);

#define TEST(mrecord, mrecord_size, checks, checks_size, ...) { \
		.netflow_src_ip = 0x04030201,                                  \
		.record = mrecord, .record_size = mrecord_size,                \
		.checkdata = checks, .checkdata_size = checks_size,            \
		__VA_ARGS__ \
	}

	struct test_params test_params[] = {
		TEST(&pkt, sizeof(pkt), &sl1_checkdata, 1,
			.config_json_path = "./tests/0000-testFlowV5.json"),
	};

	*state = prepare_tests(test_params, RD_ARRAYSIZE(test_params));
	return *state == NULL;
}

int main() {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup(testFlow, prepare_test_ipfix_pen),
	};

	return cmocka_run_group_tests(tests, nf_test_setup, nf_test_teardown);
}
