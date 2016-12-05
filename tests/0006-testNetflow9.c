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

#include <librd/rd.h>

#include <setjmp.h>
#include <cmocka.h>

static int test_nf9(void **state) {
#define FLOW_HEADER \
	.sys_uptime = constexpr_be32toh(12345), \
	.unix_secs = constexpr_be32toh(1382364130), \
	.flow_sequence = constexpr_be32toh(1080), \
	.source_id = constexpr_be32toh(1)
#define TEMPLATE_ID 259
#define T_WLAN_SSID \
	'l', 'o', 'c', 'a', 'l', '-', 'w', 'i', \
	'f', 'i', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
	0x00

#define NF9_ENTITIES(RT, R) \
	RT(STA_MAC_ADDRESS, 6, 0, 0xb8, 0x17, 0xc2, 0x28, 0xb0, 0xc7) \
	RT(STA_IPV4_ADDRESS, 4, 0, 10, 13, 94, 223) \
	RT(APPLICATION_ID, 4, 0, FLOW_APPLICATION_ID(13, 453)) \
	RT(WLAN_SSID, 33, 0, T_WLAN_SSID) \
	RT(DIRECTION, 1, 0, 0) \
	RT(IN_BYTES, 8, 0, UINT64_TO_UINT8_ARR(7603)) \
	RT(IN_PKTS, 8, 0, UINT64_TO_UINT8_ARR(263)) \
	RT(PADDING_OCTETS /*It was 98*/, 1, 0, 0) \
	RT(PADDING_OCTETS /*It was 195*/, 1, 0, 0) \
	RT(WAP_MAC_ADDRESS, 6, 0, 0x58, 0xbf, 0xea, 0x01, 0x5b, 0x40)

	static const NF9_TEMPLATE(v9Template, FLOW_HEADER, TEMPLATE_ID,
		NF9_ENTITIES);

	static const NF9_FLOW(v9Flow, FLOW_HEADER, TEMPLATE_ID, NF9_ENTITIES);

	static const struct checkdata_value checkdata_values[] = {
		{.key = "type", .value="netflowv9",},
		{.key = "client_mac", .value="b8:17:c2:28:b0:c7",},
		{.key = "src", .value="10.13.94.223",},
		{.key = "application_id", .value="13:453",},
		{.key = "wireless_id", .value="local-wifi",},
		{.key = "direction", .value="ingress",},
		{.key = "sensor_ip", .value="4.3.2.1",},
		{.key = "bytes", .value="7603",},
		{.key = "packets", .value="263"},
	};

	static const struct checkdata checkdata = {
		.size = 1, .checks = checkdata_values
	};

#define TEST(config_path, mrecord, mrecord_size, mcheckdata, mcheckdata_sz) {  \
		.config_json_path = config_path,                               \
		.host_list_path = NULL,                                        \
		.netflow_src_ip = 0x04030201,                                  \
		.record = mrecord,                                             \
		.record_size = mrecord_size,                                   \
		.checkdata = mcheckdata,                                       \
		.checkdata_size = mcheckdata_sz                                \
	}

#define TEST_TEMPLATE_FLOW(config_path, template, template_size,               \
				flow, flow_size, mcheckdata, mcheckdata_sz)    \
	TEST(config_path, template, template_size, NULL, 0),                   \
	TEST(NULL, flow, flow_size, mcheckdata, mcheckdata_sz)

	struct test_params test_params[] = {
		TEST_TEMPLATE_FLOW(
			"./tests/0000-testFlowV5.json",
			&v9Template, sizeof(v9Template),
			&v9Flow, sizeof(v9Flow),
			&checkdata, 1),
	};

	*state = prepare_tests(test_params, RD_ARRAYSIZE(test_params));
	return *state == NULL;
}

int main() {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup(testFlow, test_nf9),
	};

	return cmocka_run_group_tests(tests, nf_test_setup, nf_test_teardown);
}

