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

/* WFII-startwithtemplate pcap */

/// @todo Extract in its own header, (the current problem is end buffer size?)
struct TestV9Template{
	V9FlowHeader flowHeader;
	V9TemplateHeader flowSetHeader;
	V9TemplateDef templateHeader;
	V9FlowSet templateSet[10];
};

struct TestV9Flow{
	V9FlowHeader flowHeader;
	V9TemplateHeader flowSetHeader;
	const uint8_t buffer[72];
};

static const struct TestV9Template v9Template = {
	.flowHeader = {
		/*uint16_t*/ .version = 0x0900,           /* Current version=9*/
		/*uint16_t*/ .count = 0x0100,           /* The number of records in PDU. */
		/*uint32_t*/ .sys_uptime = 0x00003039,     /* Current time in msecs since router booted */
		/*uint32_t*/ .unix_secs = 0xe2336552,     /* Current seconds since 0000 UTC 1970 */
		/*uint32_t*/ .flow_sequence = 0x38040000, /* Sequence number of total flows seen */
		/*uint32_t*/ .source_id = 0x01000000,      /* Source id */
	},

	.flowSetHeader = {
		/*uint16_t*/ .templateFlowset = 0x0000,
		/*uint16_t*/ .flowsetLen = 0x3000,
	},

	.templateHeader = {
		/*uint16_t*/ .templateId = 0x0301, /*259*/
		/*uint16_t*/ .fieldCount = 0x0a00,
	},

	.templateSet = { /* all uint16_t*/
		[0] = {.templateId = 0x6d01 /* 365: STA_MAC_ADDRESS  */, .flowsetLen = 0x0600},
		[1] = {.templateId = 0x6e01 /* 366: STA_IPV4_ADDRESS */, .flowsetLen = 0x0400},
		[2] = {.templateId = 0x5f00 /*  95: APPLICATION_ID */,   .flowsetLen = 0x0400},
		[3] = {.templateId = 0x9300 /* 147: WLAN_SSID */, .flowsetLen = 0x2100},
		[4] = {.templateId = 0x3d00 /*  61: DIRECTION */, .flowsetLen = 0x0100},
		[5] = {.templateId = 0x0100 /*   1: BYTES */, .flowsetLen = 0x0800},
		[6] = {.templateId = 0x0200 /*   2: PKTS */, .flowsetLen = 0x0800},
		[7] = {.templateId = 0x6200 /*  98: Not processed */, .flowsetLen = 0x0100},
		[8] = {.templateId = 0xc300 /* 195: Not processed */, .flowsetLen = 0x0100},
		[9] = {.templateId = 0x616f /* 367: WAP_MAC_ADDRESS */, .flowsetLen = 0x0600},
	}
};

static const struct TestV9Flow v9Flow = {
	.flowHeader = {
		/*uint16_t*/ .version = 0x0900,           /* Current version=9*/
		/*uint16_t*/ .count = 0x0100,           /* The number of records in PDU. */
		/*uint32_t*/ .sys_uptime = 0x00003039,     /* Current time in msecs since router booted */
		/*uint32_t*/ .unix_secs = 0x98346552,     /* Current seconds since 0000 UTC 1970 */
		/*uint32_t*/ .flow_sequence = 0x76040000, /* Sequence number of total flows seen */
		/*uint32_t*/ .source_id = 0x01000000,      /* Source id */
	},

	.flowSetHeader = {
		/*uint16_t*/ .templateFlowset = 0x0301,
		/*uint16_t*/ .flowsetLen = 0x4800,
	},

	.buffer = {
		0xb8, 0x17, 0xc2, 0x28, 0xb0, 0xc7, /* STA_MAC_ADDRESS: b8:14:c2:28:b0:c7 */
		0x0a, 0x0d, 0x5e, 0xdf,             /* STA_IPV4_ADDRESS: 10.13.94.223 */
		0x0d, 0x00, 0x01, 0xc5,             /* App Id: 13:453 */
		0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x2d, /* WLAN_SSID: "local-wifi" */
		0x77, 0x69, 0x66, 0x69, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00,
		0x00,                               /* Direction: Ingress */
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1d, 0xb3, /* Octetos */
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x07, /* Paquetes */
		0x00, 0x00,                         /* Not used */
		0x58, 0xbf, 0xea, 0x01, 0x5b, 0x40, /* WAP_MAC_ADDRESS */
	}
};

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

static int prepare_test_nf9(void **state) {
	static const struct checkdata checkdata = {
		.size = 1, .checks = checkdata_values
	};

#define TEST(mrecord, mrecord_size, mcheckdata, mcheckdata_sz, ...) {  \
		.host_list_path = NULL,                                        \
		.netflow_src_ip = 0x04030201,                                  \
		.record = mrecord,                                             \
		.record_size = mrecord_size,                                   \
		.checkdata = mcheckdata,                                       \
		.checkdata_size = mcheckdata_sz,                               \
		__VA_ARGS__															 											 \
	}

#define TEST_TEMPLATE_FLOW(template, template_size, flow, flow_size, mcheckdata, mcheckdata_sz, ...)    \
	[0] = TEST(template, template_size, NULL, 0, __VA_ARGS__),             \
	[1] = TEST(flow, flow_size, mcheckdata, mcheckdata_sz,)

	struct test_params test_params[] = {
		TEST_TEMPLATE_FLOW(
			&v9Template, sizeof(v9Template),
			&v9Flow, sizeof(v9Flow),
			&checkdata, 1,
			.config_json_path = "./tests/0047-testNetflow9_dns.json",
			.kafka_test_consumer_url = "kafka:9092",
			.kafka_producer_url = "kafka:9092",
			.dns_servers = "localhost",
			.normalize_directions = true),
	};

	*state = prepare_tests(test_params, RD_ARRAYSIZE(test_params));
	return *state == NULL;
}

int main() {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup(testFlow, prepare_test_nf9),
	};

	return cmocka_run_group_tests(tests, nf_test_setup, nf_test_teardown);
}
