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

/// @todo template+flow in the same message
struct TestV10Template{
	IPFIXFlowHeader flowHeader;
	IPFIXSet flowSetHeader;
	V9TemplateHeader templateHeader;
	const uint8_t templateBuffer[92];
};

struct TestV10Flow{
	IPFIXFlowHeader flowHeader;
	IPFIXSet flowSetHeader;
	const uint8_t buffer1[85];
}__attribute__((packed));

static const struct TestV10Template v10Template = {
	.flowHeader = {
		/*uint16_t*/ .version = 0x0a00,           /* Current version=9*/
		/*uint16_t*/ .len = 0x7400,           /* The number of records in PDU. */
		/*uint32_t*/ .sysUptime = 0xdd5d6952,     /* Current time in msecs since router booted */
		/*uint32_t*/ .flow_sequence = 0x38040000, /* Sequence number of total flows seen */
		/*uint32_t*/ .observationDomainId = 0x00010000,      /* Source id */
	},

	.flowSetHeader = {
		/*uint16_t*/ .set_id = 0x0200,
		/*uint16_t*/ .set_len = 0x6400,
	},

	.templateHeader = {
		/*uint16_t*/ .templateFlowset = 0x0d01, /*269*/
		/*uint16_t*/ .flowsetLen = 0x1300,
	},

	.templateBuffer = {
		0x00, 0x08, 0x00, 0x04, /* SRC ADDR */
		0x00, 0x0c, 0x00, 0x04, /* DST ADDR */
		0x00, 0x3c, 0x00, 0x01, /* IP VERSION */
		0x00, 0x04, 0x00, 0x01, /* PROTO */
		0x00, 0x07, 0x00, 0x02, /* SRC PORT */
		0x00, 0x0b, 0x00, 0x02, /* DST PORT */
		0x00, 0x88, 0x00, 0x01, /* flowEndreason */
		0x00, 0xef, 0x00, 0x01, /* biflowDirection */
		0x00, 0x30, 0x00, 0x01, /* FLOW_SAMPLER_ID */
		0x01, 0x18, 0x00, 0x08, /* TRANSACTION_ID */
		0x00, 0x5f, 0x00, 0x04, /* APPLICATION ID*/
		0xaf, 0xcb, 0xff, 0xff, 0x00, 0x00, 0x00, 0x09, /* CISCO_URL, variable length */
		0xaf, 0xcb, 0xff, 0xff, 0x00, 0x00, 0x00, 0x09, /* CISCO_URL, variable length */
		0xaf, 0xcb, 0xff, 0xff, 0x00, 0x00, 0x00, 0x09, /* CISCO_URL, variable length */
		0xaf, 0xcb, 0xff, 0xff, 0x00, 0x00, 0x00, 0x09, /* CISCO_URL, variable length */
		0x00, 0x01, 0x00, 0x08, /* BYTES: */
		0x00, 0x02, 0x00, 0x04, /* PKTS*/
		0x00, 0x16, 0x00, 0x04, /* FIRST_SWITCHED */
		0x00, 0x15, 0x00, 0x04, /* LAST_SWITCHED*/
	}
};


static const struct TestV10Flow v10Flow = {
	.flowHeader = {
		/*uint16_t*/ .version = 0x0a00,           /* Current version=9*/
		/*uint16_t*/ .len = 0x4500,           /* The number of records in PDU. */
		/*uint32_t*/ .sysUptime = 0xdd5d6952,     /* Current time in msecs since router booted */
		/*uint32_t*/ .flow_sequence = 0x38040000, /* Sequence number of total flows seen */
		/*uint32_t*/ .observationDomainId = 0x00010000,      /* Source id */
	},

	.flowSetHeader = {
		/*uint16_t*/ .set_id = 0x0d01,
		/*uint16_t*/ .set_len = 0x5300,
	},

	.buffer1 = {
		0x0a, 0x0d, 0x7a, 0x2c, /* SRC ADDR 10.13.122.44 */
		0x42, 0xdc, 0x98, 0x13, /* DST ADDR 66.220.152.19*/
		0x04,                   /* IP VERSION: 4 */
		0x06,                   /* PROTO: 6 */
		0xd5, 0xb9,             /* SRC PORT: 54713 */
		0x01, 0xbb,             /* DST PORT: 443 */
		0x03,                   /* flowEndreason */
		0x01,                   /* biflowDirection */
		0x00,                   /* FLOW_SAMPLER_ID */
		0x8f, 0x63, 0xf3, 0x40, 0x00, 0x01, 0x00, 0x00, /* TRANSACTION_ID */
		0x0d, 0x00, 0x01, 0xc5, /* APPLICATION ID 13:453 */
		0x06, 0x03, 0x00, 0x00, 0x50, 0x34, 0x01, /* CISCO_URL */
		0x06, 0x03, 0x00, 0x00, 0x50, 0x34, 0x02, /* CISCO_URL */
		0x06, 0x03, 0x00, 0x00, 0x50, 0x34, 0x03, /* CISCO_URL */
		0x06, 0x03, 0x00, 0x00, 0x50, 0x34, 0x04, /* CISCO_URL */
		0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0xb8, /* BYTES: 2744 */
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1f, /* PKTS: 31*/
		0x0f, 0xed, 0x0a, 0xc0, /* FIRST_SWITCHED:  */
		0x0f, 0xee, 0x18, 0x00, /* LAST_SWITCHED: MALFORMED */
	},
};

static int prepare_test_nf10_malformed(void **state) {
#define TEST(config_path, mhosts_db_path, mrecord, mrecord_size) {             \
		.config_json_path = config_path,                               \
		.host_list_path = mhosts_db_path,                              \
		.netflow_src_ip = 0x04030201, .netflow_dst_port = 2055,        \
		.record = mrecord, .record_size = mrecord_size,                \
		.checkdata = NULL, .checkdata_size = 0                         \
	}

	struct test_params test_params[] = {
		[0] = TEST("./tests/0000-testFlowV5.json", "./tests/0011-data/",
				(uint8_t *)&v10Template, sizeof(v10Template)),

		// Producing malformation with -10
		[1] = TEST(NULL, NULL, (uint8_t *)&v10Flow, sizeof(v10Flow)-10),
	};

	*state = prepare_tests(test_params, RD_ARRAYSIZE(test_params));
	return *state == NULL;
}

int main() {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(testFlow,
				prepare_test_nf10_malformed, check_flow),
	};

	return cmocka_run_group_tests(tests, nf_test_setup, nf_test_teardown);
}
