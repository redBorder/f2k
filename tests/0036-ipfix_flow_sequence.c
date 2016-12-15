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

/*
	@test Extracting client mac based on flow direction
*/

struct TestV10Template{
	IPFIXFlowHeader flowHeader;
	IPFIXSet flowSetHeader;
	V9TemplateDef templateHeader; /* It's the same */
	const uint8_t templateBuffer[148];
};

struct TestV10Flow{
	IPFIXFlowHeader flowHeader;
	IPFIXSet flowSetHeader;
	const uint8_t buffer1[1048];
}__attribute__((packed));

static const struct TestV10Template v10Template = {
	.flowHeader = {
		/*uint16_t*/ .version = 0x0a00,           /* Current version=9*/
		/*uint16_t*/ .len = 0xac00,               /* The number of records in PDU. */
		/*uint32_t*/ .unix_secs = 0xdd5d6952,     /* Current time in msecs since router booted */
		/*uint32_t*/ .flow_sequence = 0x38040000, /* Sequence number of total flows seen */
		/*uint32_t*/ .observation_id = 0x00010000,      /* Source id */
	},

	.flowSetHeader = {
		/*uint16_t*/ .set_id = 0x0200,
		/*uint16_t*/ .set_len = 0x9c00,
	},

	.templateHeader = {
		/*uint16_t*/ .templateId = 0x0301, /*259*/
		/*uint16_t*/ .fieldCount = 0x1c00,
	},

	.templateBuffer = {
		0x00, 0x08, 0x00, 0x04, /* SRC ADDR */
		0x00, 0x0c, 0x00, 0x04, /* DST ADDR */
		0x00, 0x3c, 0x00, 0x01, /* IP VERSION */
		0x00, 0x04, 0x00, 0x01, /* PROTO */
		0x00, 0x07, 0x00, 0x02, /* SRC PORT */
		0x00, 0x0b, 0x00, 0x02, /* DST PORT */
		0x00, 0x38, 0x00, 0x06, /* SRC MAC */
		0x00, 0x88, 0x00, 0x01, /* flowEndreason */
		0x00, 0xef, 0x00, 0x01, /* biflowDirection */
		0x01, 0x18, 0x00, 0x08, /* TRANSACTION_ID */
		0x00, 0x50, 0x00, 0x06, /* DST MAC */
		0x00, 0x51, 0x00, 0x06, /* POST DST MAC */
		0x00, 0x3d, 0x00, 0x01, /* DIRECTION */
		0x00, 0x30, 0x00, 0x01, /* FLOW_SAMPLER_ID */
		0x00, 0x5f, 0x00, 0x04, /* APPLICATION ID*/
		0xaf, 0xcb, 0xff, 0xff, 0x00, 0x00, 0x00, 0x09, /* CISCO_URL, variable length */
		0xaf, 0xcb, 0xff, 0xff, 0x00, 0x00, 0x00, 0x09, /* CISCO_URL, variable length */
		0xaf, 0xcb, 0xff, 0xff, 0x00, 0x00, 0x00, 0x09, /* CISCO_URL, variable length */
		0xaf, 0xcb, 0xff, 0xff, 0x00, 0x00, 0x00, 0x09, /* CISCO_URL, variable length */
		0xaf, 0xcb, 0xff, 0xff, 0x00, 0x00, 0x00, 0x09, /* CISCO_URL, variable length */
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

#define FLOW \
		0x01, 0x02, 0x03, 0x04, /* SRC ADDR   */ \
		0x0a, 0x0b, 0x0c, 0x0c, /* DST ADDR   */ \
		0x04,                                  /* IP VERSION */ \
		0x06,                   /* PROTO: 6 */ \
		0xd5, 0xb9,             /* SRC PORT: 54713 */ \
		0x01, 0xbb,             /* DST PORT: 443 */ \
		0x00, 0x11, 0x44, 0x55, 0xbb, 0xdd, /* SRC MAC */ \
		0x03,                   /* flowEndreason */ \
		0x01,                   /* biflowDirection */ \
		0x8f, 0x63, 0xf3, 0x40, 0x00, 0x01, 0x00, 0x00, /* TRANSACTION_ID */ \
		0x00, 0xdf, 0x5f, 0x4e, 0x5d, 0x1e, /* DST MAC */ \
		0x00, 0x4e, 0xa3, 0x3c, 0x3d, 0x5e, /* POST DST MAC */ \
		0x01,              /* DIRECTION */ \
		0x00,                   /* SAMPLER ID */ \
		0x03, 0x00, 0x00, 0x50, /* APPLICATION ID 13:453 */ \
 \
		0x06, 0x03, 0x00, 0x00, 0x19, 0x34, 0x01, /* CISCO DPI */ \
		0x06, 0x03, 0x00, 0x00, 0x19, 0x34, 0x02, \
		0x06, 0x03, 0x00, 0x00, 0x50, 0x34, 0x01, \
		0x06, 0x03, 0x00, 0x00, 0x50, 0x34, 0x02, \
		0x06, 0x03, 0x00, 0x00, 0x50, 0x34, 0x03, \
		0x06, 0x03, 0x00, 0x00, 0x50, 0x34, 0x04, \
		0x06, 0x03, 0x00, 0x00, 0x6e, 0x34, 0x01, \
		0x06, 0x03, 0x00, 0x00, 0xc4, 0x34, 0x01, \
		0x06, 0x03, 0x00, 0x00, 0xc4, 0x34, 0x02, \
 \
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0xb8, /* BYTES: 2744 */ \
		0x00, 0x00, 0x00, 0x1f, /* PKTS: 31*/ \
		0x0f, 0xed, 0x0a, 0xc0, /* FIRST_SWITCHED:  */ \
		0x0f, 0xee, 0x18, 0x00, /* LAST_SWITCHED: */


static const struct TestV10Flow v10Flow = {
	.flowHeader = {
		/*uint16_t*/ .version = 0x0a00,           /* Current version=9*/
		/*uint16_t*/ .len = 0x2c04,               /* The number of records in PDU. */
		/*uint32_t*/ .unix_secs = 0xdd5d6952,     /* Current time in msecs since router booted */
		/*uint32_t*/ .flow_sequence = 0x38040000, /* Sequence number of total flows seen */
		/*uint32_t*/ .observation_id = 0x00010000,      /* Source id */
	},

	.flowSetHeader = {
		/*uint16_t*/ .set_id = 0x0301,
		/*uint16_t*/ .set_len = 0x1c04,
	},

	.buffer1 = {
		FLOW
		FLOW
		FLOW
		FLOW
		FLOW
		FLOW
		FLOW
		FLOW
	},
};


#define DECL_CHECKDATA_VALUE_FLOW_SEQUENCE(i) \
	static const struct checkdata_value checkdata_values_flow_seq_##i[] = { \
		{.key = "flow_sequence", .value= #i }, \
	};
#define CHECKDATA_VALUE_FLOW_SEQUENCE(i) checkdata_values_flow_seq_##i

#define CHECKDATA_VALUE_ENTRY(i) \
	{.size = RD_ARRAYSIZE(CHECKDATA_VALUE_FLOW_SEQUENCE(i)), \
		.checks=CHECKDATA_VALUE_FLOW_SEQUENCE(i)}

DECL_CHECKDATA_VALUE_FLOW_SEQUENCE(1080);
DECL_CHECKDATA_VALUE_FLOW_SEQUENCE(1081);
DECL_CHECKDATA_VALUE_FLOW_SEQUENCE(1082);
DECL_CHECKDATA_VALUE_FLOW_SEQUENCE(1083);
DECL_CHECKDATA_VALUE_FLOW_SEQUENCE(1084);
DECL_CHECKDATA_VALUE_FLOW_SEQUENCE(1085);
DECL_CHECKDATA_VALUE_FLOW_SEQUENCE(1086);
DECL_CHECKDATA_VALUE_FLOW_SEQUENCE(1087);

static const struct checkdata checkdata_v10_flow_seq[] = {
	CHECKDATA_VALUE_ENTRY(1080),
	CHECKDATA_VALUE_ENTRY(1081),
	CHECKDATA_VALUE_ENTRY(1082),
	CHECKDATA_VALUE_ENTRY(1083),
	CHECKDATA_VALUE_ENTRY(1084),
	CHECKDATA_VALUE_ENTRY(1085),
	CHECKDATA_VALUE_ENTRY(1086),
	CHECKDATA_VALUE_ENTRY(1087),
};

static int prepare_test_nf10_flow_seq(void **state) {
#define TEST(config_path, mrecord, mrecord_size, checks, checks_sz) {          \
		.config_json_path = config_path,                               \
		.netflow_src_ip = 0x04030201,                                  \
		.record = mrecord, .record_size = mrecord_size,                \
		.checkdata = checks, .checkdata_size = checks_sz               \
	}

#define TEST_TEMPLATE_FLOW(config_path, template, template_size,               \
		flow, flow_size, checks, checks_sz)                            \
	TEST(config_path, template, template_size, NULL, 0),                   \
	TEST(NULL, flow, flow_size, checks, checks_sz)


	struct test_params test_params[] = {
		TEST_TEMPLATE_FLOW("./tests/0000-testFlowV5.json",
			&v10Template, sizeof(v10Template),
			&v10Flow, sizeof(v10Flow),
			checkdata_v10_flow_seq,
			RD_ARRAYSIZE(checkdata_v10_flow_seq))
	};

	*state = prepare_tests(test_params, RD_ARRAYSIZE(test_params));
	return *state == NULL;
}

int main() {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup(testFlow, prepare_test_nf10_flow_seq),
	};

	return cmocka_run_group_tests(tests, nf_test_setup, nf_test_teardown);
}
