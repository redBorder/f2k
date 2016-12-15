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

struct TestV10Template{
	IPFIXFlowHeader flowHeader;
	IPFIXSet flowSetHeader;
	V9TemplateDef templateHeader; /* It's the same */
	const uint8_t templateBuffer[100];
};

struct TestV10Flow{
	IPFIXFlowHeader flowHeader;
	IPFIXSet flowSetHeader;
	const uint8_t buffer1[0x0104 - sizeof(IPFIXFlowHeader) - sizeof(IPFIXSet)];
}__attribute__((packed));

static const struct TestV10Template v10Template = {
	.flowHeader = {
		/*uint16_t*/ .version = 0x0a00,           /* Current version=9*/
		/*uint16_t*/ .len = 0x7c00,           /* The number of records in PDU. */
		/*uint32_t*/ .unix_secs = 0xdd5d6952,     /* Current time in msecs since router booted */
		/*uint32_t*/ .flow_sequence = 0x38040000, /* Sequence number of total flows seen */
		/*uint32_t*/ .observation_id = 0x00010000,      /* Source id */
	},

	.flowSetHeader = {
		/*uint16_t*/ .set_id = 0x0200,
		/*uint16_t*/ .set_len = 0x6c00,
	},

	.templateHeader = {
		/*uint16_t*/ .templateId = 0x0d01, /*269*/
		/*uint16_t*/ .fieldCount = 0x1400,
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
		/*uint16_t*/ .len = 0x0401,               /* The number of records in PDU. */
		/*uint32_t*/ .unix_secs = 0xdd5d6952,     /* Current time in msecs since router booted */
		/*uint32_t*/ .flow_sequence = 0x38040000, /* Sequence number of total flows seen */
		/*uint32_t*/ .observation_id = 0x00010000,      /* Source id */
	},

	.flowSetHeader = {
		/*uint16_t*/ .set_id = 0x0d01,
		/*uint16_t*/ .set_len = 0xf400,
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
		0x03, 0x00, 0x00, 0x50, /* APPLICATION ID 13:453 */
		/* CISCO HTTP URL */
		0x34, 0x03, 0x00, 0x00, 0x50, 0x34, 0x01, 0x2f, /* ....P4./ */
		0x70, 0x72, 0x6f, 0x66, 0x69, 0x6c, 0x65, 0x73, /* profiles */
		0x2f, 0x70, 0x72, 0x6f, 0x66, 0x69, 0x6c, 0x65, /* /profile */
		0x5f, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, /* _1234567 */
		0x37, 0x5f, 0x37, 0x35, 0x73, 0x71, 0x5f, 0x31, /* 7_75sq_1 */
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, /* 12345678 */
		0x32, 0x2e, 0x6a, 0x70, 0x67,                   /* 2.jpg    */
		/* CISCO HTTP HOST */
		0x1d, 0x03, 0x00, 0x00, 0x50, 0x34, 0x02, 0x69,  /* ....P4.i */
		0x6d, 0x61, 0x67, 0x65, 0x73, 0x2e, 0x61, 0x6b,  /* mages.ak */
		0x2e, 0x69, 0x6e, 0x73, 0x74, 0x61, 0x67, 0x72,  /* .instagr */
		0x61, 0x6d, 0x2e, 0x63, 0x6f, 0x6d,              /* am.com    */
		/* CISCO HTTP USER-AGENT */
		0x4e, 0x03, 0x00, 0x00, 0x50, 0x34, 0x03, 0x49,   /* ....P4.I */
		0x6e, 0x73, 0x74, 0x61, 0x67, 0x72, 0x61, 0x6d,   /* nstagram */
		0x20, 0x34, 0x2e, 0x32, 0x2e, 0x33, 0x20, 0x28,   /*  4.2.3 ( */
		0x69, 0x50, 0x68, 0x6f, 0x6e, 0x65, 0x35, 0x2c,   /* iPhone5, */
		0x31, 0x3b, 0x20, 0x69, 0x50, 0x68, 0x6f, 0x6e,   /* 1; iPhon */
		0x65, 0x20, 0x4f, 0x53, 0x20, 0x37, 0x5f, 0x30,   /* e OS 7_0 */
		0x5f, 0x32, 0x3b, 0x20, 0x65, 0x6e, 0x5f, 0x55,   /* _2; en_U */
		0x53, 0x3b, 0x20, 0x65, 0x6e, 0x29, 0x20, 0x41,   /* S; en) A */
		0x70, 0x70, 0x6c, 0x65, 0x57, 0x65, 0x62, 0x4b,   /* ppleWebK */
		0x69, 0x74, 0x2f, 0x34, 0x32, 0x30, 0x2b,         /* it/420+  */
		/* CISCO REFERER */
		0x06, 0x03, 0x00, 0x00, 0x50, 0x34, 0x04,
		/* CISCO HTTPS COMMON NAME */
		0x15, 0x0d, 0x00, 0x01, 0xc5, 0x34, 0x01, 0x2a,
		0x2e, 0x79, 0x62, 0x70, 0x2e, 0x79, 0x61, 0x68,
		0x6f, 0x6f, 0x2e, 0x63, 0x6f, 0x6d,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0xb8, /* BYTES: 2744 */
		0x00, 0x00, 0x00, 0x1f, /* PKTS: 31*/
		0x0f, 0xed, 0x0a, 0xc0, /* FIRST_SWITCHED:  */
		0x0f, 0xed, 0x0a, 0xc0, /* LAST_SWITCHED: */
	},
};

static const struct checkdata_value checkdata_values1[] = {
	{.key = "type", .value="netflowv10"},
	{.key = "http_url", .value="/profiles/profile_12345677_75sq_1123456782.jpg"},
	{.key = "http_host", .value="images.ak.instagram.com"},
	{.key = "https_common_name", .value = "*.ybp.yahoo.com"}

};

static int prepare_test_nf10_cisco_https(void **state) {
	static const struct checkdata checkdata = {
		.checks=checkdata_values1,
		.size = RD_ARRAYSIZE(checkdata_values1),
	};

#define TEST(config_path, mrecord, mrecord_size, checks, checks_sz) {          \
		.config_json_path = config_path,                               \
		.netflow_src_ip = 0x04030201,                                  \
		.record = mrecord, .record_size = mrecord_size,                \
		.checkdata = checks, .checkdata_size = checks_sz               \
	}

#define TEST_TEMPLATE_FLOW(config_path, template, template_size,               \
			flow, flow_size, checks, checks_sz)                    \
	TEST(config_path, template, template_size, NULL, 0),                   \
	TEST(NULL, flow, flow_size, checks, checks_sz)

	struct test_params test_params[] = {
		TEST_TEMPLATE_FLOW("./tests/0000-testFlowV5.json",
			&v10Template, sizeof(v10Template),
			&v10Flow, sizeof(v10Flow),
			&checkdata, 1)
	};

	*state = prepare_tests(test_params, RD_ARRAYSIZE(test_params));
	return *state == NULL;
}

int main() {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup(testFlow, prepare_test_nf10_cisco_https),
	};

	return cmocka_run_group_tests(tests, nf_test_setup, nf_test_teardown);
}
