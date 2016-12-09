/*
  Copyright (C) 2016 Eneo Tecnologia S.L.
  Author: Eugenio Perez <eupm90@gmail.com>
  Author: Diego Fernandez <bigomby@gmail.com>
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
/// template with too many fields
static const struct {
	V9FlowHeader flowHeader;
	V9TemplateHeader flowSetHeader;
	V9TemplateDef templateHeader;
	V9FlowSet templateSet[10];
} v9_template = {
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
		/*uint16_t*/ .fieldCount = 0xf000, /* 128 */
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

static const struct {
	V9FlowHeader flowHeader;
	V9TemplateHeader flowSetHeader;
	const uint8_t buffer[72];
} __attribute__((packed)) v9_flow = {
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

static const struct {
	IPFIXFlowHeader flowHeader;
	IPFIXSet flowSetHeader;
	V9TemplateDef templateHeader; /* It's the same */
	const uint8_t templateBuffer[92];
} v10_template = {
	.flowHeader = {
		/*uint16_t*/ .version = 0x0a00,           /* Current version=9*/
		/*uint16_t*/ .len = 0x7400,           /* The number of records in PDU. */
		/*uint32_t*/ .unix_secs = 0xdd5d6952,     /* Current time in msecs since router booted */
		/*uint32_t*/ .flow_sequence = 0x38040000, /* Sequence number of total flows seen */
		/*uint32_t*/ .observation_id = 0x00010000,      /* Source id */
	},

	.flowSetHeader = {
		/*uint16_t*/ .set_id = 0x0200,
		/*uint16_t*/ .set_len = 0x6400,
	},

	.templateHeader = {
		/*uint16_t*/ .templateId = 0x0d01, /*269*/
		/*uint16_t*/ .fieldCount = 0xf000, /* 128 */
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

struct {
	IPFIXFlowHeader flowHeader;
	IPFIXSet flowSetHeader;
	const uint8_t buffer1[77];
} __attribute__((packed)) v10_flow = {
	.flowHeader = {
		/*uint16_t*/ .version = 0x0a00,           /* Current version=9*/
		/*uint16_t*/ .len = 0x6100,           /* The number of records in PDU. */
		/*uint32_t*/ .unix_secs = 0xdd5d6952,     /* Current time in msecs since router booted */
		/*uint32_t*/ .flow_sequence = 0x38040000, /* Sequence number of total flows seen */
		/*uint32_t*/ .observation_id = 0x00010000,      /* Source id */
	},

	.flowSetHeader = {
		/*uint16_t*/ .set_id = 0x0d01,
		/*uint16_t*/ .set_len = 0x5100,
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
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0xb8, /* BYTES: 2744 */
		0x00, 0x00, 0x00, 0x1f, /* PKTS: 31*/
		0x0f, 0xed, 0x0a, 0xc0, /* FIRST_SWITCHED:  */
		0x0f, 0xee, 0x18, 0x00, /* LAST_SWITCHED: */
	},
};

static int prepare_test(void **state) {
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
		TEST(config_path, template, template_size, NULL, 0),           \
		TEST(NULL, flow, flow_size, mcheckdata, mcheckdata_sz)

	struct test_params test_params[] = {
		TEST_TEMPLATE_FLOW("./tests/0000-testFlowV5.json",
			&v9_template, sizeof(v9_template),
			&v9_flow, sizeof(v9_flow), NULL, 0),
		TEST_TEMPLATE_FLOW(NULL,
			&v10_template, sizeof(v10_template),
			&v10_flow, sizeof(v10_flow), NULL, 0),
	};

	*state = prepare_tests(test_params, RD_ARRAYSIZE(test_params));
	return *state == NULL;
}

int main() {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup(testFlow, prepare_test),
	};

	return cmocka_run_group_tests(tests, nf_test_setup, nf_test_teardown);
}

