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

struct TestV9Template{
	V9FlowHeader flowHeader;
	V9TemplateHeader flowSetHeader;
	V9TemplateDef templateHeader;
	V9FlowSet templateSet[19];
};

struct TestV9Flow{
	V9FlowHeader flowHeader;
	V9TemplateHeader flowSetHeader;
	const uint8_t buffer1[85];
}__attribute__((packed));

struct TestV10Template{
	IPFIXFlowHeader flowHeader;
	IPFIXSet flowSetHeader;
	V9TemplateDef templateHeader; /* It's the same */
	const uint8_t templateBuffer[128];
};

struct TestV10Flow{
	IPFIXFlowHeader flowHeader;
	IPFIXSet flowSetHeader;
	const uint8_t buffer1[112];
}__attribute__((packed));

static const struct TestV9Template v9Template = {
	.flowHeader = {
		/*uint16_t*/ .version = 0x0900,           /* Current version=9*/
		/*uint16_t*/ .count = 0x0100,             /* The number of records in PDU. */
		/*uint32_t*/ .sys_uptime = 0x00003039,    /* Current time in msecs since router booted */
		/*uint32_t*/ .unix_secs = 0xe2336552,     /* Current seconds since 0000 UTC 1970 */
		/*uint32_t*/ .flow_sequence = 0x38040000, /* Sequence number of total flows seen */
		/*uint32_t*/ .source_id = 0x01000000,      /* Source id */
	},

	.flowSetHeader = {
		/*uint16_t*/ .templateFlowset = 0x0000,
		/*uint16_t*/ .flowsetLen = 0x5000,
	},

	.templateHeader = {
		/*uint16_t*/ .templateId = 0x0201, /*258*/
		/*uint16_t*/ .fieldCount = constexpr_be16toh(18),
	},

	.templateSet = { /* all uint16_t*/
		[0] = {.templateId = 0x0100 /*   1: BYTES */, .flowsetLen = 0x0400},
		[1] = {.templateId = 0x0200 /*   2: PKTS */, .flowsetLen = 0x0400},
		[2] = {.templateId = 0x0400 /*   4: PROTO */, .flowsetLen = 0x0100},
		[3] = {.templateId = 0x0500 /*   5: IP_TOS */, .flowsetLen = 0x0100},
		[4] = {.templateId = 0x0600 /*   6: TCP_FLAGS */, .flowsetLen = 0x0100},
		[5] = {.templateId = 0x0700 /*   6: L4_SRC_PORT */, .flowsetLen = 0x0200},
		[6] = {.templateId = 0x0a00 /*  10: INPUT_SNMP */, .flowsetLen = 0x0200},
		[7] = {.templateId = 0x0b00 /*  11: L4_DST_PORT */, .flowsetLen = 0x0200},
		[8] = {.templateId = 0x0e00 /*  10: OUTPUT_SNMP */, .flowsetLen = 0x0200},
		[9] = {.templateId = 0xea00 /*  EGRESSVRFID */, .flowsetLen = 0x0400},
		[10] = {.templateId = 0xeb00 /* INGRESS VRFID */, .flowsetLen = 0x0400},
		[12] = {.templateId = 0x1500 /* 22: LAST_SWITCHED */, .flowsetLen = 0x0400},
		[11] = {.templateId = 0x1600 /* 21: FIRST_SWITCHED */, .flowsetLen = 0x0400},
		[13] = {.templateId = 0x1b00 /* 27: IPV6_SRC_ADDR */, .flowsetLen = 0x1000},
		[14] = {.templateId = 0x1c00 /* 28: IPV6_DST_ADDR */, .flowsetLen = 0x1000},
		[15] = {.templateId = 0x1d00 /* 29: IPV6_SRC_MASK */, .flowsetLen = 0x0100},
		[16] = {.templateId = 0x1e00 /* 30: IPV6_DST_MASK */, .flowsetLen = 0x0100},
		[17] = {.templateId = 0x3e00 /* 62: IPV6_NEXT_HOP */, .flowsetLen = 0x1000},
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
		/*uint16_t*/ .templateFlowset = 0x0201,
		/*uint16_t*/ .flowsetLen = 0x5700,
	},

	.buffer1 = {
		0x00, 0x01, 0xba, 0x0a, /* 113162 Octets */
		0x00, 0x00, 0x03, 0x3a, /* 826 Packets */
		0x11,                   /* Protocol 17 */
		0x00,                   /* IP ToS 0x00 */
		0x00,                   /* TCP Flags 0x00 */
		0x09, 0x61,             /* SrcPort 2401 */
		0x00, 0x00,             /* Input Interface 0 */
		0x00, 0x35,             /* DstPort 53 */
		0x00, 0x00,             /* Output Interface 0 */
		0x00, 0x00, 0x00, 0x00, /* INGRESS VRFID 16 */
		0x00, 0x00, 0x00, 0x10, /* EGRESS VRFID 0 */
		0x00, 0x00, 0x69, 0xb4, /* End time */
		0x00, 0x00, 0x00, 0x00, /* First time */
		/* Src address */
		0x3f, 0xfe, 0x05, 0x07, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00, 0x86, 0xff, 0xfe, 0x05, 0x80, 0xda,
		/* Dst address */
		0x3f, 0xfe, 0x05, 0x01, 0x48, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x42,
		0x00,                   /* SRC mask */
		0x00,                   /* DST mask */
		/* Next Hop: :: */
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	},
};

static const struct TestV10Template v10Template = {
	.flowHeader = {
		/*uint16_t*/ .version = 0x0a00,                 /* Current version=9*/
		/*uint16_t*/ .len = 0x9800,                     /* The number of records in PDU. */
		/*uint32_t*/ .unix_secs = 0x357dc754,           /* Current time in msecs since router booted */
		/*uint32_t*/ .flow_sequence = 0x00001683,       /* Sequence number of total flows seen */
		/*uint32_t*/ .observation_id = 0x00020000, /* Source id */
	},

	.flowSetHeader = {
		.set_id  = 0x0200,
		.set_len = 0x8800,
	},

	.templateHeader = {
		/*uint16_t*/ .templateId = 0x0901, /*269*/
		/*uint16_t*/ .fieldCount = 0x1c00,
	},

	.templateBuffer = {
		0x00, 0x08, 0x00, 0x04, /* SRC ADDR */
		0x00, 0x0c, 0x00, 0x04, /* DST ADDR */
		0x00, 0x3c, 0x00, 0x01, /* IP VERSION */
		0x00, 0x04, 0x00, 0x01, /* PROTO */
		0x00, 0x07, 0x00, 0x02, /* SRC PORT */
		0x00, 0x0b, 0x00, 0x02, /* DST PORT */
		0x00, 0xb7, 0x00, 0x02, /* TCP DST PORT */
		0x00, 0x38, 0x00, 0x06, /* SRC MAC */
		0x00, 0x50, 0x00, 0x06, /* DST MAC */
		0x00, 0xea, 0x00, 0x04, /* IngressVRFID */
		0x00, 0x0a, 0x00, 0x04, /* INPUT_SNMP */
		0x00, 0x88, 0x00, 0x01, /* FLOW END REASON */
		0x00, 0xef, 0x00, 0x01, /* BI-FLOW DIRECTION */
		0x00, 0x51, 0x00, 0x06, /* SRC_MAC */
		0x00, 0x39, 0x00, 0x06, /* DST_MAC*/
		0x00, 0x0e, 0x00, 0x04, /* OUTPUT SNMP */
		0x00, 0x3d, 0x00, 0x01, /* DIRECTION */
		0x00, 0x30, 0x00, 0x01, /* FLOW SAMPLER ID */
		0x00, 0xeb, 0x00, 0x04, /* EGRESS VRFID */
		0x00, 0x5f, 0x00, 0x04, /* APPLICATION ID */
		0xaf, 0xcb, 0xff, 0xff, 0x00, 0x00, 0x00, 0x09, /* CISCO PEM */
		0xaf, 0xcb, 0xff, 0xff, 0x00, 0x00, 0x00, 0x09, /* CISCO PEM */
		0xaf, 0xcb, 0xff, 0xff, 0x00, 0x00, 0x00, 0x09, /* CISCO PEM */
		0xaf, 0xcb, 0xff, 0xff, 0x00, 0x00, 0x00, 0x09, /* CISCO PEM */
		0x00, 0x01, 0x00, 0x08, /* BYTES */
		0x00, 0x02, 0x00, 0x04, /* PKTS */
		0x00, 0x16, 0x00, 0x04, /* FIRST SWITCHED */
		0x00, 0x15, 0x00, 0x04, /* LAST SWITCHED */
	}
};

static const struct TestV10Flow v10Flow = {
	.flowHeader = {
		/*uint16_t*/ .version = 0x0a00,       /* Current version=9*/
		/*uint16_t*/ .len = 0x8400,           /* The number of records in PDU. */
		/*uint32_t*/ .unix_secs = 0x277dc754,     /* Current time in msecs since router booted */
		/*uint32_t*/ .flow_sequence = 0xf8150000, /* Sequence number of total flows seen */
		/*uint32_t*/ .observation_id = 0x00020000,      /* Source id */
	},

	.flowSetHeader = {
		/*uint16_t*/ .set_id = 0x0901,
		/*uint16_t*/ .set_len = 0x7400,
	},

	.buffer1 = {
		0xad, 0xc2, 0x4e, 0xbd, /* SRC ADDR */
		0x0a, 0x00, 0x1e, 0x96, /* DST ADDR */
		0x04,                   /* IP VERSION */
		0x06,                   /* L4 PROTO*/
		0x01, 0xbb,             /* SRC PORT */
		0x98, 0x22,             /* DST PORT */
		0x98, 0x22,             /* TCP DST PORT */
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* SRC MAC ADDR */
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* DST MAC ADDR */
		0x00, 0x00, 0x00, 0x00, /* EGRESS VRFID */
		0x00, 0x00, 0x00, 0x0e, /* INPUT INT */
		0x01,                   /* FLOW END REASON */
		0x01,                   /* BIFLOW INITIATOR */
		0xe0, 0x5f, 0xb9, 0x8a, 0x85, 0xd3, /* POST_SRC_MAC_ADDR */
		0xc0, 0x3f, 0xd5, 0x69, 0x16, 0xbe, /* POST_DST_MAC_ADDR */
		0x00, 0x00, 0x00, 0x0c, /* OUTPUT INT */
		0x01,                   /* DIRECTION */
		0x00,                   /* SamplerID */
		0x00, 0x00, 0x00, 0x07, /* EGRESS VRFID */
		0x0d, 0x00, 0x00, 0x01, /* APPID */
		0x06, 0x03, 0x00, 0x00, 0x50, 0x34, 0x01, /* CISCO PEM */
		0x06, 0x03, 0x00, 0x00, 0x50, 0x34, 0x02, /* CISCO PEM */
		0x06, 0x03, 0x00, 0x00, 0x50, 0x34, 0x03, /* CISCO PEM */
		0x06, 0x03, 0x00, 0x00, 0x50, 0x34, 0x04, /* CISCO PEM */
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x9b, /* OCTETS */
		0x00, 0x00, 0x00, 0x08, /* PACKETS */
		0x15, 0xa9, 0x5d, 0x40,
		0x15, 0xa9, 0x60, 0x20,
	}
};

static const struct checkdata_value checkdata_values9[] = {
	{.key = "input_vrf", .value="0"},
	{.key = "output_vrf",  .value="16"}
};

static const struct checkdata_value checkdata_values10[] = {
	{.key = "input_vrf", .value="0"},
	{.key = "output_vrf",  .value="7"}
};

static int prepare_test_vrfid(void **state) {
	static const struct checkdata checkdata9 = {
		.checks=checkdata_values9,
		.size = RD_ARRAYSIZE(checkdata_values9),
	};

	static const struct checkdata checkdata10 = {
		.checks=checkdata_values10,
		.size = RD_ARRAYSIZE(checkdata_values10),
	};

#define TEST(config_path, mhost_path, mrecord, mrecord_size, checks,           \
								checks_size) { \
		.config_json_path = config_path,                               \
		.host_list_path = mhost_path,                                  \
		.netflow_src_ip = 0x04030301,                                  \
		.record = mrecord, .record_size = mrecord_size,                \
		.checkdata = checks, .checkdata_size = checks_size             \
	}

#define TEST_TEMPLATE_FLOW(config_path, mhost_path, template, template_size,   \
					flow, flow_size, checks, checks_size)  \
	TEST(config_path, mhost_path, template, template_size, NULL, 0),       \
	TEST(NULL, mhost_path, flow, flow_size, checks, checks_size)

	struct test_params test_params[] = {
		TEST_TEMPLATE_FLOW(
			"./tests/0024-testEnrichmentV10.json",
			"./tests/0011-data/",
			&v9Template, sizeof(v9Template),
			&v9Flow, sizeof(v9Flow),
			&checkdata9, 1),
		TEST_TEMPLATE_FLOW(NULL, NULL,
			&v10Template, sizeof(v10Template),
			&v10Flow, sizeof(v10Flow),
			&checkdata10, 1),
	};

	*state = prepare_tests(test_params, RD_ARRAYSIZE(test_params));
	return *state == NULL;
}

int main() {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup(testFlow, prepare_test_vrfid),
	};

	return cmocka_run_group_tests(tests, nf_test_setup, nf_test_teardown);
}
