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
struct TestV9Template{
	V9FlowHeader flowHeader;
	V9TemplateHeader flowSetHeader;
	V9TemplateDef templateHeader;
	V9FlowSet templateSet[18];
};

struct TestV9Flow{
	V9FlowHeader flowHeader;
	V9TemplateHeader flowSetHeader;
	const uint8_t buffer1[85];
}__attribute__((packed));

static const struct TestV9Template v9Template = {
	.flowHeader = {
		/*uint16_t*/ .version = 0x0900,           /* Current version=9*/
		/*uint16_t*/ .count = 0x0100,           /* The number of records in PDU. */
		/*uint32_t*/ .sysUptime = 0x00003039,     /* Current time in msecs since router booted */
		/*uint32_t*/ .unix_secs = 0xe2336552,     /* Current seconds since 0000 UTC 1970 */
		/*uint32_t*/ .flow_sequence = 0x38040000, /* Sequence number of total flows seen */
		/*uint32_t*/ .sourceId = 0x01000000,      /* Source id */
	},

	.flowSetHeader = {
		/*uint16_t*/ .templateFlowset = 0x0000,
		/*uint16_t*/ .flowsetLen = 0x3000,
	},

	.templateHeader = {
		/*uint16_t*/ .templateId = 0x0201, /*258*/
		/*uint16_t*/ .fieldCount = 0x1200,
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
		[9] = {.templateId = 0x1000 /*  16: SRC_AS */, .flowsetLen = 0x0400},
		[10] = {.templateId = 0x1100 /* 17: DST_AS */, .flowsetLen = 0x0400},
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
		/*uint32_t*/ .sysUptime = 0x00003039,     /* Current time in msecs since router booted */
		/*uint32_t*/ .unix_secs = 0x98346552,     /* Current seconds since 0000 UTC 1970 */
		/*uint32_t*/ .flow_sequence = 0x76040000, /* Sequence number of total flows seen */
		/*uint32_t*/ .sourceId = 0x01000000,      /* Source id */
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
		0x00, 0x00, 0x00, 0x00, /* SRC AS 0 */
		0x00, 0x00, 0x00, 0x00, /* DST AS 0 */
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


static int prepare_test_nf9_enrichment(void **state) {
	static const struct checkdata_value checkdata_values1 = {
		.key = "testing", .value="abc"
	};
	static const struct checkdata checkdata = {
		.checks = &checkdata_values1,
		.size = 1,
	};

#define TEST(config_path, mhost_path, mrecord, mrecord_size, checks,           \
								checks_size) { \
		.config_json_path = config_path,                               \
		.host_list_path = mhost_path,                                  \
		.netflow_src_ip = 0x04030301, .netflow_dst_port = 2055,        \
		.record = mrecord, .record_size = mrecord_size,                \
		.checkdata = checks, .checkdata_size = checks_size             \
	}

#define TEST_TEMPLATE_FLOW(config_path, mhost_path, template, template_size,   \
				flow, flow_size, checks, checks_size)          \
	TEST(config_path, mhost_path, template, template_size, NULL, 0),       \
	TEST(NULL, mhost_path, flow, flow_size, checks, checks_size)

	struct test_params test_params[] = {
		TEST_TEMPLATE_FLOW(
			"./tests/0024-testEnrichmentV10.json",
			"./tests/0011-data/",
			(uint8_t *)&v9Template, sizeof(v9Template),
			(uint8_t *)&v9Flow, sizeof(v9Flow),
			&checkdata, 1),
	};

	*state = prepare_tests(test_params, RD_ARRAYSIZE(test_params));
	return *state == NULL;
}

int main(){
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(testFlow,
				prepare_test_nf9_enrichment, check_flow),
	};

	return cmocka_run_group_tests(tests, nf_test_setup, nf_test_teardown);
}
