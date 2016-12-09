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
	V9FlowSet templateSet[18];
};

struct TestV9Flow{
	V9FlowHeader flowHeader;
	V9TemplateHeader flowSetHeader;
	const uint8_t buffer1[85];
}__attribute__((packed));

static const struct TestV9Template v9Template = {
	.flowHeader = {
		/*uint16_t*/ .version = constexpr_be16toh(9),
		/*uint16_t*/ .count = constexpr_be16toh(1),
		/*uint32_t*/ .sys_uptime = constexpr_be32toh(12345),
		/*uint32_t*/ .unix_secs = constexpr_be32toh(1478780782),
		/*uint32_t*/ .flow_sequence = 0x38040000, /* Sequence number of total flows seen */
		/*uint32_t*/ .source_id = 0x01000000,      /* Source id */
	},

	.flowSetHeader = {
		/*uint16_t*/ .templateFlowset = 0x0000,
		/*uint16_t*/ .flowsetLen = 0x5000,
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
		/*uint16_t*/ .version = constexpr_be16toh(9),
		/*uint16_t*/ .count = constexpr_be16toh(1),
		/*uint32_t*/ .sys_uptime = constexpr_be32toh(12345),
		/*uint32_t*/ .unix_secs = constexpr_be32toh(1478780782),
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
		0x00, 0x00, 0x00, 0x00, /* SRC AS 0 */
		0x00, 0x00, 0x00, 0x00, /* DST AS 0 */
		0x00, 0x00, 0x00, 0x00, /* End time */
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

static const struct checkdata_value checkdata_values1[] = {
	{.key = "type", .value="netflowv9"},
	{.key = "l4_proto", .value="17"},
	{.key = "tos", .value="0"},
	{.key = "tcp_flags", .value=NULL},
	{.key = "src_port", .value="2401"},
	{.key = "input_snmp", .value="0"},
	{.key = "dst_port", .value="53"},
	{.key = "output_snmp", .value="0"},
	{.key = "prev_as", .value="0"},
	{.key = "next_as", .value="0"},
	{.key = "src", .value="3ffe:0507:0000:0001:0200:86ff:fe05:80da"},
	{.key = "dst", .value="3ffe:0501:4819:0000:0000:0000:0000:0042"},
	{.key = "sensor_ip", .value="4.3.2.1"},
	{.key = "sensor_name", .value="FlowTest"},
	{.key = "first_switched", .value="1478780782"},
	{.key = "timestamp", .value="1478780782"},
	{.key = "bytes", .value="113162"},
	{.key = "pkts", .value="826"},
};

static int prepare_test_nf9_ipv6(void **state) {
	static const struct checkdata sl1_checkdata = {
		.checks = checkdata_values1,
		.size = RD_ARRAYSIZE(checkdata_values1),
	};

#define TEST(config_path, mhosts_db_path, mrecord, mrecord_size, checks,       \
								checks_size) { \
		.config_json_path = config_path,                               \
		.host_list_path = mhosts_db_path,                              \
		.netflow_src_ip = 0x04030201,                                  \
		.record = mrecord, .record_size = mrecord_size,                \
		.checkdata = checks, .checkdata_size = checks_size             \
	}

	struct test_params test_params[] = {
		[0] = TEST("./tests/0000-testFlowV5.json", "./tests/0011-data/",
				&v9Template, sizeof(v9Template), NULL, 0),

		[1] = TEST(NULL, NULL, &v9Flow, sizeof(v9Flow),
			&sl1_checkdata, 1),
	};

	*state = prepare_tests(test_params, RD_ARRAYSIZE(test_params));
	return *state == NULL;
}

int main() {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup(testFlow, prepare_test_nf9_ipv6),
	};

	return cmocka_run_group_tests(tests, nf_test_setup, nf_test_teardown);
}

