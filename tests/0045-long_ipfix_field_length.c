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

static const struct {
	IPFIXFlowHeader flow_header;
	IPFIXSet flowset_header;
	V9TemplateDef template_header; /* It's the same */
	const uint8_t template_buffer[148 -
		sizeof(IPFIXFlowHeader) - sizeof(IPFIXSet) -
		sizeof(V9TemplateDef)];
} __attribute__((packed)) v10Template = {
	.flow_header = {
		.version = constexpr_be16toh(10),
		.len = constexpr_be16toh(148),
		.unix_secs = constexpr_be32toh(1382637021),
		.flow_sequence = 0x38040000,
		.observation_id = constexpr_be32toh(256),
	},

	.flowset_header = {
		/*uint16_t*/ .set_id = constexpr_be16toh(2),
		/*uint16_t*/ .set_len = constexpr_be16toh(132),
	},

	.template_header = {
		/*uint16_t*/ .templateId = constexpr_be16toh(262),
		/*uint16_t*/ .fieldCount = constexpr_be16toh(25),
	},

	.template_buffer = {
		TEMPLATE_ENTITY(IPV4_SRC_ADDR, 4),
		TEMPLATE_ENTITY(IPV4_DST_ADDR, 4),
		TEMPLATE_ENTITY(IP_PROTOCOL_VERSION, 1),
		TEMPLATE_ENTITY(PROTOCOL, 1),
		TEMPLATE_ENTITY(L4_SRC_PORT, 2),
		TEMPLATE_ENTITY(L4_DST_PORT, 2),
		TEMPLATE_ENTITY(IN_SRC_MAC, 6),
		TEMPLATE_ENTITY(IN_DST_MAC, 6),
		TEMPLATE_ENTITY(FLOW_END_REASON, 1),
		TEMPLATE_ENTITY(BIFLOW_DIRECTION, 1),
		TEMPLATE_PRIVATE_ENTITY(12242, 4, 9),
		TEMPLATE_ENTITY(APPLICATION_ID, 4),
		TEMPLATE_ENTITY(OUT_SRC_MAC, 6),
		TEMPLATE_ENTITY(OUT_DST_MAC, 6),
		TEMPLATE_ENTITY(DIRECTION, 1),
		TEMPLATE_ENTITY(FLOW_SAMPLER_ID, 1),
		TEMPLATE_PRIVATE_ENTITY(CISCO_URL, 0xffff, 9),
		TEMPLATE_PRIVATE_ENTITY(CISCO_URL, 0xffff, 9),
		TEMPLATE_PRIVATE_ENTITY(CISCO_URL, 0xffff, 9),
		TEMPLATE_PRIVATE_ENTITY(CISCO_URL, 0xffff, 9),
		TEMPLATE_PRIVATE_ENTITY(CISCO_URL, 0xffff, 9),
		TEMPLATE_ENTITY(IN_BYTES, 8),
		TEMPLATE_ENTITY(IN_PKTS, 8),
		TEMPLATE_ENTITY(FIRST_SWITCHED, 4),
		TEMPLATE_ENTITY(LAST_SWITCHED, 4),
	}
};

static const struct {
	IPFIXFlowHeader flow_header;
	IPFIXSet flowset_header;
	const uint8_t buffer1[574 - sizeof(IPFIXFlowHeader) - sizeof(IPFIXSet)];
} __attribute__((packed)) v10Flow = {
	.flow_header = {
		/*uint16_t*/ .version = constexpr_be16toh(10),
		/*uint16_t*/ .len = constexpr_be16toh(574),
		/*uint32_t*/ .unix_secs = 0xdd5d6952ul,
		/*uint32_t*/ .flow_sequence = constexpr_be32toh(1080),
		/*uint32_t*/ .observation_id = constexpr_be32toh(256),
	},

	.flowset_header = {
		/*uint16_t*/ .set_id = constexpr_be16toh(262),
		/*uint16_t*/ .set_len = constexpr_be16toh(558),
	},

	.buffer1 = {
		10, 71, 13, 22,           /* SRC ADDR 10.13.122.44 */
		183, 110, 10, 217,        /* DST ADDR 66.220.152.19*/
		4,                        /* IP VERSION: 4 */
		IPPROTO_TCP,              /* PROTO: 6 */
		UINT16_TO_UINT8_ARR(54713), /* SRC PORT: 54713 */
		UINT16_TO_UINT8_ARR(80),    /* DST PORT: 443 */
		0x60, 0x57, 0x18, 0xc2, 0x87, 0xd8, /* IN_SRC_MAC */
		0x00, 0x0a, 0xf7, 0x4e, 0x2f, 0x0c, /* IN_DST_MAC */
		3,                        /* FLOW_END_REASON */
		1,                        /* BIFLOW_DIRECTION */
		0x31, 0xb3, 0x1b, 0x10,    /* PRIVATE_ENTITY 12242 */
		FLOW_APPLICATION_ID(3, 80),
		0,0,0,0,0,0,              /* POST SRC MAC */
		0,0,0,0,0,0,              /* POST DST MAC */
		0,                        /* DIRECTION */
		0,                        /* FLOW_SAMPLER_ID */
		/* CISCO HTTP PRIVATE ENTRY: URL */
		0xff, UINT16_TO_UINT8_ARR(405),        /* Length: 255 */
		FLOW_APPLICATION_ID(3, 80), 0x34, 1,
		'/','c','g','i','-','b','i','n','/','l',
		'y','r','i','c','s','.','c','g','i','?','c','m','d','=','f','i',
		'n','d','_','g','e','t','_','l','y','r','i','c','s','&','h','k',
		'e','y','=','6','8','F','7','2','8','7','7','E','7','5','D','&',
		'f','i','l','e','_','k','e','y','=','5','7','e','8','5','f','3',
		'2','6','a','2','d','5','a','4','2','6','0','d','1','e','6','d',
		'd','5','e','a','1','b','a','1','e','&','f','i','l','e','_','.',
		'a','m','e','=','[', 0xba, 0xd2, 0xb0, 0xe6,
		0xb5, 0xb6, 0xb0, 0xe6, '%','2','0',
		0xbc, 0xb1, 0xc1, 0xfd, ']','%','2','0',
		0xb1, 0xe8, 0xbc, 0xba, 0xb0, 0xf8, 0xbd, 0xba,
		0xb4, 0xd4, '[','\'','8','9','%','2',
		'0', 0xc3, 0xb5, 0xbc, 0xf6, 0xb0, 0xe6, 0x2c,
		0xb0, 0xfc, 0xbc, 0xbc, 0xc0, 0xbd, 0xba, 0xb8,
		0xbb, 0xec, 0xba, 0xb8, 0xb9, 0xae, 0xc7, 0xb0,
		']','-','0','2','%','2','0', 0xb9,
		0xdd, 0xbe, 0xdf, 0xbd, 0xc9, 0xb0, 0xe6, 0x2e,
		'm','p','3','&','t','i','t','l','e','=',
		0xb9, 0xdd, 0xbe, 0xdf, 0xbd, 0xc9,
		0xb0, 0xe6, '(', 0xfc, 0xa3, 0xf0, 0xe8, 0xde,
		0xc5, 0xc0, 0xc7, '%','2','0', 0xba, 0xd2,
		0xb1, 0xb3, '%','2','0', 0xc0, 0xbd, 0xbe, 0xc7,
		0xbf, 0xa9, 0xc7, 0xe0, '%','2','0',
		'B','u','d','d','h','i','s','t','i','s','c','h','e','%','2','0',
		'M','u','s','i','k','r','e','i','s','e','%','2','0','v','o','n',
		'%','2','0','H','w','a','j','o','s','s','a',')','&','a','r','t',
		'i','s','t','=','&','a','l','b','u','m','=','[','\'','8','9','%',
		'2','0', 0xc3, 0xb5, 0xbc, 0xf6, 0xb0, 0xe6, ',',
		0xb0, 0xfc, 0xbc, 0xbc, 0xc0, 0xbd, 0xba,
		0xb8, 0xbb, 0xec, 0xba, 0xb8, 0xb9, 0xae, 0xc7, 0xb0,
		']','&','d','u','r','a','t',
		'i','o','n','=','2','0','9','&','s','i','z','e','=','8','3','6',
		'4','1','6','0','&','s','u','b','_','k','e','y','=','c','5','b',
		'b','d','d','d','d','d','d','a','f','6','d','b','e','c','8','8',
		'2','&','f','r','o','m','=','g','o','m','a','u','d','i','o','_',
		'l','o','c','a','l',
		/* CISCO HTTP PRIVATE ENTRY: HOST */
		25,                                              /* LENGTH*/
		FLOW_APPLICATION_ID(3, 80), 0x34, 2,
		'n','e','w','l','y','r','i','c','s','.',
		'g','o','m','t','v','.','c','o','m',
		/* CISCO HTTP PRIVATE ENTRY: User Agent */
		31,
		FLOW_APPLICATION_ID(3, 80), 0x34, 3,
		'G','o','m','A','u','d','i','o',' ','2',
		',',' ','0',',',' ','1','1',',',' ','1','1','5','6','.','J',
		/* CISCO HTTP PRIVATE ENTRY: REFERER */
		6,                                               /* LENGTH */
		FLOW_APPLICATION_ID(3, 80), 0x34, 4,
		/* CISCO HTTP PRIVATE ENTRY: REFERER */
		6,                                               /* LENGTH */
		FLOW_APPLICATION_ID(0xd, 0x1c5), 0x34, 1,
		UINT64_TO_UINT8_ARR(818), /* BYTES */
		UINT64_TO_UINT8_ARR(7),   /* PKTS */
		0x75, 0x1e, 0xfa, 0x32,   /* FIRST SWITCHED */
		0x75, 0x1e, 0xfb, 0xf6    /* LAST SWITCHED */
	},
};

static const struct checkdata_value checkdata_values1[] = {
	{.key="type", .value="netflowv10"},
	{.key="flow_sequence", .value="1080"},
	{.key="src", .value="10.71.13.22"},
	{.key="dst", .value="183.110.10.217"},
	{.key="ip_protocol_version", .value="4"},
	{.key="l4_proto", .value="6"},
	{.key="src_port", .value="54713"},
	{.key="dst_port", .value="80"},
	{.key="flow_end_reason", .value="end of flow"},
	{.key="biflow_direction", .value="initiator"},
	{.key="application_id_name", .value="3:80"},
	{.key="engine_id_name", .value="3"},
	{.key="http_url", .value="/cgi-bin/lyrics.cgi?cmd=find_get_lyrics"
		"&hkey=68F72877E75D&file_key=57e85f326a2d5a4260d1e6dd5ea1ba1e&"
		"file_.ame=[%ba\xd2\xb0\xe6\xb5\xb6%b0%e6%20%bc%b1%c1%fd]%20%b1"
		"\xe8\xbc\xba%b0%f8%bd%ba%b4"
		"%d4['89%20\xc3\xb5%bc%f6%b0%e6,%b0%fc%bc%bc%c0%bd%ba%b8%bb"
		"\xec\xba\xb8%b9%ae\xc7\xb0]"
		"-02%20%b9\xdd\xbe\xdf\xbd\xc9\xb0%e6.mp3&title=%b9"
		"\xdd\xbe\xdf\xbd\xc9\xb0%e6(%fc%a3%f0%e8"
		"%de%c5%c0%c7%20%ba\xd2\xb1%b3%20%c0%bd%be\xc7\xbf%a9%c7%e0%20"
		"Buddhistische%20Musikreise%20von%20Hwajossa)&artist=&album="
		"['89%20\xc3\xb5%bc%f6"
		"%b0%e6,%b0%fc%bc%bc%c0%bd%ba%b8%bb\xec\xba\xb8%b9%ae\xc7\xb0]"
		"&duration=209&size="
		"8364160&sub_key=c5bbddddddaf6dbec882&from=gomaudio_local"},
	{.key = "http_host", .value="newlyrics.gomtv.com"},
	{.key = "http_user_agent", .value="GomAudio 2, 0, 11, 1156.J"},
	{.key = "direction", .value="ingress"},
	{.key = "sensor_ip", .value="4.3.2.1"},
	{.key = "sensor_name", .value="FlowTest"},
	{.key = "first_switched", .value="1382637021"},
	{.key = "timestamp", .value="1382637021"},
	{.key = "bytes", .value="818"},
	{.key = "pkts", .value="7"}
};

static int prepare_test_nf10_cisco_url(void **state) {
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
				&v10Template, sizeof(v10Template),
				NULL, 0),

		[1] = TEST(NULL, NULL, &v10Flow, sizeof(v10Flow),
			&sl1_checkdata, 1),
	};

	*state = prepare_tests(test_params, RD_ARRAYSIZE(test_params));
	return *state == NULL;
}

int main() {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup(testFlow, prepare_test_nf10_cisco_url),
	};

	return cmocka_run_group_tests(tests, nf_test_setup, nf_test_teardown);
}
