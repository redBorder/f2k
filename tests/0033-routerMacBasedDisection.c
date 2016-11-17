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

/// @todo template+flow in the same message
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
		0x00, 0x39, 0x00, 0x06, /* POST DST MAC */
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

#define FLOW(src_addr_0,src_addr_1,src_addr_2,src_addr_3, \
		     dst_addr_0,dst_addr_1,dst_addr_2,dst_addr_3, \
		     ip_version, \
		     src_mac_0, src_mac_1, src_mac_2, src_mac_3, src_mac_4, src_mac_5, \
		     dst_mac_0, dst_mac_1, dst_mac_2, dst_mac_3, dst_mac_4, dst_mac_5, \
		     pdst_mac_0, pdst_mac_1, pdst_mac_2, pdst_mac_3, pdst_mac_4, pdst_mac_5, \
		     direction) \
		src_addr_0,src_addr_1,src_addr_2,src_addr_3, /* SRC ADDR   */ \
		dst_addr_0,dst_addr_1,dst_addr_2,dst_addr_3, /* DST ADDR   */ \
		ip_version,                                  /* IP VERSION */ \
		0x06,                   /* PROTO: 6 */ \
		0xd5, 0xb9,             /* SRC PORT: 54713 */ \
		0x01, 0xbb,             /* DST PORT: 443 */ \
		src_mac_0, src_mac_1, src_mac_2, src_mac_3, src_mac_4, src_mac_5, /* SRC MAC */ \
		0x03,                   /* flowEndreason */ \
		0x01,                   /* biflowDirection */ \
		0x8f, 0x63, 0xf3, 0x40, 0x00, 0x01, 0x00, 0x00, /* TRANSACTION_ID */ \
		dst_mac_0, dst_mac_1, dst_mac_2, dst_mac_3, dst_mac_4, dst_mac_5, /* DST MAC */ \
		pdst_mac_0, pdst_mac_1, pdst_mac_2, pdst_mac_3, pdst_mac_4, pdst_mac_5, /* POST DST MAC */ \
		direction,              /* DIRECTION */ \
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


static const struct TestV10Flow v10Flow_src_router_mac = {
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
		/* FIRST FLOW: SRC in HOME_NET, DST not in HOME_NET, DIRECTION ingress */
		FLOW(
			0x0a, 0x0d, 0x1e, 0x2c,             /* SRC ADDR 10.13.30.44 */
			0x42, 0xdc, 0x98, 0x13,             /* DST ADDR 66.220.152.19 */
			0x04,                               /* IP VERSION 4 */
			0x00, 0x11, 0x22, 0x33, 0x44, 0x55, /* SRC MAC */
			0x00, 0x22, 0x55, 0x04, 0x05, 0x06, /* DST MAC */
			0x00, 0x24, 0x1d, 0x04, 0x05, 0x06, /* POST DST MAC */
			0x00)                               /* DIRECTION */

		/* FIRST FLOW: SRC in HOME_NET, DST not in HOME_NET, DIRECTION egress */
		FLOW(
			0x0a, 0x0d, 0x1e, 0x2c,             /* SRC ADDR 10.13.30.44 */
			0x42, 0xdc, 0x98, 0x13,             /* DST ADDR 66.220.152.19 */
			0x04,                               /* IP VERSION 4 */
			0x00, 0x11, 0x22, 0x33, 0x44, 0x55, /* SRC MAC */
			0x00, 0x22, 0x55, 0x04, 0x05, 0x06, /* DST MAC */
			0x00, 0x24, 0x1d, 0x04, 0x05, 0x06, /* POST DST MAC */
			0x01)                               /* DIRECTION */

		/* SECOND FLOW: SRC not in HOME_NET, DST in HOME_NET, DIRECTION ingress */
		FLOW(
			0x42, 0xdc, 0x98, 0x13,             /* SRC ADDR 66.220.152.19*/
			0x0a, 0x0d, 0x1e, 0x2c,             /* DST ADDR 10.13.30.44 */
			0x04,                               /* IP VERSION: 4 */
			0x00, 0x11, 0x22, 0x33, 0x44, 0x55, /* SRC MAC */
			0x00, 0x22, 0x55, 0x04, 0x05, 0x06, /* DST MAC */
			0x00, 0x24, 0x1d, 0x04, 0x05, 0x06, /* POST DST MAC */
			0x00)                               /* DIRECTION */

		/* SECOND FLOW: SRC not in HOME_NET, DST in HOME_NET, DIRECTION egress */
		FLOW(
			0x42, 0xdc, 0x98, 0x13,             /* SRC ADDR 66.220.152.19*/
			0x0a, 0x0d, 0x1e, 0x2c,             /* DST ADDR 10.13.30.44 */
			0x04,                               /* IP VERSION: 4 */
			0x00, 0x11, 0x22, 0x33, 0x44, 0x55, /* SRC MAC */
			0x00, 0x22, 0x55, 0x04, 0x05, 0x06, /* DST MAC */
			0x00, 0x24, 0x1d, 0x04, 0x05, 0x06, /* POST DST MAC */
			0x01)                               /* DIRECTION */

		/* THIRD  FLOW: SRC in HOME_NET, DST in HOME_NET, DIRECTION egress */
		FLOW(
			0x0a, 0x0d, 0x1e, 0x2c,             /* DST ADDR 10.13.30.44 */
			0x0a, 0x0d, 0x1e, 0x2c,             /* SRC ADDR 10.13.30.44 */
			0x04,                               /* IP VERSION: 4 */
			0x00, 0x11, 0x22, 0x33, 0x44, 0x55, /* SRC MAC */
			0x00, 0x22, 0x55, 0x04, 0x05, 0x06, /* DST MAC */
			0x00, 0x24, 0x1d, 0x04, 0x05, 0x06, /* POST DST MAC */
			0x00)                               /* DIRECTION */

		/* THIRD  FLOW: SRC in HOME_NET, DST in HOME_NET, DIRECTION egress */
		FLOW(
			0x0a, 0x0d, 0x1e, 0x2c,             /* DST ADDR 10.13.30.44 */
			0x0a, 0x0d, 0x1e, 0x2c,             /* SRC ADDR 10.13.30.44 */
			0x04,                               /* IP VERSION: 4 */
			0x00, 0x11, 0x22, 0x33, 0x44, 0x55, /* SRC MAC */
			0x00, 0x22, 0x55, 0x04, 0x05, 0x06, /* DST MAC */
			0x00, 0x24, 0x1d, 0x04, 0x05, 0x06, /* POST DST MAC */
			0x01)                               /* DIRECTION */

		/* FOURTH FLOW: SRC not in HOME_NET, DST not in HOME_NET, DIRECTION egress */
		FLOW(
			0x42, 0xdc, 0x98, 0x13,             /* SRC ADDR 66.220.152.19*/
			0x42, 0xdc, 0x98, 0x14,             /* DST ADDR 66.220.152.19*/
			0x04,                               /* IP VERSION: 4 */
			0x00, 0x11, 0x22, 0x33, 0x44, 0x55, /* SRC MAC */
			0x00, 0x22, 0x55, 0x04, 0x05, 0x06, /* DST MAC */
			0x00, 0x24, 0x1d, 0x04, 0x05, 0x06, /* POST DST MAC */
			0x00)                               /* DIRECTION */

		/* FOURTH FLOW: SRC not in HOME_NET, DST not in HOME_NET, DIRECTION egress */
		FLOW(
			0x42, 0xdc, 0x98, 0x13,             /* SRC ADDR 66.220.152.19*/
			0x42, 0xdc, 0x98, 0x14,             /* DST ADDR 66.220.152.19*/
			0x04,                               /* IP VERSION: 4 */
			0x00, 0x11, 0x22, 0x33, 0x44, 0x55, /* SRC MAC */
			0x00, 0x22, 0x55, 0x04, 0x05, 0x06, /* DST MAC */
			0x00, 0x24, 0x1d, 0x04, 0x05, 0x06, /* POST DST MAC */
			0x01)                               /* DIRECTION */
	},
};

static const struct TestV10Flow v10Flow_router_dst_macs = {
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
		/* FIRST FLOW: SRC in HOME_NET, DST not in HOME_NET, DIRECTION ingress */
		FLOW(
			0x0a, 0x0d, 0x1e, 0x2c,             /* SRC ADDR 10.13.30.44 */
			0x42, 0xdc, 0x98, 0x13,             /* DST ADDR 66.220.152.19 */
			0x04,                               /* IP VERSION 4 */
			0x00, 0x24, 0x14, 0x01, 0x02, 0x03, /* SRC MAC */
			0x00, 0x11, 0x22, 0x33, 0x44, 0x55, /* DST MAC */
			0x00, 0x24, 0x1d, 0x04, 0x05, 0x06, /* POST DST MAC */
			0x00)                               /* DIRECTION */

		/* FIRST FLOW: SRC in HOME_NET, DST not in HOME_NET, DIRECTION egress */
		FLOW(
			0x0a, 0x0d, 0x1e, 0x2c,             /* SRC ADDR 10.13.30.44 */
			0x42, 0xdc, 0x98, 0x13,             /* DST ADDR 66.220.152.19 */
			0x04,                               /* IP VERSION 4 */
			0x00, 0x24, 0x14, 0x01, 0x02, 0x03, /* SRC MAC */
			0x00, 0x11, 0x22, 0x33, 0x44, 0x55, /* DST MAC */
			0x00, 0x24, 0x1d, 0x04, 0x05, 0x06, /* POST DST MAC */
			0x01)                               /* DIRECTION */

		/* SECOND FLOW: SRC not in HOME_NET, DST in HOME_NET, DIRECTION ingress */
		FLOW(
			0x42, 0xdc, 0x98, 0x13,             /* SRC ADDR 66.220.152.19*/
			0x0a, 0x0d, 0x1e, 0x2c,             /* DST ADDR 10.13.30.44 */
			0x04,                               /* IP VERSION: 4 */
			0x00, 0x24, 0x14, 0x01, 0x02, 0x03, /* SRC MAC */
			0x00, 0x11, 0x22, 0x33, 0x44, 0x55, /* DST MAC */
			0x00, 0x24, 0x1d, 0x04, 0x05, 0x06, /* POST DST MAC */
			0x00)                               /* DIRECTION */

		/* SECOND FLOW: SRC not in HOME_NET, DST in HOME_NET, DIRECTION egress */
		FLOW(
			0x42, 0xdc, 0x98, 0x13,             /* SRC ADDR 66.220.152.19*/
			0x0a, 0x0d, 0x1e, 0x2c,             /* DST ADDR 10.13.30.44 */
			0x04,                               /* IP VERSION: 4 */
			0x00, 0x24, 0x14, 0x01, 0x02, 0x03, /* SRC MAC */
			0x00, 0x11, 0x22, 0x33, 0x44, 0x55, /* DST MAC */
			0x00, 0x24, 0x1d, 0x04, 0x05, 0x06, /* POST DST MAC */
			0x01)                               /* DIRECTION */

		/* THIRD  FLOW: SRC in HOME_NET, DST in HOME_NET, DIRECTION egress */
		FLOW(
			0x0a, 0x0d, 0x1e, 0x2c,             /* DST ADDR 10.13.30.44 */
			0x0a, 0x0d, 0x1e, 0x2c,             /* SRC ADDR 10.13.30.44 */
			0x04,                               /* IP VERSION: 4 */
			0x00, 0x24, 0x14, 0x01, 0x02, 0x03, /* SRC MAC */
			0x00, 0x11, 0x22, 0x33, 0x44, 0x55, /* DST MAC */
			0x00, 0x24, 0x1d, 0x04, 0x05, 0x06, /* POST DST MAC */
			0x00)                               /* DIRECTION */

		/* THIRD  FLOW: SRC in HOME_NET, DST in HOME_NET, DIRECTION egress */
		FLOW(
			0x0a, 0x0d, 0x1e, 0x2c,             /* DST ADDR 10.13.30.44 */
			0x0a, 0x0d, 0x1e, 0x2c,             /* SRC ADDR 10.13.30.44 */
			0x04,                               /* IP VERSION: 4 */
			0x00, 0x24, 0x14, 0x01, 0x02, 0x03, /* SRC MAC */
			0x00, 0x11, 0x22, 0x33, 0x44, 0x55, /* DST MAC */
			0x00, 0x24, 0x1d, 0x04, 0x05, 0x06, /* POST DST MAC */
			0x01)                               /* DIRECTION */

		/* FOURTH FLOW: SRC not in HOME_NET, DST not in HOME_NET, DIRECTION egress */
		FLOW(
			0x42, 0xdc, 0x98, 0x13,             /* SRC ADDR 66.220.152.19*/
			0x42, 0xdc, 0x98, 0x14,             /* DST ADDR 66.220.152.19*/
			0x04,                               /* IP VERSION: 4 */
			0x00, 0x24, 0x14, 0x01, 0x02, 0x03, /* SRC MAC */
			0x00, 0x11, 0x22, 0x33, 0x44, 0x55, /* DST MAC */
			0x00, 0x24, 0x1d, 0x04, 0x05, 0x06, /* POST DST MAC */
			0x00)                               /* DIRECTION */

		/* FOURTH FLOW: SRC not in HOME_NET, DST not in HOME_NET, DIRECTION egress */
		FLOW(
			0x42, 0xdc, 0x98, 0x13,             /* SRC ADDR 66.220.152.19*/
			0x42, 0xdc, 0x98, 0x14,             /* DST ADDR 66.220.152.19*/
			0x04,                               /* IP VERSION: 4 */
			0x00, 0x24, 0x14, 0x01, 0x02, 0x03, /* SRC MAC */
			0x00, 0x11, 0x22, 0x33, 0x44, 0x55, /* DST MAC */
			0x00, 0x24, 0x1d, 0x04, 0x05, 0x06, /* POST DST MAC */
			0x01)                               /* DIRECTION */
	},
};

static const struct TestV10Flow v10Flow_router_post_dst_macs = {
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
		/* FIRST FLOW: SRC in HOME_NET, DST not in HOME_NET, DIRECTION ingress */
		FLOW(
			0x0a, 0x0d, 0x1e, 0x2c,             /* SRC ADDR 10.13.30.44 */
			0x42, 0xdc, 0x98, 0x13,             /* DST ADDR 66.220.152.19 */
			0x04,                               /* IP VERSION 4 */
			0x00, 0x24, 0x14, 0x01, 0x02, 0x03, /* SRC MAC */
			0x00, 0x22, 0x55, 0x04, 0x05, 0x06, /* DST MAC */
			0x00, 0x11, 0x22, 0x33, 0x44, 0x55, /* POST DST MAC */
			0x00)                               /* DIRECTION */

		/* FIRST FLOW: SRC in HOME_NET, DST not in HOME_NET, DIRECTION egress */
		FLOW(
			0x0a, 0x0d, 0x1e, 0x2c,             /* SRC ADDR 10.13.30.44 */
			0x42, 0xdc, 0x98, 0x13,             /* DST ADDR 66.220.152.19 */
			0x04,                               /* IP VERSION 4 */
			0x00, 0x24, 0x14, 0x01, 0x02, 0x03, /* SRC MAC */
			0x00, 0x22, 0x55, 0x04, 0x05, 0x06, /* DST MAC */
			0x00, 0x11, 0x22, 0x33, 0x44, 0x55, /* POST DST MAC */
			0x01)                               /* DIRECTION */

		/* SECOND FLOW: SRC not in HOME_NET, DST in HOME_NET, DIRECTION ingress */
		FLOW(
			0x42, 0xdc, 0x98, 0x13,             /* SRC ADDR 66.220.152.19*/
			0x0a, 0x0d, 0x1e, 0x2c,             /* DST ADDR 10.13.30.44 */
			0x04,                               /* IP VERSION: 4 */
			0x00, 0x24, 0x14, 0x01, 0x02, 0x03, /* SRC MAC */
			0x00, 0x22, 0x55, 0x04, 0x05, 0x06, /* DST MAC */
			0x00, 0x11, 0x22, 0x33, 0x44, 0x55, /* POST DST MAC */
			0x00)                               /* DIRECTION */

		/* SECOND FLOW: SRC not in HOME_NET, DST in HOME_NET, DIRECTION egress */
		FLOW(
			0x42, 0xdc, 0x98, 0x13,             /* SRC ADDR 66.220.152.19*/
			0x0a, 0x0d, 0x1e, 0x2c,             /* DST ADDR 10.13.30.44 */
			0x04,                               /* IP VERSION: 4 */
			0x00, 0x24, 0x14, 0x01, 0x02, 0x03, /* SRC MAC */
			0x00, 0x22, 0x55, 0x04, 0x05, 0x06, /* DST MAC */
			0x00, 0x11, 0x22, 0x33, 0x44, 0x55, /* POST DST MAC */
			0x01)                               /* DIRECTION */

		/* THIRD  FLOW: SRC in HOME_NET, DST in HOME_NET, DIRECTION egress */
		FLOW(
			0x0a, 0x0d, 0x1e, 0x2c,             /* DST ADDR 10.13.30.44 */
			0x0a, 0x0d, 0x1e, 0x2c,             /* SRC ADDR 10.13.30.44 */
			0x04,                               /* IP VERSION: 4 */
			0x00, 0x24, 0x14, 0x01, 0x02, 0x03, /* SRC MAC */
			0x00, 0x22, 0x55, 0x04, 0x05, 0x06, /* DST MAC */
			0x00, 0x11, 0x22, 0x33, 0x44, 0x55, /* POST DST MAC */
			0x00)                               /* DIRECTION */

		/* THIRD  FLOW: SRC in HOME_NET, DST in HOME_NET, DIRECTION egress */
		FLOW(
			0x0a, 0x0d, 0x1e, 0x2c,             /* DST ADDR 10.13.30.44 */
			0x0a, 0x0d, 0x1e, 0x2c,             /* SRC ADDR 10.13.30.44 */
			0x04,                               /* IP VERSION: 4 */
			0x00, 0x24, 0x14, 0x01, 0x02, 0x03, /* SRC MAC */
			0x00, 0x22, 0x55, 0x04, 0x05, 0x06, /* DST MAC */
			0x00, 0x11, 0x22, 0x33, 0x44, 0x55, /* POST DST MAC */
			0x01)                               /* DIRECTION */

		/* FOURTH FLOW: SRC not in HOME_NET, DST not in HOME_NET, DIRECTION egress */
		FLOW(
			0x42, 0xdc, 0x98, 0x13,             /* SRC ADDR 66.220.152.19*/
			0x42, 0xdc, 0x98, 0x14,             /* DST ADDR 66.220.152.19*/
			0x04,                               /* IP VERSION: 4 */
			0x00, 0x24, 0x14, 0x01, 0x02, 0x03, /* SRC MAC */
			0x00, 0x22, 0x55, 0x04, 0x05, 0x06, /* DST MAC */
			0x00, 0x11, 0x22, 0x33, 0x44, 0x55, /* POST DST MAC */
			0x00)                               /* DIRECTION */

		/* FOURTH FLOW: SRC not in HOME_NET, DST not in HOME_NET, DIRECTION egress */
		FLOW(
			0x42, 0xdc, 0x98, 0x13,             /* SRC ADDR 66.220.152.19*/
			0x42, 0xdc, 0x98, 0x14,             /* DST ADDR 66.220.152.19*/
			0x04,                               /* IP VERSION: 4 */
			0x00, 0x24, 0x14, 0x01, 0x02, 0x03, /* SRC MAC */
			0x00, 0x22, 0x55, 0x04, 0x05, 0x06, /* DST MAC */
			0x00, 0x11, 0x22, 0x33, 0x44, 0x55, /* POST DST MAC */
			0x01)                               /* DIRECTION */
	},
};

static const struct checkdata_value checkdata_values_span_egress[] = {
	{.key = "type", .value="netflowv10"},
	{.key = "direction", .value="egress"},
	{.key = "client_mac", .value="00:22:55:04:05:06"},
};

static const struct checkdata_value checkdata_values_span_ingress[] = {
	{.key = "type", .value="netflowv10"},
	{.key = "direction", .value="ingress"},
	{.key = "client_mac", .value="00:24:14:01:02:03"},
};

static const struct checkdata_value checkdata_values_span_internal[] = {
	{.key = "type", .value="netflowv10"},
	{.key = "direction", .value="internal"},
	{.key = "client_mac", .value="00:22:55:04:05:06"},
};

static const struct checkdata_value checkdata_values_nospan_egress[] = {
	{.key = "type", .value="netflowv10"},
	{.key = "direction", .value="egress"},
	{.key = "client_mac", .value="00:24:1d:04:05:06"},
};

static const struct checkdata_value checkdata_values_span_egress_client_post[] = {
	{.key = "type", .value="netflowv10"},
	{.key = "direction", .value="egress"},
	{.key = "client_mac", .value="00:22:55:04:05:06"},
};

#define checkdata_values_nospan_ingress checkdata_values_span_ingress

static const struct checkdata_value checkdata_values_nospan_internal[] = {
	{.key = "type", .value="netflowv10"},
	{.key = "direction", .value="internal"},
	{.key = "client_mac", .value="00:24:1d:04:05:06"},
};

static const struct checkdata_value checkdata_values_span_internal_client_post[] = {
	{.key = "type", .value="netflowv10"},
	{.key = "direction", .value="internal"},
	{.key = "client_mac", .value="00:22:55:04:05:06"},
};

#define checkdata_values_router_src_mac_addr_span_true checkdata_values_span_egress

#define checkdata_values_router_src_mac_addr_span_false checkdata_values_nospan_egress

#define checkdata_values_router_dst_mac_addr_span_true checkdata_values_span_ingress

#define checkdata_values_router_dst_mac_addr_span_false checkdata_values_nospan_internal

#define checkdata_values_router_dst_mac_addr_no_span \
	checkdata_values_router_dst_mac_addr_span_false

#define checkdata_values_router_post_dst_mac_addr_span_true checkdata_values_span_internal

#define checkdata_values_router_post_dst_mac_addr_span_false checkdata_values_span_ingress

#define checkdata_values_router_post_dst_mac_addr_no_span \
	checkdata_values_router_post_dst_mac_addr_span_false

#define CHECKDATA(X) {.size=RD_ARRAYSIZE(X),.checks=X}

/// @TODO clean a little
static const struct checkdata checkdata_router_src_mac_span_true[] = {
	CHECKDATA(checkdata_values_router_src_mac_addr_span_true),
	CHECKDATA(checkdata_values_router_src_mac_addr_span_true),
	CHECKDATA(checkdata_values_router_src_mac_addr_span_true),
	CHECKDATA(checkdata_values_router_src_mac_addr_span_true),
	CHECKDATA(checkdata_values_router_src_mac_addr_span_true),
	CHECKDATA(checkdata_values_router_src_mac_addr_span_true),
	CHECKDATA(checkdata_values_router_src_mac_addr_span_true),
	CHECKDATA(checkdata_values_router_src_mac_addr_span_true),
};

static const struct checkdata checkdata_router_src_mac_span_false[] = {
	CHECKDATA(checkdata_values_router_src_mac_addr_span_false),
	CHECKDATA(checkdata_values_router_src_mac_addr_span_false),
	CHECKDATA(checkdata_values_router_src_mac_addr_span_false),
	CHECKDATA(checkdata_values_router_src_mac_addr_span_false),
	CHECKDATA(checkdata_values_router_src_mac_addr_span_false),
	CHECKDATA(checkdata_values_router_src_mac_addr_span_false),
	CHECKDATA(checkdata_values_router_src_mac_addr_span_false),
	CHECKDATA(checkdata_values_router_src_mac_addr_span_false),
};

#define checkdata_router_src_mac_no_span checkdata_router_src_mac_span_false

static const struct checkdata checkdata_router_dst_mac_span_true[] = {
	CHECKDATA(checkdata_values_router_dst_mac_addr_span_true),
	CHECKDATA(checkdata_values_router_dst_mac_addr_span_true),
	CHECKDATA(checkdata_values_router_dst_mac_addr_span_true),
	CHECKDATA(checkdata_values_router_dst_mac_addr_span_true),
	CHECKDATA(checkdata_values_router_dst_mac_addr_span_true),
	CHECKDATA(checkdata_values_router_dst_mac_addr_span_true),
	CHECKDATA(checkdata_values_router_dst_mac_addr_span_true),
	CHECKDATA(checkdata_values_router_dst_mac_addr_span_true),
};

static const struct checkdata checkdata_router_dst_mac_span_false[] = {
	CHECKDATA(checkdata_values_nospan_ingress),
	CHECKDATA(checkdata_values_nospan_ingress),
	CHECKDATA(checkdata_values_nospan_egress),
	CHECKDATA(checkdata_values_nospan_egress),
	CHECKDATA(checkdata_values_nospan_internal),
	CHECKDATA(checkdata_values_nospan_internal),
	CHECKDATA(checkdata_values_nospan_ingress),
	CHECKDATA(checkdata_values_nospan_egress),
};

#define checkdata_router_dst_mac_no_span checkdata_router_dst_mac_span_false

static const struct checkdata checkdata_router_post_dst_mac_span_true[] = {
	CHECKDATA(checkdata_values_span_ingress),
	CHECKDATA(checkdata_values_span_ingress),
	CHECKDATA(checkdata_values_span_egress_client_post),
	CHECKDATA(checkdata_values_span_egress_client_post),
	CHECKDATA(checkdata_values_span_internal_client_post),
	CHECKDATA(checkdata_values_span_internal_client_post),
	CHECKDATA(checkdata_values_span_ingress),
	CHECKDATA(checkdata_values_span_egress_client_post),
};

static const struct checkdata checkdata_router_post_dst_mac_span_false[] = {
	CHECKDATA(checkdata_values_router_post_dst_mac_addr_span_false),
	CHECKDATA(checkdata_values_router_post_dst_mac_addr_span_false),
	CHECKDATA(checkdata_values_router_post_dst_mac_addr_span_false),
	CHECKDATA(checkdata_values_router_post_dst_mac_addr_span_false),
	CHECKDATA(checkdata_values_router_post_dst_mac_addr_span_false),
	CHECKDATA(checkdata_values_router_post_dst_mac_addr_span_false),
	CHECKDATA(checkdata_values_router_post_dst_mac_addr_span_false),
	CHECKDATA(checkdata_values_router_post_dst_mac_addr_span_false),
};

#define checkdata_router_post_dst_mac_no_span checkdata_router_post_dst_mac_span_false

static int prepare_test_mac_direction(void **state) {
#define TEST(config_path, mmac_vendors, nf_dev_ip, mrecord, mrecord_size,      \
							checks, checks_sz) {   \
		.config_json_path = config_path,                               \
		.mac_vendor_database_path = mmac_vendors,                      \
		.netflow_src_ip = nf_dev_ip,                                   \
		.record = mrecord, .record_size = mrecord_size,                \
		.checkdata = checks, .checkdata_size = checks_sz               \
	}

#define TEST_TEMPLATE_FLOW(config_path, mmac_vendors, nf_dev_ip,               \
		template, template_size, flow, flow_size, checks, checks_sz)   \
	TEST(config_path, mmac_vendors, nf_dev_ip, template, template_size,    \
		NULL, 0),                                                      \
	TEST(NULL, NULL, nf_dev_ip, flow, flow_size, checks, checks_sz)

#define TEST_TEMPLATE_FLOW_ALL_SENSORS(config_path, mmac_vendors,              \
		template, template_size, flow, flow_size,                      \
		checks1, checks1_sz, checks2, checks2_sz, checks3, checks3_sz) \
	/* span_true */                                                        \
	TEST_TEMPLATE_FLOW(config_path, mmac_vendors, 0x04030201, template,    \
		template_size, flow, flow_size, checks1, checks1_sz),          \
	/* span_false */                                                       \
	TEST_TEMPLATE_FLOW(config_path, mmac_vendors, 0x04030301, template,    \
		template_size, flow, flow_size, checks2, checks2_sz),          \
	/* nospan */                                                           \
	TEST_TEMPLATE_FLOW(config_path, mmac_vendors, 0x04030401, template,    \
		template_size, flow, flow_size, checks3, checks3_sz)

	struct test_params test_params[] = {
		/* POST DST MAC */
		TEST_TEMPLATE_FLOW_ALL_SENSORS(
			"./tests/0033-routerMacBasedDisection.json",
			"./tests/0008-data/mac_vendors",
			&v10Template, sizeof(v10Template),
			&v10Flow_router_post_dst_macs,
					sizeof(v10Flow_router_post_dst_macs),
			checkdata_router_post_dst_mac_span_true,
			RD_ARRAYSIZE(checkdata_router_post_dst_mac_span_true),
			checkdata_router_post_dst_mac_span_false,
			RD_ARRAYSIZE(checkdata_router_post_dst_mac_span_false),
			checkdata_router_post_dst_mac_no_span,
			RD_ARRAYSIZE(checkdata_router_post_dst_mac_no_span)),

		/* SRC MAC */
		TEST_TEMPLATE_FLOW_ALL_SENSORS(NULL, NULL,
			&v10Template, sizeof(v10Template),
			&v10Flow_src_router_mac,
					sizeof(v10Flow_src_router_mac),
			checkdata_router_src_mac_span_true,
			RD_ARRAYSIZE(checkdata_router_src_mac_span_true),
			checkdata_router_src_mac_span_false,
			RD_ARRAYSIZE(checkdata_router_src_mac_span_false),
			checkdata_router_src_mac_no_span,
			RD_ARRAYSIZE(checkdata_router_src_mac_no_span)),

		/* DST MAC */
		TEST_TEMPLATE_FLOW_ALL_SENSORS(NULL, NULL,
			&v10Template, sizeof(v10Template),
			&v10Flow_router_dst_macs,
					sizeof(v10Flow_router_dst_macs),
			checkdata_router_dst_mac_span_true,
			RD_ARRAYSIZE(checkdata_router_dst_mac_span_true),
			checkdata_router_dst_mac_span_false,
			RD_ARRAYSIZE(checkdata_router_dst_mac_span_false),
			checkdata_router_dst_mac_no_span,
			RD_ARRAYSIZE(checkdata_router_dst_mac_no_span)),
	};

	*state = prepare_tests(test_params, RD_ARRAYSIZE(test_params));
	return *state == NULL;
}

int main() {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(testFlow,
					prepare_test_mac_direction, check_flow),
	};

	return cmocka_run_group_tests(tests, nf_test_setup, nf_test_teardown);
}
