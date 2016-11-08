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

#pragma once

#include "rb_json_test.h"

#include "rb_netflow_meta.h"

#include <stdint.h>
#include <string.h>

#ifdef __GNUC__
// For some reason, GCC <= 4.7 does not provide these macros
#if !__GNUC_PREREQ(4,8)
#define __BYTE_ORDER__ __BYTE_ORDER
#define __ORDER_LITTLE_ENDIAN__ __LITTLE_ENDIAN
#define __ORDER_BIG_ENDIAN__ __BIG_ENDIAN
#define __builtin_bswap16(a) (((a)&0xff)<<8u)|((a)>>8u)
#endif // GCC < 4.8
#endif // __GNUC__

#if __BYTE_ORDER__==__ORDER_LITTLE_ENDIAN__
#define constexpr_be16toh(x) __builtin_bswap16(x)
#define constexpr_be32toh(x) __builtin_bswap32(x)
#else
#define constexpr_be16toh(x) (x)
#define constexpr_be32toh(x) (x)
#endif

#define NF5_IP(a, b, c, d) (((a)<<24)|((b)<<16)|((c)<<8)|(d))

// Convert an uint16_t to BIG ENDIAN uint8_t[2] array initializer
#define UINT16_TO_UINT8_ARR(x) ((x)>>8), ((x)&0xff)

#define UINT32_TO_UINT8_ARR(x) \
	UINT16_TO_UINT8_ARR((x)>>16), UINT16_TO_UINT8_ARR((x)&0xffff)

#define UINT64_TO_UINT8_ARR(x) \
	UINT32_TO_UINT8_ARR((x##l)>>32), UINT32_TO_UINT8_ARR((x##l)&0xffffffff)

#define TEMPLATE_ENTITY(entity, len) \
	UINT16_TO_UINT8_ARR(entity), UINT16_TO_UINT8_ARR(len)

#define TEMPLATE_PRIVATE_ENTITY(field_type, len, pen) \
	UINT16_TO_UINT8_ARR(field_type | 0x8000), \
	UINT16_TO_UINT8_ARR(len), UINT32_TO_UINT8_ARR(pen)

#define FLOW_APPLICATION_ID(type, id) UINT32_TO_UINT8_ARR(type<<24 | id)

int nf_test_setup(void **state);

int nf_test_teardown(void **state);

struct nf_test_state {
#define NF_TEST_STATE_MAGIC 0x355AEA1C355AEA1C
	uint64_t magic;
	struct {
		struct test_params {
			const char *config_json_path;
			const char *mac_vendor_database_path;
			const char *host_list_path;
			const char *geoip_path;
			const char *template_save_path;
			const char *zk_url;
			const char *templates_zk_node;

			uint32_t netflow_src_ip;
			uint16_t netflow_dst_port;

			const void *record;
			size_t record_size;

			const struct checkdata *checkdata;
			size_t checkdata_size;
		} *records;
		size_t records_size;
	} params;
	struct {
		struct string_list **sl;
	} ret;
};

struct nf_test_state *prepare_tests(struct test_params *test_params,
						size_t test_params_size);

void testFlow(void **state);

int check_flow(void **state);

/** Try to fail every allocation in testFlow
 * @param vstate Same as testFlow
 */
void mem_test(void **vstate);
