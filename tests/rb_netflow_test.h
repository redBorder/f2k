// rb_netflow_test.c

#pragma once

#include "rb_json_test.h"

#include <stdint.h>
#include <string.h>

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

			uint8_t *record;
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
