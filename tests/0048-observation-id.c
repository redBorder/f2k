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

/* ******************************* NETFLOW V5 ******************************* */

/// Test default NF5 header
#define NF5_RECORD_HEADER_DEFAULTS \
	.version = constexpr_be16toh(5), \
	.sys_uptime = constexpr_be32toh(12345), \
	.unix_secs = constexpr_be32toh(12345), \
	.unix_nsecs = constexpr_be32toh(12345), \
	.flow_sequence = constexpr_be32toh(1050), \
	.sampleRate = constexpr_be16toh(0)

/// Test default NF5 record with parametrized src and dst address
#define NF5_RECORD_ADDR(...) { \
	.srcaddr = NF5_IP(10, 13, 0, 1), .dstaddr = NF5_IP(10, 14, 0, 1), \
	.input   = constexpr_be16toh(0), .output  = constexpr_be16toh(255), \
	.first   = 0xa8484205, .last    = 0xa8484205, \
	.srcport = constexpr_be16toh(443), \
	.dstport = constexpr_be16toh(10101), \
	__VA_ARGS__ }

#define NF5_RECORD(mengine_type, mengine_id, ...) { \
	.flowHeader = { NF5_RECORD_HEADER_DEFAULTS, \
		.count = constexpr_be16toh(1), \
		.engine_type = mengine_type, .engine_id  = mengine_id}, \
	.flowRecord = { \
		NF5_RECORD_ADDR(__VA_ARGS__)}}

static const NetFlow5Record record_obs_id_1 = NF5_RECORD(0, 1,
	.dPkts = constexpr_be32toh(1),
	.dOctets = constexpr_be32toh(88));
static const NetFlow5Record record_obs_id_2 = NF5_RECORD(0, 2,
	.dPkts = constexpr_be32toh(2),
	.dOctets = constexpr_be32toh(10));

/* ******************************* NETFLOW V9 ******************************* */

#define FLOW_ADDR_BASE(RT, R) \
	RT(IPV4_SRC_ADDR, 4, 0, 10, 13, 0, 1) \
	RT(IPV4_DST_ADDR, 4, 0, 10, 14, 0, 1) \

#define FLOW_ENTITIES_OBSERVATION_ID_1(RT, R) FLOW_ADDR_BASE(RT, R) \
	RT(IN_PKTS, 4, 0, UINT32_TO_UINT8_ARR(1)) \
	RT(IN_BYTES, 4, 0, UINT32_TO_UINT8_ARR(88)) \

// Changing template order in observation id 2
#define FLOW_ENTITIES_OBSERVATION_ID_2(RT, R) FLOW_ADDR_BASE(RT, R) \
	RT(IN_BYTES, 4, 0, UINT32_TO_UINT8_ARR(10)) \
	RT(IN_PKTS, 4, 0, UINT32_TO_UINT8_ARR(2)) \

#define TEST_FLOW_HEADER(mobsrvation_id) \
	.unix_secs = constexpr_be32toh(1467220140), \
	.flow_sequence = constexpr_be32toh(12372811), \
	.observation_id = constexpr_be32toh(mobsrvation_id)

#define TEST_TEMPLATE_ID 1025

static const IPFIX_TEMPLATE(ipfix_template_oid_1, TEST_FLOW_HEADER(1),
		TEST_TEMPLATE_ID, FLOW_ENTITIES_OBSERVATION_ID_1);
static const IPFIX_TEMPLATE(ipfix_template_oid_2, TEST_FLOW_HEADER(2),
		TEST_TEMPLATE_ID, FLOW_ENTITIES_OBSERVATION_ID_2);

static const IPFIX_FLOW(ipfix_flow_oid_1, TEST_FLOW_HEADER(1),
		TEST_TEMPLATE_ID, FLOW_ENTITIES_OBSERVATION_ID_1);
static const IPFIX_FLOW(ipfix_flow_oid_2, TEST_FLOW_HEADER(2),
		TEST_TEMPLATE_ID, FLOW_ENTITIES_OBSERVATION_ID_2);

/* ********************************* CHECKS ********************************* */

static const struct checkdata_value checkdata_values_obs_id_1[] = {
	// Test observation id enrichment
	{.key = "observation_id", .value="observation_1"},

	// Test observation id home nets
	{.key = "dst_net", .value="10.14.0.0/16"},
	{.key = "dst_net_name", .value="users14"},

	// Test observation ID templates
	{.key = "pkts", .value = "1"},
	{.key = "bytes", .value = "88"},
};

// Same comments of checkdata_values_obs_id_1
static const struct checkdata_value checkdata_values_obs_id_2[] = {
	{.key = "observation_id", .value="default"},

	{.key = "src_net", .value="10.13.0.0/16"},
	{.key = "src_net_name", .value="users13"},

	{.key = "pkts", .value = "2"},
	{.key = "bytes", .value = "10"},
};

static int prepare_test_observation_id_enrichment(void **state) {


#define CHECKDATA(checkdata_values) { \
	.checks = checkdata_values, .size = RD_ARRAYSIZE(checkdata_values) }

	static const struct checkdata checkdata_oid1 =
		CHECKDATA(checkdata_values_obs_id_1);

	static const struct checkdata checkdata_oid2 =
		CHECKDATA(checkdata_values_obs_id_2);

#define TEST(mrecord, mrecord_size, checks, checks_size, ...) {                \
		.netflow_src_ip = 0x04030201,                                  \
		.record = mrecord, .record_size = mrecord_size,                \
		.checkdata = checks, .checkdata_size = checks_size,            \
		__VA_ARGS__ }

	struct test_params test_params[] = {
		// NF5
		TEST(&record_obs_id_1, sizeof(record_obs_id_1),
			&checkdata_oid1, 1,
			.config_json_path = "./tests/0048-observation-id.json"),
		TEST(&record_obs_id_2, sizeof(record_obs_id_2),
			&checkdata_oid2, 1, ),

		// IPFIX templates, in different oids
		TEST(&ipfix_template_oid_1, sizeof(ipfix_template_oid_1),
			NULL, 0, ),
		TEST(&ipfix_template_oid_2, sizeof(ipfix_template_oid_2),
			NULL, 0, ),

		// IPFIX flows, different observations id
		TEST(&ipfix_flow_oid_1, sizeof(ipfix_flow_oid_1),
			&checkdata_oid1, 1, ),
		TEST(&ipfix_flow_oid_2, sizeof(ipfix_flow_oid_2),
			&checkdata_oid2, 1, ),
	};

	*state = prepare_tests(test_params, RD_ARRAYSIZE(test_params));
	return *state == NULL;
}

int main() {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup(testFlow,
			prepare_test_observation_id_enrichment),
	};

	return cmocka_run_group_tests(tests, nf_test_setup, nf_test_teardown);
}
