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

#include "rb_netflow_test.h"

#include "f2k.h"

#include <jansson.h>

#include <setjmp.h>
#include <cmocka.h>

static const NetFlow5Record record1 = {
	.flowHeader = {
		.version = constexpr_be16toh(5),          /* Current version=5*/
		.count = constexpr_be16toh(1),            /* The number of records in PDU. */
		.sys_uptime = constexpr_be32toh(1048576000),    /* Current time in msecs since router booted */
		.unix_secs = constexpr_be32toh(1389604720),    /* Current seconds since 0000 UTC 1970 */
		.unix_nsecs = constexpr_be32toh(7954200),   /* Residual nanoseconds since 0000 UTC 1970 */
		.flow_sequence = constexpr_be32toh(48), /* Sequence number of total flows seen */
		.engine_type = 0,     /* Type of flow switching engine (RP,VIP,etc.)*/
		.engine_id  = 0,       /* Slot number of the flow switching engine */
		.sampleRate = 0,      /* Packet capture sample rate */
	},
	.flowRecord = {
		[0] = {
			.srcaddr = 0x08080808L,    /* Source IP Address */
			.dstaddr = 0x0A0A0A0AL,    /* Destination IP Address */
			.nexthop = 0x00000000L,    /* Next hop router's IP Address */
			.input   = 0,              /* Input interface index */
			.output  = 255,            /* Output interface index */
			.dPkts   = constexpr_be32toh(65536),
			.dOctets = constexpr_be32toh(4587520),
			.first   = constexpr_be32toh(1048513918),
			.last    = constexpr_be32toh(1048513918),
			.srcport = constexpr_be16toh(443),
			.dstport = constexpr_be16toh(10101),
			.pad1    = 0,        /* pad to word boundary */
			.tcp_flags = 0,   /* Cumulative OR of tcp flags */
			.proto   = 2,        /* IP protocol, e.g., 6=TCP, 17=UDP, etc... */
			.tos     = 0,         /* IP Type-of-Service */
			.src_as  = 0,     /* source peer/origin Autonomous System */
			.dst_as  = 0,     /* dst peer/origin Autonomous System */
			.src_mask = 0,    /* source route's mask bits */
			.dst_mask = 0,    /* destination route's mask bits */
			.pad2    = 0,       /* pad to word boundary */
		}
	}
};

static const struct checkdata_value checkdata_values[] = {
	{.key="type",.value="netflowv5"},
	{.key="src",.value="8.8.8.8"},
	{.key="dst",.value="10.10.10.10"},
	{.key="input_snmp",.value="0"},
	{.key="output_snmp",.value="65280"},
	{.key="pkts",.value="65536"},
	{.key="bytes",.value="4587520"},
	{.key="tos",.value="0"},
	{.key="src_port",.value="443"},
	{.key="dst_port",.value="10101"},
	{.key="tcp_flags",.value=NULL},
	{.key="l4_proto",.value="2"},
	{.key="engine_type",.value="0"},
	{.key="sensor_ip",.value="4.3.2.1"},
	{.key="first_switched",.value="1389604657"},
	{.key="timestamp",.value="1389604657"},
};

static int prepare_test_nf_v5(void **state) {
	static const struct checkdata checkdata = {
		.checks = checkdata_values,
		.size = RD_ARRAYSIZE(checkdata_values),
	};

	struct test_params test_params[] = {
		[0] = {
			.config_json_path = "./tests/0000-testFlowV5.json",
			.host_list_path = NULL,
			.netflow_src_ip = 0x04030201,
			.record = &record1,
			.record_size = sizeof(record1),
			.checkdata = &checkdata,
			.checkdata_size = 1,
		},
	};

	*state = prepare_tests(test_params, RD_ARRAYSIZE(test_params));
	return *state == NULL;
}

int main() {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup(testFlow, prepare_test_nf_v5),
	};

	return cmocka_run_group_tests(tests, nf_test_setup, nf_test_teardown);
}
