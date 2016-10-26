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

static const NetFlow5Record record = {
	.flowHeader = {
		.version = 0x0500,     /* Current version=5*/
		.count = 0x0100,       /* The number of records in PDU. */
		.sysUptime = 12345,    /* Current time in msecs since router booted */
		.unix_secs = 12345,    /* Current seconds since 0000 UTC 1970 */
		.unix_nsecs = 12345,   /* Residual nanoseconds since 0000 UTC 1970 */
		.flow_sequence = 1050, /* Sequence number of total flows seen */
		.engine_type = 0,      /* Type of flow switching engine (RP,VIP,etc.)*/
		.engine_id  = 0,       /* Slot number of the flow switching engine */
		.sampleRate = 0,       /* Packet capture sample rate */
	},

	.flowRecord = {
		/* Second: Source belongs to home net from ANOTHER sensors */
		[0] = {
			.srcaddr = 0x0a1e000aL,    /* Source IP Address */
			.dstaddr = 0x0201a8c0L,    /* Destination IP Address */
			.nexthop = 0x00000000L,    /* Next hop router's IP Address */
			.input   = 0,              /* Input interface index */
			.output  = 255,            /* Output interface index */
			.dPkts   = 0x0100,              /* Packets sent in Duration (milliseconds between 1st
			                             & last packet in this flow)*/
			.dOctets = 0x4600,             /* Octets sent in Duration (milliseconds between 1st
			                             & last packet in  this flow)*/
			.first   = 0xa8484205,     /* SysUptime at start of flow */
			.last    = 0xa8484205,     /* and of last packet of the flow */
			.srcport = 0xbb01,     /* ntohs(443)  */  /* TCP/UDP source port number (.e.g, FTP, Telnet, etc.,or equivalent) */
			.dstport = 0x7527,   /* ntohs(10101)*/  /* TCP/UDP destination port number (.e.g, FTP, Telnet, etc.,or equivalent) */
			.pad1    = 0,        /* pad to word boundary */
			.tcp_flags = 0,   /* Cumulative OR of tcp flags */
			.proto   = 0,     /* IP protocol, e.g., 6=TCP, 17=UDP, etc... */
			.tos     = 0,     /* IP Type-of-Service */
			.src_as  = 0,     /* source peer/origin Autonomous System */
			.dst_as  = 0,     /* dst peer/origin Autonomous System */
			.src_mask = 0,    /* source route's mask bits */
			.dst_mask = 0,    /* destination route's mask bits */
			.pad2    = 0,       /* pad to word boundary */
		},
	}
};

static const struct checkdata_value checkdata_values_2055[] = {
	{.key = "sensor_name", .value = "test1"},
	{.key = "sensor_ip", .value = "4.3.2.0/24"}
};

static const struct checkdata_value checkdata_values_2056[] = {
	{.key = "sensor_name", .value = "test2"},
	{.key = "sensor_ip", .value = "4.3.2.0/24"}
};

static int prepare_test_port_direction(void **state) {
	static const struct checkdata checkdata_2055 = {
		.checks=checkdata_values_2055,
		.size = RD_ARRAYSIZE(checkdata_values_2055),
	};

	static const struct checkdata checkdata_2056 = {
		.checks=checkdata_values_2056,
		.size = RD_ARRAYSIZE(checkdata_values_2056),
	};

#define TEST(config_path, port, mrecord, mrecord_size, checks, checks_size) {  \
		.config_json_path = config_path,                               \
		.netflow_src_ip = 0x04030201, .netflow_dst_port = port,        \
		.record = mrecord, .record_size = mrecord_size,                \
		.checkdata = checks, .checkdata_size = checks_size             \
	}

	struct test_params test_params[] = {
		TEST("./tests/0032-portBasedDisection.json",
				2055, (uint8_t *)&record, sizeof(record),
				&checkdata_2055, 1),
		TEST(NULL, 2056, (uint8_t *)&record, sizeof(record),
				&checkdata_2056, 1)
	};

	*state = prepare_tests(test_params, RD_ARRAYSIZE(test_params));
	return *state == NULL;
}

int main() {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(testFlow,
				prepare_test_port_direction, check_flow),
	};

	return cmocka_run_group_tests(tests, nf_test_setup, nf_test_teardown);
}
