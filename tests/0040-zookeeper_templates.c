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
#include "integration_tests.h"
#include "rb_netflow_test.h"

#include <setjmp.h>

#include <cmocka.h>

#include <fts.h>

/*
        @test Extracting client mac based on flow direction
*/

struct TestV10Template {
  IPFIXFlowHeader flowHeader;
  IPFIXSet flowSetHeader;
  V9TemplateDef templateHeader; /* It's the same */
  const uint8_t templateBuffer[92];
};

struct TestV10Flow {
  IPFIXFlowHeader flowHeader;
  IPFIXSet flowSetHeader;
  const uint8_t buffer1[77];
} __attribute__((packed));

static const struct TestV10Template v10Template = {
    .flowHeader =
        {
            /*uint16_t*/.version = 0x0a00, /* Current version=10*/
            /*uint16_t*/.len = 0x7400,     /* The number of records in PDU. */
            /*uint32_t*/.unix_secs =
                0xdd5d6952, /* Current time in msecs since router booted */
            /*uint32_t*/.flow_sequence =
                0x38040000, /* Sequence number of total flows seen */
            /*uint32_t*/.observation_id = 0x00010000, /* Source id */
        },

    .flowSetHeader =
        {
            /*uint16_t*/.set_id = 0x0200,
            /*uint16_t*/.set_len = 0x6400,
        },

    .templateHeader =
        {
            /*uint16_t*/.templateId = 0x0301, /*259*/
            /*uint16_t*/.fieldCount = 0x1300,
        },

    .templateBuffer =
        {
            0x00, 0x08, 0x00, 0x04, /* SRC ADDR */
            0x00, 0x0c, 0x00, 0x04, /* DST ADDR */
            0x00, 0x3c, 0x00, 0x01, /* IP VERSION */
            0x00, 0x04, 0x00, 0x01, /* PROTO */
            0x00, 0x07, 0x00, 0x02, /* SRC PORT */
            0x00, 0x0b, 0x00, 0x02, /* DST PORT */
            0x00, 0x88, 0x00, 0x01, /* flowEndreason */
            0x00, 0xef, 0x00, 0x01, /* biflowDirection */
            0x00, 0x30, 0x00, 0x01, /* FLOW_SAMPLER_ID */
            0x01, 0x18, 0x00, 0x08, /* TRANSACTION_ID */
            0x00, 0x5f, 0x00, 0x04, /* APPLICATION ID*/
            0xaf, 0xcb, 0xff, 0xff,
            0x00, 0x00, 0x00, 0x09, /* CISCO_URL, variable length */
            0xaf, 0xcb, 0xff, 0xff,
            0x00, 0x00, 0x00, 0x09, /* CISCO_URL, variable length */
            0xaf, 0xcb, 0xff, 0xff,
            0x00, 0x00, 0x00, 0x09, /* CISCO_URL, variable length */
            0xaf, 0xcb, 0xff, 0xff,
            0x00, 0x00, 0x00, 0x09, /* CISCO_URL, variable length */
            0x00, 0x01, 0x00, 0x08, /* BYTES: */
            0x00, 0x02, 0x00, 0x04, /* PKTS*/
            0x00, 0x16, 0x00, 0x04, /* FIRST_SWITCHED */
            0x00, 0x15, 0x00, 0x04, /* LAST_SWITCHED*/
        }};

static const struct TestV10Flow v10Flow = {
    .flowHeader =
        {
            /*uint16_t*/.version = 0x0a00, /* Current version=9*/
            /*uint16_t*/.len = 0x6100,     /* The number of records in PDU. */
            /*uint32_t*/.unix_secs =
                0xdd5d6952, /* Current time in msecs since router booted */
            /*uint32_t*/.flow_sequence =
                0x38040000, /* Sequence number of total flows seen */
            /*uint32_t*/.observation_id = 0x00010000, /* Source id */
        },

    .flowSetHeader =
        {
            /*uint16_t*/.set_id = 0x0301,
            /*uint16_t*/.set_len = 0x5100,
        },

    .buffer1 =
        {
            0x0a, 0x0d, 0x7a, 0x2c, /* SRC ADDR 10.13.122.44 */
            0x42, 0xdc, 0x98, 0x13, /* DST ADDR 66.220.152.19*/
            0x04,                   /* IP VERSION: 4 */
            0x06,                   /* PROTO: 6 */
            0xd5, 0xb9,             /* SRC PORT: 54713 */
            0x01, 0xbb,             /* DST PORT: 443 */
            0x03,                   /* flowEndreason */
            0x01,                   /* biflowDirection */
            0x00,                   /* FLOW_SAMPLER_ID */
            0x8f, 0x63, 0xf3, 0x40, 0x00, 0x01, 0x00, 0x00, /* TRANSACTION_ID */
            0x0d, 0x00, 0x01, 0xc5, /* APPLICATION ID 13:453 */
            0x06, 0x03, 0x00, 0x00, 0x50, 0x34, 0x01,       /* CISCO_URL */
            0x06, 0x03, 0x00, 0x00, 0x50, 0x34, 0x02,       /* CISCO_URL */
            0x06, 0x03, 0x00, 0x00, 0x50, 0x34, 0x03,       /* CISCO_URL */
            0x06, 0x03, 0x00, 0x00, 0x50, 0x34, 0x04,       /* CISCO_URL */
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0xb8, /* BYTES: 2744 */
            0x00, 0x00, 0x00, 0x1f,                         /* PKTS: 31*/
            0x0f, 0xed, 0x0a, 0xc0, /* FIRST_SWITCHED:  */
            0x0f, 0xee, 0x18, 0x00, /* LAST_SWITCHED: */
        },
};

#ifdef TESTS_ZK_HOST
static int prepare_test_nf_template_save0(void **state, const void *record,
                                          size_t record_size,
                                          const struct checkdata *checkdata,
                                          size_t checkdata_sz) {
  struct test_params test_params = {.config_json_path =
                                        "./tests/0000-testFlowV5.json",
                                    .zk_url = TESTS_ZK_HOST,
                                    .templates_zk_node = "/f2k/templates",
                                    .netflow_src_ip = 0x04030201,
                                    .record = record,
                                    .record_size = record_size,
                                    .checkdata = checkdata,
                                    .checkdata_size = checkdata_sz};

  *state = prepare_tests(&test_params, 1);
  return *state == NULL;
}

static int prepare_test_nf_template_save(void **state) {
  SKIP_IF_NOT_INTEGRATION;

  return prepare_test_nf_template_save0(state, &v10Template,
                                        sizeof(v10Template), NULL, 0);
}

static int prepare_test_nf_template_load(void **state) {
  SKIP_IF_NOT_INTEGRATION;

  static const struct checkdata_value checkdata_value[] = {
      {.key = "type", .value = "netflowv10"},
      {.key = "flow_sequence", .value = "1080"},
      {.key = "src", .value = "10.13.122.44"},
      {.key = "dst", .value = "66.220.152.19"},
      {.key = "ip_protocol_version", .value = "4"},
      {.key = "l4_proto", .value = "6"},
      {.key = "src_port", .value = "54713"},
      {.key = "dst_port", .value = "443"},
      {.key = "biflow_direction", .value = "initiator"},
      {.key = "sensor_name", .value = "FlowTest"},
      {.key = "sensor_ip", .value = "4.3.2.1"},
      {.key = "first_switched", .value = "1382636953"},
      {.key = "timestamp", .value = "1382637021"},
      {.key = "bytes", .value = "2744"},
      {.key = "pkts", .value = "31"},
  };

  static const struct checkdata checkdata = {
      .size = RD_ARRAYSIZE(checkdata_value), .checks = checkdata_value};

  return prepare_test_nf_template_save0(state, &v10Flow, sizeof(v10Flow),
                                                                &checkdata, 1);
}
#else // TESTS_ZK_HOST

static void skip_test() { skip(); }

#endif // TESTS_ZK_HOST

int main() {
#ifdef TESTS_ZK_HOST
  const struct CMUnitTest tests[] = {
      cmocka_unit_test_setup(testFlow, prepare_test_nf_template_save),
      cmocka_unit_test_setup(testFlow, prepare_test_nf_template_load),
  };
  return cmocka_run_group_tests(tests, nf_test_setup, nf_test_teardown);
#else
  const struct CMUnitTest tests[] = {cmocka_unit_test(skip_test)};
  return cmocka_run_group_tests(tests, NULL, NULL);
#endif // TESTS_ZK_HOST
}
