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

#define TEST_IPFIX_FLOW_HEADER  \
	.unix_secs = 0xdd5d6952, \
	.flow_sequence = 0x38040000, \
	.observation_id = 0x00010000,

#define IPFIX_TEMPLATE_ID 0x0200

/// @todo handle case of >255
#define ARGS(...) __VA_ARGS__
#define CISCO_DPI_LEN(HOST) 6+sizeof((uint8_t[]) {HOST})
#define CISCO_DPI_FIELD(ID, ...) CISCO_DPI_LEN(ARGS(__VA_ARGS__)), ID, \
	__VA_ARGS__
#define CISCO_DPI_EMPTY_FIELD(ID) 0x06, ID

#define CISCO_HTTP_ID    0x03, 0x00, 0x00, 0x50, 0x34
#define CISCO_HTTP_URL_ID     CISCO_HTTP_ID, 0x01
#define CISCO_HTTP_HOST_ID    CISCO_HTTP_ID, 0x02
#define CISCO_HTTP_UA_ID      CISCO_HTTP_ID, 0x03
#define CISCO_HTTP_REFERER_ID CISCO_HTTP_ID, 0x04
#define CISCO_SSL_CN_ID  0x0d, 0x00, 0x01, 0xc5, 0x34, 0x01

#define CISCO_HTTP_URL(...)  CISCO_DPI_FIELD(CISCO_HTTP_URL_ID, __VA_ARGS__)
#define CISCO_HTTP_HOST(...) CISCO_DPI_FIELD(CISCO_HTTP_HOST_ID, __VA_ARGS__)
#define CISCO_HTTP_UA(...)   CISCO_DPI_FIELD(CISCO_HTTP_UA_ID, __VA_ARGS__)
#define CISCO_HTTP_REFERER(...) \
	CISCO_DPI_FIELD(CISCO_HTTP_REFERER_ID, __VA_ARGS__)
#define CISCO_SSL_CN(...)    CISCO_DPI_FIELD(CISCO_SSL_CN_ID, __VA_ARGS__)

#define T_CISCO_URL CISCO_HTTP_URL('/', \
		'p',  'r',  'o',  'f',  'i',  'l',  'e',  's', \
		'/',  'p',  'r',  'o',  'f',  'i',  'l',  'e', \
		'_',  '1',  '2',  '3',  '4',  '5',  '6',  '7', \
		'7',  '_',  '7',  '5',  's',  'q',  '_',  '1', \
		'1',  '2',  '3',  '4',  '5',  '6',  '7',  '8', \
		'2',  '.',  'j',  'p',  'g')

#define T_CISCO_HOST CISCO_HTTP_HOST('i', \
		'm', 'a', 'g', 'e', 's', '.', 'a', 'k', \
		'.', 'i', 'n', 's', 't', 'a', 'g', 'r', \
		'a', 'm', '.', 'c', 'o', 'm')

#define CISCO_DOT_L2_HOST CISCO_HTTP_HOST('.', \
		'i', 'n', 's', 't', 'a', 'g', 'r', 'a', \
		'm', '.', 'c', 'o', 'm')

#define CISCO_DOT_L1_HOST CISCO_HTTP_HOST('.', 'c', 'o', 'm')
#define CISCO_L1_HOST CISCO_HTTP_HOST('c', 'o', 'm')

#define CISCO_L2_HOST0 'i', \
		'n', 's', 't', 'a', 'g', 'r', 'a', 'm', \
		'.', 'c', 'o', 'm'

#define HTTP_PROTO 'h','t','t','p',':','/','/'
#define HTTPS_PROTO 'h','t','t','p','s',':','/','/'
#define EXAMPLE_URL '/','i','n','d','e','x','.','p','h','p'

#define T_CISCO_L2_HOST CISCO_HTTP_HOST(CISCO_L2_HOST0)
#define CISCO_L2_HOST_H CISCO_HTTP_HOST(HTTP_PROTO, CISCO_L2_HOST0)
#define CISCO_L2_HOST_HS CISCO_HTTP_HOST(HTTPS_PROTO, CISCO_L2_HOST0)
#define CISCO_L2_HOST_U CISCO_HTTP_HOST(CISCO_L2_HOST0, EXAMPLE_URL)
#define CISCO_L2_HOST_HU CISCO_HTTP_HOST(HTTP_PROTO, CISCO_L2_HOST0, \
	EXAMPLE_URL)
#define CISCO_L2_HOST_HSU CISCO_HTTP_HOST(HTTPS_PROTO, CISCO_L2_HOST0, \
	EXAMPLE_URL)

#define T_CISCO_UA CISCO_HTTP_UA('I', \
		'n',  's',  't',  'a',  'g',  'r',  'a',  'm', \
		' ',  '4',  '.',  '2',  '.',  '3',  ' ',  '(', \
		'i',  'P',  'h',  'o',  'n',  'e',  '5',  ',', \
		'1',  ';',  ' ',  'i',  'P',  'h',  'o',  'n', \
		'e',  ' ',  'O',  'S',  ' ',  '7',  '_',  '0', \
		'_',  '2',  ';',  ' ',  'e',  'n',  '_',  'U', \
		'S',  ';',  ' ',  'e',  'n',  ')',  ' ',  'A', \
		'p',  'p',  'l',  'e',  'W',  'e',  'b',  'K', \
		'i',  't',  '/',  '4',  '2',  '0',  '+')

#define T_CISCO_REFERER0 \
	'w','w','w','.','e','l','m','u','n','d','o','.','e','s'
#define T_CISCO_REFERER CISCO_HTTP_REFERER(T_CISCO_REFERER0)
#define T_CISCO_REFERER_H CISCO_HTTP_REFERER(HTTP_PROTO, T_CISCO_REFERER0)
#define T_CISCO_REFERER_HS CISCO_HTTP_REFERER(HTTPS_PROTO, T_CISCO_REFERER0)
#define T_CISCO_REFERER_U CISCO_HTTP_REFERER(T_CISCO_REFERER0, EXAMPLE_URL)
#define T_CISCO_REFERER_HU CISCO_HTTP_REFERER(HTTP_PROTO, T_CISCO_REFERER0, \
	EXAMPLE_URL)
#define T_CISCO_REFERER_HSU CISCO_HTTP_REFERER(HTTPS_PROTO, T_CISCO_REFERER0, \
	EXAMPLE_URL)

#define T_CISCO_SSL_CN0 \
	'w','w','w','.','e','x','a','m','p','l','e','.','c','o','m'
#define T_CISCO_SSL_CN CISCO_SSL_CN(T_CISCO_SSL_CN0)
#define T_CISCO_SSL_CN_H CISCO_SSL_CN(HTTP_PROTO, T_CISCO_SSL_CN0)
#define T_CISCO_SSL_CN_HS CISCO_SSL_CN(HTTPS_PROTO, T_CISCO_SSL_CN0)
#define T_CISCO_SSL_CN_U CISCO_SSL_CN(T_CISCO_SSL_CN0, EXAMPLE_URL)
#define T_CISCO_SSL_CN_HU CISCO_SSL_CN(HTTP_PROTO, T_CISCO_SSL_CN0, \
	EXAMPLE_URL)
#define T_CISCO_SSL_CN_HSU CISCO_SSL_CN(HTTPS_PROTO, T_CISCO_SSL_CN0, \
	EXAMPLE_URL)

#define EMPTY_CISCO_SSL_CN CISCO_DPI_EMPTY_FIELD(CISCO_SSL_CN_ID)
#define EMPTY_CISCO_HOST CISCO_DPI_EMPTY_FIELD(CISCO_HTTP_HOST_ID)
#define EMPTY_CISCO_REFERER CISCO_DPI_EMPTY_FIELD(CISCO_HTTP_REFERER_ID)

#define TEST_EXPECTED_IPv4 "192.168.1.2"
#define IPv4_HTTP_ADDR '1','9','2','.','1','6','8','.','1','.','2'
#define TEST_EXPECTED_IPv6 "2001:0db8:0000:0000:0000:ff00:0042:8329"
#define IPv6_HTTP_ADDR '2','0','0','1',':','0','d','b','8',':', \
		       '0','0','0','0',':','0','0','0','0',':', \
		       '0','0','0','0',':','f','f','0','0',':', \
		       '0','0','4','2',':','8','3','2','9'
#define TEST_EXPECTED_LONG "2001:0db8:0000:0000:0000:ff00:0042:8329:long"
// Definitely not an ipv6 address because is too long!
#define LONG_HTTP_ADDR '2','0','0','1',':','0','d','b','8',':', \
		       '0','0','0','0',':','0','0','0','0',':', \
		       '0','0','0','0',':','f','f','0','0',':', \
		       '0','0','4','2',':','8','3','2','9',':', \
		       'l','o','n','g'

#define T_CISCO_IPv4_HOST CISCO_HTTP_HOST(IPv4_HTTP_ADDR)
#define CISCO_IPv4_HOST_H CISCO_HTTP_HOST(HTTP_PROTO, IPv4_HTTP_ADDR)
#define CISCO_IPv4_HOST_HS CISCO_HTTP_HOST(HTTPS_PROTO, IPv4_HTTP_ADDR)
#define CISCO_IPv4_HOST_U CISCO_HTTP_HOST(IPv4_HTTP_ADDR, EXAMPLE_URL)
#define CISCO_IPv4_HOST_HU \
	CISCO_HTTP_HOST(HTTP_PROTO, IPv4_HTTP_ADDR, EXAMPLE_URL)
#define CISCO_IPv4_HOST_HSU \
	CISCO_HTTP_HOST(HTTPS_PROTO, IPv4_HTTP_ADDR, EXAMPLE_URL)
#define CISCO_LONG_HOST CISCO_HTTP_HOST(LONG_HTTP_ADDR)

#define T_CISCO_IPv6_REFERER CISCO_HTTP_REFERER(IPv6_HTTP_ADDR)
#define CISCO_IPv6_REFERER_H CISCO_HTTP_REFERER(HTTP_PROTO, IPv6_HTTP_ADDR)
#define CISCO_IPv6_REFERER_HS \
	CISCO_HTTP_REFERER(HTTPS_PROTO, IPv6_HTTP_ADDR)
#define CISCO_IPv6_REFERER_U \
	CISCO_HTTP_REFERER(IPv6_HTTP_ADDR, EXAMPLE_URL)
#define CISCO_IPv6_REFERER_HU CISCO_HTTP_REFERER(HTTP_PROTO, \
	IPv6_HTTP_ADDR, EXAMPLE_URL)
#define CISCO_IPv6_REFERER_HSU CISCO_HTTP_REFERER(HTTPS_PROTO, \
	IPv6_HTTP_ADDR, EXAMPLE_URL)


/*
	Regression test 1:
	Bad h1/h2 domain detection: it detects point in next field as own field
	(buffer overflow)

	Regression test 2:
	Bad l2 identification if only one dot: l2_d.l1_d
 */

#define BASE_ENTITIES(X, T_CISCO_URL, T_CISCO_HOST, T_CISCO_UA, \
		T_CISCO_REFERER, T_CISCO_SSL_CN, T_BYTES, T_PKTS) \
	X(IPV4_SRC_ADDR, 4, 0, 10, 13, 122, 44) \
	X(IPV4_DST_ADDR, 4, 0, 66, 220, 152, 19) \
	X(IP_PROTOCOL_VERSION, 1, 0, 4) \
	X(PROTOCOL, 1, 0, 6) \
	X(L4_SRC_PORT, 2, 0, UINT16_TO_UINT8_ARR(54713)) \
	X(L4_DST_PORT, 2, 0, UINT16_TO_UINT8_ARR(443)) \
	X(FLOW_END_REASON, 1, 0, 3) \
	X(BIFLOW_DIRECTION, 1, 0, 1) \
	X(FLOW_SAMPLER_ID, 1, 0, 0) \
	X(TRANSACTION_ID, 8, 0, 0x8f, 0x63, 0xf3, 0x40, \
				0x00, 0x01, 0x00, 0x00) \
	X(APPLICATION_ID, 4, 0, FLOW_APPLICATION_ID(13, 459)) \
	X(CISCO_URL, 0xffff, 9, T_CISCO_SSL_CN) \
	X(CISCO_URL, 0xffff, 9, T_CISCO_URL) \
	X(CISCO_URL, 0xffff, 9, T_CISCO_HOST) \
	X(CISCO_URL, 0xffff, 9, T_CISCO_UA) \
	X(CISCO_URL, 0xffff, 9, T_CISCO_REFERER) \
	X(IN_BYTES, 8, 0, T_BYTES) \
	X(IN_PKTS, 4, 0, T_PKTS) \
	X(FIRST_SWITCHED, 4, 0, 0x0f, 0xed, 0x0a, 0xc0) \
	X(LAST_SWITCHED, 4, 0, 0x0f, 0xee, 0x18, 0x00)

#define BASE_PKTS  UINT32_TO_UINT8_ARR(31)
#define BASE_BYTES UINT64_TO_UINT8_ARR(2744)
#define PKTS_AS_DOTS  '.', '.', '.', '.'
#define BYTES_AS_DOTS '.', '.', '.', '.', '.', '.', '.', '.'

// check l2 extraction
#define L2_ENTITIES(RT, R) \
	BASE_ENTITIES(RT, T_CISCO_URL, T_CISCO_HOST, T_CISCO_UA, \
		EMPTY_CISCO_REFERER, EMPTY_CISCO_SSL_CN, BASE_BYTES, \
		BASE_PKTS) \
	/* Regression test 1 */ \
	BASE_ENTITIES(R, T_CISCO_URL, T_CISCO_UA, EMPTY_CISCO_REFERER, \
		T_CISCO_HOST, EMPTY_CISCO_SSL_CN, BYTES_AS_DOTS, PKTS_AS_DOTS) \
	/* Regression test 2 */ \
	BASE_ENTITIES(R, T_CISCO_URL, CISCO_L1_HOST, T_CISCO_UA, \
		EMPTY_CISCO_REFERER, EMPTY_CISCO_SSL_CN, BASE_BYTES, \
		BASE_PKTS) \
	BASE_ENTITIES(R, T_CISCO_URL, CISCO_DOT_L1_HOST, T_CISCO_UA, \
		EMPTY_CISCO_REFERER, EMPTY_CISCO_SSL_CN, BASE_BYTES, \
		BASE_PKTS) \
	BASE_ENTITIES(R, T_CISCO_URL, T_CISCO_L2_HOST, T_CISCO_UA, \
		EMPTY_CISCO_REFERER, EMPTY_CISCO_SSL_CN, BASE_BYTES, \
		BASE_PKTS) \
	BASE_ENTITIES(R, T_CISCO_URL, CISCO_DOT_L2_HOST, T_CISCO_UA, \
		EMPTY_CISCO_REFERER, EMPTY_CISCO_SSL_CN, BASE_BYTES, \
		BASE_PKTS)

/// @TODO add user agent
#define CHECKDATA_BASE \
	{.key = "type", .value="netflowv10"}, \
	{.key = "http_url", \
		.value = "/profiles/profile_12345677_75sq_1123456782.jpg"}, \
	{.key = "http_user_agent", \
		.value = "Instagram 4.2.3 " \
		       "(iPhone5,1; iPhone OS 7_0_2; en_US; en) " \
			"AppleWebKit/420+"}

static const struct checkdata_value checkdata_values_fullhost[] = {
	CHECKDATA_BASE,
	{.key = "http_host", .value="images.ak.instagram.com"},
	{.key = "http_host_l2", .value="instagram.com"},
	{.key = "http_referer", .value=NULL},
	{.key = "host", .value = "images.ak.instagram.com"},
	{.key = "host_l2_domain", .value = "instagram.com"},
	{.key = "referer", .value = "images.ak.instagram.com"},
	{.key = "referer_l2", .value = "instagram.com"},
};

static const struct checkdata_value checkdata_values_l1host[] = {
	CHECKDATA_BASE,
	{.key = "http_host", .value="com"},
	{.key = "http_host_l2", .value="com"},
};

static const struct checkdata_value checkdata_values_dotl1host[] = {
	CHECKDATA_BASE,
	{.key = "http_host", .value=".com"},
	{.key = "http_host_l2", .value="com"},
};

static const struct checkdata_value checkdata_values_l2host[] = {
	CHECKDATA_BASE,
	{.key = "http_host", .value="instagram.com"},
	{.key = "http_host_l2", .value="instagram.com"},
};

static const struct checkdata_value checkdata_values_dotl2host[] = {
	CHECKDATA_BASE,
	{.key = "http_host", .value=".instagram.com"},
	{.key = "http_host_l2", .value="instagram.com"},
};

// check the field (referer, host, ssl_cname)
#define HOST_REFERER_ENTITIES(RT, R) \
	/* (0, 0, 0) -> no referer, no host, no ssl cn */ \
	BASE_ENTITIES(RT, T_CISCO_URL, EMPTY_CISCO_HOST, T_CISCO_UA, \
		EMPTY_CISCO_REFERER, EMPTY_CISCO_SSL_CN, BASE_BYTES, \
		BASE_PKTS) \
	/* (0, 0, 1) -> no referer, no host, ssl_cn */ \
	BASE_ENTITIES(RT, T_CISCO_URL, EMPTY_CISCO_HOST, T_CISCO_UA, \
		EMPTY_CISCO_REFERER, T_CISCO_SSL_CN, BASE_BYTES, \
		BASE_PKTS) \
	/* (0, 1, 0) -> no referer, host, no ssl_cn */ \
	BASE_ENTITIES(RT, T_CISCO_URL, T_CISCO_HOST, T_CISCO_UA, \
		EMPTY_CISCO_REFERER, EMPTY_CISCO_SSL_CN, BASE_BYTES, \
		BASE_PKTS) \
	/* (0, 1, 1) -> no referer, host, no ssl_cn */ \
	BASE_ENTITIES(RT, T_CISCO_URL, T_CISCO_HOST, T_CISCO_UA, \
		EMPTY_CISCO_REFERER, T_CISCO_SSL_CN, BASE_BYTES, \
		BASE_PKTS) \
	/* (1, 0, 0) -> referer, no host, no ssl cn */ \
	BASE_ENTITIES(RT, T_CISCO_URL, EMPTY_CISCO_HOST, T_CISCO_UA, \
		T_CISCO_REFERER, EMPTY_CISCO_SSL_CN, BASE_BYTES, \
		BASE_PKTS) \
	/* (1, 0, 1) -> referer, no host, ssl_cn */ \
	BASE_ENTITIES(RT, T_CISCO_URL, EMPTY_CISCO_HOST, T_CISCO_UA, \
		T_CISCO_REFERER, T_CISCO_SSL_CN, BASE_BYTES, \
		BASE_PKTS) \
	/* (1, 1, 0) -> referer, host, no ssl_cn */ \
	BASE_ENTITIES(RT, T_CISCO_URL, T_CISCO_HOST, T_CISCO_UA, \
		T_CISCO_REFERER, EMPTY_CISCO_SSL_CN, BASE_BYTES, \
		BASE_PKTS) \
	/* (1, 1, 1) -> referer, host, ssl_cn */ \
	BASE_ENTITIES(RT, T_CISCO_URL, T_CISCO_HOST, T_CISCO_UA, \
		T_CISCO_REFERER, T_CISCO_SSL_CN, BASE_BYTES, \
		BASE_PKTS) \

static const struct checkdata_value checkdata_values_hrd_000[] = {
	CHECKDATA_BASE,
	{.key = "https_common_name", .value = NULL},
	{.key = "http_host",         .value = NULL},
	{.key = "http_host_l2",      .value = NULL},
	{.key = "http_referer",      .value = NULL},
	{.key = "host",              .value = NULL},
	{.key = "host_l2_domain",    .value = NULL},
	{.key = "referer",           .value = NULL},
	{.key = "referer_l2",        .value = NULL},
};

static const struct checkdata_value checkdata_values_hrd_001[] = {
	CHECKDATA_BASE,
	{.key = "https_common_name", .value = "www.example.com"},
	{.key = "http_host",         .value = NULL},
	{.key = "http_host_l2",      .value = NULL},
	{.key = "http_referer",      .value = NULL},
	{.key = "host",              .value = "www.example.com"},
	{.key = "host_l2_domain",    .value = "example.com"},
	{.key = "referer",           .value = "www.example.com"},
	{.key = "referer_l2",        .value = "example.com"},
};

static const struct checkdata_value checkdata_values_hrd_010[] = {
	CHECKDATA_BASE,
	{.key = "https_common_name", .value = NULL},
	{.key = "http_host",         .value = "images.ak.instagram.com"},
	{.key = "http_host_l2",      .value = "instagram.com"},
	{.key = "http_referer",      .value = NULL},
	{.key = "host",              .value = "images.ak.instagram.com"},
	{.key = "host_l2_domain",    .value = "instagram.com"},
	{.key = "referer",           .value = "images.ak.instagram.com"},
	{.key = "referer_l2",        .value = "instagram.com"},
};

static const struct checkdata_value checkdata_values_hrd_011[] = {
	CHECKDATA_BASE,
	{.key = "https_common_name", .value = "www.example.com"},
	{.key = "http_host",         .value = "images.ak.instagram.com"},
	{.key = "http_host_l2",      .value = "instagram.com"},
	{.key = "http_referer",      .value = NULL},
	{.key = "host",              .value = "images.ak.instagram.com"},
	{.key = "host_l2_domain",    .value = "instagram.com"},
	{.key = "referer",           .value = "images.ak.instagram.com"},
	{.key = "referer_l2",        .value = "instagram.com"},
};

static const struct checkdata_value checkdata_values_hrd_100[] = {
	CHECKDATA_BASE,
	{.key = "https_common_name", .value = NULL},
	{.key = "http_host",         .value = NULL},
	{.key = "http_host_l2",      .value = NULL},
	{.key = "http_referer",      .value = "www.elmundo.es"},
	{.key = "host",              .value = NULL},
	{.key = "host_l2_domain",    .value = NULL},
	{.key = "referer",           .value = "www.elmundo.es"},
	{.key = "referer_l2",        .value = "elmundo.es"},
};

static const struct checkdata_value checkdata_values_hrd_101[] = {
	CHECKDATA_BASE,
	{.key = "https_common_name", .value = "www.example.com"},
	{.key = "http_host",         .value = NULL},
	{.key = "http_host_l2",      .value = NULL},
	{.key = "http_referer",      .value = "www.elmundo.es"},
	{.key = "host",              .value = "www.example.com"},
	{.key = "host_l2_domain",    .value = "example.com"},
	{.key = "referer",           .value = "www.elmundo.es"},
	{.key = "referer_l2",        .value = "elmundo.es"},
};

static const struct checkdata_value checkdata_values_hrd_110[] = {
	CHECKDATA_BASE,
	{.key = "https_common_name", .value = NULL},
	{.key = "http_host",         .value = "images.ak.instagram.com"},
	{.key = "http_host_l2",      .value = "instagram.com"},
	{.key = "http_referer",      .value = "www.elmundo.es"},
	{.key = "host",              .value = "images.ak.instagram.com"},
	{.key = "host_l2_domain",    .value = "instagram.com"},
	{.key = "referer",           .value = "www.elmundo.es"},
	{.key = "referer_l2",        .value = "elmundo.es"},
};

static const struct checkdata_value checkdata_values_hrd_111[] = {
	CHECKDATA_BASE,
	{.key = "https_common_name", .value = "www.example.com"},
	{.key = "http_host",         .value = "images.ak.instagram.com"},
	{.key = "http_host_l2",      .value = "instagram.com"},
	{.key = "http_referer",      .value = "www.elmundo.es"},
	{.key = "host",              .value = "images.ak.instagram.com"},
	{.key = "host_l2_domain",    .value = "instagram.com"},
	{.key = "referer",           .value = "www.elmundo.es"},
	{.key = "referer_l2",        .value = "elmundo.es"},
};

/*
                 3RD TEST: HTTPS://xxxx/ or ip host/referer/url
 */

#define PROTO_URL_ENTITIES(RT, R) \
	/* http: entries*/ \
	BASE_ENTITIES(RT, T_CISCO_URL, CISCO_L2_HOST_H, T_CISCO_UA, \
		T_CISCO_REFERER_H, T_CISCO_SSL_CN_H, BASE_BYTES, \
		BASE_PKTS) \
	/* https: entries*/ \
	BASE_ENTITIES(R, T_CISCO_URL, CISCO_L2_HOST_HS, T_CISCO_UA, \
		T_CISCO_REFERER_HS, T_CISCO_SSL_CN_HS, BASE_BYTES, \
		BASE_PKTS) \
	/* host/url entries*/ \
	BASE_ENTITIES(R, T_CISCO_URL, CISCO_L2_HOST_U, T_CISCO_UA, \
		T_CISCO_REFERER_U, T_CISCO_SSL_CN_U, BASE_BYTES, \
		BASE_PKTS) \
	/* http: xxx/url entries*/ \
	BASE_ENTITIES(R, T_CISCO_URL, CISCO_L2_HOST_HU, T_CISCO_UA, \
		T_CISCO_REFERER_HU, T_CISCO_SSL_CN_HU, BASE_BYTES, \
		BASE_PKTS) \
	/* https: xxx/url entries*/ \
	BASE_ENTITIES(R, T_CISCO_URL, CISCO_L2_HOST_HSU, T_CISCO_UA, \
		T_CISCO_REFERER_HSU, T_CISCO_SSL_CN_HSU, BASE_BYTES, \
		BASE_PKTS)

#define PROTO_URL_CHECKDATA(PRE, POST) {\
	{.key = "host",          .value = PRE "instagram.com" POST}, \
	{.key = "host_l2_domain",    .value = "instagram.com"}, \
	{.key = "referer",           .value = PRE "www.elmundo.es" POST}, \
	{.key = "referer_l2",        .value = "elmundo.es"}, \
	{.key = "https_common_name", .value = PRE "www.example.com" POST}, \
	{.key = "http_host",     .value = PRE "instagram.com" POST}, \
	{.key = "http_host_l2",      .value = "instagram.com"}, \
	{.key = "http_referer",      .value = PRE "www.elmundo.es" POST}, \
}

#define PROTO_URL_ENTITIES(RT, R) \
	/* http: entries*/ \
	BASE_ENTITIES(RT, T_CISCO_URL, CISCO_L2_HOST_H, T_CISCO_UA, \
		T_CISCO_REFERER_H, T_CISCO_SSL_CN_H, BASE_BYTES, \
		BASE_PKTS) \
	/* https: entries*/ \
	BASE_ENTITIES(R, T_CISCO_URL, CISCO_L2_HOST_HS, T_CISCO_UA, \
		T_CISCO_REFERER_HS, T_CISCO_SSL_CN_HS, BASE_BYTES, \
		BASE_PKTS) \
	/* host/url entries*/ \
	BASE_ENTITIES(R, T_CISCO_URL, CISCO_L2_HOST_U, T_CISCO_UA, \
		T_CISCO_REFERER_U, T_CISCO_SSL_CN_U, BASE_BYTES, \
		BASE_PKTS) \
	/* http: xxx/url entries*/ \
	BASE_ENTITIES(R, T_CISCO_URL, CISCO_L2_HOST_HU, T_CISCO_UA, \
		T_CISCO_REFERER_HU, T_CISCO_SSL_CN_HU, BASE_BYTES, \
		BASE_PKTS) \
	/* https: xxx/url entries*/ \
	BASE_ENTITIES(R, T_CISCO_URL, CISCO_L2_HOST_HSU, T_CISCO_UA, \
		T_CISCO_REFERER_HSU, T_CISCO_SSL_CN_HSU, BASE_BYTES, \
		BASE_PKTS)

#define PROTO_URL_CHECKDATA(PRE, POST) {\
	{.key = "host",          .value = PRE "instagram.com" POST}, \
	{.key = "host_l2_domain",    .value = "instagram.com"}, \
	{.key = "referer",           .value = PRE "www.elmundo.es" POST}, \
	{.key = "referer_l2",        .value = "elmundo.es"}, \
	{.key = "https_common_name", .value = PRE "www.example.com" POST}, \
	{.key = "http_host",     .value = PRE "instagram.com" POST}, \
	{.key = "http_host_l2",      .value = "instagram.com"}, \
	{.key = "http_referer",      .value = PRE "www.elmundo.es" POST}, \
}

static const struct checkdata_value proto_url_checkdata_values_h[] =
	PROTO_URL_CHECKDATA("http://",);

static const struct checkdata_value proto_url_checkdata_values_hs[] =
	PROTO_URL_CHECKDATA("https://",);

static const struct checkdata_value proto_url_checkdata_values_u[] =
	PROTO_URL_CHECKDATA(,"/index.php");

static const struct checkdata_value proto_url_checkdata_values_hu[] =
	PROTO_URL_CHECKDATA("http://","/index.php");

static const struct checkdata_value proto_url_checkdata_values_hsu[] =
	PROTO_URL_CHECKDATA("https://","/index.php");

/*
                              IP HOSTS / REFERERS
 */

#define PROTO_IP_ENTITIES(RT, R) \
	/* http: entries*/ \
	BASE_ENTITIES(RT, T_CISCO_URL, T_CISCO_IPv4_HOST, T_CISCO_UA, \
		T_CISCO_IPv6_REFERER, EMPTY_CISCO_SSL_CN, BASE_BYTES, \
		BASE_PKTS) \
	/* http: entries*/ \
	BASE_ENTITIES(RT, T_CISCO_URL, CISCO_IPv4_HOST_H, T_CISCO_UA, \
		CISCO_IPv6_REFERER_H, EMPTY_CISCO_SSL_CN, BASE_BYTES, \
		BASE_PKTS) \
	/* https: entries*/ \
	BASE_ENTITIES(R, T_CISCO_URL, CISCO_IPv4_HOST_HS, T_CISCO_UA, \
		CISCO_IPv6_REFERER_HS, EMPTY_CISCO_SSL_CN, BASE_BYTES, \
		BASE_PKTS) \
	/* host/url entries*/ \
	BASE_ENTITIES(R, T_CISCO_URL, CISCO_IPv4_HOST_U, T_CISCO_UA, \
		CISCO_IPv6_REFERER_U, EMPTY_CISCO_SSL_CN, BASE_BYTES, \
		BASE_PKTS) \
	/* http: xxx/url entries*/ \
	BASE_ENTITIES(R, T_CISCO_URL, CISCO_IPv4_HOST_HU, T_CISCO_UA, \
		CISCO_IPv6_REFERER_HU, EMPTY_CISCO_SSL_CN, BASE_BYTES, \
		BASE_PKTS) \
	/* https: xxx/url entries*/ \
	BASE_ENTITIES(R, T_CISCO_URL, CISCO_IPv4_HOST_HSU, T_CISCO_UA, \
		CISCO_IPv6_REFERER_HSU, EMPTY_CISCO_SSL_CN, BASE_BYTES, \
		BASE_PKTS) \
	/* too long one: Never should be an ipv6 */ \
	BASE_ENTITIES(R, T_CISCO_URL, CISCO_LONG_HOST, T_CISCO_UA, \
		EMPTY_CISCO_REFERER, EMPTY_CISCO_SSL_CN, BASE_BYTES, \
		BASE_PKTS)


#define PROTO_IP_CHECKDATA(PRE, POST) { \
	{.key = "host",          .value = PRE TEST_EXPECTED_IPv4 POST}, \
	{.key = "host_l2_domain",    .value = TEST_EXPECTED_IPv4}, \
	{.key = "referer",           .value = PRE TEST_EXPECTED_IPv6 POST}, \
	{.key = "referer_l2",        .value = TEST_EXPECTED_IPv6}, \
	{.key = "https_common_name", .value = NULL}, \
	{.key = "http_host",     .value = PRE TEST_EXPECTED_IPv4 POST}, \
	{.key = "http_host_l2",      .value = TEST_EXPECTED_IPv4}, \
	{.key = "http_referer",      .value = PRE TEST_EXPECTED_IPv6 POST}, \
}

static const struct checkdata_value proto_ip_checkdata_values_n[] =
	PROTO_IP_CHECKDATA(,);

static const struct checkdata_value proto_ip_checkdata_values_h[] =
	PROTO_IP_CHECKDATA("http://",);

static const struct checkdata_value proto_ip_checkdata_values_hs[] =
	PROTO_IP_CHECKDATA("https://",);

static const struct checkdata_value proto_ip_checkdata_values_u[] =
	PROTO_IP_CHECKDATA(,"/index.php");

static const struct checkdata_value proto_ip_checkdata_values_hu[] =
	PROTO_IP_CHECKDATA("http://","/index.php");

static const struct checkdata_value proto_ip_checkdata_values_hsu[] =
	PROTO_IP_CHECKDATA("https://","/index.php");

static const struct checkdata_value long_no_ip_checkdata_values[] = {
	{.key = "host",          .value = TEST_EXPECTED_LONG},
	{.key = "host_l2_domain",    .value = TEST_EXPECTED_LONG},
	{.key = "referer",           .value = TEST_EXPECTED_LONG},
	{.key = "referer_l2",        .value = TEST_EXPECTED_LONG},
	{.key = "https_common_name", .value = NULL},
	{.key = "http_host",     .value = TEST_EXPECTED_LONG},
	{.key = "http_host_l2",      .value = TEST_EXPECTED_LONG},
	{.key = "http_referer",      .value = NULL},
};

/*
                                  ACTUAL TESTS
 */

static int prepare_test_nf10_cisco_url(void **state) {
	static const IPFIX_TEMPLATE(v10Template, TEST_IPFIX_FLOW_HEADER,
		IPFIX_TEMPLATE_ID, L2_ENTITIES);

	static const IPFIX_FLOW(l2d_v10Flow, TEST_IPFIX_FLOW_HEADER,
		IPFIX_TEMPLATE_ID, L2_ENTITIES);
	static const IPFIX_FLOW(hrd_flow, TEST_IPFIX_FLOW_HEADER,
		IPFIX_TEMPLATE_ID, HOST_REFERER_ENTITIES);
	static const IPFIX_FLOW(https_url_flow, TEST_IPFIX_FLOW_HEADER,
		IPFIX_TEMPLATE_ID, PROTO_URL_ENTITIES);
	static const IPFIX_FLOW(ip_flow, TEST_IPFIX_FLOW_HEADER,
		IPFIX_TEMPLATE_ID, PROTO_IP_ENTITIES);

#define CHECK(checkdata) {.checks = checkdata, .size = RD_ARRAYSIZE(checkdata)}
	static const struct checkdata sl1_checkdata[] = {
		CHECK(checkdata_values_fullhost),
		CHECK(checkdata_values_fullhost),
		CHECK(checkdata_values_l1host),
		CHECK(checkdata_values_dotl1host),
		CHECK(checkdata_values_l2host),
		CHECK(checkdata_values_dotl2host),
	};

	static const struct checkdata host_domain_checkdata[] = {
		CHECK(checkdata_values_hrd_000),
		CHECK(checkdata_values_hrd_001),
		CHECK(checkdata_values_hrd_010),
		CHECK(checkdata_values_hrd_011),
		CHECK(checkdata_values_hrd_100),
		CHECK(checkdata_values_hrd_101),
		CHECK(checkdata_values_hrd_110),
		CHECK(checkdata_values_hrd_111),
	};

	static const struct checkdata https_url_flow_checkdata[] = {
		CHECK(proto_url_checkdata_values_h),
		CHECK(proto_url_checkdata_values_hs),
		CHECK(proto_url_checkdata_values_u),
		CHECK(proto_url_checkdata_values_hu),
		CHECK(proto_url_checkdata_values_hsu),
	};

	static const struct checkdata ip_flow_checkdata[] = {
		CHECK(proto_ip_checkdata_values_n),
		CHECK(proto_ip_checkdata_values_h),
		CHECK(proto_ip_checkdata_values_hs),
		CHECK(proto_ip_checkdata_values_u),
		CHECK(proto_ip_checkdata_values_hu),
		CHECK(proto_ip_checkdata_values_hsu),
		CHECK(long_no_ip_checkdata_values),
	};
#undef CHECK

#define TEST(mrecord, mrecord_size, checks, checks_size, ...) { \
		.netflow_src_ip = 0x04030201,                                  \
		.record = mrecord, .record_size = mrecord_size,                \
		.checkdata = checks, .checkdata_size = checks_size,            \
		__VA_ARGS__                                                    \
	}

	struct test_params test_params[] = {
		TEST(&v10Template, sizeof(v10Template),
			NULL, 0,
			.config_json_path = "./tests/0000-testFlowV5.json",
			.host_list_path = "./tests/0011-data/"),
		TEST(&l2d_v10Flow, sizeof(l2d_v10Flow),
			sl1_checkdata, RD_ARRAYSIZE(sl1_checkdata),),
		TEST(&hrd_flow, sizeof(hrd_flow),
			host_domain_checkdata,
			RD_ARRAYSIZE(host_domain_checkdata),),
		TEST(&https_url_flow, sizeof(https_url_flow),
			https_url_flow_checkdata,
			RD_ARRAYSIZE(https_url_flow_checkdata),),
		TEST(&ip_flow, sizeof(ip_flow),
			ip_flow_checkdata, RD_ARRAYSIZE(ip_flow_checkdata),),
	};

	*state = prepare_tests(test_params, RD_ARRAYSIZE(test_params));
	return *state == NULL;
}

int main() {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup(testFlow,
				prepare_test_nf10_cisco_url),
	};

	return cmocka_run_group_tests(tests, nf_test_setup, nf_test_teardown);
}
