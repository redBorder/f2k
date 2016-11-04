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


#include "util.c"
#include <librd/rd.h>
#include <jansson.h>
#include <assert.h>

#include <setjmp.h>
#include <cmocka.h>

static struct {
	const char *src,*expected_dst;
	int try_json;
} test_cases[] = {
	{
		.src = "hello",
		.expected_dst = "hello",
		.try_json = 1
	},{
		/* Escape some characters */
		.src = "{\"h\\e\bl\fl\no\r/\t!}",
		.expected_dst = "{\\\"h\\\\e\\bl\\fl\\no\\r\\/\\t!}",
		.try_json = 1
	},{
		// Two byte character
		.src = "españa",
		.expected_dst = "españa",
		.try_json = 1
	},{
		// Two byte character, start of string
		.src = "ñu",
		.expected_dst = "ñu",
		.try_json = 0
	},{
		// Two byte character, end of string
		.src = "ññ",
		.expected_dst = "ññ",
		.try_json = 0
	},{
		// Trying to overencode ASCII
		.src = (const char []){0xc0u, 'a', '\0'},
		.expected_dst = "%c0a",
		.try_json = 1
	},{
		// Trying to overencode an invalid ascii
		.src = (const char []){0xc0, 0xbc, 'a', '\0'},
		.expected_dst = "%c0%bca",
		.try_json = 1
	},{
		// Invalid character
		.src = (const char []){'i','b','y','t','e', 0x99,'\0'},
		.expected_dst = (const char []){"ibyte%99"},
		.try_json = 1
	},{
		// Three valid characters
		.src = (const char []){'i','b','y','t','e', 0xe2, 0x82, 0xac,'\0'},
		.expected_dst = (const char []){'i','b','y','t','e', 0xE2, 0x82, 0xAC, '\0'},
		.try_json = 1
	},{
		// Three characters, first invalid
		.src = (const char []){'i','b','y','t','e', 0xff, 0x82, 0xac,'\0'},
		.expected_dst = (const char []){"ibyte%ff%82%ac"},
		.try_json = 1
	},{
		// Three characters, second invalid
		.src = (const char []){'i','b','y','t','e', 0xe2, 0xff, 0xac, '\0'},
		.expected_dst = (const char []){"ibyte%e2%ff%ac"},
		.try_json = 1
	},{
		// Three characters, third invalid
		.src = (const char []){'i','b','y','t','e', 0xe2, 0x82, 0xff, '\0'},
		.expected_dst = (const char []){"ibyte%e2%82%ff"},
		.try_json = 1
	},{
		// Four valid characters
		.src = (const char []){'i','b','y','t','e', 0xf0, 0x90, 0x8d, 0x88, '\0'},
		.expected_dst = (const char []){'i','b','y','t','e', 0xf0, 0x90, 0x8d, 0x88, '\0'},
		.try_json = 1
	},{
		// Four characters, third invalid
		.src = (const char []){'i','b','y','t','e', 0xff, 0x90, 0x8d, 0x88, '\0'},
		.expected_dst = (const char []){"ibyte%ff%90%8d%88"},
		.try_json = 1
	},{
		// Four characters, third invalid
		.src = (const char []){'i','b','y','t','e', 0xf0, 0xff, 0x8d, 0x88, '\0'},
		.expected_dst = (const char []){"ibyte%f0%ff%8d%88"},
		.try_json = 1
	},{
		// Four characters, third invalid
		.src = (const char []){'i','b','y','t','e', 0xf0, 0x90, 0xff, 0x88, '\0'},
		.expected_dst = (const char []){"ibyte%f0%90%ff%88"},
		.try_json = 1
	},{
		// Four characters, third invalid
		.src = (const char []){'i','b','y','t','e', 0xf0, 0x90, 0x8d, 0xff, '\0'},
		.expected_dst = (const char []){"ibyte%f0%90%8d%ff"},
		.try_json = 1
	},
};

static void assert_escape_fn(const char *src,const char *expected_result,int try_json) {
	struct printbuf *printbuf = printbuf_new();

	append_escaped(printbuf,src,strlen(src));
	assert_string_equal(printbuf->buf,expected_result);

	if(try_json) {
		json_t *j = json_string(printbuf->buf /*,printbuf->bpos */);
		assert(NULL != j);
		json_decref(j);
	}
	printbuf_free(printbuf);
}

static void test_utf8(void **state) {
	(void)state;
	size_t i=0;
	for (i=0;i<RD_ARRAY_SIZE(test_cases);++i) {
		assert_escape_fn(test_cases[i].src,test_cases[i].expected_dst,
			test_cases[i].try_json);
	}
}

int main() {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_utf8)
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
