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

#define HAVE_STRNSTR

#include "f2k.h"

#include "rb_netflow_test.h"

#include <setjmp.h>
#include <cmocka.h>


#if 0

/*
	@TODO all test
	@test testing rb_l1_domain extraction
*/

struct testCase{
	const char *input;
	const char *expected_result;
};

const struct testCase testCases[] = {
    {.input = "youtube.com",.expected_result = "youtube"},
    {.input = "youtube.com.es",.expected_result = "youtube"},
    {.input = "192.168.101.165",.expected_result = "192.168.101.165"},
    {.input = "http://192.168.101.165",.expected_result = "192.168.101.165"},
    {.input = "http://192.168.101.165:80",.expected_result = "192.168.101.165"},
    {.input = "domain",.expected_result = "domain"},
    {.input = "video.co.ja",.expected_result = "video"},
    {.input = "touch.latimes.com",.expected_result = "latimes"},
    {.input = "google.com:80",.expected_result = "google"},
    {.input = "http://www.google.com:80",.expected_result = "google"},
    {.input = "http://fbcdn.com", .expected_result = "facebook"},
};

void rb_domains_test(const NumNameAssoc *domains_name_as_list){
  const size_t bufsize = 1024;
  char buf[bufsize];
  int i;
  for(i=0;i<sizeof(testCases)/sizeof(testCases[0]);++i){
    size_t size;
    const char * first_domain;
    first_domain = rb_l1_domain(urls[test_iterator],&size, domains_name_as_list);
    strlcpy(buf,first_domain,size);
    buf[size]='\0';
    assert_true(0==strcmp(testCases[i].expected_result,buf))
  }
}

/// @test first check, try to dissect one netflow record v5
static void doTestCase(const struct testCase *tc,const NumNameAssoc *domains_name_as_list){
	const size_t bufsize = 1024;
	char buf[bufsize];

	assert_true(tc->input);
	size_t size;
	const char *first_domain = rb_l1_domain(tc->input,&size,domains_name_as_list);
	if(expected_result != NULL){
		strlcpy(buf,first_domain,size);

		assert_true(tc->expected_result);
		assert_true(0==strcmp(tc->input,tc->expected_result));
	}
}

static void testAllTestCase(){
	int i;
	for(i=0;i<sizeof(testCases)/sizeof(testCases[0]);++i){
		doTestCase(&testCases[i],readOnlyGlobals.rb_databases.domains_name_as_list);
	}
}
#endif

static void testRbDomainFn() {
	#if 0
	readOnlyGlobals.rb_databases.hosts_database_path = "./tests/0016-data";
	readOnlyGlobals.rb_databases.reload_domains_database = 1;

	testAllTestCase();
	#endif
}

int main(){
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(testRbDomainFn)
	};

	return cmocka_run_group_tests(tests, nf_test_setup, nf_test_teardown);
}
