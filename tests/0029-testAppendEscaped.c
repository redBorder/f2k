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
#include "util.h"

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

static void test_append_escaped0(const char *input,const char *expected){
	struct printbuf *kafka_line_buffer = printbuf_new();
	append_escaped(kafka_line_buffer,input,strlen(input));
	if(0!=strcmp(kafka_line_buffer->buf,expected)) {
		fprintf(stderr,
			"Error: Input [%s] produces output [%s], expected [%s]\n",
			input,kafka_line_buffer->buf,expected);

		assert_true(0);
	}
	printbuf_free(kafka_line_buffer);
}

static void test_append_escaped()
{
	test_append_escaped0("test1","test1");
	test_append_escaped0("test\"2","test\\\"2");
	test_append_escaped0("test\"3\"","test\\\"3\\\"");

	test_append_escaped0("test\\","test\\\\");
}

int main(void){
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_append_escaped)
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
