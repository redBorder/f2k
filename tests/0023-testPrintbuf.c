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

#undef NDEBUG

#include "printbuf.h"
#include <stdio.h>

#include <setjmp.h>
#include <cmocka.h>

static void checkSecuence(struct printbuf *p) {
	size_t i;
	for(i=0; i<p->bpos-1; ++i) {
		if(p->buf[i] == 'Z'){
			// printf("Checking %c == %c\n",p->buf[i+1],'A');
			assert_true(p->buf[i+1] == 'A');
		} else {
			// printf("Checking %c == %c\n",p->buf[i+1],p->buf[i]+1);
			assert_true(p->buf[i+1] == p->buf[i]+1);
		}
	}
}

static void testExtend() {
	size_t i;
	struct printbuf *p = printbuf_new();
	const size_t initial_size = p->size;

	for(i=0;i<initial_size+4;++i) {
		/*
		Trying to append more characters that initial size,
		printbuf should extend
		*/
		const char to_add = (i)%('Z'-'A'+1) + 'A'; /* ABCDEF... */
		printbuf_memappend_fast(p, &to_add, 1);
	}

	assert_true(p->size > initial_size);
	checkSecuence(p);
	//printf("%s\n",p->buf);
	printbuf_free(p);
}

int main(){
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(testExtend)
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
