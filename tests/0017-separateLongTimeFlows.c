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


#include <jansson.h>

#include <assert.h>
#include <stdio.h>

#include <f2k.h>
#include <librd/rdfloat.h>

#include <setjmp.h>
#include <cmocka.h>

#define double_equals rd_deq

static void free_string_list(struct string_list *sl){
	while(sl) {
		struct string_list *next = sl->next;
		printbuf_free(sl->string);
		free(sl);
		sl = next;
	}
}

// @todo use the same checks as the rest of the tests!
static void rb_test_separate_long_time_flow()
{
	json_t *json_o,*json_object_son;
	struct string_list * sl = NULL;
	struct printbuf *kafka_line_buffer = NULL;

	// traceEvent(TRACE_NORMAL, "Testing a very short flow (duration=0)");
	kafka_line_buffer = printbuf_new();
	sprintbuf(kafka_line_buffer, "{\"foo\":\"bar\"");
	sl = rb_separate_long_time_flow(kafka_line_buffer,1000, 0, 60,60,20,30);
	// traceEvent(TRACE_NORMAL,"  -> Checking if just one kafka message generated...");
	assert_null(sl->next);
	// traceEvent(TRACE_NORMAL,"  -> Checking if kafka message has the correct data...");
	json_o = json_loads(sl->string->buf,0,NULL);
	assert_non_null(json_o);
	// traceEvent(TRACE_NORMAL,"    -> Checking if kafka message has the correct timestamp...");
	json_object_son = json_object_get(json_o,"timestamp");
	assert_true(double_equals(json_number_value(json_object_son),1000));
	// traceEvent(TRACE_NORMAL,"    -> Checking if kafka message has the correct bytes...");
	json_object_son = json_object_get(json_o,"bytes");
	assert_true(double_equals(json_number_value(json_object_son),20));
	// traceEvent(TRACE_NORMAL,"    -> Checking if kafka message has the correct packets...");
	json_object_son = json_object_get(json_o,"pkts");
	assert_true(double_equals(json_number_value(json_object_son),30));

	json_decref(json_o);
	free_string_list(sl);

	// traceEvent(TRACE_NORMAL, "Testing a flow with duration 0 < d < 60");
	kafka_line_buffer = printbuf_new();
	sprintbuf(kafka_line_buffer, "{\"foo\":\"bar\"");
	sl = rb_separate_long_time_flow(kafka_line_buffer,1000, 16, 60,60,20,30);
	// traceEvent(TRACE_NORMAL,"  -> Checking if just one kafka message generated...");
	assert_null(sl->next);
	// traceEvent(TRACE_NORMAL,"  -> Checking if kafka message has the correct data...");
	json_o = json_loads(sl->string->buf,0,NULL);
	assert_non_null(json_o);
	// traceEvent(TRACE_NORMAL,"    -> Checking if kafka message has the correct timestamp...");
	json_object_son = json_object_get(json_o,"timestamp");
	assert_true(double_equals(json_number_value(json_object_son),1000));
	// traceEvent(TRACE_NORMAL,"    -> Checking if kafka message has the correct bytes...");
	json_object_son = json_object_get(json_o,"bytes");
	assert_true(double_equals(json_number_value(json_object_son),20));
	// traceEvent(TRACE_NORMAL,"    -> Checking if kafka message has the correct packets...");
	json_object_son = json_object_get(json_o,"pkts");
	assert_true(double_equals(json_number_value(json_object_son),30));

	json_decref(json_o);
	free_string_list(sl);

	// traceEvent(TRACE_NORMAL, "Testing a flow with duration 60 < d < 120");
	kafka_line_buffer = printbuf_new();
	sprintbuf(kafka_line_buffer, "{\"foo\":\"bar\"");
	sl = rb_separate_long_time_flow(kafka_line_buffer,1000, 70, 60,60,20,30);
	// traceEvent(TRACE_NORMAL,"  -> Checking if just two kafka message generated...");
	assert_non_null(sl->next);
	assert_null(sl->next->next);

	// traceEvent(TRACE_NORMAL,"  -> Checking if kafka 1st message has the correct data...");
	json_o = json_loads(sl->string->buf,0,NULL);
	assert_non_null(json_o);
	// traceEvent(TRACE_NORMAL,"    -> Checking if kafka message has the correct timestamp...");
	json_object_son = json_object_get(json_o,"timestamp");
	assert_true(double_equals(json_number_value(json_object_son),1060));
	// traceEvent(TRACE_NORMAL,"    -> Checking if kafka message has the correct bytes...");
	json_object_son = json_object_get(json_o,"bytes");
	assert_true(double_equals(json_number_value(json_object_son),2));
	// traceEvent(TRACE_NORMAL,"    -> Checking if kafka message has the correct packets...");
	json_object_son = json_object_get(json_o,"pkts");
	assert_true(double_equals(json_number_value(json_object_son),4));
	json_decref(json_o);

	// traceEvent(TRACE_NORMAL,"  -> Checking if kafka 2nd message has the correct data...");
	json_o = json_loads(sl->next->string->buf,0,NULL);
	assert_non_null(json_o);
	// traceEvent(TRACE_NORMAL,"    -> Checking if kafka message has the correct timestamp...");
	json_object_son = json_object_get(json_o,"timestamp");
	assert_true(double_equals(json_number_value(json_object_son),1000));
	// traceEvent(TRACE_NORMAL,"    -> Checking if kafka message has the correct bytes...");
	json_object_son = json_object_get(json_o,"bytes");
	assert_true(double_equals(json_number_value(json_object_son),18));
	// traceEvent(TRACE_NORMAL,"    -> Checking if kafka message has the correct packets...");
	json_object_son = json_object_get(json_o,"pkts");
	assert_true(double_equals(json_number_value(json_object_son),26));
	free_string_list(sl);
	json_decref(json_o);

	// traceEvent(TRACE_NORMAL, "Testing a flow with duration d > 120");
	kafka_line_buffer = printbuf_new();
	sprintbuf(kafka_line_buffer, "{\"foo\":\"bar\"");
	sl = rb_separate_long_time_flow(kafka_line_buffer,1000, 140, 60,60,40,60);
	// traceEvent(TRACE_NORMAL,"  -> Checking if just three kafka message generated...");
	assert_non_null(sl->next);
	assert_non_null(sl->next->next);
	assert_null(sl->next->next->next);

	// traceEvent(TRACE_NORMAL,"  -> Checking if kafka 1st message has the correct data...");
	json_o = json_loads(sl->string->buf,0,NULL);
	assert_non_null(json_o);
	// traceEvent(TRACE_NORMAL,"    -> Checking if kafka message has the correct timestamp...");
	json_object_son = json_object_get(json_o,"timestamp");
	assert_true(double_equals(json_number_value(json_object_son),1120));
	// traceEvent(TRACE_NORMAL,"    -> Checking if kafka message has the correct bytes...");
	json_object_son = json_object_get(json_o,"bytes");
	assert_true(double_equals(json_number_value(json_object_son),6));
	// traceEvent(TRACE_NORMAL,"    -> Checking if kafka message has the correct packets...");
	json_object_son = json_object_get(json_o,"pkts");
	assert_true(double_equals(json_number_value(json_object_son),8));
	json_decref(json_o);

	// traceEvent(TRACE_NORMAL,"  -> Checking if kafka 2nd message has the correct data...");
	json_o = json_loads(sl->next->string->buf,0,NULL);
	json_object_son = json_object_get(json_o,"timestamp");
	assert_true(double_equals(json_number_value(json_object_son),1060));
	// traceEvent(TRACE_NORMAL,"    -> Checking if kafka message has the correct bytes...");
	json_object_son = json_object_get(json_o,"bytes");
	assert_true(double_equals(json_number_value(json_object_son),17));
	// traceEvent(TRACE_NORMAL,"    -> Checking if kafka message has the correct packets...");
	json_object_son = json_object_get(json_o,"pkts");
	assert_true(double_equals(json_number_value(json_object_son),26));
	json_decref(json_o);

	// traceEvent(TRACE_NORMAL,"  -> Checking if kafka 3rd message has the correct data...");
	json_o = json_loads(sl->next->next->string->buf,0,NULL);
	assert_non_null(json_o);
	// traceEvent(TRACE_NORMAL,"    -> Checking if kafka message has the correct timestamp...");
	json_object_son = json_object_get(json_o,"timestamp");
	assert_true(double_equals(json_number_value(json_object_son),1000));
	// traceEvent(TRACE_NORMAL,"    -> Checking if kafka message has the correct bytes...");
	json_object_son = json_object_get(json_o,"bytes");
	assert_true(double_equals(json_number_value(json_object_son),17));
	// traceEvent(TRACE_NORMAL,"    -> Checking if kafka message has the correct packets...");
	json_object_son = json_object_get(json_o,"pkts");
	assert_true(double_equals(json_number_value(json_object_son),26));
	json_decref(json_o);

	free_string_list(sl);

	// traceEvent(TRACE_NORMAL,"separateLongTimeFlow() work properly.");
}

static void test_separate_long_time_flow(void) {
	readWriteGlobals = calloc(1,sizeof(readWriteGlobals[0]));

	rb_test_separate_long_time_flow();
	free(readWriteGlobals);
}

int main() {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_separate_long_time_flow)
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
