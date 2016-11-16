// rb_json_tests.h

#pragma once

#include "rb_lists.h"

#include <string.h>
#include <jansson.h>

/// you have to json_decref(return) when done
void *rb_json_assert_unpack(const char *json, size_t flags,
							const char *fmt,...);

void free_json_unpacked(void *mem);

void free_string_list(struct string_list *sl);

struct checkdata_value{
	const char *key;
	json_type type;
	const char *value;
};

struct checkdata{
	size_t size;
	const struct checkdata_value *checks;
};

void rb_assert_json(const char *str, const size_t size, const struct checkdata *checkdata);

