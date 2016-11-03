#include "rb_mem_wraps.h"

size_t mem_wrap_fail_in = 0;

size_t mem_wraps_get_fail_in() {
	return mem_wrap_fail_in;
}

void mem_wraps_set_fail_in(size_t i) {
	mem_wrap_fail_in = i;
}

#define COMMA ,

#define WRAP_MEM_FN(fun, ret_t, args, real_args)                               \
ret_t __real_##fun (args);                                              \
ret_t __wrap_##fun (args); \
ret_t __wrap_##fun (args) { \
	return (mem_wrap_fail_in == 0 || --mem_wrap_fail_in) ?                 \
						__real_##fun (real_args) : 0;\
}

WRAP_MEM_FN(malloc, void *, size_t m, m)
WRAP_MEM_FN(realloc, void *, void *ptr COMMA size_t m, ptr COMMA m)
WRAP_MEM_FN(calloc, void *, size_t n COMMA size_t m, n COMMA m)
WRAP_MEM_FN(strdup, char *, const char *str, str)
WRAP_MEM_FN(__strdup, char *, const char *str, str)
