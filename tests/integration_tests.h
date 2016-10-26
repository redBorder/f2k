#include "../config.h"

#ifdef TESTS_ZK_HOST
#define SKIP_IF_NOT_INTEGRATION
#else
#define SKIP_IF_NOT_INTEGRATION                                                \
  do {                                                                         \
    skip();                                                                    \
    return;                                                                    \
  } while (0)
#endif
