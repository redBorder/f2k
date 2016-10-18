# Makefile wrapper for expanding 0*.c glob.

all test clean:
	@(export TEST_SRCS="`echo 0*.c`"; make -B -f Makefile.tests $@)

testcontinue:
	@(export TEST_SRCS="`echo 0*.c`"; make -B -k -f Makefile.tests test)
