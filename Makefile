
include Makefile.config


BIN=f2k

.PHONY+=version.c

SRCS_SFLOW_$(WITH_SFLOW) += sflow_collect.c
SRCS=	collect.c  export.c  globals.c f2k.c \
	printbuf.c  rb_sensor.c  template.c \
	util.c  version.c NumNameAssocTree.c \
	rb_kafka.c rb_listener.c rb_zk.c \
	rb_mac.c rb_dns_cache.c $(SRCS_SFLOW_y)
OBJS=	$(SRCS:.c=.o)

TESTS_C = $(wildcard tests/0*.c)

TESTS = $(TESTS_C:.c=.test)
TESTS_OBJS = $(TESTS:.test=.o)
TESTS_CHECKS_XML = $(TESTS_C:.c=.xml)
TESTS_MEM_XML = $(TESTS_C:.c=.mem.xml)
TESTS_HELGRIND_XML = $(TESTS_C:.c=.helgrind.xml)
TESTS_DRD_XML = $(TESTS_C:.c=.drd.xml)
TESTS_VALGRIND_XML = $(TESTS_MEM_XML) $(TESTS_HELGRIND_XML) $(TESTS_DRD_XML)
TESTS_XML = $(TESTS_CHECKS_XML) $(TESTS_VALGRIND_XML)
MAXMIND_DB = tests/asn.dat tests/country.dat tests/asnv6.dat tests/countryv6.dat
COV_FILES = $(foreach ext,gcda gcno, $(SRCS:.c=.$(ext)) $(TESTS_C:.c=.$(ext)))

VALGRIND ?= valgrind
SUPPRESSIONS_FILE ?= tests/valgrind.suppressions
ifneq ($(wildcard $(SUPPRESSIONS_FILE)),)
SUPPRESSIONS_VALGRIND_ARG = --suppressions=$(SUPPRESSIONS_FILE)
endif

.PHONY: version.c tests checks memchecks drdchecks helchecks coverage \
	check_coverage manuf

all: $(BIN)

include mklove/Makefile.base

manuf:
	tools/manuf.py

version.c:
	@rm -f $@
	@echo "const char *f2k_revision=\"`git describe --abbrev=6 --tags HEAD --always`\";" >> $@
	@echo "const char *version=\"6.13.`date +"%y%m%d"`\";" >> $@

install: bin-install

clean: bin-clean
	@echo -e '\033[1;33m[Workdir cleaned]\033[0m\t $<'
	@rm -f $(TESTS) $(TESTS_OBJS) $(TESTS_XML) $(COV_FILES)

run_tests = tests/run_tests.sh $(1) $(TESTS_C:.c=)
run_valgrind = $(VALGRIND) --tool=$(1) $(SUPPRESSIONS_VALGRIND_ARG) --xml=yes \
					--xml-file=$(2) $(3)  &>/dev/null

setup-tests:
	@echo -e '\033[1;33m[Initializing Zookeeper container...]\033[0m\t $<'
	@docker network create --subnet=172.26.0.0/24 test
	@docker run -d --net test --ip 172.26.0.2 --name zookeeper wurstmeister/zookeeper

teardown-tests:
	@echo -e '\033[1;33m[Cleaning Zookeeper container...]\033[0m\t $<'
	@-docker rm -f zookeeper
	@-docker network rm test

tests: $(TESTS_XML)
	@$(call run_tests, -cvdh)

checks: $(TESTS_CHECKS_XML)
	@$(call run_tests,-c)

memchecks: $(TESTS_MEM_XML)
	@$(call run_tests,-v)

drdchecks: $(TESTS_DRD_XML)
	@$(call run_tests,-d)

helchecks: $(TESTS_HELGRIND_XML)
	@$(call run_tests,-h)

tests/%.mem.xml: tests/%.test $(MAXMIND_DB)
	@echo -e '\033[1;34m[Checking memory ]\033[0m\t $<'
	-@$(call run_valgrind,memcheck,"$@","./$<")

tests/%.helgrind.xml: tests/%.test $(MAXMIND_DB)
	@echo -e '\033[1;34m[Checking concurrency with HELGRIND]\033[0m\t $<'
	-@$(call run_valgrind,helgrind,"$@","./$<")

tests/%.drd.xml: tests/%.test $(MAXMIND_DB)
	@echo -e '\033[1;34m[Checking concurrency with DRD]\033[0m\t $<'
	-@$(call run_valgrind,drd,"$@","./$<")

tests/%.xml: tests/%.test $(MAXMIND_DB)
	@echo -e '\033[1;34m[Testing ]\033[0m\t $<'
	@CMOCKA_XML_FILE="$@" CMOCKA_MESSAGE_OUTPUT=XML "./$<" >/dev/null 2>&1

MALLOC_FUNCTIONS := $(strip malloc calloc realloc strdup __strdup)
WRAP_ALLOC_FUNCTIONS := $(foreach fn, $(MALLOC_FUNCTIONS)\
	,-Wl,-u,$(fn) -Wl,-wrap,$(fn))
TEST_DEPS := tests/rb_netflow_test.o tests/rb_json_test.o tests/rb_mem_wraps.o
tests/0023-testPrintbuf.test: TEST_DEPS = tests/rb_mem_wraps.o
tests/%.test: CPPFLAGS := -I. $(CPPFLAGS)
tests/%.test: tests/%.o tests/%.objdeps $(TEST_DEPS) $(OBJS)
	@echo -e '\033[1;32m[Building]\033[0m\t $@'
	@$(CC) $(CPPFLAGS) $(LDFLAGS) $< $(WRAP_ALLOC_FUNCTIONS) $(shell cat $(@:.test=.objdeps)) $(TEST_DEPS) -o $@ $(LIBS) -lcmocka > /dev/null

get_maxmind_db = wget $(1) -O $@.gz; gunzip $@

tests/asn.dat:
	$(call get_maxmind_db,http://download.maxmind.com/download/geoip/database/asnum/GeoIPASNum.dat.gz)

tests/asnv6.dat:
	$(call get_maxmind_db,http://download.maxmind.com/download/geoip/database/asnum/GeoIPASNumv6.dat.gz)

tests/country.dat:
	$(call get_maxmind_db,http://geolite.maxmind.com/download/geoip/database/GeoLiteCountry/GeoIP.dat.gz)

tests/countryv6.dat:
	$(call get_maxmind_db,http://geolite.maxmind.com/download/geoip/database/GeoIPv6.dat.gz)

check_coverage:
	@( if [[ "x$(WITH_COVERAGE)" == "xn" ]]; then \
	echo "$(MKL_RED) You need to configure using --enable-coverage"; \
	echo -n "$(MKL_CLR_RESET)"; \
	false; \
	fi)

COVERAGE_INFO ?= coverage.info
COVERAGE_OUTPUT_DIRECTORY ?= coverage.out.html
COV_VALGRIND ?= valgrind
COV_GCOV ?= gcov
COV_LCOV ?= lcov

coverage: check_coverage $(TESTS) checks
	@$(COV_LCOV) --gcov-tool=$(COV_GCOV) -q \
                --rc lcov_branch_coverage=1 \
								--capture \
                --directory ./ --output-file ${COVERAGE_INFO} >/dev/null 2>&1
	@$(COV_LCOV) --remove coverage.info '/app/tests/*' 'include/*' \
								--rc lcov_branch_coverage=1 \
								--compat-libtool \
								--output-file coverage.info >/dev/null 2>&1
	@$(COV_LCOV) --list --rc lcov_branch_coverage=1 coverage.info

coverage-html: coverage
	genhtml --branch-coverage ${COVERAGE_INFO} --output-directory \
				${COVERAGE_OUTPUT_DIRECTORY} > coverage.out

-include $(DEPS)
