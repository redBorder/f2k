
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
	rm -f $(TESTS) $(TESTS_OBJS) $(TESTS_XML) $(COV_FILES)

run_tests = tests/run_tests.sh $(1) $(TESTS_C:.c=)
run_valgrind = $(VALGRIND) --tool=$(1) $(SUPPRESSIONS_VALGRIND_ARG) --xml=yes \
					--xml-file=$(2) $(3)  &>/dev/null

setup-tests:
	docker network create --subnet=172.26.0.0/24 test
	docker run -d --net test --ip 172.26.0.2 --name zookeeper wurstmeister/zookeeper

teardown-tests:
	docker rm -f zookeeper
	docker network rm test

tests: $(TESTS_XML)
	$(call run_tests, -cvdh)

checks: $(TESTS_CHECKS_XML)
	$(call run_tests,-c)

memchecks: $(TESTS_MEM_XML)
	$(call run_tests,-v)

drdchecks: $(TESTS_DRD_XML)
	$(call run_tests,-d)

helchecks: $(TESTS_HELGRIND_XML)
	$(call run_tests,-h)

tests/%.mem.xml: tests/%.test $(MAXMIND_DB)
	-$(call run_valgrind,memcheck,"$@","./$<")

tests/%.helgrind.xml: tests/%.test $(MAXMIND_DB)
	-$(call run_valgrind,helgrind,"$@","./$<")

tests/%.drd.xml: tests/%.test $(MAXMIND_DB)
	-$(call run_valgrind,drd,"$@","./$<")

tests/%.xml: tests/%.test $(MAXMIND_DB)
	CMOCKA_XML_FILE="$@" CMOCKA_MESSAGE_OUTPUT=XML "./$<" &>/dev/null

TEST_DEPS := tests/rb_netflow_test.o tests/rb_json_test.o
tests/0023-testPrintbuf.test: TEST_DEPS =
tests/%.test: CPPFLAGS := -I. $(CPPFLAGS)
tests/%.test: tests/%.o tests/%.objdeps $(TEST_DEPS) $(OBJS)
	$(CC) $(CPPFLAGS) $(LDFLAGS) $< $(shell cat $(@:.test=.objdeps)) $(TEST_DEPS) -o $@ $(LIBS) -lcmocka

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

coverage: check_coverage $(TESTS)
	( for test in $(TESTS); do ./$$test; done )
	$(COV_LCOV) --gcov-tool=$(COV_GCOV) -q \
                --rc lcov_branch_coverage=1 --capture \
                --directory ./ --output-file ${COVERAGE_INFO}
	genhtml --branch-coverage ${COVERAGE_INFO} --output-directory \
				${COVERAGE_OUTPUT_DIRECTORY} > coverage.out
	# ./display_coverage.sh

-include $(DEPS)
#
