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

#include "rb_listener.c"
#include "f2k.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <setjmp.h>
#include <cmocka.h>

#if 0

static const char PORT_2055[] =
	"{"
		"\"sensors_networks\":{"
			"\"4.3.2.0/24\":{"
				"\"2055\":{"
					"\"enrichment\":{"
						"\"sensor_name\":\"test1\","
						"\"sensor_ip\":\"4.3.2.0/24\""
					"},"
					"\"home_nets\":["
						"{\"network\":\"10.13.30.0/16\", \"network_name\":\"users\"}"
					"]"
				"}"
			"}"
		"}"
	"}";

static const char PORT_2055_2056[] =
	"{"
		"\"sensors_networks\":{"
			"\"4.3.2.0/24\":{"
				"\"2055\":{"
					"\"enrichment\":{"
						"\"sensor_name\":\"test1\","
						"\"sensor_ip\":\"4.3.2.0/24\""
					"},"
					"\"home_nets\":["
						"{\"network\":\"10.13.30.0/16\", \"network_name\":\"users\"}"
					"]"
				"},"
				"\"2056\":{"
					"\"enrichment\":{"
						"\"sensor_name\":\"test1\","
						"\"sensor_ip\":\"4.3.2.0/24\""
					"},"
					"\"home_nets\":["
						"{\"network\":\"10.13.30.0/16\", \"network_name\":\"users\"}"
					"]"
				"}"
			"}"
		"}"
	"}\n";

static const char PORT_2056[] =
	"{"
		"\"sensors_networks\":{"
			"\"4.3.2.0/24\":{"
				"\"2056\":{"
					"\"enrichment\":{"
						"\"sensor_name\":\"test1\","
						"\"sensor_ip\":\"4.3.2.0/24\""
					"},"
					"\"home_nets\":["
						"{\"network\":\"10.13.30.0/16\", \"network_name\":\"users\"}"
					"]"
				"}"
			"}"
		"}"
	"}";

static int write_in_file(int fd,const char *buffer,size_t bufsiz) {
	errno = 0;
	const int rc = write(fd,buffer,bufsiz);
	if(rc != (int)bufsiz) {
		perror("Can't write to file");
	}
	return rc;
}

static int temp_file(char *path, size_t pathsz) {
	static const char tmp_path_template[] = "/tmp/f2k_test31_XXXXXX";
	(void)pathsz; assert(pathsz >= sizeof(tmp_path_template));
	strcpy(path, tmp_path_template);
	int fd = mkstemp(path);
	if(fd < 0){
		perror("Can't create temp file");
	}

	return fd;
}

static size_t listener_list_size(const listener_list *l) {
	size_t ret = 0;
	struct port_collector *i = NULL;
	listener_list_foreach(i,l)
		++ret;
	return ret;
}

static void test_listeners() {
	const struct port_collector pc_udp_2055 = {
		.proto = UDP,
		.port = 2055
	},
	pc_udp_2056 = {
		.proto = UDP,
		.port = 2056
	};
	worker_t *worker = new_collect_worker();

	char tmpFilePath[BUFSIZ];
	int fd = temp_file(tmpFilePath,sizeof(tmpFilePath));
	write_in_file(fd,PORT_2055,strlen(PORT_2055));

	listener_list ll;
	listener_list_init(&ll);
	struct rb_sensors_db *db = read_rb_config(tmpFilePath, &ll, &worker, 1);
	assert_non_null(db);
	assert_true(1==listener_list_size(&ll));
	assert_true(is_present(&pc_udp_2055,&ll));

	// Same config file => Same config.
	delete_rb_sensors_db(db);
	db = read_rb_config(tmpFilePath, &ll, &worker, 1);
	unlink(tmpFilePath);
	assert_non_null(db);
	assert_true(1==listener_list_size(&ll));
	assert_true(is_present(&pc_udp_2055,&ll));

	// Config with two listeners
	close(fd);
	fd = temp_file(tmpFilePath,sizeof(tmpFilePath));

	write_in_file(fd,PORT_2055_2056,strlen(PORT_2055_2056));
	delete_rb_sensors_db(db);
	db = read_rb_config(tmpFilePath, &ll, &worker, 1);
	unlink(tmpFilePath);
	assert_non_null(db);
	assert_true(2==listener_list_size(&ll));
	assert_true(is_present(&pc_udp_2055,&ll));
	assert_true(is_present(&pc_udp_2056,&ll));

	// Config with one listener again
	close(fd);
	fd = temp_file(tmpFilePath,sizeof(tmpFilePath));

	write_in_file(fd,PORT_2056,strlen(PORT_2056));
	delete_rb_sensors_db(db);
	db = read_rb_config(tmpFilePath, &ll, &worker, 1);
	unlink(tmpFilePath);
	assert_non_null(db);
	assert_true(1==listener_list_size(&ll));
	assert_true(is_present(&pc_udp_2056,&ll));

	delete_rb_sensors_db(db);
	close(fd);
	listener_list_done(&ll);
	collect_worker_done(worker);
}

int main() {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_listeners)
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}

#endif

static void success() {}

int main() {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(success),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
