// rb_netflow_test.c

#include "rb_netflow_test.h"

#include "f2k.h"
#include "collect.c"

#include "rb_zk.c"

#include "rb_json_test.h"

#include "librd/rdfile.h"

#include <assert.h>
#include <jansson.h>
#include <setjmp.h>
#include <cmocka.h>

int nf_test_setup(void **state) {
	(void)state;
	/// @TODO we have, to get away of this stuff!! the code is too dependent of itself
	readWriteGlobals = calloc(1,sizeof(readWriteGlobals[0]));

	readOnlyGlobals.dontReforgeFarTimestamp = 1; /* We can't test if this is not setted */
	return 0;
}

int nf_test_teardown(void **state) {
	(void)state;
	if (readOnlyGlobals.rb_databases.sensors_info) {
		delete_rb_sensors_db(readOnlyGlobals.rb_databases.sensors_info);
	}
	freeHostsList(readOnlyGlobals.rb_databases.ip_name_as_list);
	freeHostsList(readOnlyGlobals.rb_databases.nets_name_as_list);
	deleteGeoIPDatabases();
	if (readOnlyGlobals.zk.zh != NULL) {
		stop_f2k_zk();
	}
	free(readWriteGlobals);
	return 0;
}

struct nf_test_state *prepare_tests(struct test_params *test_params,
						size_t test_params_size) {
	struct string_list *sl[test_params_size];
	memset(sl, 0, test_params_size*sizeof(sl[0]));

	struct nf_test_state *st = NULL;
	rd_calloc_struct(&st, sizeof(*st),
		test_params_size*sizeof(test_params[0]), test_params,
							&st->params.records,
		sizeof(sl), sl, &st->ret.sl,
		RD_MEM_END_TOKEN);

	assert_non_null(st);

	st->magic = NF_TEST_STATE_MAGIC;
	st->params.records_size = test_params_size;

	return st;
}

static int load_geoip_databases(const char *geoip_path) {
	const char *AS_path = NULL, *country_path = NULL;

	char *config_file = rd_file_read(geoip_path, NULL);
	if (!config_file) {
		fprintf(stderr,"[WARNING] Can't read config file.\n");
		return 0;
	} else {
		void *unpack_private = rb_json_assert_unpack(config_file, 0,
			"{s:s,s:s}",
			"as-path" ,&AS_path,
			"country-path" ,&country_path);

		readASs(AS_path);
		readCountries(country_path);

		free_json_unpacked(unpack_private);
		free(config_file);
		return 1;
	}
}

static struct string_list *test_flow_i(const struct test_params *params,
							worker_t *worker) {
	if (params->host_list_path) {
		if (readOnlyGlobals.rb_databases.hosts_database_path) {
			free(readOnlyGlobals.rb_databases.hosts_database_path);
		}
		readOnlyGlobals.rb_databases.hosts_database_path =
						strdup(params->host_list_path);
		/// @todo do we need this?
		readOnlyGlobals.rb_databases.reload_hosts_database = 1;
		readOnlyGlobals.rb_databases.reload_nets_database = 1;
		readOnlyGlobals.rb_databases.reload_apps_database = 1;
		readOnlyGlobals.rb_databases.reload_engines_database = 1;
	}

	if (params->config_json_path) {
		if (readOnlyGlobals.rb_databases.sensors_info) {
			delete_rb_sensors_db(
				readOnlyGlobals.rb_databases.sensors_info);
		}
		readOnlyGlobals.rb_databases.sensors_info = read_rb_config(
				params->config_json_path, NULL, &worker, 1);
	}

	if (params->mac_vendor_database_path) {
		if (readOnlyGlobals.rb_databases.mac_vendor_database_path) {
			free(readOnlyGlobals.rb_databases.mac_vendor_database_path);
		}
		readOnlyGlobals.rb_databases.mac_vendor_database_path =
				strdup(params->mac_vendor_database_path);
		readOnlyGlobals.rb_databases.reload_macs_vendor_database = 1;
	}

	if (params->geoip_path) {
		const int load_rc = load_geoip_databases(params->geoip_path);
		if(!load_rc) {
			fprintf(stderr,"[Coulnd't unpack %s]\n",
				params->geoip_path);
			skip();
		}
	}

	if (params->template_save_path) {
		snprintf(readOnlyGlobals.templates_database_path,
			sizeof(readOnlyGlobals.templates_database_path),
			"%s", params->template_save_path);
		loadTemplates(params->template_save_path);
	}

	if (params->zk_url) {
		init_f2k_zk(params->zk_url);
	}

	check_if_reload(&readOnlyGlobals.rb_databases);

	const uint32_t netflow_device_ip = params->netflow_src_ip;
	const uint16_t dst_port = params->netflow_dst_port;
	const uint8_t *record = params->record;
	const size_t record_len = params->record_size;
        struct sensor *sensor_object = get_sensor(
		readOnlyGlobals.rb_databases.sensors_info, netflow_device_ip,
		dst_port);
        if (sensor_object) {
  		worker_t *worker = sensor_worker(sensor_object);
		struct string_list *ret = dissectNetFlow(worker, sensor_object,
			netflow_device_ip, dst_port, record, record_len);
		rb_sensor_decref(sensor_object);
		return ret;
        } else {
        	return NULL;
        }
}

static void check_string_list(struct string_list *sl,
		const struct checkdata *checkdata, size_t checkdata_size) {
	size_t i = 0;
	const struct string_list *iter = NULL;

	for(i=0, iter=sl; i<checkdata_size && iter; ++i, iter = iter->next) {
		rb_assert_json(iter->string->buf,&checkdata[i]);
	}

	// Have we consumed all string list messages?
	assert_null(iter);
	assert_true(i == checkdata_size);

	if (sl) {
		free_string_list(sl);
	}
}

int check_flow(void **state) {
	size_t record_idx;
	struct nf_test_state *st = *state;
	assert_true(st->magic == NF_TEST_STATE_MAGIC);

	for (record_idx = 0; record_idx < st->params.records_size;
								++record_idx) {
		check_string_list(st->ret.sl[record_idx],
				st->params.records[record_idx].checkdata,
				st->params.records[record_idx].checkdata_size);
	}

	free(st);
	return 0;
}

void testFlow(void **state) {
	size_t i;
	struct nf_test_state *st = *state;
	assert_true(st->magic == NF_TEST_STATE_MAGIC);

	worker_t *worker = new_collect_worker();

	for (i=0; i<st->params.records_size; ++i) {
		st->ret.sl[i] = test_flow_i(&st->params.records[i], worker);
	}

	collect_worker_done(worker);

}
