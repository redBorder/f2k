// rb_netflow_test.c

#include "rb_netflow_test.h"
#include "rb_mem_wraps.h"

#include "f2k.h"
#include "collect.c"

#include "rb_zk.h"

#include "rb_json_test.h"

#include "librd/rdfile.h"

#include <assert.h>
#include <jansson.h>
#include <setjmp.h>
#include <cmocka.h>

#include <librdkafka/rdkafka.h>

struct rb_netflow_test {
#define NF_TEST_STATE_MAGIC 0x355AEA1C355AEA1C
	uint64_t magic;
	struct {
		struct test_params *records;
		size_t records_size;
	} params;
	struct {
		struct string_list **sl;
	} ret;
	rd_memctx_t memctx;
};

static struct dns_ctx *dns_ctx;

static rd_kafka_t *test_consumer_rk = NULL;
static rd_kafka_t *test_producer_rk = NULL;
static rd_kafka_topic_t *test_producer_rkt = NULL;

static char *rand_tmpl(const char *preffix) {
	char *template = calloc(strlen(preffix) + 1 + 6, sizeof(char));
	strcat(template, preffix);
	strcat(template, "XXXXXX");
  int mktmp_fd = mkstemp(template);
  close(mktmp_fd);
  remove(template);

	return template;
}

/**
 * Initializes a Kafka consumer for obtain the output of f2k and verify the
 * data.
 *
 * @param  kafka_url URL of the Kafka broker
 */
static void init_test_kafka_consumer(const char *brokers, const char *topic) {
  rd_kafka_topic_conf_t *topic_conf = rd_kafka_topic_conf_new();
  rd_kafka_conf_t *conf = rd_kafka_conf_new();
  rd_kafka_topic_partition_list_t *topics;
  rd_kafka_resp_err_t err;
  char errstr[2048];

  if (rd_kafka_conf_set(conf, "group.id", "tests", errstr, sizeof(errstr)) !=
      RD_KAFKA_CONF_OK) {
    fprintf(stderr, "%% %s\n", errstr);
    return;
  }

  if (rd_kafka_topic_conf_set(topic_conf, "offset.store.method", "broker",
                              errstr, sizeof(errstr)) != RD_KAFKA_CONF_OK) {
    fprintf(stderr, "%% %s\n", errstr);
    return;
  }

  rd_kafka_conf_set_default_topic_conf(conf, topic_conf);

  if (!(test_consumer_rk =
            rd_kafka_new(RD_KAFKA_CONSUMER, conf, errstr, sizeof(errstr)))) {
    fprintf(stderr, "%% Failed to create new consumer: %s\n", errstr);
    return;
  }

  if (rd_kafka_brokers_add(test_consumer_rk, brokers) == 0) {
    fprintf(stderr, "%% No valid brokers specified\n");
    return;
  }

  rd_kafka_poll_set_consumer(test_consumer_rk);

  topics = rd_kafka_topic_partition_list_new(1);
  rd_kafka_topic_partition_list_add(topics, topic, 0);

  if ((err = rd_kafka_assign(test_consumer_rk, topics))) {
    fprintf(stderr, "%% Failed to assign partitions: %s\n",
            rd_kafka_err2str(err));
  }

  rd_kafka_topic_partition_list_destroy(topics);
}

/**
 * Initializes a Kafka producer for sending test data to f2k
 *
 * @param  kafka_url URL of the Kafka broker
 */
static void init_test_kafka_producer(const char *brokers, const char *topic) {
  rd_kafka_topic_conf_t *rkt_conf = rd_kafka_topic_conf_new();
  rd_kafka_conf_t *rk_conf = rd_kafka_conf_new();
  char errstr[2048];

  if (!(test_producer_rk =
            rd_kafka_new(RD_KAFKA_PRODUCER, rk_conf, errstr, sizeof(errstr)))) {
    fprintf(stderr, "%% Failed to create new consumer: %s\n", errstr);
    return;
  }

  if (rd_kafka_brokers_add(test_producer_rk, brokers) == 0) {
    fprintf(stderr, "%% No valid brokers specified\n");
    return;
  }

  if (test_producer_rk != NULL) {
    test_producer_rkt =
        rd_kafka_topic_new(test_producer_rk, topic, rkt_conf);
    if (test_producer_rkt != NULL) {
      rkt_conf = NULL;
    } else {
      traceEvent(TRACE_ERROR, "Unable to create a kafka topic");
      rd_kafka_destroy(test_producer_rk);
      test_producer_rk = NULL;
      return;
    }
  }
}

/**
 * Initializes internal f2k Kafka producer for sending processed netflow
 *
 * @param  kafka_url URL of the Kafka broker
 */
static void init_kafka_producer() {
  rd_kafka_topic_conf_t *rkt_conf = rd_kafka_topic_conf_new();
  rd_kafka_conf_t *rk_conf = rd_kafka_conf_new();
  char errstr[2048];

  if (!(readWriteGlobals->kafka.rk =
            rd_kafka_new(RD_KAFKA_PRODUCER, rk_conf, errstr, sizeof(errstr)))) {
    fprintf(stderr, "%% Failed to create new consumer: %s\n", errstr);
    return;
  }

  if (rd_kafka_brokers_add(readWriteGlobals->kafka.rk,
                           readOnlyGlobals.kafka.broker_ip) == 0) {
    fprintf(stderr, "%% No valid brokers specified\n");
    return;
  }

  if (readWriteGlobals->kafka.rk != NULL) {
    readWriteGlobals->kafka.rkt =
        rd_kafka_topic_new(readWriteGlobals->kafka.rk, readOnlyGlobals.kafka.topic, rkt_conf);
    if (readWriteGlobals->kafka.rkt != NULL) {
      rkt_conf = NULL;
    } else {
      traceEvent(TRACE_ERROR, "Unable to create a kafka topic");
      rd_kafka_destroy(readWriteGlobals->kafka.rk);
      readWriteGlobals->kafka.rk = NULL;
      return;
    }
  }
}

int nf_test_setup(void **state) {
	(void)state;
	/// @TODO we have, to get away of this stuff!! the code is too dependent of itself
	readWriteGlobals = calloc(1,sizeof(readWriteGlobals[0]));

	readOnlyGlobals.dontReforgeFarTimestamp = 1; /* We can't test if this is not setted */
	return 0;
}

int nf_test_teardown(void **state) {
  (void)state;
  size_t i;

  IPNameAssoc *hosts_lists[] = {
      readOnlyGlobals.rb_databases.ip_name_as_list,
      readOnlyGlobals.rb_databases.nets_name_as_list,
  };

  for (i = 0; i < RD_ARRAYSIZE(hosts_lists); ++i) {
    freeHostsList(hosts_lists[i]);
  }
  deleteGeoIPDatabases();
  if (readOnlyGlobals.zk.zh != NULL) {
    stop_f2k_zk();
    readOnlyGlobals.zk.zh = NULL;
  }

  if (readOnlyGlobals.rb_databases.sensors_info) {
    delete_rb_sensors_db(readOnlyGlobals.rb_databases.sensors_info);
    readOnlyGlobals.rb_databases.sensors_info = NULL;
  }

#ifdef HAVE_UDNS
  if (readOnlyGlobals.udns.dns_poll_threads) {
    for (i = 0; i < readOnlyGlobals.numProcessThreads; i++) {
      rd_thread_kill_join(readOnlyGlobals.udns.dns_poll_threads[i], NULL);
    }

    free(readOnlyGlobals.udns.dns_info_array);
    free(readOnlyGlobals.udns.dns_poll_threads);
    free(readOnlyGlobals.udns.csv_dns_servers);
  }

	if (dns_ctx) {
		dns_close(dns_ctx);
	}
#endif

  if (readWriteGlobals->kafka.rk) {
    while (rd_kafka_outq_len(readWriteGlobals->kafka.rk) > 0) {
      rd_kafka_poll(readWriteGlobals->kafka.rk, 50);
    }

    rd_kafka_topic_destroy(readWriteGlobals->kafka.rkt);
    rd_kafka_destroy(readWriteGlobals->kafka.rk);
    // rd_kafka_wait_destroyed(readWriteGlobals->kafka.rk);
    readWriteGlobals->kafka.rk = NULL;
    readWriteGlobals->kafka.rkt = NULL;
  }

  free(readWriteGlobals);
  readWriteGlobals = NULL;
  return 0;
}

struct nf_test_state *prepare_tests(const struct test_params *test_params,
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
  const size_t mem_stash = mem_wraps_get_fail_in();
  mem_wraps_set_fail_in(0); // no fail in initialization

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
      delete_rb_sensors_db(readOnlyGlobals.rb_databases.sensors_info);
    }
    readOnlyGlobals.rb_databases.sensors_info =
        read_rb_config(params->config_json_path, &worker, 1);
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
    if (!load_rc) {
      fprintf(stderr, "[Coulnd't unpack %s]\n", params->geoip_path);
      skip();
    }
  }

  if (params->template_save_path) {
    snprintf(readOnlyGlobals.templates_database_path,
             sizeof(readOnlyGlobals.templates_database_path), "%s",
             params->template_save_path);
    loadTemplates(params->template_save_path);
  }

  if (params->zk_url) {
    if (readOnlyGlobals.zk.zh) {
      stop_f2k_zk();
      readOnlyGlobals.zk.zh = NULL;
    }
    init_f2k_zk(params->zk_url);
  }

#ifdef HAVE_UDNS
  if (params->dns_servers) {
    readOnlyGlobals.numProcessThreads = 1;
    size_t i = 0;
    readOnlyGlobals.udns.csv_dns_servers = strdup(params->dns_servers);
    if (NULL == readOnlyGlobals.udns.csv_dns_servers) {
      traceEvent(TRACE_ERROR, "Memory error, can't strdup");
      return NULL;
    }

    dns_init(&dns_defctx, 0 /* don't do_open */);
    readOnlyGlobals.udns.dns_poll_threads =
        calloc(readOnlyGlobals.numProcessThreads,
               sizeof(readOnlyGlobals.udns.dns_poll_threads[0]));
    if (NULL == readOnlyGlobals.udns.dns_poll_threads) {
      traceEvent(TRACE_ERROR, "Can't allocate DNS polling threads");
      free(readOnlyGlobals.udns.csv_dns_servers);
      readOnlyGlobals.udns.csv_dns_servers = NULL;
    }
    readOnlyGlobals.udns.dns_info_array =
        calloc(readOnlyGlobals.numProcessThreads,
               sizeof(readOnlyGlobals.udns.dns_info_array[0]));
    if (NULL == readOnlyGlobals.udns.dns_info_array) {
      traceEvent(TRACE_ERROR, "Can't allocate DNS polling threads context");
      free(readOnlyGlobals.udns.dns_poll_threads);
      free(readOnlyGlobals.udns.csv_dns_servers);
      readOnlyGlobals.udns.csv_dns_servers = NULL;
    }
    for (i = 0; NULL != readOnlyGlobals.udns.dns_poll_threads &&
                readOnlyGlobals.udns.dns_info_array &&
                i < readOnlyGlobals.numProcessThreads;
         ++i) {
      static const char *thread_name = NULL;
      static const pthread_attr_t *attr = NULL;

      struct rb_dns_info *info = &readOnlyGlobals.udns.dns_info_array[i];

#ifdef RB_DNS_MAGIC
      info->magic = RB_DNS_MAGIC;
#endif

      info->dns_ctx = dns_new(&dns_defctx);
      dns_ctx = info->dns_ctx;
      if (NULL == info->dns_ctx) {
        traceEvent(TRACE_ERROR, "Can't allocate DNS context %zu info", i);
      }

      const int thread_create_rc =
          rd_thread_create(&readOnlyGlobals.udns.dns_poll_threads[i],
                           thread_name, attr, udns_pool_routine, info);

      if (thread_create_rc < 0) {
        char errstr[BUFSIZ];
        strerror_r(errno, errstr, sizeof(errstr));
        traceEvent(TRACE_ERROR, "Can't allocate DNS polling thread %zu: %s", i,
                   errstr);
      }
    }
  }
#endif

  if (test_producer_rkt) {
    char *buf = calloc(params->record_size, sizeof(char));
    memcpy(buf, params->record, params->record_size);
    if (rd_kafka_produce(test_producer_rkt, 0, RD_KAFKA_MSG_F_COPY, buf,
                         params->record_size, &params->netflow_src_ip,
                         sizeof(uint32_t), NULL) == -1) {
      fprintf(stderr, "%% Failed to produce to topic %s "
                      "partition %i: %s\n",
              rd_kafka_topic_name(test_producer_rkt), 0,
              rd_kafka_err2str(rd_kafka_last_error()));
    }
    free(buf);
  } else {
    check_if_reload(&readOnlyGlobals.rb_databases);

    const uint32_t netflow_device_ip = params->netflow_src_ip;
    const uint8_t *record = params->record;
    const size_t record_len = params->record_size;

    struct sensor *sensor_object = get_sensor(
        readOnlyGlobals.rb_databases.sensors_info, netflow_device_ip);

    if (sensor_object) {
      // wait until worker end to process all templates
      while (true) {
        pthread_mutex_lock(&worker->templates_queue.rfq_lock);
        const int cnt = worker->templates_queue.rfq_cnt;
        pthread_mutex_unlock(&worker->templates_queue.rfq_lock);

        if (cnt > 0) {
          usleep(1);
        } else {
          break;
        }
      }

      // Let's lock to make drd & helgrind happy
      pthread_mutex_lock(&worker->templates_queue.rfq_lock);
      pthread_mutex_lock(&worker->packetsQueue.rfq_lock);

      mem_wraps_set_fail_in(mem_stash); // fail beyond this point
      struct string_list *ret = dissectNetFlow(
          worker, sensor_object, netflow_device_ip, record, record_len);
      rb_sensor_decref(sensor_object);

      pthread_mutex_unlock(&worker->packetsQueue.rfq_lock);
      pthread_mutex_unlock(&worker->templates_queue.rfq_lock);

      return ret;
    }

    return NULL;
  }

  return NULL;
}

static void check_string_list(struct string_list *sl,
		const struct checkdata *checkdata, size_t checkdata_size) {
	size_t i = 0;
	const struct string_list *iter = NULL;

	for(i=0, iter=sl; i<checkdata_size && iter; ++i, iter = iter->next) {
		rb_assert_json(iter->string->buf,iter->string->bpos,&checkdata[i]);
	}

	// Have we consumed all string list messages?
	assert_null(iter);
	assert_true(i == checkdata_size);
}

/** Checks flow return string
 * @todo No need for re-scan all string list in response
 * @param  state Test state
 */
static void check_flow(struct nf_test_state *st) {
	size_t record_idx;
	assert_true(st->magic == NF_TEST_STATE_MAGIC);

	for (record_idx = 0; record_idx < st->params.records_size;
								++record_idx) {
		check_string_list(st->ret.sl[record_idx],
				st->params.records[record_idx].checkdata,
				st->params.records[record_idx].checkdata_size);
	}
}

static void free_state_returned_string_lists(struct nf_test_state *state) {
        size_t i = 0;
        for (i = 0; i < state->params.records_size; ++i) {
                struct string_list *list = state->ret.sl[i];
                state->ret.sl[i] = NULL;
                while (list) {
                        struct string_list *aux = list;
                        list = list->next;

                        printbuf_free(aux->string);
                        free(aux);
                }
        }
}

void testFlow(void **state) {
  size_t i;
  struct nf_test_state *st = *state;
  assert_true(st->magic == NF_TEST_STATE_MAGIC);
  char *input_topic = rand_tmpl("rb_flow_pre");
  char *output_topic = rand_tmpl("rb_flow");

  // TESTER: Produce Netflow test data to "rb_flow_pre"
  if (st->params.records->kafka_test_producer_url) {
    init_test_kafka_producer(st->params.records->kafka_test_producer_url,
                             input_topic);
    if (NULL == test_producer_rkt) {
      printf("TEST Producer: Can't connect to Kafka broker\n");
      exit(1);
    }
  }

  // F2K: Consume Netflow test data from "rb_flow_pre"
  if (st->params.records->kafka_consumer_url) {
    char *group_id = rand_tmpl("test");

    readOnlyGlobals.kafka_consumer.topic_conf = rd_kafka_topic_conf_new();
    readOnlyGlobals.kafka_consumer.conf = rd_kafka_conf_new();

    char errstr[512];
    if (rd_kafka_conf_set(readOnlyGlobals.kafka_consumer.conf, "group.id",
                          group_id, errstr,
                          sizeof(errstr)) != RD_KAFKA_CONF_OK) {
      traceEvent(TRACE_ERROR, "%% %s\n", errstr);
    }

    if (rd_kafka_conf_set(readOnlyGlobals.kafka_consumer.conf,
                          "metadata.broker.list",
                          st->params.records->kafka_consumer_url, errstr,
                          sizeof(errstr)) != RD_KAFKA_CONF_OK) {
      traceEvent(TRACE_ERROR, "%% %s\n", errstr);
    }

    if (rd_kafka_topic_conf_set(readOnlyGlobals.kafka_consumer.topic_conf,
                                "offset.store.method", "broker", errstr,
                                sizeof(errstr)) != RD_KAFKA_CONF_OK) {
      traceEvent(TRACE_ERROR, "%% %s\n", errstr);
    }

    if (rd_kafka_topic_conf_set(readOnlyGlobals.kafka_consumer.topic_conf,
                                "auto.offset.reset", "smallest", errstr,
                                sizeof(errstr)) != RD_KAFKA_CONF_OK) {
      traceEvent(TRACE_ERROR, "%% %s\n", errstr);
    }

    readOnlyGlobals.kafka_consumer.topic = input_topic;
		free(group_id);
  }

  // F2K: Produce JSON test data to "rb_flow"
  if (st->params.records->kafka_producer_url) {
    readOnlyGlobals.kafka.broker_ip =
        strdup(st->params.records->kafka_producer_url);
    readOnlyGlobals.kafka.topic = output_topic;
    init_kafka_producer();
    if (NULL == readWriteGlobals->kafka.rkt) {
      printf("F2K Producer: Can't connect to Kafka broker\n");
      exit(1);
    }
  }

  // TESTER: Consume JSON test data from "rb_flow"
  if (st->params.records->kafka_test_consumer_url) {
    init_test_kafka_consumer(st->params.records->kafka_test_consumer_url,
                             output_topic);
    if (NULL == test_consumer_rk) {
      printf("TEST Consumer: Can't connect to Kafka broker\n");
      exit(1);
    }
  }

  worker_t *worker = NULL;
  // Repeat if we are testing memory
  while (!worker) {
    worker = new_collect_worker();
  }

  // Consume f2k output messages to verify them
  if (test_consumer_rk) {
    rd_kafka_message_t *rkmessage;

    // Discard all messages in the queue and go to the last offset
    while (true) {
      rkmessage = rd_kafka_consumer_poll(test_consumer_rk, 100);
      if (rkmessage) {
        const rd_kafka_resp_err_t err = rkmessage->err;
        rd_kafka_message_destroy(rkmessage);

        if (err == RD_KAFKA_RESP_ERR__PARTITION_EOF) {
          break;
        }
      }
    }

    for (i = 0; i < st->params.records_size; ++i) {
      test_flow_i(&st->params.records[i], worker);
    }

    rkmessage = rd_kafka_consumer_poll(test_consumer_rk, 2000);
    if (rkmessage) {
      st->ret.sl[1] =
          (struct string_list *)calloc(1, sizeof(struct string_list));
      st->ret.sl[1]->string =
          (struct printbuf *)calloc(1, sizeof(struct printbuf));
      st->ret.sl[1]->string->buf = (char *)calloc(rkmessage->len, sizeof(char));
      st->ret.sl[1]->string->bpos = rkmessage->len;
      st->ret.sl[1]->string->size = rkmessage->len;
      memcpy(st->ret.sl[1]->string->buf, rkmessage->payload, rkmessage->len);
      rd_kafka_message_destroy(rkmessage);
    }
  } else {
    for (i = 0; i < st->params.records_size; ++i) {
      st->ret.sl[i] = test_flow_i(&st->params.records[i], worker);
    }
  }

  collect_worker_done(worker);
  check_flow(st);

  if (test_producer_rkt) {
    rd_kafka_topic_destroy(test_producer_rkt);
  }

  if (test_producer_rk) {
    rd_kafka_destroy(test_producer_rk);
  }

  if (readOnlyGlobals.kafka.broker_ip) {
    free(readOnlyGlobals.kafka.broker_ip);
  }

  if (test_consumer_rk) {
    rd_kafka_consumer_close(test_consumer_rk);
    rd_kafka_destroy(test_consumer_rk);
  }

  if (input_topic) {
    free(input_topic);
  }

  if (output_topic) {
    free(output_topic);
  }

  free_state_returned_string_lists(st);
  free(st);
}

void mem_test(void **vstate) {
  size_t i = 1;
  struct nf_test_state *state = *vstate;
  do {
    mem_wrap_fail_in = i++;
    free_state_returned_string_lists(state);
  } while (0 == mem_wrap_fail_in);
  mem_wrap_fail_in = 0;
  free(state);
}
