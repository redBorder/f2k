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

#include "config.h"
#include "f2k.h"
#include "export.h"
#include "template.h"
#include "util.h"
#include "rb_sensor.h"

#include "rb_zk.h"
#include "printbuf.h"

#ifdef HAVE_UDNS
#include "rb_dns_cache.h"
#endif

#include <librdkafka/rdkafka.h>
#include <librd/rdevent.h>
#include <stdint.h>
#include <stdbool.h>

#define DEBUG_FLOWS

#ifdef HAVE_UDNS

struct udns_opaque {
#ifndef NDEBUG
  #define UDNS_OPAQUE_MAGIC 0xD0AED0AED0AED0AEL
  uint64_t magic;
#endif
  atomic_uint64_t refcnt;

  struct printbuf *curr_printbuf;
  struct flowCache *flowCache;

};

#endif /* HAVE_UDNS */

/* ********* Templates queue ********** */

typedef struct queued_template_s {
#ifndef NDEBUG
#define QUEUED_TEMPLATE_MAGIC 0x333A3A1C333A3A1C
  uint64_t magic;
#endif
  observation_id_t *observation_id;
  FlowSetV9Ipfix *template;
} queued_template_t;

static queued_template_t *new_queued_template(FlowSetV9Ipfix *mtemplate,
    observation_id_t *observation_id) {
  queued_template_t *qt = calloc(1, sizeof(*qt));
  if (qt) {
#ifdef QUEUED_TEMPLATE_MAGIC
    qt->magic = QUEUED_TEMPLATE_MAGIC;
#endif
    qt->template = mtemplate;
    qt->observation_id = observation_id;
  }

  return qt;
}

typedef rd_fifoq_t template_queue_t;
#define template_queue_init(q) rd_fifoq_init(q)
#define template_queue_destroy(q) rd_fifoq_destroy(q);
/* ********* Template queue ******* */
static void template_queue_push(queued_template_t *qtemplate,
                                                            rd_fifoq_t *queue) {
  rd_fifoq_add(queue,qtemplate);
}

/** Convenience function to pop freeing rd_fifoq_elm_t
 * @param  queue Queue to pop
 * @return       [description]
 */
static void *rb_rd_fifoq_pop(rd_fifoq_t *queue) {
  rd_fifoq_elm_t *fifoq_elm = rd_fifoq_pop(queue);
  if(fifoq_elm) {
    void *elm = fifoq_elm->rfqe_ptr;
    rd_fifoq_elm_release(queue, fifoq_elm);
    return elm;
  }
  return NULL;
}

static queued_template_t *template_queue_pop(template_queue_t *queue) {
  return rb_rd_fifoq_pop(queue);
}

/* ******************* */

void sum_worker_stats(struct worker_stats *a, const struct worker_stats *b) {
  if (b->first_flow_processed_timestamp < a->first_flow_processed_timestamp) {
    a->first_flow_processed_timestamp = b->first_flow_processed_timestamp;
  }

  a->num_packets_received += b->num_packets_received;
  a->num_dissected_flow_packets += b->num_dissected_flow_packets;
  a->num_flows_unknown_template += b->num_flows_unknown_template;
  a->num_flows_processed += b->num_flows_processed;
  a->num_good_templates_received += b->num_good_templates_received;
  a->num_known_templates += b->num_known_templates;
  a->num_bad_templates_received += b->num_bad_templates_received;
}

struct worker_s {
#ifndef NDEBUG
#define WORKER_S_MAGIC 0x035A1C035A1C
  uint64_t magic;
#endif

  atomic_uint64_t run;
  /* Collector */
  struct worker_stats stats;

  rd_fifoq_t packetsQueue;
  template_queue_t templates_queue;
  pthread_t tid;
};

/* ********************************************************* */

static void kafka_produce(struct printbuf *kafka_line_buffer, uint64_t client_mac){
  //if(unlikely(readOnlyGlobals.enable_debug))
  //  traceEvent(TRACE_WARNING,"[KAFKA] line buffer: [len=%d] %s \n",kafka_line_buffer->bpos,kafka_line_buffer->buf);

  pthread_rwlock_rdlock(&readWriteGlobals->kafka.rwlock);
  const int produce_ret = rd_kafka_produce(readWriteGlobals->kafka.rkt, RD_KAFKA_PARTITION_UA,
    RD_KAFKA_MSG_F_FREE,
    /* Payload and length */
    kafka_line_buffer->buf, kafka_line_buffer->bpos,
    /* Optional key and its length */
    NULL,0,
    /* Message opaque, provided in
     * delivery report callback as
     * msg_opaque. */
    // WARN! if you change this behavior, you need to change the partitioner too.
    (void *)(intptr_t)client_mac);
  pthread_rwlock_unlock(&readWriteGlobals->kafka.rwlock);


  if(unlikely(produce_ret<0)){
    const rd_kafka_resp_err_t err = rd_kafka_errno2err(errno);
    traceEvent(TRACE_ERROR,"Cannot produce message: %s",rd_kafka_err2str(err));
  }else{
    kafka_line_buffer->buf = NULL; /* librdkafka will free it */
  }

  printbuf_free(kafka_line_buffer);
}

static void send_string_list_to_kafka(struct string_list *list){
  while(list){
    if(list->string)
      kafka_produce(list->string, list->client_mac);

    struct string_list * aux_list_node = list;
    list = list->next;
    free(aux_list_node);
  }
}

static void printNetflowElementRawBuffer(const uint8_t *buffer,size_t real_field_len,const char *element_name) {
  static const size_t max_element_length = 8;
  char output[512];
  size_t output_cursor = 0;

  output_cursor += snprintf(output+output_cursor,sizeof(output)-output_cursor,"Dissecting %s field: [",element_name);
  if(real_field_len > max_element_length) {
    output_cursor += snprintf(output+output_cursor,sizeof(output)-output_cursor,"(Element too long to print )");
  } else {
    size_t buffer_cursor;
    for(buffer_cursor=0;buffer_cursor<max_element_length;++buffer_cursor)
      output_cursor += snprintf(output+output_cursor,sizeof(output)-output_cursor,"%02x ",buffer[buffer_cursor]);
  }
  output_cursor += snprintf(output+output_cursor,sizeof(output)-output_cursor,"]");

  traceEvent(TRACE_NORMAL,"%s", output);
}

/// Arguments to sanitize_timestamp
struct sanitize_timestamp_args {
  uint64_t timestamp;   ///< Timestamp to sanitize
  uint64_t now;         ///< Current moment, used as fallback
  uint64_t low_limit;   ///< Minimum acceptable timestamp
  uint64_t upper_limit; ///< Max acceptable timestamp

  // fallback-first-switch. If first_timestamp == last_timestamp, it will be
  // changed by timestamp - fallback_first_switched
  struct {
    uint64_t last_timestamp_s;         ///< known last timestamp
    int64_t fallback_first_switched_s; ///< fallback back step
  } fallback;

  // Debug
  const char *past_error; ///< Error if timestamp is too low (debug)
  const char *future_error; ///< Error if timestamp is too high (debug)
  const char *netflow_device_ip; ///< IP of probe (debug)
};

/** Set a timestamp in the present again
 * @todo review function & childs for time arithmetic
 */
static uint64_t sanitize_timestamp(
                              const struct sanitize_timestamp_args *args) {
  const bool timestamp_too_future = args->timestamp > args->upper_limit;
  const bool timestamp_too_past = args->timestamp < args->low_limit;

  if (timestamp_too_future || timestamp_too_past) {
    if (unlikely(readOnlyGlobals.enable_debug)) {
      traceEvent(TRACE_ERROR, "%s (timestamp: %ld, src_ip: %s)",
        timestamp_too_future ? args->future_error : args->past_error,
        args->timestamp, args->netflow_device_ip);
    }

    if (!readOnlyGlobals.dontReforgeFarTimestamp) {
      return args->now;
    }
  }

  if (args->fallback.fallback_first_switched_s &&
        args->timestamp == args->fallback.last_timestamp_s) {
    /* We are in first_switched AND we have defined a fallback_first_switch
       AND first_switched == last_switched */
    return args->timestamp + args->fallback.fallback_first_switched_s;
  }

  return args->timestamp;
}

/**
 * Split flow in timestamp slices
 * @param  kafka_line_buffer String buffer with flow shared data
 * @param  first_timestamp   First flow switched packet timestamp
 * @param  dSwitched         Flow diration
 * @param  bytes             Bytes of all flow
 * @param  pkts              Packets of all flow
 * @param  flowCache         Common elements of the flow
 * @todo review function & childs for time arithmetic
 * @return                   String list with splitted flow
 */
static struct string_list *time_split_flow(struct printbuf *kafka_line_buffer,
                  struct flowCache *flowCache) {
  const struct sensor *sensor = flowCache->sensor;
  const observation_id_t *observation_id = flowCache->observation_id;
  const time_t now = time(NULL);

  if (0 == flowCache->time.export_timestamp_s) {
    flowCache->time.export_timestamp_s = now;
  }

  const time_t actual_last_timestamp_s = flowCache->time.last_timestamp_s ?
                flowCache->time.last_timestamp_s
        : (flowCache->time.sys_uptime_s &&
                                      flowCache->time.last_switched_uptime_s) ?
                flowCache->time.export_timestamp_s
                - flowCache->time.sys_uptime_s
                + flowCache->time.last_switched_uptime_s
        : flowCache->time.export_timestamp_s;

  const struct sanitize_timestamp_args last_timestamp_make_present_args = {
    .timestamp = actual_last_timestamp_s,
    .now = now,
    .low_limit = now - 60*10,
    .upper_limit = now + 60*10,
    .past_error = "Received a flow with last timestamp from the past",
    .future_error = "Received a flow with last timestamp from the future",
    .netflow_device_ip = sensor_ip_string(sensor),
  };

  const time_t last_timestamp_s = sanitize_timestamp(
                                            &last_timestamp_make_present_args);

  // @todo join with first one
  const time_t actual_first_timestamp_s = flowCache->time.first_timestamp_s ?
                flowCache->time.first_timestamp_s
        : (flowCache->time.sys_uptime_s &&
                                      flowCache->time.first_switched_uptime_s) ?
                flowCache->time.export_timestamp_s
                - flowCache->time.sys_uptime_s
                + flowCache->time.first_switched_uptime_s
        : flowCache->time.export_timestamp_s
                - flowCache->time.last_switched_uptime_s
                + flowCache->time.first_switched_uptime_s;

  const struct sanitize_timestamp_args first_timestamp_make_present_args = {
    .timestamp = actual_first_timestamp_s,
    .now = now,
    .low_limit = now - 60*10,
    .upper_limit = now + 60*10,
    .past_error = "Received a flow with first timestamp from the past",
    .future_error = "Received a flow with first timestamp from the future",
    .netflow_device_ip = sensor_ip_string(sensor),
    .fallback = {
      .last_timestamp_s = last_timestamp_s,
      .fallback_first_switched_s = observation_id_fallback_first_switch(
        observation_id),
    },
  };

  const time_t first_timestamp_s = sanitize_timestamp(
                                            &first_timestamp_make_present_args);

  const uint64_t dSwitched = last_timestamp_s - first_timestamp_s;
  const uint64_t bytes = flowCache->bytes;
  const uint64_t pkts = flowCache->packets;
  struct string_list *ret = NULL;
  assert(kafka_line_buffer);

  if (readOnlyGlobals.separate_long_flows) {
      ret = rb_separate_long_time_flow(kafka_line_buffer,first_timestamp_s,
        dSwitched,60 /* segs */,60 /*60 intervals: an hour */,bytes,pkts);
  } else {
    const uint64_t first_timestamp_sw = ntohll(first_timestamp_s);
    const uint64_t last_timestamp_sw = ntohll(first_timestamp_s + dSwitched);
    const uint64_t bytes_sw = ntohll(bytes);
    const uint64_t pkts_sw = ntohll(pkts);
    printNetflowRecordWithTemplate(kafka_line_buffer,
      TEMPLATE_OF(PRINT_FIRST_SWITCHED), &first_timestamp_sw,
      sizeof(first_timestamp_sw), 0, flowCache);
    printNetflowRecordWithTemplate(kafka_line_buffer,
      TEMPLATE_OF(PRINT_LAST_SWITCHED), &last_timestamp_sw,
      sizeof(last_timestamp_sw), 0, flowCache);
    printNetflowRecordWithTemplate(kafka_line_buffer,
      TEMPLATE_OF(PRINT_IN_BYTES), &bytes_sw, sizeof(bytes_sw), 0, flowCache);
    printNetflowRecordWithTemplate(kafka_line_buffer,
      TEMPLATE_OF(PRINT_IN_PKTS), &pkts_sw, sizeof(pkts_sw), 0, flowCache);
    printbuf_memappend_fast(kafka_line_buffer, "}", strlen("}"));
    /// @TODO make a function that create a list with 1 node
    ret = calloc(1,sizeof(ret[0]));
    if (likely(ret)) {
      ret->string = kafka_line_buffer;
      ret->client_mac = flowCache->client_mac;
    } else {
      traceEvent(TRACE_ERROR,
        "Can't allocate string list node (out of memory?)");
      printbuf_free(kafka_line_buffer);
    }
  }

  return ret;
}

static void dissectNetFlowV5Field(const NetFlow5Record *the5Record,
      const size_t flow_idx,const size_t field_idx,struct printbuf *kafka_line_buffer,
      struct flowCache *flowCache) {
  size_t value_ret = 0;
  const void *buffer = NULL;
  size_t real_field_len=0;

  switch (v5TemplateFields[field_idx]->templateElementId) {
  case DST_AS: // Will be printed in src and dst
  case SRC_AS:
      break;
  case IPV4_DST_ADDR:
      real_field_len=4;
      buffer = &the5Record->flowRecord[flow_idx].dstaddr;
      break;
  case IPV4_SRC_ADDR:
      buffer = &the5Record->flowRecord[flow_idx].srcaddr;
      real_field_len=4;
      break;
  case IN_PKTS:
      buffer = &the5Record->flowRecord[flow_idx].dPkts;
      real_field_len=4;
      break;
  case IN_BYTES:
      buffer = &the5Record->flowRecord[flow_idx].dOctets;
      real_field_len=4;
      break;
  case FIRST_SWITCHED:
      buffer = &the5Record->flowRecord[flow_idx].first;
      real_field_len=4;
      break;
  case LAST_SWITCHED:
      buffer = &the5Record->flowRecord[flow_idx].last;
      real_field_len=4;
      break;
  case L4_SRC_PORT:
    real_field_len = 2;
    buffer = &the5Record->flowRecord[flow_idx].srcport;
    break;
  case L4_DST_PORT:
    real_field_len = 2;
    buffer = &the5Record->flowRecord[flow_idx].dstport;
    break;
  case INPUT_SNMP:
    real_field_len = 2;
    buffer = &the5Record->flowRecord[flow_idx].input;
    break;
  case OUTPUT_SNMP:
    real_field_len = 2;
    buffer = &the5Record->flowRecord[flow_idx].output;
    break;
  case ENGINE_ID:
    real_field_len = 1;
    buffer = &the5Record->flowHeader.engine_id;
    break;
  case ENGINE_TYPE:
    real_field_len = 1;
    buffer = &the5Record->flowHeader.engine_type;
    break;
  case IPV4_NEXT_HOP:
    real_field_len = 4;
    buffer = &the5Record->flowRecord[flow_idx].nexthop;
    break;
  case SRC_TOS:
    real_field_len = 1;
    buffer = &the5Record->flowRecord[flow_idx].tos;
    break;
  case PROTOCOL:
    real_field_len = 1;
    buffer = &the5Record->flowRecord[flow_idx].proto;
    break;
  case TCP_FLAGS:
    real_field_len = 1;
    buffer = &the5Record->flowRecord[flow_idx].tcp_flags;
    break;
  default:
    traceEvent(TRACE_ERROR,"Unknown case in V5 flow");
    break;
  };

  if (unlikely(readOnlyGlobals.enable_debug)) {
    printNetflowElementRawBuffer(buffer, real_field_len,
      v5TemplateFields[field_idx]->jsonElementName);
  }

  if (NULL==buffer) {
    return;
  }

  const int start_bpos = kafka_line_buffer->bpos;
  value_ret = printNetflowRecordWithTemplate(kafka_line_buffer,
    v5TemplateFields[field_idx], buffer, real_field_len, 0, flowCache);
  if (value_ret == 0) {
    kafka_line_buffer->bpos = start_bpos;
    kafka_line_buffer->buf[start_bpos] = '\0';
  }
}

/** Extract export timestamp & system uptime from a v9/v10 flow and sanitize it
 * @param  handle_ipfix      We are handling v9 or v10 flow
 * @param  flowHeader        Header of the flow
 * @param  export_timestamp  Where to save export timestamp
 * @param  sys_uptime        Where to save system uptime
 */
static void flow_export_timestamp_uptime(const bool handle_ipfix,
    const void *flow_header, uint64_t *export_timestamp_s,
    uint64_t *sys_uptime_s) {

/// Wrapper to make easy call to net2number
#define SIZED_NET2NUMBER(x) net2number(&x, sizeof(x))

  *sys_uptime_s = handle_ipfix ? 0 :
    SIZED_NET2NUMBER(((const V9FlowHeader *)flow_header)->sys_uptime)/1000;
  *export_timestamp_s = handle_ipfix ?
    SIZED_NET2NUMBER(((const IPFIXFlowHeader *)flow_header)->unix_secs) :
    SIZED_NET2NUMBER(((const V9FlowHeader *)flow_header)->unix_secs);

#undef SIZED_NET2NUMBER
}

/** Dissect a single flow of netflow 5
 * @param  the5Record    Netflow 5 record
 * @param  flow_idx      Netflow flow idx
 * @param  sensor_object Sensor that sent this flow
 * @return               String list with record
 */
static struct string_list *dissectNetFlowV5Record(const NetFlow5Record *the5Record,
                const int flow_idx, const struct sensor *sensor_object,
                observation_id_t *observation_id) {
  struct printbuf *kafka_line_buffer = printbuf_new();
  const uint16_t *flowVersion = &the5Record->flowHeader.version;
  const uint32_t flowSecuence_h = ntohl(the5Record->flowHeader.flow_sequence)
                                                                    + flow_idx;
  const uint32_t flowSecuence = htonl(flowSecuence_h);

  if(unlikely(NULL==kafka_line_buffer)){
    traceEvent(TRACE_ERROR,"Memory error");
    return NULL;
  }

  printbuf_memappend_fast(kafka_line_buffer, "{", strlen("{"));
  struct flowCache flowCache = {
    .sensor = sensor_object,
    .observation_id = observation_id
  };
  uint64_t field_idx=0;
  printNetflowRecordWithTemplate(kafka_line_buffer, TEMPLATE_OF(REDBORDER_TYPE),
    flowVersion, 2, 0, &flowCache);
  printNetflowRecordWithTemplate(kafka_line_buffer, TEMPLATE_OF(FLOW_SEQUENCE),
    &flowSecuence, sizeof(flowSecuence), 0, &flowCache);

  flow_export_timestamp_uptime(false, the5Record,
    &flowCache.time.export_timestamp_s, &flowCache.time.sys_uptime_s);

  for (field_idx=0; NULL!=v5TemplateFields[field_idx]; ++field_idx) {
    dissectNetFlowV5Field(the5Record, flow_idx, field_idx, kafka_line_buffer,
      &flowCache);
  }

  guessDirection(&flowCache);

  printNetflowRecordWithTemplate(kafka_line_buffer,
    TEMPLATE_OF(PRINT_DIRECTION), NULL, 0, 0, &flowCache);
  print_sensor_enrichment(kafka_line_buffer,&flowCache);

  struct string_list *kafka_buffers_list = time_split_flow(kafka_line_buffer,
                                  &flowCache);

  return kafka_buffers_list;
}

static struct string_list *dissectNetFlowV5(worker_t *worker,
              const struct sensor *sensor_object,
              observation_id_t *observation_id,
              const NetFlow5Record *the5Record) {
    uint16_t numFlows = ntohs(the5Record->flowHeader.count);

    if(numFlows > V5FLOWS_PER_PAK) numFlows = V5FLOWS_PER_PAK;

#ifdef DEBUG_FLOWS
    if(unlikely(readOnlyGlobals.enable_debug))
      traceEvent(TRACE_INFO, "dissectNetFlow(%d flows)", numFlows);
#endif

    struct string_list *string_list = NULL;
    unsigned int flow_idx;
    for(flow_idx=0; flow_idx<numFlows; flow_idx++){
      struct string_list *sl2 = dissectNetFlowV5Record(the5Record,
        flow_idx, sensor_object, observation_id);
      string_list_concat(&string_list,sl2);
    }

    worker->stats.num_flows_processed+=numFlows;
    return string_list;
}

static int create_template_filename(char *buf, size_t bufsize,
    const char *database_path, const FlowSetV9Ipfix *template) {
  char buffer_ipv4[BUFSIZ];
  return snprintf(buf, bufsize, "%s/%s_%"PRIu32"_%"PRIu16".dat",
    database_path,
    _intoaV4(template->templateInfo.netflow_device_ip, buffer_ipv4,
                                                          sizeof(buffer_ipv4)),
    template->templateInfo.observation_domain_id,
    template->templateInfo.templateId);
}

static void saveGoodTemplateInFile(const FlowSetV9Ipfix *new_template) {
  char filename[BUFSIZ];

  create_template_filename(filename, sizeof(filename),
    readOnlyGlobals.templates_database_path,
    new_template);

  if (unlikely(readOnlyGlobals.enable_debug)) {
    traceEvent(TRACE_NORMAL, ">>>>> Saving template in %s",filename);
  }
  saveTemplateInFile(new_template,filename);
}

#ifdef HAVE_ZOOKEEPER
/* @TODO move to rb_zk.h? */

struct aset_template_data {
  char path[BUFSIZ];
  char *buffer;
  size_t bufsize;
  zhandle_t *zh;
  int creating;
  struct ACL_vector acl;
};

static void set_template_complete(int rc, const struct Stat *zk_stat __attribute__((unused)), const void *_data);
static void create_template_complete(int rc, const char *value __attribute__((unused)), const void *_data);

static void zoo_template_complete(int rc,void *_data) {
  struct aset_template_data *data = _data;
  switch(rc){
  case ZOK:
    traceEvent(TRACE_INFO,"ZK node %s with value %s",
      data->creating ? "created" : "setted", data->buffer);
    break;

  case ZNONODE:
    if(0 == data->creating) {
      traceEvent(TRACE_INFO,"Can't write to ZK node %s because it does not exists: Creating",data->path);
      data->creating = 1;
      const int create_rc = zoo_acreate(data->zh,data->path,data->buffer,
                                        data->bufsize,&data->acl,0,
                                        create_template_complete,data);
      if(create_rc == ZOK) {
        data = 0; /* Do not free data */
      } else {
        traceEvent(TRACE_ERROR,"Can't create ZK template node: %s",zerror(create_rc));
      }
    } else {
      traceEvent(TRACE_ERROR,
        "Can't create ZK node %s because parent node does not exists",
        data->path);
    }
    break;

  case ZNODEEXISTS:
    /* This error can only be throwed in create(), so node must have been created  */
    traceEvent(TRACE_ERROR,
      "Node %s created in a race condition. Will not overwrite.",
      data->path);
    break;

  case ZNOAUTH:
    traceEvent(TRACE_ERROR,"Does not have permission to %s node %s.",
      data->creating ? "create" : "write in", data->path);
    break;

  case ZBADVERSION:
    traceEvent(TRACE_ERROR,"Trying to write a previous version of template %s",data->path);
    break;

  case ZNOCHILDRENFOREPHEMERALS:
    traceEvent(TRACE_ERROR,"Can't create child nodes of ephimeral nodes");
    break;

  default:
    traceEvent(TRACE_ERROR,"Unknown error returned: %d (%s)",rc,zerror(rc));
    break;
  };

  if(data){
    free(data->buffer);
    free(data);
  }
}

/**
 * Remove const of a void pointer, with no warning. Use with caution, only for
 * zk functions!
 */
static void *not_const_cast(const void *p) {
  void *r;
  memcpy(&r, &p, sizeof(r));
  return r;
}

static void set_template_complete(int rc,
        const struct Stat *zk_stat __attribute__((unused)), const void *data) {
  zoo_template_complete(rc, not_const_cast(data));
}

static void create_template_complete(int rc,
                                    const char *value __attribute__((unused)),
                                    const void *data) {
  zoo_template_complete(rc, not_const_cast(data));
}

static void saveGoodTemplateInZooKeeper(zhandle_t *zh,
    const FlowSetV9Ipfix *new_template) {

  struct aset_template_data *data = calloc(1,sizeof(*data));
  if(!data){
    traceEvent(TRACE_ERROR,"Can't allocate data struct to save template in zookeeper");
    return;
  }

  data->zh = zh;
  memcpy(&data->acl,&ZOO_OPEN_ACL_UNSAFE,sizeof(data->acl));
  const size_t print_rc = create_template_filename(data->path,
    sizeof(data->path), ZOOKEEPER_PATH, new_template);

  if(!(print_rc > 0 && print_rc < sizeof(data->path))) {
    traceEvent(TRACE_ERROR,"Can't print zookeeper path: snprintf returned %zu, it should be 0<rc<%zu",
      print_rc,sizeof(data->path));
  }

  data->buffer = serialize_template(new_template,&data->bufsize);

  if(NULL == data->buffer) {
    traceEvent(TRACE_ERROR,"Can't serialize ZK template");
    free(data);
    return;
  }

  const int set_rc = zoo_aset(zh,data->path,
      data->buffer /* Value */,
      data->bufsize /* Valuelen*/,
      -1, /* version */
      set_template_complete,
      data);

    if(set_rc != ZOK)
      traceEvent(TRACE_ERROR, "Can't set template %s in zookeeper: %s",
        data->path, zerror(set_rc));
}

#endif

#ifdef HAVE_UDNS

static void split_after_dns_query_completed(struct dns_ctx *ctx,
    struct udns_opaque *opaque) {
  (void)ctx;
  printNetflowRecordWithTemplate(opaque->curr_printbuf,
    TEMPLATE_OF(DNS_CLIENT_NAME),NULL,0,0,opaque->flowCache);
  printNetflowRecordWithTemplate(opaque->curr_printbuf,
    TEMPLATE_OF(DNS_TARGET_NAME),NULL,0,0,opaque->flowCache);

  struct string_list *string_list = time_split_flow(opaque->curr_printbuf,
    opaque->flowCache);

  send_string_list_to_kafka(string_list);

  if(opaque->flowCache->address.client_name) {
    free(opaque->flowCache->address.client_name);
  }
  if(opaque->flowCache->address.target_name) {
    free(opaque->flowCache->address.target_name);
  }
  if(opaque->flowCache->address.client_name_cache) {
    dns_cache_decref_elm(opaque->flowCache->address.client_name_cache);
  }
  if(opaque->flowCache->address.target_name_cache) {
    dns_cache_decref_elm(opaque->flowCache->address.target_name_cache);
  }

  free(opaque->flowCache);
  free(opaque);
}

static void dns_query_completed0(struct dns_ctx *ctx,
          struct dns_rr_ptr *result, struct udns_opaque *opaque,
          char **hostname_dst,struct dns_cache_elm ** cache_elm_dst,
          const uint8_t * (*addr_fn)(const struct flowCache *)) {
#ifdef UDNS_OPAQUE_MAGIC
  assert(UDNS_OPAQUE_MAGIC == opaque->magic);
#endif

  const uint8_t *addr = (const uint8_t *) addr_fn(opaque->flowCache);

  if(result && result->dnsptr_nrr > 0) {
    struct dns_cache_elm *cache_elm = NULL;
    if(cache_elm_dst) {
      /* Cache specified, save result in cache */
      const size_t name_len = strlen(result->dnsptr_ptr[0]);
      cache_elm = dns_cache_save_elm(readOnlyGlobals.udns.cache,addr,
        result->dnsptr_ptr[0],name_len,time(NULL));
      (*cache_elm_dst) = cache_elm;
    }

    if(NULL == cache_elm_dst || (cache_elm_dst && NULL == cache_elm)) {
      /* No cache or cache full, neet to return result in another way */
      (*hostname_dst) = strdup(result->dnsptr_ptr[0]);
    }
  }

  if(0 == ATOMIC_OP(sub,fetch,&opaque->refcnt.value,1)) {
    /* src and dst have been fetched: enqueue to process */
    rd_thread_t *curr_thread = rd_currthread_get();
    assert(curr_thread);
    rd_thread_func_call2(curr_thread,split_after_dns_query_completed,ctx,opaque);
  }

  if(result) {
    free(result);
  }
}

static void dns_query_completed_client(struct dns_ctx *ctx, struct dns_rr_ptr *result,
                                        void *void_opaque) {
  struct udns_opaque *opaque = void_opaque;
#ifdef UDNS_OPAQUE_MAGIC
  assert(UDNS_OPAQUE_MAGIC == opaque->magic);
#endif

  dns_query_completed0(ctx,result, opaque,
    &opaque->flowCache->address.client_name,
    &opaque->flowCache->address.client_name_cache,
    get_direction_based_client_ip);
}

static void dns_query_completed_target(struct dns_ctx *ctx, struct dns_rr_ptr *result,
                                        void *void_opaque) {
  struct udns_opaque *opaque = void_opaque;
#ifdef UDNS_OPAQUE_MAGIC
  assert(UDNS_OPAQUE_MAGIC == opaque->magic);
#endif

  dns_query_completed0(ctx,result,opaque,&opaque->flowCache->address.target_name,
    &opaque->flowCache->address.target_name_cache, get_direction_based_target_ip);
}

#endif /* HAVE_UDNS */

static void dumpFlow(size_t begin, size_t end, const uint8_t *buffer) {
  if(0 && readOnlyGlobals.enable_debug) {
    size_t i;

    traceEvent(TRACE_INFO, ">>>>> Stats [%zu...%zu]", begin, end);

    for(i=begin; i<end; i++)
      traceEvent(TRACE_INFO, "%02X [%zu]", buffer[i] & 0xFF, i);
  }
}

struct sized_buffer {
  const void *buffer_start;
  const void *buffer;
  size_t size;
};

struct netflow_sensor {
  uint32_t netflow_device_ip;
  struct sensor *sensor;
  uint16_t dst_port;
};

static int dissectNetFlowV9V10Template(worker_t *worker,
                                const struct sized_buffer *_buffer,
                                const struct netflow_sensor *sensor,
                                observation_id_t *observation_id,
                                size_t *readed,
                                size_t numEntries, int handle_ipfix) {

  const uint8_t *buffer = _buffer->buffer;
  const ssize_t bufferLen = (ssize_t)_buffer->size;
  const uint32_t netflow_device_ip = sensor->netflow_device_ip;
  V9V10TemplateField *fields = NULL;
  uint32_t observation_domain_id = 0;

  ssize_t displ = 0;
  V9IpfixSimpleTemplate template;

  uint8_t isOptionTemplate = (uint8_t)buffer[displ+1];

  /* Template */
  if(handle_ipfix && (isOptionTemplate == 2 /* Template Flowset */)) {
    /*
      IPFIX (isOptionTemplate)

      A value of 2 is reserved for the
      Template Set.  A value of 3 is reserved for the Option Template
      Set.  All other values from 4 to 255 are reserved for future use.
      Values above 255 are used for Data Sets.  The Set ID values of 0
      and 1 are not used for historical reasons
    */

    /* This trick is necessary as only option template flowsets
       have to be handled differently from other templates
    */
    isOptionTemplate = 0;
  }

  if(unlikely(readOnlyGlobals.enable_debug)) {
    traceEvent(TRACE_INFO, "Found Template [displ=%zd]", displ);
    traceEvent(TRACE_INFO, "Found Template Type: %s", isOptionTemplate ? "Option" : "Flow");
  }

  if(bufferLen > (displ+(ssize_t)sizeof(V9TemplateHeader))) {
    V9TemplateHeader header;
    bool template_done = false;

    memcpy(&header, &buffer[displ], sizeof(V9TemplateHeader));
    header.templateFlowset = ntohs(header.templateFlowset), header.flowsetLen = ntohs(header.flowsetLen);
    /* Do not change to uint: this way I can catch template length issues */
    ssize_t stillToProcess = header.flowsetLen - sizeof(V9TemplateHeader);
    displ += sizeof(V9TemplateHeader);

    while((bufferLen >= (displ+stillToProcess)) && (!template_done)) {
      size_t len = 0;
      int fieldId;
      bool good_template = false;
      size_t accumulatedLen = 0;

      memset(&template, 0, sizeof(template));
      template.isOptionTemplate = isOptionTemplate,
      template.netflow_device_ip = netflow_device_ip;

      if(isOptionTemplate) {
        memcpy(&template.templateId, &buffer[displ], 2);
        template.templateId = htons(template.templateId), template.fieldCount = (header.flowsetLen - 14)/4;

        if(handle_ipfix) {
          uint16_t tot_field_count, tot_scope_field_count;

          displ += 2, stillToProcess -= 2 /*, len += 2 */;
          memcpy(&tot_field_count, &buffer[displ], 2); tot_field_count = htons(tot_field_count);
          displ += 2, stillToProcess -= 2 /* , len += 2 */;
          memcpy(&tot_scope_field_count, &buffer[displ], 2); tot_scope_field_count = htons(tot_scope_field_count);
          displ += 2, stillToProcess -= 2 /* , len += 2 */;
          template.scopeFieldCount = tot_scope_field_count;

          if(tot_field_count >= tot_scope_field_count) {
            const size_t num = tot_scope_field_count * 4; /* FIX: check PEN here */
            const size_t field_num = (tot_field_count-tot_scope_field_count) * 4;
            const size_t delta = num + field_num;

            displ += delta, stillToProcess -= delta /* , len += num */;
          } else {
            traceEvent(TRACE_WARNING,
               "It looks looks like the template is broken (tot_field_count=%d,"
               "tot_scope_field_count=%d) [num_dissected_flows=%"PRIu64"]"
               "[templateType=%d]",
               tot_field_count, tot_scope_field_count,
               worker->stats.num_dissected_flow_packets,
               isOptionTemplate);
            displ += 4 /* , len += 4 */; /* Using default skip */
          }
        } else {
          memcpy(&template.v9ScopeLen, &buffer[displ+8], 2);
          template.v9ScopeLen = htons(template.v9ScopeLen);
          displ += 10, /* len = 0, */ stillToProcess -= 10;
        }
      } else {
        V9TemplateDef templateDef;

        memcpy(&templateDef, &buffer[displ], sizeof(V9TemplateDef));
        displ += sizeof(V9TemplateDef), len = 0, stillToProcess -= sizeof(V9TemplateDef);

        template.templateId = htons(templateDef.templateId), template.fieldCount = htons(templateDef.fieldCount);
      }

      if (unlikely(template.fieldCount > 128)) {
        traceEvent(TRACE_WARNING, "Too many template fields (%d): skept", template.fieldCount);
        good_template = false;
      } else {
        if(handle_ipfix) {
          fields = calloc(template.fieldCount, sizeof(V9V10TemplateField));
          if(fields == NULL) {
            traceEvent(TRACE_WARNING, "Not enough memory");
            break;
          }

          if(((template.fieldCount * 4) + sizeof(FlowSet) + 4 /* templateFlowSet + FlowsetLen */) >  header.flowsetLen) {
            traceEvent(TRACE_WARNING, "Bad length [expected=%d][real=%lu]",
                       template.fieldCount * 4,
                       numEntries + sizeof(FlowSet));
          } else {
            good_template = true;

            if(bufferLen < (displ+stillToProcess)) {
              traceEvent(TRACE_INFO,
                "Broken flow format (bad length) [received: %zd]"
                "[displ: %zd][stillToProcess: %zd][available: %zd]",
                bufferLen, displ, stillToProcess, (displ+stillToProcess));
              free(fields);
              return 0;
            }

            /* Check the template before handling it */
            for(fieldId=0; fieldId < template.fieldCount; fieldId++) {
              const bool is_enterprise_specific = (buffer[displ+len] & 0x80);
              const V9FlowSet *set = (const V9FlowSet*)&buffer[displ+len];

              len += 4; /* Field Type (2) + Field Length (2) */

              if(is_enterprise_specific) {
                len += 4; /* PEN (Private Enterprise Number) */
              }

              fields[fieldId].fieldId = htons(set->templateId) & 0x7FFF;
              fields[fieldId].fieldLen = htons(set->flowsetLen);
              fields[fieldId].v9_template = find_template(ntohs(set->templateId) & 0x7FFF);

              if(fields[fieldId].fieldLen != (uint16_t)-1) /* Variable lenght fields */
                accumulatedLen += fields[fieldId].fieldLen;

              if(unlikely(readOnlyGlobals.enable_debug))
                traceEvent(TRACE_NORMAL, "[%d] fieldId=%d/PEN=%s/len=%d [tot=%zu]",
                           1+fieldId, fields[fieldId].fieldId,
                           is_enterprise_specific ? "true" : "false",
                           fields[fieldId].fieldLen, len);
            }
          }
        } else {
          /* NetFlow */
          fields = calloc(template.fieldCount, sizeof(V9V10TemplateField));
          if (unlikely(!fields)) {
            traceEvent(TRACE_WARNING, "Not enough memory");
            break;
          }

          good_template = true;

          if(unlikely(readOnlyGlobals.enable_debug))
          {
            const size_t bufsize = 1024;
            char buf[bufsize];
            traceEvent(TRACE_NORMAL, "Template [sensor=%s][id=%d] fields: %d", _intoaV4(netflow_device_ip,buf,bufsize), template.templateId, template.fieldCount);
          }

          /* Check the template before handling it */
          for(fieldId=0;fieldId < template.fieldCount; fieldId++) {
            const V9FlowSet *set = (const V9FlowSet*)&buffer[displ+len];

            fields[fieldId].fieldId = htons(set->templateId);
            fields[fieldId].fieldLen = htons(set->flowsetLen);
            fields[fieldId].v9_template = find_template(ntohs(set->templateId));

            len += 4; /* Field Type (2) + Field Length (2) */
            accumulatedLen +=  fields[fieldId].fieldLen;

            if(unlikely(readOnlyGlobals.enable_debug))
              traceEvent(TRACE_NORMAL, "[%d] fieldId=%d (%s)/fieldLen=%d/totLen=%zu/templateLen=%zu [%02X %02X %02X %02X]",
                         1+fieldId, fields[fieldId].fieldId,
                         getStandardFieldId(fields[fieldId].fieldId), fields[fieldId].fieldLen,
                         accumulatedLen, len,
                         buffer[displ+len-4] & 0xFF,
                         buffer[displ+len-3] & 0xFF,
                         buffer[displ+len-2] & 0xFF,
                         buffer[displ+len-1] & 0xFF);
          }
        }
      }

      if(accumulatedLen > 1500) {
        good_template = false;
      }

      if (likely(good_template)) {
        worker->stats.num_good_templates_received++;

        struct flowSetV9Ipfix *new_template = calloc(1, sizeof(*new_template));
        if (unlikely(!new_template)) {
          traceEvent(TRACE_WARNING, "Not enough memory");
          free(fields);
          break;
        }

        /// @TODO save the fields directly in a new malloced template.
        new_template->templateInfo.templateId = template.templateId;
        new_template->templateInfo.fieldCount = template.fieldCount;
        new_template->templateInfo.v9ScopeLen = template.v9ScopeLen;
        new_template->templateInfo.scopeFieldCount  = template.scopeFieldCount;
        new_template->templateInfo.isOptionTemplate = template.isOptionTemplate;
        new_template->templateInfo.netflow_device_ip = netflow_device_ip;
        new_template->templateInfo.observation_domain_id = observation_domain_id;
        new_template->fields                  = fields;

        // Save template for future use
        if(readOnlyGlobals.templates_database_path && strlen(readOnlyGlobals.templates_database_path) > 0)
          saveGoodTemplateInFile(new_template);
#ifdef HAVE_ZOOKEEPER
        if(readOnlyGlobals.zk.zh)
          saveGoodTemplateInZooKeeper(readOnlyGlobals.zk.zh,new_template);
#endif

        save_template(observation_id, new_template);
        worker->stats.num_known_templates++;
      } else {
        if(unlikely(readOnlyGlobals.enable_debug))
          traceEvent(TRACE_INFO, ">>>>> Skipping bad template [id=%d]", template.templateId);
        worker->stats.num_bad_templates_received++;
        free(fields);
      }

      displ += len, stillToProcess -= len;

      if(unlikely(readOnlyGlobals.enable_debug))
        traceEvent(TRACE_INFO,
          "Moving %zu bytes forward: new offset is %zd [stillToProcess=%zd]",
          len, displ, stillToProcess);
      if(stillToProcess < 4)  {
        /* Pad */
        displ += stillToProcess;
        stillToProcess = 0;
      }

      if(stillToProcess <= 0) template_done = true;
    }
  }

  *readed = displ;

  return 1;
}

#ifdef HAVE_UDNS

static const uint32_t *ipv6_ptr_to_ipv4_ptr(const void *vipv6) {
  const uint8_t *ipv6 = vipv6;
  return (const uint32_t *)&ipv6[12];
}

#endif

/** Dissect a netflow V9/V10 set with a given template
 * @param  worker       Worker that is managing this flow
 * @param  cursor       Template to decode flow with
 * @param  fs           Flow set
 * @param  tot_len      Length of the flow set
 * @param  _buffer      Current set
 * @param  _sensor      Netflow sensor
 * @param  flowVersion  Flow version
 * @param  handle_ipfix true if flowVersion==10 (@todo refundant?)
 * @param  flowHeader   Flow header
 * @param  flowSequence Flow sequence number
 * @return              String list with netflow information
 */
static struct string_list *dissectNetFlowV9V10FlowSetWithTemplate(
            worker_t *worker, const FlowSetV9Ipfix *cursor, const V9FlowSet *fs,
            size_t *tot_len, const struct sized_buffer *_buffer,
            const struct netflow_sensor *_sensor,
            observation_id_t *observation_id,
            int flowVersion, int handle_ipfix,
            const struct flow_ver9_hdr *flowHeader, uint16_t *flowSequence) {

  const uint16_t flowVersion_sw = ntohs(flowVersion);
  struct string_list *kafka_string_list = NULL;
  ssize_t displ = 0;
  const uint8_t *buffer  = _buffer->buffer;
  struct sensor *sensor_object = _sensor->sensor;

  int fieldId, init_displ;
  const int scopeOffset =
    (4*cursor->templateInfo.scopeFieldCount) + cursor->templateInfo.v9ScopeLen;
  int end_flow;
  V9V10TemplateField *fields = cursor->fields;

  init_displ = displ + scopeOffset;
  displ += sizeof(V9FlowSet) + scopeOffset;

  end_flow = init_displ + fs->flowsetLen-scopeOffset;
  *tot_len += scopeOffset;

  while(displ < end_flow) {
    const uint32_t _flowSequence = htonl(*flowSequence);
    (*flowSequence)++;
    size_t accum_len = 0;

    if(end_flow-displ < 4) break;

#ifdef DEBUG_FLOWS
    dumpFlow(displ,init_displ + fs->flowsetLen-scopeOffset,buffer);
#endif

    struct printbuf *kafka_line_buffer = printbuf_new();
    if (unlikely(!kafka_line_buffer)) {
      traceEvent(TRACE_ERROR,"Unable to allocate a kafka buffer.");
      return kafka_string_list;
    }

    struct flowCache *flowCache = calloc(1,sizeof(flowCache[0]));
    if (unlikely(!flowCache)) {
      traceEvent(TRACE_ERROR,"Unable to allocate flow cache.");
      printbuf_free(kafka_line_buffer);
      return kafka_string_list;
    }
    flow_export_timestamp_uptime(handle_ipfix, flowHeader,
      &flowCache->time.export_timestamp_s, &flowCache->time.sys_uptime_s);

    printbuf_memappend_fast(kafka_line_buffer,"{",strlen("{"));

    flowCache->sensor = sensor_object;
    flowCache->observation_id = observation_id;

    printNetflowRecordWithTemplate(kafka_line_buffer,
      TEMPLATE_OF(REDBORDER_TYPE), &flowVersion_sw,
      sizeof(flowVersion_sw), 0, flowCache);
    printNetflowRecordWithTemplate(kafka_line_buffer,
        TEMPLATE_OF(FLOW_SEQUENCE), &_flowSequence,
        sizeof(_flowSequence), 0, flowCache);

    for(fieldId=0; fieldId<cursor->templateInfo.fieldCount; fieldId++) {
      uint16_t real_field_len = 0, real_field_len_offset = 0;
      if(!(displ < end_flow)) break; /* Flow too short */

      if(handle_ipfix && (fields[fieldId].fieldLen == 65535)) {
        /* IPFIX Variable lenght field */
        uint8_t len8 = buffer[displ];

        if(len8 < 255)
          real_field_len = len8, real_field_len_offset = 1;
        else {
          uint16_t len16;

          memcpy(&len16, &buffer[displ+1], 2);
          len16 = ntohs(len16);
          // REDBORDER commented this. flows with len>255 doesn't work if executed.
          //len16 += 1 /* 255 */ + 2 /* len */;
          real_field_len = len16, real_field_len_offset = 3;
        }
      } else
        real_field_len = fields[fieldId].fieldLen, real_field_len_offset = 0;

      if(unlikely(readOnlyGlobals.enable_debug)) {
        /* if(cursor->templateInfo.isOptionTemplate) */ {
          traceEvent(TRACE_NORMAL, ">>>>> Dissecting flow field "
                     "[optionTemplate=%d][displ=%zd/%d][template=%d][fieldId=%d][fieldLen=%d]"
                     "[field=%d/%d] [%zd...%d] [accum_len=%zu] [%02X %02X %02X %02X]",
                     cursor->templateInfo.isOptionTemplate, displ, fs->flowsetLen,
                     fs->templateId, fields[fieldId].fieldId,
                     real_field_len,
                     fieldId, cursor->templateInfo.fieldCount,
                     displ, (init_displ + fs->flowsetLen), accum_len,
                     buffer[displ] & 0xFF, buffer[displ+1] & 0xFF,
                     buffer[displ+2] & 0xFF, buffer[displ+3] & 0xFF);
        }
      }

      if (fields[fieldId].v9_template) {
        printNetflowRecordWithTemplate(kafka_line_buffer,
          fields[fieldId].v9_template, &buffer[displ],
          real_field_len, real_field_len_offset, flowCache);
      } else if(unlikely(readOnlyGlobals.enable_debug)) {
        traceEvent(TRACE_WARNING, "Unknown template id (%d)",fields[fieldId].fieldId);
      }

      accum_len += real_field_len+real_field_len_offset, displ += real_field_len+real_field_len_offset;
    } /* for */

    worker->stats.num_flows_processed++;

    guessDirection(flowCache);
    printNetflowRecordWithTemplate(kafka_line_buffer,
      TEMPLATE_OF(PRINT_DIRECTION), NULL, 0, 0, flowCache);
    printNetflowRecordWithTemplate(kafka_line_buffer,
      TEMPLATE_OF(CLIENT_MAC_BASED_ON_DIRECTION), NULL, 0, 0, flowCache);
    print_sensor_enrichment(kafka_line_buffer,flowCache);

#ifdef HAVE_UDNS
    const bool solve_client = observation_id_want_client_dns(
                flowCache->observation_id),
               solve_target = observation_id_want_target_dns(
                flowCache->observation_id);

    if((solve_client || solve_target) && readOnlyGlobals.udns.csv_dns_servers) {
      static __thread size_t dns_worker_i = 0; /// @TODO use another way, please.
      if(++dns_worker_i >= readOnlyGlobals.numProcessThreads) {
        dns_worker_i = 0;
      }

      rd_thread_t *curr_worker = readOnlyGlobals.udns.dns_poll_threads[dns_worker_i];
      /* Need to reverse solve addresses */

      struct udns_opaque *opaque = calloc(1,sizeof(opaque[0]));
#ifdef UDNS_OPAQUE_MAGIC
      opaque->magic = UDNS_OPAQUE_MAGIC;
#endif
      opaque->flowCache = flowCache;
      opaque->curr_printbuf = kafka_line_buffer;
      const uint8_t *client_addr = get_direction_based_client_ip(flowCache);
      const uint8_t *target_addr = get_direction_based_target_ip(flowCache);
      opaque->refcnt.value = (solve_client && client_addr ? 1 : 0)
                           + (solve_target && target_addr ? 1 : 0);

      /// @TODO remove duplication
      if(readOnlyGlobals.udns.cache) {
        time_t now = time(NULL);

        if(solve_client && client_addr) {
          opaque->flowCache->address.client_name_cache = dns_cache_get_elm(
            readOnlyGlobals.udns.cache,(const uint8_t *)client_addr,now);
          if(NULL != opaque->flowCache->address.client_name_cache) {
            opaque->refcnt.value--;
          }
        }

        if(solve_target && target_addr) {
          opaque->flowCache->address.target_name_cache = dns_cache_get_elm(
            readOnlyGlobals.udns.cache,(const uint8_t *)target_addr,now);
          if(NULL != opaque->flowCache->address.target_name_cache) {
            opaque->refcnt.value--;
          }
        }
      }

      if (0 == opaque->refcnt.value) {
        // We had the needed addresses in cache, so we can sent the flow to dissect
        rd_thread_func_call2(curr_worker,split_after_dns_query_completed,
          readOnlyGlobals.udns.dns_info_array[dns_worker_i].dns_ctx,opaque);
      } else {
        if(solve_client && NULL == flowCache->address.client_name_cache) {
          void *client = not_const_cast(ipv6_ptr_to_ipv4_ptr(client_addr));
          rd_thread_func_call4(curr_worker, dns_submit_a4ptr,
            readOnlyGlobals.udns.dns_info_array[dns_worker_i].dns_ctx,
            client, dns_query_completed_client, opaque);
        }

        if(solve_target && NULL == opaque->flowCache->address.target_name_cache) {
          void *target = not_const_cast(ipv6_ptr_to_ipv4_ptr(target_addr));
          rd_thread_func_call4(curr_worker, dns_submit_a4ptr,
            readOnlyGlobals.udns.dns_info_array[dns_worker_i].dns_ctx,
            target, dns_query_completed_target, opaque);
        }
      }
    } else {
#endif

      struct string_list *current_record_string_list = time_split_flow(
            kafka_line_buffer, flowCache);
      string_list_concat(&kafka_string_list,current_record_string_list);

      free(flowCache);
#ifdef HAVE_UDNS
    }
#endif


    // RB_NOMEMCPY_PATCH: this was done later before.
    *tot_len += accum_len;
  } /* while */

  return kafka_string_list;
}

/// @param flowHeader flow header as netflow5 record.
/// @TODO change flowHeader to netflow 9/10 header union
static struct string_list *dissectNetFlowV9V10Flow(worker_t *worker,
            const struct sized_buffer *_buffer,
            const struct netflow_sensor *_sensor,
            observation_id_t *observation_id, int flowVersion,
            int handle_ipfix, const struct flow_ver9_hdr *flowHeader,
            uint16_t *flowSequence) {

  V9FlowSet fs;

  struct string_list *kafka_string_list = NULL;

  const uint8_t *buffer  = _buffer->buffer;

  /// @TODO show right display.
  ssize_t displ = 0;

  memcpy(&fs, &buffer[displ], sizeof(V9FlowSet));
  fs.flowsetLen = ntohs(fs.flowsetLen);
  fs.templateId = ntohs(fs.templateId);

  size_t tot_len = 4; /* @TODO why is this used? */

  const FlowSetV9Ipfix *cursor = find_observation_id_template(observation_id,
    fs.templateId);
  if(unlikely(cursor && cursor->templateInfo.fieldCount==0)) {
    /* If we don't protect, f2k will freeze because a posterior while(displ < end_flow) */
    cursor = NULL;
  }

  if(NULL == cursor) {
#ifdef DEBUG_FLOWS
    char ipv4_buf[1024];
    if(unlikely(readOnlyGlobals.enable_debug)) {
      const uint32_t netflow_device_ip = _sensor->netflow_device_ip;
      traceEvent(TRACE_NORMAL, ">>>>> Rcvd flow with UNKNOWN template %d "
        "[sensor=%s][displ=%zd][len=%d]",
        fs.templateId, _intoaV4(netflow_device_ip,ipv4_buf,1024), displ,
        fs.flowsetLen);
    }
#endif
    worker->stats.num_flows_unknown_template++;
    return NULL;
  }

  /* We process only flows, not option templates */
  if(cursor->templateInfo.isOptionTemplate != 0) {
    return NULL;
  }

  if(unlikely(readOnlyGlobals.enable_debug))
    traceEvent(TRACE_INFO, ">>>>> Rcvd flow with known template %d [%zd...%d]",
             fs.templateId, displ, fs.flowsetLen);

  /* Template found */
  kafka_string_list = dissectNetFlowV9V10FlowSetWithTemplate(worker, cursor,
    &fs, &tot_len, _buffer, _sensor, observation_id, flowVersion, handle_ipfix,
    flowHeader, flowSequence);

#ifdef DEBUG_FLOWS
  if(unlikely(readOnlyGlobals.enable_debug))
    traceEvent(TRACE_INFO, ">>>>> tot_len=%zu / fs.flowsetLen=%d", tot_len, fs.flowsetLen);
#endif

  if(tot_len < fs.flowsetLen) {
    size_t padding = fs.flowsetLen - tot_len;

    if(padding > 4) {
      traceEvent(TRACE_WARNING,
                 "Template len mismatch [tot_len=%zu][flow_len=%d][padding=%zu]"
                 "[num_dissected_flow_packets=%"PRIu64"]",
                 tot_len, fs.flowsetLen, padding,
                 worker->stats.num_dissected_flow_packets);
    } else {
#ifdef DEBUG_FLOWS
      if(unlikely(readOnlyGlobals.enable_debug))
        traceEvent(TRACE_INFO, ">>>>> %zu bytes padding [tot_len=%zu][flow_len=%d]",
                   padding, tot_len, fs.flowsetLen);
#endif
      displ += padding;
    }
  }

  return kafka_string_list;
}

/// @ TODO right name is flowLength, not NumEntries, and is redundant with _buffer->size.
static struct string_list *dissectNetFlowV9V10Set(worker_t *worker,
                              const struct sized_buffer *_buffer,
                              const struct netflow_sensor *_sensor,
                              observation_id_t *observation_id,
                              ssize_t *_displ,
                              int handle_ipfix, size_t numEntries,
                              const uint16_t flowVersion,
                              uint16_t flowSequence) {
  const uint8_t *buffer = _buffer->buffer;
  const ssize_t displ = (*_displ);
  struct string_list *kafka_string_list = NULL;

  if(unlikely(readOnlyGlobals.enable_debug)) {
    traceEvent(TRACE_INFO, "Found FlowSet [displ=%zd]", displ);
  }

  if (_buffer->size < (displ+sizeof(V9FlowSet))) {
    /* Buffer is not big enough to have even flowset header -> act like if
    a set with buffer length was readed */
    traceEvent(TRACE_ERROR,"V9/V10 flow expected, get end of buffer");
    *_displ = _buffer->size + 1;
    return NULL;
  }

  V9FlowSet fs;
  memcpy(&fs, &buffer[displ], sizeof(V9FlowSet));

  fs.flowsetLen = ntohs(fs.flowsetLen);
  fs.templateId = ntohs(fs.templateId);

  if((ssize_t)_buffer->size < (displ+fs.flowsetLen)) {
    /* Buffer is not big enough to have even flowset header -> act like if
    a set with buffer length was readed */
    traceEvent(TRACE_ERROR,
      "UDP data is not enough to hold flow set (size %zu, expected >=%zu)",
      _buffer->size,displ+fs.flowsetLen);
    *_displ = _buffer->size + 1;
    return NULL;
  }

  const struct sized_buffer netflow_set_buffer = {
    .buffer_start = _buffer->buffer_start,
    .buffer = &buffer[displ],
    .size   = fs.flowsetLen
  };

  /* @TODO pass here buffer[displ] instead of all buffer */
  if(buffer[displ] == 0) {
    size_t readed = 0;
    dissectNetFlowV9V10Template(worker, &netflow_set_buffer, _sensor,
      observation_id, &readed, numEntries, handle_ipfix);
  } else {
    struct string_list *_kafka_string_list = NULL;
    _kafka_string_list = dissectNetFlowV9V10Flow(worker, &netflow_set_buffer,
                            _sensor, observation_id, flowVersion, handle_ipfix,
                            (const struct flow_ver9_hdr *)buffer,
                            &flowSequence);
    string_list_concat(&kafka_string_list,_kafka_string_list);
  }

  (*_displ) += fs.flowsetLen;

  return kafka_string_list;
}

/* NetFlowV9/IPFIX Record */
static struct string_list *dissectNetflowV9V10(worker_t *worker,
                    struct sensor *sensor_object,
                    const uint8_t *_buffer, const ssize_t bufferLen,
                    const uint32_t netflow_device_ip) {
  struct string_list *kafka_string_list = NULL;
  uint8_t done = 0;
  ssize_t numEntries;
  uint32_t flowSequence;
  ssize_t displ;
  uint32_t observation_id_n;
  int i;

  /* TODO do not use Netflow5Record * in this function */
  const uint16_t flowVersion = ntohs(((const NetFlow5Record *) _buffer)->flowHeader.version);
  const int handle_ipfix = (flowVersion == 9) ? 0 : 1;

  if (handle_ipfix) {
    numEntries = ntohs(((const IPFIXFlowHeader *)_buffer)->len);
    displ = sizeof(V9FlowHeader)-4; // FIX
    flowSequence = ntohl(((const IPFIXFlowHeader *)_buffer)->flow_sequence);
    observation_id_n =
      ntohl(((const IPFIXFlowHeader *)_buffer)->observation_id);
  } else {
    // in NF9, numEntries is netflow length
    numEntries = ntohs(((const V9FlowHeader *)_buffer)->count);
    displ = sizeof(V9FlowHeader);
    flowSequence = ntohl(((const V9FlowHeader *)_buffer)->flow_sequence);
    observation_id_n = ntohl(((const V9FlowHeader *)_buffer)->source_id);
  }

  if(unlikely(readOnlyGlobals.enable_debug)) {
    traceEvent(TRACE_INFO, "%s Length: %zd",
      handle_ipfix ? "IPFIX" : "V9", numEntries);
  }

  const struct netflow_sensor sensor = {
    .netflow_device_ip = netflow_device_ip,
    .sensor = sensor_object,
  };

  // @TODO check this in netflow V5 too
  if(handle_ipfix && numEntries != bufferLen) {
    traceEvent(TRACE_ERROR,
      "Netflow V10 length (%zd) != received buffer length (%zd).",
      numEntries, bufferLen);
    traceEvent(TRACE_ERROR, "Assuming minimum.");
  }

  observation_id_t *observation_id = get_sensor_observation_id(sensor_object,
    observation_id_n);

  if (!observation_id) {
    traceEvent(TRACE_ERROR,
      "Received sensor %s flow with unknown observation id %"PRIu32,
      sensor_ip_string(sensor_object), observation_id_n);
    return NULL;
  }

  const struct sized_buffer buffer = {
    .buffer_start = _buffer,
    .buffer = _buffer,
    .size = handle_ipfix ? min(bufferLen,numEntries) : bufferLen,
  };

  for(i=0; (!done) && (displ < bufferLen) && (i < numEntries); i++) {
    struct string_list *_kafka_string_list = NULL;
    _kafka_string_list = dissectNetFlowV9V10Set(worker, &buffer, &sensor,
                  observation_id, &displ, handle_ipfix, numEntries, flowVersion,
                  flowSequence);
    string_list_concat(&kafka_string_list,_kafka_string_list);
  } /* for */

  observation_id_decref(observation_id);

  return kafka_string_list;
}

static struct string_list *dissectNetFlow(worker_t *worker,
                      struct sensor *sensor_object,
                      const uint32_t netflow_device_ip,
                      const void *buffer, const ssize_t bufferLen) {
  const NetFlow5Record *the5Record = (const NetFlow5Record*)buffer;

  assert(worker);
  assert(sensor_object);
  assert(buffer);

  if(unlikely(NULL == readOnlyGlobals.rb_databases.sensors_info)) {
    traceEvent(TRACE_ERROR, "Can't get a sensor list");
    return NULL;
  }

  worker->stats.num_dissected_flow_packets++;

  const uint16_t flowVersion = ntohs(((const NetFlow5Record *) buffer)->flowHeader.version);

#ifdef DEBUG_FLOWS
  if(unlikely(readOnlyGlobals.enable_debug)) {
    traceEvent(TRACE_INFO,
        "NETFLOW: dissectNetFlow(len=%zd) [tot flow packets=%"PRIu64"]",
        bufferLen, worker->stats.num_dissected_flow_packets);
  }
#endif

#ifdef DEBUG_FLOWS
  if(unlikely(readOnlyGlobals.enable_debug))
    traceEvent(TRACE_INFO, "NETFLOW: +++++++ version=%d",  flowVersion);
#endif

  if((flowVersion == 9) || (flowVersion == 10)) {
    return dissectNetflowV9V10(worker, sensor_object, buffer, bufferLen,
                                                  netflow_device_ip);
  } else if(the5Record->flowHeader.version == htons(5)) {
    // @todo use proper observation id!
    const NetFlow5Record *record = buffer;
    const uint32_t observation_id_n = (record->flowHeader.engine_type<<8)
      + record->flowHeader.engine_id;
    observation_id_t *observation_id = get_sensor_observation_id(sensor_object,
      observation_id_n);
    struct string_list *ret = dissectNetFlowV5(worker, sensor_object,
      observation_id, the5Record);
    observation_id_decref(observation_id);
    return ret;
  } else {
    traceEvent(TRACE_ERROR,"Uknown flow version %d",flowVersion);
  }

  return NULL;
}

/* ********************************************************* */

static int isSflow(const uint8_t *buffer){
  if((buffer[0] == '\0') && (buffer[1] == '\0') && (buffer[2] == '\0')){
    if((buffer[3] == 2) /* sFlow v2 */ || (buffer[3] == 5) /* sFlow v5 */)
      return 1;
  }
  return 0;
}

/** pop all templates of the template queue
 * @param queue Template queue
 */
static void pop_all_templates(template_queue_t *template_queue) {
  queued_template_t *qtemplate = NULL;
  while((qtemplate = template_queue_pop(template_queue))) {
    if (unlikely(readOnlyGlobals.enable_debug)) {
      char buf[BUFSIZ];
      traceEvent(TRACE_INFO, "Adding template from sensor %s observation_id %"
                              PRIu32,
        _intoaV4(qtemplate->template->templateInfo.netflow_device_ip,
          buf, sizeof(buf)),
        qtemplate->template->templateInfo.observation_domain_id);
    }

    save_template(qtemplate->observation_id, qtemplate->template);
    observation_id_decref(qtemplate->observation_id);
    free(qtemplate);
  }
}

static void *netFlowConsumerLoop(void *vworker) {
  worker_t *worker = vworker;
  static const time_t timeout_ms = 800;
  // traceEvent(TRACE_NORMAL,"Creating consumer loop");

  while(true) {
    QueuedPacket *packet = popPacketFromQueue_timedwait(&worker->packetsQueue,
                                                                    timeout_ms);
    pop_all_templates(&worker->templates_queue);

    if (packet) {
      // Consume all pending templates first
      pop_all_templates(&worker->templates_queue);

      if(worker->stats.first_flow_processed_timestamp == 0) {
        worker->stats.first_flow_processed_timestamp = time(NULL);
      }

      worker->stats.num_packets_received++;

      if(isSflow(packet->buffer)) {
        // dissectSflow(packet->buffer, packet->buffer_len, packet->netflow_device_ip); /* sFlow */
      } else {
        struct string_list *sl = dissectNetFlow(worker, packet->sensor,
                    packet->netflow_device_ip, packet->buffer,
                    packet->buffer_len);
        rb_sensor_decref(packet->sensor);
        send_string_list_to_kafka(sl);
      }

      freeQueuedPacket(packet);
    } else if (ATOMIC_OP(fetch, add, &worker->run.value, 0) == 0) {
      // No pending packet & don't keep running
      // Consume all pending templates to avoid memory leaks
      pop_all_templates(&worker->templates_queue);

      worker->stats.last_flow_processed_timestamp = time(NULL);
      break;
    }
  }

  return NULL;
}

/* ********************************************************* */

/** Creates a worker */
worker_t *new_collect_worker() {
  worker_t *ret = calloc(1, sizeof(*ret));
  if (likely(ret)) {
#ifdef WORKER_S_MAGIC
    ret->magic = WORKER_S_MAGIC;
#endif

    pthread_attr_t tattr;
    struct sched_param param;

    /* initialized with default attributes */
    if(pthread_attr_init(&tattr) == 0) {
      /* safe to get existing scheduling param */
      if(pthread_attr_getschedparam (&tattr, &param) == 0) {
        param.sched_priority++; /* Increase priority */

        /* setting the new scheduling param */
        pthread_attr_setschedparam (&tattr, &param);
      }
    }

    ret->run.value = 1;
    rd_fifoq_init(&ret->packetsQueue);
    template_queue_init(&ret->templates_queue);

    const int pthread_create_rc = pthread_create(&ret->tid, &tattr,
                                                      netFlowConsumerLoop, ret);
    if (unlikely(pthread_create_rc != 0)) {
      char berr[BUFSIZ];
      strerror_r(errno, berr, sizeof(berr));
      traceEvent(TRACE_ERROR, "Couldn't create worker thread: %s", berr);
      rd_fifoq_destroy(&ret->packetsQueue);
      free(ret);
      ret = 0;
    }
  }

  return ret;
};

/** Adds a packet to worker
  @param qpacket Packet to add
  @param worker Worker queue to add
  */
void add_packet_to_worker(struct queued_packet_s *qpacket, worker_t *worker) {
  addPacketToQueue(qpacket, &worker->packetsQueue);
}

void add_template_to_worker(struct flowSetV9Ipfix *template,
                          observation_id_t *observation_id, worker_t *worker) {
  queued_template_t *qtemplate = new_queued_template(template, observation_id);
  if (qtemplate) {
    template_queue_push(qtemplate, &worker->templates_queue);
  }
}

/** Get workers stats
  @param worker Worker to get stats
  @param stats where to store stats
  */
void get_worker_stats(worker_t *worker, struct worker_stats *stats) {
  memcpy(stats, &worker->stats, sizeof(*stats));
}

/** Free worker's allocated resources */
void collect_worker_done(worker_t *worker) {
  ATOMIC_OP(fetch,and,&worker->run.value,0);
  pthread_join(worker->tid, NULL);
  template_queue_destroy(&worker->templates_queue);
  rd_fifoq_destroy(&worker->packetsQueue);
  free(worker);
}
