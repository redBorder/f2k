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
//#define CISCO_DEBUG
#define LEN_SMALL_WORK_BUFFER 2048

#ifdef HAVE_UDNS
#ifndef NDEBUG
#define UDNS_OPAQUE_MAGIC 0xD0AED0AED0AED0AEL
#endif
struct udns_opaque {
#ifdef UDNS_OPAQUE_MAGIC
  uint64_t magic;
#endif

  struct printbuf *curr_printbuf;
  struct flowCache *flowCache;

/// @TODO use flowCache to this
  uint64_t export_timestamp,dSwitched,bytes,pkts;
#ifdef HAVE_ATOMICS_32
  uint32_t refcnt;
#else
#error "You do not have support for atomics!!"
#endif
};
#endif

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

/* forward */
size_t printNetflowRecordWithTemplate(struct printbuf * line_buffer, const V9V10TemplateElementId * template_id, const char * buffer,const size_t real_field_len, const size_t real_field_len_offset, struct flowCache *flowCache);

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

/**
 * Split flow in timestamp slices
 * @param  kafka_line_buffer String buffer with flow shared data
 * @param  first_timestamp   First flow switched packet timestamp
 * @param  dSwitched         Flow diration
 * @param  bytes             Bytes of all flow
 * @param  pkts              Packets of all flow
 * @param  flowCache         Common elements of the flow
 * @return                   String list with splitted flow
 */
static struct string_list *time_split_flow(struct printbuf *kafka_line_buffer,
    const uint64_t first_timestamp,
    const uint64_t dSwitched, const uint64_t bytes, const uint64_t pkts,
    struct flowCache *flowCache) {
  struct string_list *ret = NULL;
  assert(kafka_line_buffer);

  if (readOnlyGlobals.separate_long_flows) {
      ret = rb_separate_long_time_flow(kafka_line_buffer,first_timestamp,
        dSwitched,60 /* segs */,60 /*60 intervals: an hour */,bytes,pkts);
  } else {
    const uint64_t first_timestamp_sw = ntohll(first_timestamp);
    const uint64_t last_timestamp_sw = ntohll(first_timestamp + dSwitched);
    const uint64_t bytes_sw = ntohll(bytes);
    const uint64_t pkts_sw = ntohll(pkts);
    printNetflowRecordWithTemplate(kafka_line_buffer,
      TEMPLATE_OF(FIRST_SWITCHED), (const char *)&first_timestamp_sw,
      sizeof(first_timestamp_sw), 0, flowCache);
    printNetflowRecordWithTemplate(kafka_line_buffer,
      TEMPLATE_OF(LAST_SWITCHED), (const char *)&last_timestamp_sw,
      sizeof(last_timestamp_sw), 0, flowCache);
    printNetflowRecordWithTemplate(kafka_line_buffer,
      TEMPLATE_OF(IN_BYTES), (const char *)&bytes_sw,
      sizeof(bytes_sw), 0, flowCache);
    printNetflowRecordWithTemplate(kafka_line_buffer,
      TEMPLATE_OF(IN_PKTS), (const char *)&pkts_sw,
      sizeof(pkts_sw), 0, flowCache);
    printbuf_memappend_fast(kafka_line_buffer,"}",(ssize_t)strlen("}"));
    /// @TODO make a function that create a list with 1 node
    ret = calloc(1,sizeof(ret[0]));
    if(NULL != ret) {
      ret->string = kafka_line_buffer;
      ret->client_mac = flowCache->client_mac;
    } else {
      traceEvent(TRACE_ERROR,"Can't allocate string list node (out of memory?)");
    }
  }

  return ret;
}

static void dissectNetFlowV5Field(const NetFlow5Record *the5Record,
      const size_t flow_idx,const size_t field_idx,struct printbuf *kafka_line_buffer,
      struct flowCache *flowCache) {
  size_t value_ret = 0;
  const char * buffer = NULL;
  size_t real_field_len=0;

  switch (v5TemplateFields[field_idx]->templateElementId) {
  case DST_AS: // Will be printed in src and dst
  case SRC_AS:
      break;
  case IPV4_DST_ADDR:
      real_field_len=4;
      buffer = (const char *)&the5Record->flowRecord[flow_idx].dstaddr;
      break;
  case IPV4_SRC_ADDR:
      buffer = (const char *)&the5Record->flowRecord[flow_idx].srcaddr;
      real_field_len=4;
      break;
  case IN_PKTS:
  case IN_BYTES:
      // time_split_flow will print
      break;
  case L4_SRC_PORT:
    real_field_len = 2;
    buffer = (const char *)&the5Record->flowRecord[flow_idx].srcport;
    break;
  case L4_DST_PORT:
    real_field_len = 2;
    buffer = (const char *)&the5Record->flowRecord[flow_idx].dstport;
    break;
  case INPUT_SNMP:
    real_field_len = 2;
    buffer = (const char *)&the5Record->flowRecord[flow_idx].input;
    break;
  case OUTPUT_SNMP:
    real_field_len = 2;
    buffer = (const char *)&the5Record->flowRecord[flow_idx].output;
    break;
  case ENGINE_ID:
    real_field_len = 1;
    buffer = (const char *)&the5Record->flowHeader.engine_id;
    break;
  case ENGINE_TYPE:
    real_field_len = 1;
    buffer = (const char *)&the5Record->flowHeader.engine_type;
    break;
  case IPV4_NEXT_HOP:
    real_field_len = 4;
    buffer = (const char *)&the5Record->flowRecord[flow_idx].nexthop;
    break;
  case SRC_TOS:
    real_field_len = 1;
    buffer = (const char *)&the5Record->flowRecord[flow_idx].tos;
    break;
  case PROTOCOL:
    real_field_len = 1;
    buffer = (const char *)&the5Record->flowRecord[flow_idx].proto;
    break;
  case TCP_FLAGS:
    real_field_len = 1;
    buffer = (const char *)&the5Record->flowRecord[flow_idx].tcp_flags;
    break;
  default:
    traceEvent(TRACE_ERROR,"Unknown case in V5 flow");
    break;
  };

  if(unlikely(readOnlyGlobals.enable_debug)){
    printNetflowElementRawBuffer((const uint8_t *)buffer, real_field_len,
      v5TemplateFields[field_idx]->jsonElementName);
  }

  if(NULL==buffer){
    assert(v5TemplateFields[field_idx]->templateElementId == IN_BYTES ||
            v5TemplateFields[field_idx]->templateElementId == IN_PKTS);
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

/** Extract export timestamp from a v9/v10 flow and sanitize it
 * @param  handle_ipfix      We are handling v9 or v10 flow
 * @param  flowHeader        Header of the flow
 * @param  netflow_device_ip Ip of netflow device (debug purposes)
 * @return                   Flow export timestamp
 */
static uint64_t flow_export_timestamp(const bool handle_ipfix,
    const struct flow_ver9_hdr *flowHeader, const char *netflow_device_ip) {
  const time_t now = time(NULL);
  uint64_t export_timestamp = handle_ipfix ?
    net2number((const char *)&flowHeader->sysUptime, sizeof(flowHeader->sysUptime)) :
    net2number((const char *)&flowHeader->unix_secs, sizeof(flowHeader->unix_secs));

  if (export_timestamp > (uint64_t)now + 60*10) {
    if(readOnlyGlobals.enable_debug) {
      traceEvent(TRACE_ERROR,
        "Received a flow from the future (timestamp: %ld, src_ip: %s)",
        export_timestamp, netflow_device_ip);
    }
    if(!readOnlyGlobals.dontReforgeFarTimestamp) {
      export_timestamp = now;
    }
  }

  if(export_timestamp < (uint64_t)now - 3600) {
    if(readOnlyGlobals.enable_debug) {
      traceEvent(TRACE_ERROR,
        "Received a flow from the past (TS: %ld, src_ip: %s)",
        export_timestamp, netflow_device_ip);
    }
    if(!readOnlyGlobals.dontReforgeFarTimestamp) {
      export_timestamp = now;
    }
  }

  return export_timestamp;

}

/** Dissect a single flow of netflow 5
 * @param  the5Record    Netflow 5 record
 * @param  flow_idx      Netflow flow idx
 * @param  sensor_object Sensor that sent this flow
 * @return               String list with record
 */
static struct string_list *dissectNetFlowV5Record(const NetFlow5Record *the5Record,
                const int flow_idx, struct sensor *sensor_object) {
  struct printbuf * kafka_line_buffer = printbuf_new();
  const uint16_t *flowVersion = &the5Record->flowHeader.version;
  const uint32_t flowSecuence = htonl(
                        ntohl(the5Record->flowHeader.flow_sequence) + flow_idx);

  if(unlikely(NULL==kafka_line_buffer)){
    traceEvent(TRACE_ERROR,"Memory error");
    return NULL;
  }

  printbuf_memappend_fast(kafka_line_buffer, "{", (ssize_t)strlen("{"));
  struct flowCache *flowCache = calloc(1,sizeof(flowCache[0]));
  associateSensor(flowCache,sensor_object);
  uint64_t field_idx=0;
  printNetflowRecordWithTemplate(kafka_line_buffer, TEMPLATE_OF(REDBORDER_TYPE),
    (const char *)flowVersion, 2, 0, flowCache);
  printNetflowRecordWithTemplate(kafka_line_buffer, TEMPLATE_OF(FLOW_SEQUENCE),
    (const char *)&flowSecuence, sizeof(flowSecuence), 0, flowCache);

  for (field_idx=0; NULL!=v5TemplateFields[field_idx]; ++field_idx) {
    dissectNetFlowV5Field(the5Record, flow_idx, field_idx, kafka_line_buffer,
      flowCache);
  }

  const uint64_t export_timestamp = flow_export_timestamp(false,
    (const struct flow_ver9_hdr *)the5Record, sensor_ip_string(sensor_object));
  uint64_t last_timestamp  = export_timestamp - ntohl(the5Record->flowHeader.sysUptime)/1000 + ntohl(the5Record->flowRecord[flow_idx].last)/1000;
  uint64_t first_timestamp = export_timestamp - ntohl(the5Record->flowHeader.sysUptime)/1000 + ntohl(the5Record->flowRecord[flow_idx].first)/1000;

  guessDirection(flowCache);
  printNetflowRecordWithTemplate(kafka_line_buffer,
    TEMPLATE_OF(PRINT_DIRECTION), NULL, 0, 0, flowCache);
  print_sensor_enrichment(kafka_line_buffer,flowCache);

  struct string_list *kafka_buffers_list = time_split_flow(kafka_line_buffer,
    last_timestamp, last_timestamp-first_timestamp,
    ntohl(the5Record->flowRecord[flow_idx].dOctets),
    ntohl(the5Record->flowRecord[flow_idx].dPkts),flowCache);

  free(flowCache);

  return kafka_buffers_list;
}

static struct string_list *dissectNetFlowV5(worker_t *worker,
              struct sensor *sensor_object, const NetFlow5Record *the5Record) {
    uint16_t numFlows = ntohs(the5Record->flowHeader.count);

    if(numFlows > V5FLOWS_PER_PAK) numFlows = V5FLOWS_PER_PAK;

#ifdef DEBUG_FLOWS
    if(readOnlyGlobals.enable_debug)
      traceEvent(TRACE_INFO, "dissectNetFlow(%d flows)", numFlows);
#endif

    struct string_list *string_list = NULL;
    unsigned int flow_idx;
    for(flow_idx=0; flow_idx<numFlows; flow_idx++){
      struct string_list *sl2 = dissectNetFlowV5Record(the5Record,
                                                      flow_idx, sensor_object);
      string_list_concat(&string_list,sl2);
    }

    worker->stats.num_flows_processed+=numFlows;
    return string_list;
}

static void saveGoodTemplateInFile(const FlowSetV9Ipfix *new_template){
  char filename[BUFSIZ];
  char buffer_ipv4[BUFSIZ];
  snprintf(filename,sizeof(filename),"%s/%s_%u_%d.dat",
    readOnlyGlobals.templates_database_path,
    _intoaV4(new_template->templateInfo.netflow_device_ip,buffer_ipv4,sizeof(buffer_ipv4)),
    new_template->templateInfo.dst_port,
    new_template->templateInfo.templateId);
  if(readOnlyGlobals.enable_debug)
    traceEvent(TRACE_NORMAL, ">>>>> Saving template in %s",filename);
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

static void set_template_complete(int rc, const struct Stat *stat __attribute__((unused)), const void *_data);
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

static void set_template_complete(int rc, const struct Stat *stat __attribute__((unused)), const void *_data) {
  zoo_template_complete(rc,(void *)_data);
}

static void create_template_complete(int rc, const char *value __attribute__((unused)), const void *_data) {
  zoo_template_complete(rc,(void *)_data);
}

static void saveGoodTemplateInZooKeeper(zhandle_t *zh,const FlowSetV9Ipfix *new_template) {

  char ip_buffer[BUFSIZ];
  struct aset_template_data *data = calloc(1,sizeof(*data));
  if(!data){
    traceEvent(TRACE_ERROR,"Can't allocate data struct to save template in zookeeper");
    return;
  }

  data->zh = zh;
  memcpy(&data->acl,&ZOO_OPEN_ACL_UNSAFE,sizeof(data->acl));
  const size_t print_rc = snprintf(data->path,sizeof(data->path),"%s/%s_%u_%d",
    ZOOKEEPER_PATH,
    _intoaV4(new_template->templateInfo.netflow_device_ip,ip_buffer,sizeof(ip_buffer)),
    new_template->templateInfo.dst_port,
    new_template->templateInfo.templateId);

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

static void split_after_dns_query_completed(struct dns_ctx *ctx,struct udns_opaque *opaque) {
  assert(readOnlyGlobals.rb_cached_templates.dns_client_name_template);
  assert(readOnlyGlobals.rb_cached_templates.dns_target_name_template);

  printNetflowRecordWithTemplate(opaque->curr_printbuf,
    readOnlyGlobals.rb_cached_templates.dns_client_name_template,NULL,0,0,opaque->flowCache);
  printNetflowRecordWithTemplate(opaque->curr_printbuf,
    readOnlyGlobals.rb_cached_templates.dns_target_name_template,NULL,0,0,opaque->flowCache);

  struct string_list *string_list = time_split_flow(opaque->curr_printbuf,
    opaque->export_timestamp,opaque->dSwitched,opaque->bytes,opaque->pkts,opaque->flowCache);

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
          const uint8_t * (*addr_fn)(struct flowCache *)) {
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

  if(0 == ATOMIC_OP32(sub,fetch,&opaque->refcnt,1)) {
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

  dns_query_completed0(ctx,result,opaque,&opaque->flowCache->address.client_name,
    &opaque->flowCache->address.client_name_cache, get_direction_based_client_ip);
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
  const uint8_t *buffer_start;
  const uint8_t *buffer;
  size_t size;
};

struct netflow_sensor {
  uint32_t netflow_device_ip;
  struct sensor *sensor;
  uint16_t dst_port;
};

static int dissectNetFlowV9V10Template(worker_t *worker,
                                const struct sized_buffer *_buffer,
                                struct netflow_sensor *sensor, size_t *readed,
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

  if(readOnlyGlobals.enable_debug) {
    traceEvent(TRACE_INFO, "Found Template [displ=%zd]", displ);
    traceEvent(TRACE_INFO, "Found Template Type: %s", isOptionTemplate ? "Option" : "Flow");
  }

  if(bufferLen > (displ+(ssize_t)sizeof(V9TemplateHeader))) {
    V9TemplateHeader header;
    uint8_t templateDone = 0;

    memcpy(&header, &buffer[displ], sizeof(V9TemplateHeader));
    header.templateFlowset = ntohs(header.templateFlowset), header.flowsetLen = ntohs(header.flowsetLen);
    /* Do not change to uint: this way I can catch template length issues */
    ssize_t stillToProcess = header.flowsetLen - sizeof(V9TemplateHeader);
    displ += sizeof(V9TemplateHeader);

    while((bufferLen >= (displ+stillToProcess)) && (!templateDone)) {
      size_t len = 0;
      int fieldId;
      uint8_t goodTemplate = 0;
      uint accumulatedLen = 0;

      memset(&template, 0, sizeof(template));
      template.isOptionTemplate = isOptionTemplate,
      template.netflow_device_ip = netflow_device_ip;
      template.dst_port          = sensor->dst_port;

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

      if(template.fieldCount > 128) {
        traceEvent(TRACE_WARNING, "Too many template fields (%d): skept", template.fieldCount);
        goodTemplate = 0;
      } else {
        if(handle_ipfix) {
          fields = (V9V10TemplateField*)malloc(template.fieldCount * sizeof(V9V10TemplateField));
          if(fields == NULL) {
            traceEvent(TRACE_WARNING, "Not enough memory");
            break;
          }

          if(((template.fieldCount * 4) + sizeof(FlowSet) + 4 /* templateFlowSet + FlowsetLen */) >  header.flowsetLen) {
            traceEvent(TRACE_WARNING, "Bad length [expected=%d][real=%lu]",
                       template.fieldCount * 4,
                       numEntries + sizeof(FlowSet));
            free(fields);
          } else {
            goodTemplate = 1;

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
              uint8_t is_enterprise_specific = (buffer[displ+len] & 0x80) ? 1 : 0;
              V9FlowSet *set = (V9FlowSet*)&buffer[displ+len];

              len += 4; /* Field Type (2) + Field Length (2) */

              if(is_enterprise_specific) {
                len += 4; /* PEN (Private Enterprise Number) */
              }

              fields[fieldId].fieldId = htons(set->templateId) & 0x7FFF;
              fields[fieldId].fieldLen = htons(set->flowsetLen);
              fields[fieldId].isPenField = is_enterprise_specific;
              fields[fieldId].v9_template = find_template(ntohs(set->templateId) & 0x7FFF);

              if(fields[fieldId].fieldLen != (uint16_t)-1) /* Variable lenght fields */
                accumulatedLen += fields[fieldId].fieldLen;

              if(readOnlyGlobals.enable_debug)
                traceEvent(TRACE_NORMAL, "[%d] fieldId=%d/PEN=%d/len=%d [tot=%zu]",
                           1+fieldId, fields[fieldId].fieldId,
                           is_enterprise_specific, fields[fieldId].fieldLen, len);
            }

            template.flowsetLen = len;
          }
        } else {
          /* NetFlow */
          fields = (V9V10TemplateField*)malloc(template.fieldCount * sizeof(V9V10TemplateField));
          if(fields == NULL) {
            traceEvent(TRACE_WARNING, "Not enough memory");
            break;
          }

          goodTemplate = 1;
          template.flowsetLen = 4 * template.fieldCount;

          if(readOnlyGlobals.enable_debug)
          {
            const size_t bufsize = 1024;
            char buf[bufsize];
            traceEvent(TRACE_NORMAL, "Template [sensor=%s][id=%d] fields: %d", _intoaV4(netflow_device_ip,buf,bufsize), template.templateId, template.fieldCount);
          }

          /* Check the template before handling it */
          for(fieldId=0;fieldId < template.fieldCount; fieldId++) {
            V9FlowSet *set = (V9FlowSet*)&buffer[displ+len];

            fields[fieldId].fieldId = htons(set->templateId);
            fields[fieldId].fieldLen = htons(set->flowsetLen);
            fields[fieldId].v9_template = find_template(ntohs(set->templateId));

            len += 4; /* Field Type (2) + Field Length (2) */
            accumulatedLen +=  fields[fieldId].fieldLen;

            if(readOnlyGlobals.enable_debug)
              traceEvent(TRACE_NORMAL, "[%d] fieldId=%d (%s)/fieldLen=%d/totLen=%d/templateLen=%zu [%02X %02X %02X %02X]",
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

      if((template.flowsetLen > 1500) || (accumulatedLen > 1500)) {
        goodTemplate = 0;
        free(fields);
      }


      if(goodTemplate) {
        worker->stats.num_good_templates_received++;

        struct flowSetV9Ipfix *new_template = malloc(sizeof(*new_template));

        /// @TODO save the fields directly in a new malloced template.
        new_template->templateInfo.flowsetLen = len + sizeof(header);
        new_template->templateInfo.templateId = template.templateId;
        new_template->templateInfo.fieldCount = template.fieldCount;
        new_template->templateInfo.v9ScopeLen = template.v9ScopeLen;
        new_template->templateInfo.dst_port   = template.dst_port;
        new_template->templateInfo.scopeFieldCount  = template.scopeFieldCount;
        new_template->templateInfo.isOptionTemplate = template.isOptionTemplate;
        new_template->templateInfo.netflow_device_ip = netflow_device_ip;
        new_template->templateInfo.observation_domain_id = observation_domain_id;
        new_template->flowLen                 = accumulatedLen;
        new_template->fields                  = fields;

        // Save template for future use
        if(readOnlyGlobals.templates_database_path && strlen(readOnlyGlobals.templates_database_path) > 0)
          saveGoodTemplateInFile(new_template);
#ifdef HAVE_ZOOKEEPER
        if(readOnlyGlobals.zk.zh)
          saveGoodTemplateInZooKeeper(readOnlyGlobals.zk.zh,new_template);
#endif

        saveTemplate(sensor->sensor, new_template);
        worker->stats.num_known_templates++;
      } else {
        if(readOnlyGlobals.enable_debug)
          traceEvent(TRACE_INFO, ">>>>> Skipping bad template [id=%d]", template.templateId);
        worker->stats.num_bad_templates_received++;
      }

      displ += len, stillToProcess -= len;

      if(readOnlyGlobals.enable_debug)
        traceEvent(TRACE_INFO,
          "Moving %zu bytes forward: new offset is %zd [stillToProcess=%zd]",
          len, displ, stillToProcess);
      if(stillToProcess < 4)  {
        /* Pad */
        displ += stillToProcess;
        stillToProcess = 0;
      }

      if(stillToProcess <= 0) templateDone = 1;
    }
  }

  *readed = displ;

  return 1;
}

static inline uint32_t *ipv6_ptr_to_ipv4_ptr(const uint8_t *ipv6) {
  return (uint32_t *)&ipv6[12];
}

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
            struct netflow_sensor *_sensor, int flowVersion, int handle_ipfix,
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
  const uint64_t export_timestamp = flow_export_timestamp(handle_ipfix,
                                flowHeader, sensor_ip_string(_sensor->sensor));

  init_displ = displ + scopeOffset;
  displ += sizeof(V9FlowSet) + scopeOffset;

  end_flow = init_displ + fs->flowsetLen-scopeOffset;
  *tot_len += scopeOffset;

  while(displ < end_flow) {
    const uint32_t _flowSequence = htonl(*flowSequence);
    (*flowSequence)++;
    size_t accum_len = 0;
    uint32_t first_switched = 0, last_switched = 0;
    uint64_t bytes = 0, pkts = 0;

    if(end_flow-displ < 4) break;

#ifdef DEBUG_FLOWS
    dumpFlow(displ,init_displ + fs->flowsetLen-scopeOffset,buffer);
#endif

    struct printbuf * kafka_line_buffer = printbuf_new();

    if(unlikely(!kafka_line_buffer)) {
      traceEvent(TRACE_ERROR,"Unable to allocate a kafka buffer.");
      return NULL;
    }
    struct flowCache *flowCache = calloc(1,sizeof(flowCache[0]));
    if(NULL == flowCache) {
      traceEvent(TRACE_ERROR,"Unable to allocate flow cache.");
      free(kafka_line_buffer);
      return NULL;
    }
    printbuf_memappend_fast(kafka_line_buffer,"{",(ssize_t)strlen("{"));

    associateSensor(flowCache, sensor_object);

    printNetflowRecordWithTemplate(kafka_line_buffer,
      TEMPLATE_OF(REDBORDER_TYPE), (const char *)&flowVersion_sw,
      sizeof(flowVersion_sw), 0, flowCache);
    printNetflowRecordWithTemplate(kafka_line_buffer,
        TEMPLATE_OF(FLOW_SEQUENCE), (const char *)&_flowSequence,
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

      if(readOnlyGlobals.enable_debug) {
        /* if(cursor->templateInfo.isOptionTemplate) */ {
          traceEvent(TRACE_NORMAL, ">>>>> Dissecting flow field "
                     "[optionTemplate=%d][displ=%zd/%d][template=%d][fieldId=%d][fieldLen=%d]"
                     "[isPenField=%d][field=%d/%d] [%zd...%d] [accum_len=%zu] [%02X %02X %02X %02X]",
                     cursor->templateInfo.isOptionTemplate, displ, fs->flowsetLen,
                     fs->templateId, fields[fieldId].fieldId,
                     real_field_len,
                     fields[fieldId].isPenField,
                     fieldId, cursor->templateInfo.fieldCount,
                     displ, (init_displ + fs->flowsetLen), accum_len,
                     buffer[displ] & 0xFF, buffer[displ+1] & 0xFF,
                     buffer[displ+2] & 0xFF, buffer[displ+3] & 0xFF);
        }
      }

      if(fields[fieldId].v9_template) {
        switch(fields[fieldId].v9_template->templateElementId) {
          // @TODO move all this to flowCache structure
          case IN_BYTES:
            bytes = net2number((const char *)&buffer[displ], real_field_len);
            break;
          case IN_PKTS:
            pkts = net2number((const char *)&buffer[displ], real_field_len);
            break;
          case LAST_SWITCHED:
            last_switched = net2number((const char *)&buffer[displ],
                                                          real_field_len)/1000;
            break;
          case FIRST_SWITCHED:
            first_switched = net2number((const char *)&buffer[displ],
                                                          real_field_len)/1000;
            break;

          default:
            /// @TODO delete this cast, move all to uint8_t *
            printNetflowRecordWithTemplate(kafka_line_buffer,
              fields[fieldId].v9_template, (const char *)&buffer[displ],
              real_field_len, real_field_len_offset, flowCache);
            break;
        };
      }
      else
      {
        if(readOnlyGlobals.enable_debug)
          traceEvent(TRACE_WARNING, "Unknown template id (%d)",fields[fieldId].fieldId);
      }

      accum_len += real_field_len+real_field_len_offset, displ += real_field_len+real_field_len_offset;
    } /* for */

    uint64_t dSwitched = last_switched-first_switched;
    if (dSwitched > 59*60) {
      dSwitched = 59*60; /* 1 hour max */
    } else if (dSwitched == 0
                            && sensor_fallback_first_switch(_sensor->sensor)) {
      dSwitched = -sensor_fallback_first_switch(_sensor->sensor);
    }

    worker->stats.num_flows_processed++;

    guessDirection(flowCache);
    printNetflowRecordWithTemplate(kafka_line_buffer,
      TEMPLATE_OF(PRINT_DIRECTION), NULL, 0, 0, flowCache);
    printNetflowRecordWithTemplate(kafka_line_buffer,
      TEMPLATE_OF(CLIENT_MAC_BASED_ON_DIRECTION), NULL, 0, 0, flowCache);
    print_sensor_enrichment(kafka_line_buffer,flowCache);

#ifdef HAVE_UDNS
    const int solve_client=flowCache_want_client_dns(flowCache),
              solve_target=flowCache_want_target_dns(flowCache);

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
      opaque->export_timestamp = export_timestamp;
      opaque->dSwitched = dSwitched;
      opaque->bytes = bytes;
      opaque->pkts = pkts;
      const uint8_t *client_addr = get_direction_based_client_ip(flowCache);
      const uint8_t *target_addr = get_direction_based_target_ip(flowCache);
      opaque->refcnt = (solve_client && client_addr ? 1 : 0)
                     + (solve_target && target_addr ? 1 : 0);

      /// @TODO remove duplication
      if(readOnlyGlobals.udns.cache) {
        time_t now = time(NULL);

        if(solve_client && client_addr) {
          opaque->flowCache->address.client_name_cache = dns_cache_get_elm(
            readOnlyGlobals.udns.cache,(const uint8_t *)client_addr,now);
          if(NULL != opaque->flowCache->address.client_name_cache) {
            opaque->refcnt--;
          }
        }

        if(solve_target && target_addr) {
          opaque->flowCache->address.target_name_cache = dns_cache_get_elm(
            readOnlyGlobals.udns.cache,(const uint8_t *)target_addr,now);
          if(NULL != opaque->flowCache->address.target_name_cache) {
            opaque->refcnt--;
          }
        }
      }

      if(0 == opaque->refcnt) {
        // We had the needed addresses in cache, so we can sent the flow to dissect
        rd_thread_func_call2(curr_worker,split_after_dns_query_completed,
          readOnlyGlobals.udns.dns_info_array[dns_worker_i].dns_ctx,opaque);
      } else {
        if(solve_client && NULL == flowCache->address.client_name_cache) {
          uint32_t *pclient = ipv6_ptr_to_ipv4_ptr(client_addr);
          rd_thread_func_call4(curr_worker,dns_submit_a4ptr,
            readOnlyGlobals.udns.dns_info_array[dns_worker_i].dns_ctx,
            pclient,dns_query_completed_client,opaque);
        }

        if(solve_target && NULL == opaque->flowCache->address.target_name_cache) {
          uint32_t *ptarget = ipv6_ptr_to_ipv4_ptr(target_addr);
          rd_thread_func_call4(curr_worker,dns_submit_a4ptr,
            readOnlyGlobals.udns.dns_info_array[dns_worker_i].dns_ctx,
            ptarget,dns_query_completed_target,opaque);
        }
      }
    } else {
#endif

      struct string_list *current_record_string_list = time_split_flow(
        kafka_line_buffer, export_timestamp - dSwitched, dSwitched, bytes, pkts,
        flowCache);
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
            const struct sized_buffer *_buffer, struct netflow_sensor *_sensor,
            int flowVersion, int handle_ipfix,
            const struct flow_ver9_hdr *flowHeader, uint16_t *flowSequence) {

  V9FlowSet fs;

  struct string_list *kafka_string_list = NULL;

  const uint8_t *buffer  = _buffer->buffer;

  struct sensor *sensor_object = _sensor->sensor;

  /// @TODO show right display.
  ssize_t displ = 0;

  memcpy(&fs, &buffer[displ], sizeof(V9FlowSet));
  fs.flowsetLen = ntohs(fs.flowsetLen);
  fs.templateId = ntohs(fs.templateId);

  size_t tot_len = 4; /* @TODO why is this used? */

  const FlowSetV9Ipfix *cursor = find_sensor_template(sensor_object,fs.templateId);
  if(unlikely(cursor && cursor->templateInfo.fieldCount==0)) {
    /* If we don't protect, f2k will freeze because a posterior while(displ < end_flow) */
    cursor = NULL;
  }

  if(NULL == cursor) {
#ifdef DEBUG_FLOWS
    char ipv4_buf[1024];
    if(readOnlyGlobals.enable_debug) {
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

  if(readOnlyGlobals.enable_debug)
    traceEvent(TRACE_INFO, ">>>>> Rcvd flow with known template %d [%zd...%d]",
             fs.templateId, displ, fs.flowsetLen);

  /* Template found */
  kafka_string_list = dissectNetFlowV9V10FlowSetWithTemplate(worker, cursor,
    &fs, &tot_len, _buffer, _sensor, flowVersion, handle_ipfix, flowHeader,
    flowSequence);

#ifdef DEBUG_FLOWS
  if(readOnlyGlobals.enable_debug)
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
      if(readOnlyGlobals.enable_debug)
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
                              struct netflow_sensor *_sensor, ssize_t *_displ,
                              int handle_ipfix, size_t numEntries,
                              const uint16_t flowVersion,
                              uint16_t flowSequence) {
  const uint8_t *buffer = _buffer->buffer;
  const ssize_t displ = (*_displ);
  struct string_list *kafka_string_list = NULL;

  if(readOnlyGlobals.enable_debug) {
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
    dissectNetFlowV9V10Template(worker, &netflow_set_buffer, _sensor, &readed,
                                                      numEntries, handle_ipfix);
  } else {
    struct string_list *_kafka_string_list = NULL;
    _kafka_string_list = dissectNetFlowV9V10Flow(worker, &netflow_set_buffer,
                                          _sensor, flowVersion, handle_ipfix,
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
                    const uint32_t netflow_device_ip,
                    const uint16_t netflow_dst_port) {
  struct string_list *kafka_string_list = NULL;
  uint8_t done = 0;
  ssize_t numEntries;
  uint32_t flowSequence;
  ssize_t displ;
  int i;

  /* TODO do not use Netflow5Record * in this function */
  const uint16_t flowVersion = ntohs(((NetFlow5Record *) _buffer)->flowHeader.version);
  const int handle_ipfix = (flowVersion == 9) ? 0 : 1;

  if(handle_ipfix) {
    numEntries = ntohs((((NetFlow5Record *)_buffer)->flowHeader).count), displ = sizeof(V9FlowHeader)-4, // FIX
    flowSequence = ntohl(((IPFIXFlowHeader *)_buffer)->flow_sequence);
  } else {
    // in NF9, numEntries is netflow length
    numEntries = ntohs((((NetFlow5Record *)_buffer)->flowHeader).count), displ = sizeof(V9FlowHeader),
    flowSequence = ntohl((((V9FlowHeader *)_buffer))->flow_sequence);
  }

  if(readOnlyGlobals.enable_debug) {
    traceEvent(TRACE_INFO, "%s Length: %zd",
      handle_ipfix ? "IPFIX" : "V9", numEntries);
  }

  struct netflow_sensor sensor = {
    .netflow_device_ip = netflow_device_ip,
    .sensor = sensor_object,
    .dst_port = netflow_dst_port
  };

  // @TODO check this in netflow V5 too
  if(handle_ipfix && numEntries != bufferLen) {
    traceEvent(TRACE_ERROR,
      "Netflow V10 length (%zd) != received buffer length (%zd).",
      numEntries, bufferLen);
    traceEvent(TRACE_ERROR, "Assuming minimum.");
  }

  const struct sized_buffer buffer = {
    .buffer_start = _buffer,
    .buffer = _buffer,
    .size = handle_ipfix ? min(bufferLen,numEntries) : bufferLen,
  };

  for(i=0; (!done) && (displ < bufferLen) && (i < numEntries); i++) {
    struct string_list *_kafka_string_list = NULL;
    _kafka_string_list = dissectNetFlowV9V10Set(worker, &buffer, &sensor,
                  &displ, handle_ipfix, numEntries, flowVersion, flowSequence);
    string_list_concat(&kafka_string_list,_kafka_string_list);
  } /* for */

  return kafka_string_list;
}

static struct string_list *dissectNetFlow(worker_t *worker,
                      struct sensor *sensor_object,
                      const uint32_t netflow_device_ip, const uint16_t dst_port,
                      const uint8_t *buffer, const ssize_t bufferLen) {
  if(unlikely(NULL == readOnlyGlobals.rb_databases.sensors_info)) {
    traceEvent(TRACE_ERROR, "Can't get a sensor list");
    return NULL;
  }

  worker->stats.num_dissected_flow_packets++;

  NetFlow5Record *the5Record = (NetFlow5Record*)buffer;
  const uint16_t flowVersion = ntohs(((NetFlow5Record *) buffer)->flowHeader.version);

#ifdef DEBUG_FLOWS
  if(readOnlyGlobals.enable_debug) {
    traceEvent(TRACE_INFO,
        "NETFLOW: dissectNetFlow(len=%zd) [tot flow packets=%"PRIu64"]",
        bufferLen, worker->stats.num_dissected_flow_packets);
  }
#endif

#ifdef DEBUG_FLOWS
  if(readOnlyGlobals.enable_debug)
    traceEvent(TRACE_INFO, "NETFLOW: +++++++ version=%d",  flowVersion);
#endif

  if((flowVersion == 9) || (flowVersion == 10)) {
    return dissectNetflowV9V10(worker, sensor_object, buffer, bufferLen,
                                                  netflow_device_ip, dst_port);
  } else if(the5Record->flowHeader.version == htons(5)) {
    return dissectNetFlowV5(worker, sensor_object, the5Record);
  } else {
    traceEvent(TRACE_ERROR,"Uknown flow version %d",flowVersion);
  }

  return NULL;
}

/* ********************************************************* */

static inline int isSflow(const uint8_t *buffer){
  if((buffer[0] == '\0') && (buffer[1] == '\0') && (buffer[2] == '\0')){
    if((buffer[3] == 2) /* sFlow v2 */ || (buffer[3] == 5) /* sFlow v5 */)
      return 1;
  }
  return 0;
}

static void *netFlowConsumerLoop(void *vworker) {
  worker_t *worker = vworker;
  static const time_t timeout_ms = 800;
  // traceEvent(TRACE_NORMAL,"Creating consumer loop");

  while(true) {
    queued_template_t *qtemplate = template_queue_pop(&worker->templates_queue);
    if (qtemplate) {
      saveTemplate(qtemplate->sensor, qtemplate->template);
      rb_sensor_decref(qtemplate->sensor);
      continue;
    }

    QueuedPacket *packet = popPacketFromQueue_timedwait(&worker->packetsQueue,
                                                                    timeout_ms);
    if(packet) {
      if(worker->stats.first_flow_processed_timestamp == 0) {
        worker->stats.first_flow_processed_timestamp = time(NULL);
      }

      worker->stats.num_packets_received++;

      if(isSflow(packet->buffer)) {
        // dissectSflow(packet->buffer, packet->buffer_len, packet->netflow_device_ip); /* sFlow */
      } else {
        struct string_list *sl = dissectNetFlow(worker, packet->sensor,
                    packet->netflow_device_ip, packet->dst_port, packet->buffer,
                    packet->buffer_len);
        rb_sensor_decref(packet->sensor);
        send_string_list_to_kafka(sl);
      }

      freeQueuedPacket(packet);
    } else if (ATOMIC_OP(fetch, add, &worker->run.value, 0) == 0) {
      /* No pending packet & don't keep running */
      break;
    }

    worker->stats.last_flow_processed_timestamp = time(NULL);
  }

  return NULL;
}

/* ********************************************************* */

/** Creates a worker */
worker_t *new_collect_worker() {
  worker_t *ret = calloc(1, sizeof(*ret));
  if (NULL != ret) {
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
    if (pthread_create_rc != 0) {
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
