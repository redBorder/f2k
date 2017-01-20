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

#include "export.h"
#include "util.h"
#include "rb_mac.h"
#include "rb_sensor.h"

#ifdef HAVE_UDNS
#include "rb_dns_cache.h"
#endif

#include <librd/rdfile.h>

#define NETFLOW_DIRECTION_INGRESS 0
#define NETFLOW_DIRECTION_EGRESS  1

typedef size_t (*entity_fn)(struct printbuf *kafka_line_buffer,
    const void *vbuffer, const size_t real_field_len,
    struct flowCache *flowCache);

#define assert_multi(...) do {size_t assert_i; \
  for(assert_i=0; \
      assert_i<sizeof((const void *[]){__VA_ARGS__})/sizeof(const void *);\
      ++assert_i) {assert(((const void *[]){__VA_ARGS__})[assert_i]);}}while(0)

/// Get rid of unused parameters
static void unused_params0(const void *p,...) {(void)p;}
#define unused_params(p...) unused_params0(&p)

typedef enum {
  DIRECTION_UNSET,      ///< Unknown traffic direction
  DIRECTION_UPSTREAM,   ///< Traffic goes from LAN to WAN
  DIRECTION_DOWNSTREAM, ///< Traffic goes from WAN to LAN
  DIRECTION_INTERNAL,   ///< Traffic is home_net internal
} direction_t;

struct flowCache *new_flowCache(){
  return calloc(1,sizeof(struct flowCache));
}

void associateSensor(struct flowCache *flowCache, struct sensor *sensor){
  assert_multi(flowCache, sensor);

  flowCache->sensor = sensor;
}

void free_flowCache(struct flowCache *cache){
  free(cache);
}

static int ip_direction(int known_src,int known_dst) {
  if(!known_src && known_dst) {
    return DIRECTION_DOWNSTREAM;
  } else if(known_src && !known_dst) {
    return DIRECTION_UPSTREAM;
  } else if(known_src && known_dst) {
    return DIRECTION_INTERNAL;
  }
  // No "external"
  return DIRECTION_UNSET;
}

/*
  Try to guess direction based on source and destination address
  return: true if guessed/already setted. false if couldn't set
*/
bool guessDirection(struct flowCache *cache) {
  assert(cache);
  static const char zeros[sizeof(cache->address.src)] = {0};

  if (0 == memcmp(cache->address.src, zeros, sizeof(cache->address.src)) ||
      0 == memcmp(cache->address.dst, zeros, sizeof(cache->address.dst))) {
    /* Can't guess direction */
    return false;
  }

  const int src_ip_in_home_net = NULL!=network_ip(cache->observation_id,
                                                            cache->address.src);
  const int dst_ip_in_home_net = NULL!=network_ip(cache->observation_id,
                                                            cache->address.dst);

  const int ip_guessed_direction = ip_direction(src_ip_in_home_net,dst_ip_in_home_net);
  if (ip_guessed_direction != DIRECTION_UNSET) {
    cache->macs.direction = ip_guessed_direction;
    return true;
  }

  return true;
}

#if 0
/* Just for templating */
/*
 * Function: C++ version 0.4 char* style "itoa", Written by Lukás Chmela. (Modified)
 *
 * Purpose: Fast itoa conversion. snprintf is slow.
 *
 * Arguments:   value => Number.
 *             result => Where to save result
 *               base => Number base.
 *
 * Return: result
 * TODO: Return writed buffer lenght.
 *
 */
static char* _itoa(uint64_t value, char* result, int base, size_t bufsize) {
    // check that the base if valid
    if (base < 2 || base > 36) { *result = '\0'; return result; }

    char *ptr = result+bufsize;
    uint64_t tmp_value;

    *--ptr = '\0';
    do {
        tmp_value = value;
        value /= base;
        *--ptr = "zyxwvutsrqponmlkjihgfedcba9876543210123456789abcdefghijklmnopqrstuvwxyz" [35 + (tmp_value - value * base)];
    } while ( value );


    if (tmp_value < 0) *--ptr = '-';
    return ptr;
}
#endif

static char* _itoa10(int64_t value, char* result, size_t bufsize) {
    assert(result);
    char *ptr = result+bufsize;
    int64_t tmp_value;

    *--ptr = '\0';
    do {
        tmp_value = value;
        value /= 10;
        *--ptr = "zyxwvutsrqponmlkjihgfedcba9876543210123456789abcdefghijklmnopqrstuvwxyz" [35 + (tmp_value - value * 10)];
    } while ( value );


    if (tmp_value < 0) *--ptr = '-';
    return ptr;
}

static size_t printbuf_memappend_fast_n10(struct printbuf *kafka_line_buffer,const uint64_t value){
  assert(kafka_line_buffer);
  static const size_t bufsize = 64;
  char buf[bufsize];

  const char *buf_start = _itoa10(value,buf,bufsize);
  const size_t number_strlen = buf+bufsize-buf_start-1;

  printbuf_memappend_fast(kafka_line_buffer,buf_start,number_strlen);
  return number_strlen;
}

#define get_mac(buffer) net2number(buffer,6);

size_t print_string(struct printbuf *kafka_line_buffer,
    const void *vbuffer, const size_t real_field_len,
    struct flowCache *flowCache){
  const char *buffer = vbuffer;
  assert_multi(kafka_line_buffer, vbuffer);
  unused_params(flowCache);

  const size_t bef_len = kafka_line_buffer->bpos;
  printbuf_memappend_fast(kafka_line_buffer, buffer, real_field_len);
  return kafka_line_buffer->bpos - bef_len;
}

#define SAVE_FLOWCACHE_NUMBER_PARAMETER(kafka_line_buffer, buffer,             \
                real_field_len, flowCache, parameter) do {                     \
  assert_multi(buffer, flowCache); unused_params(kafka_line_buffer);           \
  flowCache->parameter = net2number(                                           \
    (const uint8_t *)buffer, real_field_len);                                  \
  return 0; } while(0)

size_t save_first_second(struct printbuf *kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flowCache) {
  SAVE_FLOWCACHE_NUMBER_PARAMETER(kafka_line_buffer, buffer,
      real_field_len, flowCache, time.first_timestamp_s);
}

size_t save_last_second(struct printbuf *kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flowCache) {
  SAVE_FLOWCACHE_NUMBER_PARAMETER(kafka_line_buffer, buffer,
      real_field_len, flowCache, time.last_timestamp_s);
}

/** Auxiliar function for first/last switched
 * @param  dst               Destination to save buffer
 * @param  buffer            Uptime buffer
 * @param  real_field_len    Buffer length
 */
static void save_x_switched(uint64_t *dst, const void *vbuffer,
    const size_t real_field_len) {
  const uint8_t *buffer = vbuffer;
  assert_multi(dst, buffer);
  // uptime switched in miliseconds
  *dst = net2number(buffer, real_field_len)/1000;
}

size_t save_first_switched(struct printbuf *kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flowCache) {
  unused_params(kafka_line_buffer);
  save_x_switched(&flowCache->time.first_switched_uptime_s,
    buffer, real_field_len);
  return 0;
}

size_t save_last_switched(struct printbuf *kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flowCache) {
  unused_params(kafka_line_buffer);
  save_x_switched(&flowCache->time.last_switched_uptime_s,
    buffer, real_field_len);
  return 0;
}

size_t save_flow_bytes(struct printbuf *kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flowCache) {
  SAVE_FLOWCACHE_NUMBER_PARAMETER(kafka_line_buffer, buffer, real_field_len,
    flowCache, bytes);
}

size_t save_flow_pkts(struct printbuf *kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flowCache) {
  SAVE_FLOWCACHE_NUMBER_PARAMETER(kafka_line_buffer, buffer, real_field_len,
    flowCache, packets);
}

/** Calls cb assuming that buffers brings the number in mili(units)
 * @param  cb                Callback to call with number(buffer)/1000
 * @param  kafka_line_buffer Kafka line buffer to use with cb
 * @param  buffer            Buffer that contains the mili-value
 * @param  real_field_len    Length of buffer
 * @param  flowCache         Flow cache to call with number(buffer)/1000
 * @return                   Callback return
 */
static size_t callback_mili_buffer(entity_fn cb,
    struct printbuf *kafka_line_buffer,
    const void *vbuffer, const size_t real_field_len,
    struct flowCache *flowCache) {
  const uint8_t *buffer = vbuffer;
  assert_multi(buffer);

  const uint64_t number = net2number(buffer, real_field_len);
  const uint64_t be_number = htonll(number);
  return cb(kafka_line_buffer, &be_number, sizeof(be_number), flowCache);
}

size_t save_first_msecond(struct printbuf *kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flowCache) {
  return callback_mili_buffer(save_first_second, kafka_line_buffer,
    buffer, real_field_len, flowCache);
}

size_t save_last_msecond(struct printbuf *kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flowCache) {
  return callback_mili_buffer(save_last_second, kafka_line_buffer,
    buffer, real_field_len, flowCache);
}

size_t print_tcp_flags(struct printbuf *kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flowCache) {
  // Avoid warning storm
  static bool warned = false;

  const size_t start_bpos = kafka_line_buffer->bpos;
  char tcp_flags_str[8];
  size_t i;

  assert_multi(kafka_line_buffer, buffer);
  unused_params(flowCache);

  if (unlikely(real_field_len != 1 && real_field_len != 2)) {
    if (unlikely(ATOMIC_TEST_AND_SET(&warned))) {
      traceEvent(TRACE_ERROR, "TCP flags length %zu not in (1,2)",
        real_field_len);
    }
    return 0;
  }

  const uint8_t tcp_flags = 1==real_field_len ? ((const uint8_t *)buffer)[0] :
    ((const uint8_t *)buffer)[1];

  if (0 == tcp_flags) {
    // Not interesting
    return 0;
  }

  for (i=0; i<RD_ARRAYSIZE(tcp_flags_str); ++i) {
    // 0x80, CWR  Congestion Window Reduced
    // 0x40, ECE  ECN Echo
    // 0x20, URG  Urgent Pointer
    // 0x10, ACK  Acknowledgment
    // 0x08, PSH  Push Function
    // 0x04, RST  Reset the connection
    // 0x02, SYN  Synchronize sequence numbers
    // 0x01, FIN  No more data from sender'
    static const char flag_id_char[] = "CEUAPRSF";
    tcp_flags_str[i] = (tcp_flags & 1<<(7-i)) ? flag_id_char[i] : '.';
  }

  printbuf_memappend_fast(kafka_line_buffer, tcp_flags_str,
                                              sizeof(tcp_flags_str));
  return kafka_line_buffer->bpos - start_bpos;
}


size_t print_number(struct printbuf *kafka_line_buffer, const void *vbuffer,
    const size_t real_field_len, struct flowCache *flowCache) {
  const uint8_t *buffer = vbuffer;
  assert_multi(kafka_line_buffer, buffer);
  unused_params(flowCache);

  const uint64_t number = net2number(buffer, real_field_len);
  return printbuf_memappend_fast_n10(kafka_line_buffer,number);
}

size_t print_netflow_type(struct printbuf *kafka_line_buffer,
    const void *vbuffer, const size_t real_field_len,
    struct flowCache *flowCache) {

    static const char *type_msg = "netflowv";
    const uint8_t *buffer = vbuffer;

    assert_multi(kafka_line_buffer, buffer);
    unused_params(flowCache);

    const size_t start_bpos = kafka_line_buffer->bpos;
    const uint64_t type = net2number(buffer, real_field_len);
    printbuf_memappend_fast(kafka_line_buffer,type_msg,strlen(type_msg));
    printbuf_memappend_fast_n10(kafka_line_buffer,type);
    return kafka_line_buffer->bpos - start_bpos;
}

/**
 * Append string in print buffer and return increased length
 * @param  kafka_line_buffer Line buffer to append into
 * @param  str               String to append
 * @return                   Increased length
 */
static size_t printbuf_memappend_fast_string(struct printbuf *kafka_line_buffer,const char *str){
  assert_multi(kafka_line_buffer, str);
  const size_t len = strlen(str);
  printbuf_memappend_fast(kafka_line_buffer,str,len);
  return len;
}

size_t print_flow_end_reason(struct printbuf *kafka_line_buffer,
    const void *vbuffer, const size_t real_field_len,
    struct flowCache *flowCache) {
  const char *buffer = vbuffer;
  static const char *reasons[] = {
    [1] = "idle timeout",
    [2] = "active timeout",
    [3] = "end of flow",
    [4] = "forced end",
    [5] = "lack of resources",
  };
  const uint8_t reason = buffer[0];
  assert_multi(kafka_line_buffer, buffer);
  unused_params(real_field_len, flowCache);
  assert(real_field_len > 0);

  if (likely(reason > 0 && reason < sizeof(reasons)/sizeof(reasons[0]))) {
    return printbuf_memappend_fast_string(kafka_line_buffer, reasons[reason]);
  } else {
    traceEvent(TRACE_WARNING,"UNKNOWN flow end reason %d",buffer[0]);
    return 0;
  }
}

size_t print_biflow_direction(struct printbuf *kafka_line_buffer,
    const void *vbuffer, const size_t real_field_len,
    struct flowCache *flowCache) {

  static const char *directions[] = {
    [0] = "arbitrary",
    [1] = "initiator",
    [2] = "reverse initiator",
    [3] = "perimeter",
  };
  const uint8_t *buffer = vbuffer;
  const uint8_t direction = buffer[0];

  assert(real_field_len > 0);
  unused_params(real_field_len, flowCache);

  assert_multi(kafka_line_buffer, buffer);
  if (likely(direction < RD_ARRAYSIZE(directions))) {
    return printbuf_memappend_fast_string(kafka_line_buffer,
                                                        directions[direction]);
  } else {
    traceEvent(TRACE_WARNING,"UNKNOWN buflow direction: %d",buffer[0]);
    return 0;

  }
}

static size_t print_netflow_direction(struct printbuf *kafka_line_buffer,
    const uint8_t direction) {
  return printbuf_memappend_fast_string(kafka_line_buffer,
    (direction == NETFLOW_DIRECTION_INGRESS) ? "ingress" :
    (direction == NETFLOW_DIRECTION_EGRESS)  ? "egress"  :
    "");
}

size_t print_flow_cache_direction(struct printbuf *kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flow_cache) {
  assert_multi(kafka_line_buffer, flow_cache);
  unused_params(buffer, real_field_len);

  const char *to_print = "";
  switch (flow_cache->macs.direction) {
  case DIRECTION_UPSTREAM:
    to_print = "upstream";
    break;
  case DIRECTION_DOWNSTREAM:
    to_print = "downstream";
    break;
  case DIRECTION_INTERNAL:
    to_print = "internal";
    break;
  default:
    break;
  }

  return printbuf_memappend_fast_string(kafka_line_buffer, to_print);
}

size_t process_direction(struct printbuf *kafka_line_buffer,
    const void *vbuffer, const size_t real_field_len,
    struct flowCache *flow_cache) {
  const uint8_t *buffer = vbuffer;
  assert_multi(buffer);
  unused_params(real_field_len, kafka_line_buffer);
  const uint64_t direction = net2number(buffer, real_field_len);

  if (unlikely(direction > 1)) {
    traceEvent(TRACE_ERROR, "Unknown netflow direction %"PRIu64, direction);
    return 0;
  }

  if (readOnlyGlobals.normalize_directions) {
    uint64_t netflow_direction = direction;
    if (is_exporter_in_wan_side(flow_cache->observation_id)) {
      netflow_direction = !netflow_direction;
    }
    flow_cache->macs.direction =
      (netflow_direction == NETFLOW_DIRECTION_INGRESS) ? DIRECTION_UPSTREAM :
        DIRECTION_DOWNSTREAM;
    return 0; /* nothing printed */
  } else {
    return print_netflow_direction(kafka_line_buffer, direction);
  }
}

/**
 * Save MAC address in given buffer
 * @param dst_buffer          Destination buffer (have to be sizeof()>6)
 * @param src_buffer_mac_name MAC name description for errors
 * @param kafka_line_buffer   unused
 * @param vbuffer             Buffer where MAC address is
 * @param real_field_len      Length of buffer (needs to be 6)
 * @param flowCache           unused
 */
static void save_mac(uint8_t *dst_buffer, const char *src_buffer_mac_name,
    const void *vbuffer, const size_t real_field_len) {

  const uint8_t *buffer = vbuffer;
  assert_multi(buffer);

  if (likely(real_field_len == 6)) {
    memcpy(dst_buffer, buffer, 6);
  } else {
    traceEvent(TRACE_WARNING, "%s length != 6.", src_buffer_mac_name);
  }
}

/**
 * Process a given MAC
 * @param  dst_buffer          Buffer to save if we are going to process it
 *                             later
 * @param  src_buffer_mac_name MAC name for debug purposes
 * @param  kafka_line_buffer   Buffer to print MAC
 * @param  vbuffer             MAC buffer
 * @param  real_field_len      MAC length
 * @return                     [description]
 */
static size_t process_mac0(uint8_t *dst_buffer, const char *src_buffer_mac_name,
    struct printbuf *kafka_line_buffer,
    const void *vbuffer, const size_t real_field_len) {
  if (readOnlyGlobals.normalize_directions) {
    save_mac(dst_buffer, src_buffer_mac_name, vbuffer, real_field_len);
    return 0;
  } else {
    return print_mac(kafka_line_buffer, vbuffer, real_field_len, NULL);
  }
}

size_t process_src_mac(struct printbuf *kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flow_cache) {
  unused_params(flow_cache);
  return process_mac0(flow_cache->macs.src_mac, "Source mac",
    kafka_line_buffer, buffer, real_field_len);
}

size_t process_post_src_mac(struct printbuf *kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flow_cache) {
  unused_params(flow_cache);
  return process_mac0(flow_cache->macs.post_src_mac, "PST Source mac",
    kafka_line_buffer, buffer, real_field_len);
}

size_t process_dst_mac(struct printbuf *kafka_line_buffer, const void *buffer,
    const size_t real_field_len, struct flowCache *flow_cache) {
  unused_params(flow_cache);
  return process_mac0(flow_cache->macs.dst_mac, "DST mac",
    kafka_line_buffer, buffer, real_field_len);
}

size_t process_post_dst_mac(struct printbuf *kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flow_cache) {
  unused_params(flow_cache);
  return process_mac0(flow_cache->macs.post_dst_mac, "POST DST mac",
    kafka_line_buffer, buffer, real_field_len);
}

static size_t print_ssid_name0(struct printbuf *kafka_line_buffer,const void *buffer,const uint16_t real_field_len){
  const size_t len = strnlen(buffer,real_field_len);
  printbuf_memappend_fast(kafka_line_buffer,buffer,len);
  return len;
}

size_t print_ssid_name(struct printbuf *kafka_line_buffer,
    const void *vbuffer,const size_t real_field_len,
    struct flowCache *flowCache) {
  const uint8_t *buffer = vbuffer;
  assert_multi(kafka_line_buffer, buffer);
  unused_params(flowCache);


  return print_ssid_name0(kafka_line_buffer, buffer, real_field_len);
}

/** Transforms ipv4 buffer in ipv6
  @param vbuffer Buffer of ipv6
  @param ipv6 Buffer to sabe IP
  */
static void ipv4buf_to_6(uint8_t ipv6[16],const void *vbuffer){
  const uint8_t *buffer = vbuffer;
  assert_multi(ipv6, buffer);
  int i;
  for (i = 0; i < 10; i++)
    ipv6[i] = 0;

  ipv6[10] = 0xFF;
  ipv6[11] = 0xFF;
  ipv6[12] = buffer[0];
  ipv6[13] = buffer[1];
  ipv6[14] = buffer[2];
  ipv6[15] = buffer[3];
}

/** Prints net information
  @param kafka_line_buffer Buffer to print net information
  @param vbuffer Buffer where net is
  @param real_field_len Length of buffer
  @param flowCache Flow cache information
  @param sensor_list_search_cb Callback to search in sensor information
  @param global_net_list_cb Callback to manage global nets list.
  @return Printed length
 */

static size_t print_net0(struct printbuf *kafka_line_buffer,
    const void *vbuffer, const size_t real_field_len,
    struct flowCache *flowCache,
    const char *(*sensor_list_search_cb)(observation_id_t *,const uint8_t[16]),
      const char *(*global_net_list_cb)(const IPNameAssoc *)) {
  const uint8_t *buffer = vbuffer;
  assert_multi(kafka_line_buffer, buffer, flowCache);

  if (unlikely(16 != real_field_len)) {
    traceEvent(TRACE_ERROR, "IPv6 net length %zu != 16", real_field_len);
    return 0;
  }

  /* First try: Has the observation id a home net that contains this ip? */
  const char *sensor_home_net = sensor_list_search_cb(flowCache->observation_id,
                                                      buffer);
  if(sensor_home_net){
    return printbuf_memappend_fast_string(kafka_line_buffer, sensor_home_net);
  }

  /* Second try: General nets ip list */
  const IPNameAssoc *ip_name_as = ipInList(buffer,
    readOnlyGlobals.rb_databases.nets_name_as_list);

  if (ip_name_as) {
    const char *to_print = global_net_list_cb(ip_name_as);
    return printbuf_memappend_fast_string(kafka_line_buffer, to_print);
  } else {
    /* Nothing more to do, sorry */
    return 0;
  }
}

static const char *global_net_list_number(const IPNameAssoc *assoc) {
  return assoc->number;
}

static const char *global_net_list_name(const IPNameAssoc *assoc) {
  return assoc->name;
}

static size_t print_net_v6_0(struct printbuf *kafka_line_buffer,
    const void *vbuffer,const size_t real_field_len,
    struct flowCache *flowCache) {
  return print_net0(kafka_line_buffer, vbuffer, real_field_len, flowCache,
    network_ip, global_net_list_number);
}

static size_t print_net_name_v6_0(struct printbuf *kafka_line_buffer,
    const void *vbuffer,const size_t real_field_len,
    struct flowCache *flowCache) {
  return print_net0(kafka_line_buffer, vbuffer, real_field_len, flowCache,
    network_name, global_net_list_name);
}

size_t print_net_v6(struct printbuf *kafka_line_buffer,
    const void *buffer,const size_t real_field_len,
    struct flowCache *flow_cache) {
  return (!readOnlyGlobals.normalize_directions) ?
    print_net_v6_0(kafka_line_buffer, buffer, real_field_len, flow_cache) : 0;
}

size_t print_net_name_v6(struct printbuf *kafka_line_buffer,
    const void *buffer,const size_t real_field_len,
    struct flowCache *flow_cache) {
  return (!readOnlyGlobals.normalize_directions) ?
    print_net_name_v6_0(kafka_line_buffer, buffer, real_field_len, flow_cache) :
      0;
}

/** Decorate a function making an ipv6 function be called over an ipv4 buffer
 * @param  kafka_line_buffer Kafka line buffer to print
 * @param  vbuffer           Buffer
 * @param  real_field_len    IPv4 length length
 * @param  flowCache         Flow cache
 * @param  cb                Function to call with IPv6 buffer
 * @return                   Printed length
 */
static size_t ipv4_to_6_decorator(struct printbuf *kafka_line_buffer,
    const void *vbuffer, const size_t real_field_len,
    struct flowCache *flowCache,
    size_t (cb)(struct printbuf *, const void *, const size_t,
                                                          struct flowCache *)) {
  const uint8_t *buffer = vbuffer;
  assert(buffer);
  uint8_t ipv6[16];
  if (unlikely(4 != real_field_len)) {
    traceEvent(TRACE_WARNING, "Net length %zu != 4", real_field_len);
    return 0;
  }

  ipv4buf_to_6(ipv6, buffer);
  return cb(kafka_line_buffer, ipv6, sizeof(ipv6), flowCache);
}

size_t print_net(struct printbuf *kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flowCache) {
  return ipv4_to_6_decorator(kafka_line_buffer, buffer, real_field_len,
            flowCache, print_net_v6);
}

size_t print_net_name(struct printbuf *kafka_line_buffer,
    const void *buffer,const size_t real_field_len,
    struct flowCache *flowCache) {
  return ipv4_to_6_decorator(kafka_line_buffer, buffer, real_field_len,
            flowCache, print_net_name_v6);
}

static size_t print_ipv4_addr0(struct printbuf *kafka_line_buffer,
    const uint32_t ipv4) {
  assert(kafka_line_buffer);
  static const size_t bufsize = sizeof("255.255.255.255")+1;
  char buf[bufsize];

  const char *ip_as_text = _intoaV4(ipv4,buf,bufsize);
  const size_t ip_as_text_size = buf+bufsize-ip_as_text-1;

  printbuf_memappend_fast(kafka_line_buffer,ip_as_text,ip_as_text_size);
  return ip_as_text_size;
}

static size_t print_ipv6_addr0(struct printbuf *kafka_line_buffer,
    const void *vbuffer) {
  size_t i=0;
  const uint8_t *buffer = vbuffer;
  for (i=0;i<8;++i) {
    printbuf_memappend_fast_n16(kafka_line_buffer,buffer[2*i]);
    printbuf_memappend_fast_n16(kafka_line_buffer,buffer[2*i+1]);
    if(i<7)
      printbuf_memappend_fast(kafka_line_buffer,":",1);
  }

  return strlen("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
}

static size_t print_ipv4_addr(struct printbuf *kafka_line_buffer,
    const void *vbuffer, const size_t real_field_len,
    const struct flowCache *flow_cache) {
  const char *buffer = vbuffer;
  (void)flow_cache;
  assert_multi(kafka_line_buffer, buffer);

  if (unlikely(4 != real_field_len)) {
    traceEvent(TRACE_ERROR, "IPv4 real field len %zu != 4", real_field_len);
    return 0;
  }

  const uint32_t ipv4 = net2number(buffer, 4);
  return print_ipv4_addr0(kafka_line_buffer, ipv4);
}

static void flow_cache_save_ipv4(void *dst_buf, const void *vbuffer,
    const size_t real_field_len) {
  const uint8_t *buffer = vbuffer;
  if (unlikely(real_field_len != 4)) {
    traceEvent(TRACE_ERROR, "ipv4 length != 4");
    return;
  }

  ipv4buf_to_6(dst_buf, buffer);
}

static size_t process_ipv4_addr0(void *dst_buf,
                                 struct printbuf *kafka_line_buffer,
                                 const void *buffer,
                                 const size_t real_field_len,
                                 struct flowCache *flowCache) {
  if (readOnlyGlobals.normalize_directions) {
    flow_cache_save_ipv4(dst_buf, buffer, real_field_len);
    return 0;
  } else {
    return print_ipv4_addr(kafka_line_buffer, buffer, real_field_len,
      flowCache);
  }
}

size_t print_ipv4_src_addr(struct printbuf *kafka_line_buffer,
    const void *buffer,const size_t real_field_len,
    struct flowCache *flow_cache) {
  return process_ipv4_addr0(flow_cache->address.src, kafka_line_buffer, buffer,
    real_field_len, flow_cache);
}

size_t print_ipv4_dst_addr(struct printbuf *kafka_line_buffer,
    const void *buffer,const size_t real_field_len,
    struct flowCache *flow_cache) {

  return process_ipv4_addr0(flow_cache->address.dst, kafka_line_buffer, buffer,
    real_field_len, flow_cache);
}

static bool is_ipv4_mapped(const void *ipv6) {
  static const uint8_t ipv4_mapped[12] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                          0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF};
  return 0 == memcmp(ipv6, ipv4_mapped, 12);
}

static size_t print_flow_cache_address(struct printbuf *kafka_line_buffer,
    struct flowCache *flow_cache,
    const uint8_t *(*get_addr_cb)(const struct flowCache *flowCache),
    size_t (*print_addr_cb)(struct printbuf *kafka_line_buffer,
      const void *addr, struct flowCache *flow_cache)) {
  assert(kafka_line_buffer);
  assert(flow_cache);

  const uint8_t *client_ip = get_addr_cb(flow_cache);
  if (NULL == client_ip) {
    return 0;
  }

  return print_addr_cb(kafka_line_buffer, client_ip, flow_cache);
}

static size_t print_flow_cache_addr(struct printbuf *kafka_line_buffer,
    const void *vip_addr, struct flowCache *flow_cache) {
  (void)flow_cache;
  const uint8_t *ip_addr = vip_addr;
  return is_ipv4_mapped(ip_addr) ?
    print_ipv4_addr0(kafka_line_buffer,
                                ip_addr[15] + (ip_addr[14] << 8) +
                                (ip_addr[13] << 16) + (ip_addr[12] << 24))
    : print_ipv6_addr0(kafka_line_buffer, ip_addr);
}

static size_t print_flow_cache_net0(struct printbuf *kafka_line_buffer,
    const void *vip_addr, struct flowCache *flow_cache,
    size_t (*print_net_cb)(struct printbuf *kafka_line_buffer,
      const void *vip_addr, const size_t len,
      struct flowCache *flow_cache)) {
  static const size_t addr_len = 16;
  return print_net_cb(kafka_line_buffer, vip_addr, addr_len, flow_cache);
}

static size_t print_flow_cache_net(struct printbuf *kafka_line_buffer,
    const void *ip_addr, struct flowCache *flow_cache) {
  return print_flow_cache_net0(kafka_line_buffer, ip_addr, flow_cache,
    print_net_v6_0);
}

static size_t print_flow_cache_net_name(struct printbuf *kafka_line_buffer,
    const void *ip_addr, struct flowCache *flow_cache) {
  return print_flow_cache_net0(kafka_line_buffer, ip_addr, flow_cache,
    print_net_name_v6_0);
}

size_t print_sta_ipv4_address(struct printbuf *kafka_line_buffer,
                              const void *vbuffer, const size_t real_field_len,
                              struct flowCache *flow_cache) {
  const char *buffer = vbuffer;
  if (unlikely(real_field_len != 4)) {
    traceEvent(TRACE_ERROR, "Bad client ip addr received");
    return 0;
  }

  /* Save client address for DNS query */
  flow_cache->address.client[10] = flow_cache->address.client[11] = 0xff;
  memcpy(&flow_cache->address.client[12], buffer, 4);

  /* print */
  const uint32_t addr = net2number(buffer, real_field_len);
  return print_ipv4_addr0(kafka_line_buffer, addr);
}

size_t print_lan_addr(struct printbuf *kafka_line_buffer,
                      const void *buffer, const size_t real_field_len,
                      struct flowCache *flow_cache) {
  unused_params(buffer, real_field_len);

  if (!readOnlyGlobals.normalize_directions) {
    return 0;
  }

  return print_flow_cache_address(kafka_line_buffer, flow_cache,
    get_direction_based_client_ip, print_flow_cache_addr);
}

size_t print_lan_addr_net(struct printbuf *kafka_line_buffer,
                            const void *buffer, const size_t real_field_len,
                            struct flowCache *flowCache) {
  unused_params(buffer, real_field_len);
  assert_multi(kafka_line_buffer, flowCache);
  return print_flow_cache_address(kafka_line_buffer, flowCache,
    get_direction_based_client_ip, print_flow_cache_net);
}

size_t print_wan_addr_net(struct printbuf *kafka_line_buffer,
                            const void *buffer, const size_t real_field_len,
                            struct flowCache *flowCache) {
  unused_params(buffer, real_field_len);
  assert_multi(kafka_line_buffer, flowCache);
  return print_flow_cache_address(kafka_line_buffer, flowCache,
    get_direction_based_target_ip, print_flow_cache_net);
}

size_t print_lan_addr_net_name(struct printbuf *kafka_line_buffer,
                            const void *buffer, const size_t real_field_len,
                            struct flowCache *flowCache) {
  unused_params(buffer, real_field_len);
  assert_multi(kafka_line_buffer, flowCache);
  return print_flow_cache_address(kafka_line_buffer, flowCache,
    get_direction_based_client_ip, print_flow_cache_net_name);
}

size_t print_wan_addr_net_name(struct printbuf *kafka_line_buffer,
                            const void *buffer, const size_t real_field_len,
                            struct flowCache *flowCache) {
  unused_params(buffer, real_field_len);
  assert_multi(kafka_line_buffer, flowCache);
  return print_flow_cache_address(kafka_line_buffer, flowCache,
    get_direction_based_target_ip, print_flow_cache_net_name);
}

size_t print_wan_addr(struct printbuf *kafka_line_buffer,
                            const void *buffer, const size_t real_field_len,
                            struct flowCache *flowCache) {
  unused_params(buffer, real_field_len);
  return print_flow_cache_address(kafka_line_buffer, flowCache,
    get_direction_based_target_ip, print_flow_cache_addr);
}

static size_t print_mac0(struct printbuf *kafka_line_buffer,
    const void *vbuffer) {
  const uint8_t *buffer = vbuffer;
  assert_multi(kafka_line_buffer, buffer);
  int i;
  for(i=0;i<6;++i){
    printbuf_memappend_fast_n16(kafka_line_buffer,buffer[i]);
    if(i<5)
      printbuf_memappend_fast(kafka_line_buffer,":",1);
  }

  return strlen("ff:ff:ff:ff:ff:ff");
}

size_t print_mac(struct printbuf *kafka_line_buffer,
    const void *vbuffer,const size_t real_field_len,
    struct flowCache *flowCache) {
  const char *buffer = vbuffer;
  assert_multi(kafka_line_buffer, buffer);
  unused_params(flowCache);

  if (unlikely(real_field_len!=6)) {
    traceEvent(TRACE_ERROR,"Mac with len %zu != 6", real_field_len);
    return 0;
  }

  return print_mac0(kafka_line_buffer, buffer);
}

static size_t print_mac_vendor0(struct printbuf *kafka_line_buffer,const void *buffer){
  const uint64_t mac = get_mac(buffer);

  if(mac){
    const char *vendor = NULL;
    pthread_rwlock_rdlock(&readOnlyGlobals.rb_databases.mutex);
    if(readOnlyGlobals.rb_databases.mac_vendor_database)
      vendor = rb_find_mac_vendor(mac,readOnlyGlobals.rb_databases.mac_vendor_database);
    pthread_rwlock_unlock(&readOnlyGlobals.rb_databases.mutex);
    if(vendor){
      const size_t vendor_len = strlen(vendor);
      printbuf_memappend_fast(kafka_line_buffer,vendor,vendor_len);
      return vendor_len;
    }
  }

  return 0;
}

static bool empty_ipv6_addr(const uint8_t *addr) {
  static const uint8_t ipv6[16];
  return !memcmp(addr, ipv6, sizeof(ipv6));
}

#define GET_CLIENT_ENDPOINT(t_direction, t_src, t_dst) ({                      \
  const typeof(t_src) src = (t_src), dst = (t_dst);                            \
  /* Default exporter position is LAN side */                                  \
  const uint8_t direction = (t_direction);                                     \
  (direction == DIRECTION_DOWNSTREAM) ? dst : src;})

static const uint8_t *get_direction_based_client_mac(struct flowCache *flowCache){
  assert(flowCache);

  const uint8_t *src_mac = flowCache->macs.src_mac;
  const uint8_t *dst_mac = is_span_observation_id(flowCache->observation_id) ?
    flowCache->macs.dst_mac : flowCache->macs.post_dst_mac;

  return GET_CLIENT_ENDPOINT(flowCache->macs.direction,
    src_mac, dst_mac);
}

static uint64_t get_direction_based_client_port(
    const struct flowCache *flow_cache) {
  assert(flow_cache);

  return GET_CLIENT_ENDPOINT(flow_cache->macs.direction, flow_cache->ports.src,
    flow_cache->ports.dst);
}

static uint64_t get_direction_based_target_port(
    const struct flowCache *flow_cache) {
  assert(flowCache);

  const uint64_t client_port = get_direction_based_client_port(flow_cache);
  return (client_port == flow_cache->ports.src) ? flow_cache->ports.dst :
    flow_cache->ports.src;
}

size_t print_direction_based_client_mac(struct printbuf *kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flowCache) {
  unused_params(buffer, real_field_len);
  assert_multi(kafka_line_buffer, flowCache);

  if (flowCache->client_mac != 0) {
    /* Already printed */
    return 0;
  }

  const uint8_t *mac = get_direction_based_client_mac(flowCache);
  if(mac!=NULL){
    flowCache->client_mac = net2number(mac, 6);
    return print_mac0(kafka_line_buffer, mac);
  }
  return 0;
}

size_t print_client_mac(struct printbuf *kafka_line_buffer,const void *vbuffer,const size_t real_field_len,
  struct flowCache *flowCache) {
  static const size_t mac_length = 6;
  const char *buffer = vbuffer;

  if (unlikely(real_field_len != mac_length)) {
    traceEvent(TRACE_ERROR, "Length %zu, Expected %zu", real_field_len,
      mac_length);
    return 0;
  }

  if(flowCache->client_mac != 0) {
    /* Already printed */
    return 0;
  }

  flowCache->client_mac = net2number(buffer, mac_length);
  return print_mac0(kafka_line_buffer,buffer);
}

size_t print_direction_based_client_mac_vendor(
    struct printbuf *kafka_line_buffer, const void *buffer,
    const size_t real_field_len, struct flowCache *flowCache) {
  unused_params(buffer, real_field_len);

  const uint8_t *mac = get_direction_based_client_mac(flowCache);
  if(mac!=NULL)
    return print_mac_vendor0(kafka_line_buffer, mac);
  return 0;
}

/* try to print vendor:xx:xx:xx */
static size_t print_mac_vendor_addr_format0(struct printbuf *kafka_line_buffer,
    const void *vbuffer) {
  const uint8_t *buffer = vbuffer;
  assert_multi(kafka_line_buffer, buffer);
  const size_t vendor_bytes_written = print_mac_vendor0(kafka_line_buffer,buffer);
  if(vendor_bytes_written>0){
    int i;
    for(i=3;i<6;++i){
      printbuf_memappend_fast(kafka_line_buffer,":",1);
      printbuf_memappend_fast_n16(kafka_line_buffer,buffer[i]);
    }
    return vendor_bytes_written + strlen(":ff:ff:ff");
  }else{
    return 0;
  }
}

static size_t print_mac_map0(struct printbuf *kafka_line_buffer,const void *buffer){
  const uint64_t mac = get_mac(buffer);
  if(mac){
    pthread_rwlock_rdlock(&readOnlyGlobals.rb_databases.mutex);
    const char *char_map = find_mac_name(mac,&readOnlyGlobals.rb_databases.mac_name_database);
    pthread_rwlock_unlock(&readOnlyGlobals.rb_databases.mutex);
    if(char_map){
      printbuf_memappend_fast_string(kafka_line_buffer,char_map);
    }else{
      const size_t bytes_written = print_mac_vendor_addr_format0(kafka_line_buffer,buffer);
      if(bytes_written>0)
        return bytes_written;
    }
  }

  return print_mac0(kafka_line_buffer,buffer);
}

size_t print_mac_map(struct printbuf *kafka_line_buffer,
    const void *vbuffer, const size_t real_field_len,
    struct flowCache *flowCache) {
  const uint8_t *buffer = vbuffer;
  assert_multi(kafka_line_buffer, buffer);
  unused_params(flowCache);
  if (unlikely(real_field_len!=6)) {
    traceEvent(TRACE_ERROR,"Mac with real_field_len!=6");
    return 0;
  }

  return print_mac_map0(kafka_line_buffer, buffer);
}

size_t print_mac_vendor(struct printbuf *kafka_line_buffer,
    const void *vbuffer, const size_t real_field_len,
    struct flowCache *flowCache) {
  const uint8_t *buffer = vbuffer;
  assert_multi(kafka_line_buffer, buffer);
  unused_params(flowCache);
  if(real_field_len!=6){
    traceEvent(TRACE_ERROR,"Mac with real_field_len!=6");
    return 0;
  }

  return print_mac_vendor0(kafka_line_buffer, buffer);
}

static size_t print_engine_id(struct printbuf *kafka_line_buffer,
                              const uint8_t engine_id) {
  assert(kafka_line_buffer);

  if (engine_id == 0)
    return 0;

  return printbuf_memappend_fast_n10(kafka_line_buffer, engine_id);
}

static size_t print_engine_id_name0(struct printbuf *kafka_line_buffer,const uint8_t engine_id){
  assert(kafka_line_buffer);

  if(engine_id == 0)
    return 0;

  pthread_rwlock_rdlock(&readOnlyGlobals.rb_databases.mutex);
  // @TODO change it to an array!
  const NumNameAssoc * node =  numInList(engine_id,readOnlyGlobals.rb_databases.engines_name_as_list);
  const size_t ret = node ?
    printbuf_memappend_fast_string(kafka_line_buffer,node->name) :
    print_engine_id(kafka_line_buffer,engine_id);

  pthread_rwlock_unlock(&readOnlyGlobals.rb_databases.mutex);
  return ret;
}

size_t print_engine_id_name(struct printbuf *kafka_line_buffer,
    const void *vbuffer,const size_t real_field_len,
    struct flowCache *flowCache) {
  const uint8_t *buffer = vbuffer;
  assert_multi(kafka_line_buffer, buffer);
  unused_params(real_field_len, flowCache);


  const uint8_t engine_id = net2number(buffer, 1);
  return print_engine_id_name0(kafka_line_buffer,engine_id);
}

static size_t print_application_id0(struct printbuf *kafka_line_buffer,
    const void *vbuffer, const size_t real_field_len) {
  const uint8_t *buffer = vbuffer;
  assert_multi(kafka_line_buffer, buffer);
  if (unlikely(4 != real_field_len)) {
    traceEvent(TRACE_ERROR, "APP_ID length %zu != 4", real_field_len);
    return 0;
  }

  const uint8_t  major_proto = buffer[0];
  const uint32_t minor_proto = net2number(buffer,4) & 0x00FFFFFF;

  if(major_proto == 0 && minor_proto == 0)
    return 0;

  size_t bytes_printed = 0;
  bytes_printed += print_engine_id_name0(kafka_line_buffer,major_proto);
  printbuf_memappend_fast(kafka_line_buffer,":",1);
  bytes_printed += 1;
  bytes_printed += printbuf_memappend_fast_n10(kafka_line_buffer,minor_proto);
  return bytes_printed;
}

static size_t print_application_id_name0(struct printbuf *kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    observation_id_t *observation_id) {

  const uint64_t appid = net2number(buffer,real_field_len);

  if (appid == 0) {
    return 0;
  }

  /* Search in observation id */
  const char *appid_str = observation_id_application_name(observation_id,
    appid);

  if (!appid_str && readOnlyGlobals.rb_databases.apps_name_as_list) {
    // Search in default db
    appid_str = searchNameAssociatedInTree(
      readOnlyGlobals.rb_databases.apps_name_as_list, appid, NULL, 0);
  }

  if (appid_str) {
    return printbuf_memappend_fast_string(kafka_line_buffer,appid_str);
  } else {
    return print_application_id0(kafka_line_buffer,buffer,real_field_len);
  }
}

size_t print_application_id(struct printbuf *kafka_line_buffer,
    const void *vbuffer,const size_t real_field_len,
    struct flowCache *flowCache) {
  const char *buffer = vbuffer;
  assert_multi(kafka_line_buffer, buffer);
  unused_params(flowCache);
  return print_application_id0(kafka_line_buffer, buffer,
    real_field_len);
}

size_t print_application_id_name(struct printbuf *kafka_line_buffer,
    const void *vbuffer,const size_t real_field_len,
    struct flowCache *flowCache) {
  const char *buffer = vbuffer;
  assert_multi(kafka_line_buffer, buffer, flowCache);
  return print_application_id_name0(kafka_line_buffer,
    buffer, real_field_len, flowCache->observation_id);
}

static size_t print_port0(struct printbuf *kafka_line_buffer,const uint16_t port){
  return printbuf_memappend_fast_n10(kafka_line_buffer,port);
}

static size_t process_port0(uint16_t *save_port, const char *port_type,
    struct printbuf *kafka_line_buffer,
    const void *vbuffer, const size_t real_field_len,
    struct flowCache *flowCache) {
  const uint8_t *buffer = vbuffer;
  assert_multi(kafka_line_buffer, buffer, flowCache);

  if (unlikely(real_field_len != 2)) {
    traceEvent(TRACE_ERROR, "%s with len %zu != 2", port_type, real_field_len);
    return 0;
  }

  const uint16_t port = net2number(buffer, real_field_len);
  if (readOnlyGlobals.normalize_directions) {
    *save_port = port;
    return 0;
  } else {
    return print_port0(kafka_line_buffer, port);
  }
}

size_t process_src_port(struct printbuf *kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flowCache) {

  return process_port0(&flowCache->ports.src, "SRC PORT", kafka_line_buffer,
    buffer, real_field_len, flowCache);
}

size_t process_dst_port(struct printbuf *kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flowCache) {

  return process_port0(&flowCache->ports.dst, "DST PORT", kafka_line_buffer,
    buffer, real_field_len, flowCache);
}

static size_t print_flow_cache_number(struct printbuf *kafka_line_buffer,
    const struct flowCache *flow_cache,
    uint64_t (*get_number_cb)(const struct flowCache *)) {
  const uint64_t number = get_number_cb(flow_cache);
  return printbuf_memappend_fast_n10(kafka_line_buffer, number);
}

size_t print_lan_port(struct printbuf *kafka_line_buffer, const void *buffer,
                      const size_t real_field_len,
                      struct flowCache *flow_cache) {

  assert_multi(kafka_line_buffer, flow_cache);
  unused_params(buffer, real_field_len);

  return print_flow_cache_number(kafka_line_buffer, flow_cache,
    get_direction_based_client_port);
}

size_t print_wan_port(struct printbuf *kafka_line_buffer, const void *buffer,
                         const size_t real_field_len,
                         struct flowCache *flow_cache) {

  assert_multi(kafka_line_buffer, flow_cache);
  unused_params(buffer, real_field_len);

  return print_flow_cache_number(kafka_line_buffer, flow_cache,
    get_direction_based_target_port);
}

/** Print and store ipv6
 * @param  dst_buf           Destination buffer to save ipv6
 * @param  kafka_line_buffer buffer to print ipv6
 * @param  vbuffer           IPv6 Buffer
 * @param  real_field_len    IPv6 length in bytes
 * @param  flowCache         Flow cache
 * @return                   Bytes written in kafka_line_buffer
 */
static size_t print_ipv6(void *vdst_buf, struct printbuf *kafka_line_buffer,
      const void *vbuffer, const size_t real_field_len) {

  const uint8_t *buffer = vbuffer;
  uint8_t *dst_buf = vdst_buf;
  size_t i;
  assert_multi(kafka_line_buffer, buffer);

  if (unlikely(real_field_len != 16)) {
    traceEvent(TRACE_ERROR,"IPv6 field len is not 16");
    return 0;
  }

  if (dst_buf) {
    // @TODO memcpy(dst_buf, buffer);
    for (i = 0; i < 16; ++i) {
      dst_buf[i] = buffer[i];
    }
  }

  return print_ipv6_addr0(kafka_line_buffer, buffer);
}

size_t print_ipv6_src_addr(struct printbuf *kafka_line_buffer,
      const void *buffer, const size_t real_field_len,
      struct flowCache *flowCache) {
  assert_multi(flowCache);

  return print_ipv6(flowCache->address.src, kafka_line_buffer, buffer,
    real_field_len);
}

size_t print_ipv6_dst_addr(struct printbuf *kafka_line_buffer,
    const void *buffer,const size_t real_field_len,
    struct flowCache *flowCache) {
  assert_multi(flowCache);

  return print_ipv6(flowCache->address.dst, kafka_line_buffer, buffer,
    real_field_len);
}

#ifdef HAVE_GEOIP

size_t print_country_code(struct printbuf *kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flowCache) {

  assert(buffer);
  unused_params(flowCache);

  if (readOnlyGlobals.normalize_directions) {
    /* Nothing to do */
    return 0;
  }

  if (unlikely(real_field_len!=4)) {
    traceEvent(TRACE_ERROR,"IP length %zu != 4 bytes.", real_field_len);
    return 0;
  }

  const uint32_t ipv4 = net2number(buffer, 4);
  if (readOnlyGlobals.geo_ip_country_db) {
    pthread_rwlock_rdlock(&readWriteGlobals->geoipRwLock);
    const char *country = GeoIP_country_code_by_ipnum(
      readOnlyGlobals.geo_ip_country_db,ipv4);
    pthread_rwlock_unlock(&readWriteGlobals->geoipRwLock);
    if (country) {
      return append_escaped(kafka_line_buffer, country, strlen(country));
    }
  }

  return 0;
}

struct AS_info{
  const char *number;
  size_t number_len;
  const char *name;
};

static struct AS_info extract_as_from_geoip_response(char *rsp) {
  /* rsp = ASDDDDD SSSSSSS */
  char *aux = NULL;
  struct AS_info asinfo = {NULL,0,NULL};
  asinfo.number = strtok_r(rsp," ",&aux);
  if (asinfo.number) {
    asinfo.number+=2;
    asinfo.number_len = aux-rsp-3;
    asinfo.name = strtok_r(NULL,"",&aux);
  }

  return asinfo;
}

size_t print_AS_ipv4(struct printbuf *kafka_line_buffer,
    const void *vbuffer,const size_t real_field_len,
    struct flowCache *flowCache) {

  const uint8_t *buffer = vbuffer;
  assert(buffer);
  unused_params(flowCache);

  if (unlikely(4 != real_field_len)) {
    traceEvent(TRACE_ERROR, "IPv4 length %zu != 4", real_field_len);
    return 0;
  }

  const unsigned long ipv4 = net2number(buffer, 4);
  size_t written_len = 0;

  if(ipv4){
    char *rsp=NULL;
    pthread_rwlock_rdlock(&readWriteGlobals->geoipRwLock);
    if(readOnlyGlobals.geo_ip_asn_db)
      rsp = GeoIP_name_by_ipnum(readOnlyGlobals.geo_ip_asn_db, ipv4);
    pthread_rwlock_unlock(&readWriteGlobals->geoipRwLock);

    if(rsp){
      struct AS_info asinfo = extract_as_from_geoip_response(rsp);
      if(asinfo.number){
        printbuf_memappend_fast(kafka_line_buffer,asinfo.number,asinfo.number_len);
        written_len = asinfo.number_len;
      }
      free(rsp);
    }
  }

  return written_len;
}

static size_t print_buffer_geoip_AS_name(struct printbuf *kafka_line_buffer,char *rsp) {
  size_t written_len = 0;

  assert(rsp);

  char *toprint = strchr(rsp,' ');
  if(toprint && *(toprint+1)!='\0')
    written_len = append_escaped(kafka_line_buffer,toprint+1,strlen(toprint+1));
  free(rsp);

  return written_len;
}

static size_t print_AS_ipv4_name0(struct printbuf *kafka_line_buffer,
    const uint32_t ipv4){
  size_t written_len = 0;
  assert(kafka_line_buffer);

  char * rsp=NULL;
  if(readOnlyGlobals.geo_ip_asn_db){
    pthread_rwlock_rdlock(&readWriteGlobals->geoipRwLock);
    rsp = GeoIP_name_by_ipnum(readOnlyGlobals.geo_ip_asn_db, ipv4);
    pthread_rwlock_unlock(&readWriteGlobals->geoipRwLock);
  }

  if(rsp){
    written_len = print_buffer_geoip_AS_name(kafka_line_buffer,rsp);
  }

  return written_len;
}

size_t print_AS_ipv4_name(struct printbuf *kafka_line_buffer,
    const void *vbuffer,const size_t real_field_len,
    struct flowCache *flowCache) {
  const uint8_t *buffer = vbuffer;
  assert(buffer);
  (void)flowCache;

  if (readOnlyGlobals.normalize_directions) {
    /* Nothing to do */
    return 0;
  }

  if (likely(real_field_len==4)) {
    const uint32_t ipv4 = net2number(buffer, 4);
    return print_AS_ipv4_name0(kafka_line_buffer, ipv4);
  } else {
    traceEvent(TRACE_ERROR,"IPv4 with len %zu != 4.", real_field_len);
    return 0;
  }
}

#define IPV6_LEN 16
static struct in6_addr get_ipv6(const uint8_t *buffer){
  struct in6_addr ipv6;
  memcpy(&ipv6.s6_addr,buffer,IPV6_LEN);
  return ipv6;
}

static bool is_private_v4(const uint32_t ipv4) {
  return (ipv4 & 0xff000000) == 0x0a000000 || // 10.X.X.X/10
         (ipv4 & 0xfff00000) == 0xac100000 || // 172.16.X.X/12
         (ipv4 & 0xffff0000) == 0xc0a80000;   // 192.168.X.X/16
}

static bool is_private_v6(const struct in6_addr ipv6) {
  return (ipv6.s6_addr[0] & 0x30) == 0x20;
}

static uint32_t ipv6_to_v4(const struct in6_addr ipv6) {
  return net2number(&ipv6.s6_addr[12], 4);
}

static bool is_private(const struct in6_addr ipv6) {
  if (is_ipv4_mapped(&ipv6)) {
    const uint32_t ipv4 = ipv6_to_v4(ipv6);
    return is_private_v4(ipv4);
  }

  return is_private_v6(ipv6);
}

/// Decorate geoip call
static size_t geoip_decorator(struct printbuf *kafka_line_buffer,
    const struct in6_addr ipv6,
    size_t (*print_geoip_cb)(struct printbuf *kafka_line_buffer,
      const struct in6_addr ipv6)) {
  assert(kafka_line_buffer);

  if (is_private(ipv6)) {
    return 0;
  }

  pthread_rwlock_rdlock(&readWriteGlobals->geoipRwLock);
  const size_t written_len = print_geoip_cb(kafka_line_buffer, ipv6);
  pthread_rwlock_unlock(&readWriteGlobals->geoipRwLock);

  return written_len;
}

/**
 * Print ipv6 AS name with no locking or checking
 * @param  kafka_line_buffer Line buffer to print AS name
 * @param  ipv6              IPv6 to print
 * @return                   Bytes printed
 */
static size_t print_AS6_name_nl(struct printbuf *kafka_line_buffer,
    const struct in6_addr ipv6){
  if (!readOnlyGlobals.geo_ip_asn_db_v6) {
    return 0;
  }

  char *rsp=NULL;
  rsp = GeoIP_name_by_ipnum_v6(readOnlyGlobals.geo_ip_asn_db_v6, ipv6);
  if (!rsp) {
    return 0;
  }

  return print_buffer_geoip_AS_name(kafka_line_buffer, rsp);
}

size_t print_AS6_name(struct printbuf *kafka_line_buffer,
    const void *vbuffer, const size_t real_field_len,
    struct flowCache *flowCache) {
  const uint8_t *buffer = vbuffer;
  assert(buffer);
  (void)flowCache;

  if (unlikely(real_field_len!=16)) {
    traceEvent(TRACE_ERROR,"IPv6 length %zu != 16.", real_field_len);
    return 0;
  }

  const struct in6_addr ipv6 = get_ipv6(buffer);
  return geoip_decorator(kafka_line_buffer, ipv6, print_AS6_name_nl);
}

static size_t print_AS6_0(struct printbuf *kafka_line_buffer,const struct in6_addr *ipv6){
  assert(ipv6);

  char *rsp=NULL;
  size_t bytes_printed = 0;
  if(readOnlyGlobals.geo_ip_asn_db_v6){
    pthread_rwlock_rdlock(&readWriteGlobals->geoipRwLock);
    rsp = GeoIP_name_by_ipnum_v6(readOnlyGlobals.geo_ip_asn_db_v6, *ipv6);
    pthread_rwlock_unlock(&readWriteGlobals->geoipRwLock);
  }

  if(rsp){
    struct AS_info asinfo = extract_as_from_geoip_response(rsp);
    if(asinfo.number){
      printbuf_memappend_fast(kafka_line_buffer,asinfo.number,asinfo.number_len);
      bytes_printed = asinfo.number_len;
    }
    free(rsp);
  }

  return bytes_printed;
}

size_t print_AS6(struct printbuf *kafka_line_buffer,
    const void *vbuffer,const size_t real_field_len,
    struct flowCache *flowCache) {
  const uint8_t *buffer = vbuffer;
  (void)flowCache;

  if (unlikely(real_field_len!=16)) {
    traceEvent(TRACE_ERROR,"IPv6 length %zu != 16.", real_field_len);
    return 0;
  }

  const struct in6_addr ipv6 = get_ipv6(buffer);
  return print_AS6_0(kafka_line_buffer,&ipv6);
}

/**
 * Print ipv6 country code with no locking or checking
 * @param  kafka_line_buffer Line buffer to print country code
 * @param  ipv6              IPv6 to print
 * @return                   Bytes printed
 */
static size_t print_country6_code_nl(struct printbuf *kafka_line_buffer,
    const struct in6_addr ipv6) {
  if (!readOnlyGlobals.geo_ip_country_db_v6) {
    return 0;
  }

  const char *country = is_ipv4_mapped(&ipv6) ?
    GeoIP_country_code_by_ipnum(readOnlyGlobals.geo_ip_country_db,
      ipv6_to_v4(ipv6)) :
    GeoIP_country_code_by_ipnum_v6(readOnlyGlobals.geo_ip_country_db_v6, ipv6);
  if (!country) {
    return 0;
  }

  return append_escaped(kafka_line_buffer, country, strlen(country));
}

// Same function as print_country6_code0 but with an extra flowCache parameter
static size_t print_country6_code_fc(struct printbuf *kafka_line_buffer,
    const void *vipv6, struct flowCache *flow_cache) {
  (void)flow_cache;
  const struct in6_addr ipv6 = get_ipv6(vipv6);
  return geoip_decorator(kafka_line_buffer, ipv6, print_country6_code_nl);
}

size_t print_country6_code(struct printbuf *kafka_line_buffer,
    const void *vbuffer, const size_t real_field_len,
    struct flowCache *flowCache) {
  const uint8_t *buffer = vbuffer;
  assert_multi(kafka_line_buffer, buffer);
  (void)flowCache;

  if(unlikely(real_field_len!=16)){
    traceEvent(TRACE_ERROR,"IPv6 length != 16.");
    return 0;
  }

  const struct in6_addr ipv6 = get_ipv6(buffer);
  return geoip_decorator(kafka_line_buffer, ipv6, print_country6_code_nl);
}

size_t print_lan_country_code(struct printbuf *kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flow_cache) {
  unused_params(buffer, real_field_len);
  return print_flow_cache_address(kafka_line_buffer, flow_cache,
    get_direction_based_client_ip, print_country6_code_fc);
}

size_t print_wan_country_code(struct printbuf *kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flow_cache) {
  unused_params(buffer, real_field_len);
  return print_flow_cache_address(kafka_line_buffer, flow_cache,
    get_direction_based_target_ip, print_country6_code_fc);
}

/// Wrapper to call print_AS6_0 with a flow_cache
static size_t print_AS6_name_fc(struct printbuf *kafka_line_buffer,
    const void *vipv6, struct flowCache *flow_cache) {
  (void)flow_cache;
  struct in6_addr ipv6 = get_ipv6(vipv6);
  return geoip_decorator(kafka_line_buffer, ipv6, print_AS6_name_nl);
}

size_t print_lan_AS_name(struct printbuf *kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flow_cache) {
  unused_params(buffer, real_field_len);
  return print_flow_cache_address(kafka_line_buffer, flow_cache,
    get_direction_based_client_ip, print_AS6_name_fc);
}

size_t print_wan_AS_name(struct printbuf *kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flow_cache) {
  unused_params(buffer, real_field_len);
  return print_flow_cache_address(kafka_line_buffer, flow_cache,
    get_direction_based_target_ip, print_AS6_name_fc);
}

#endif /* HAVE_GEOIP */

size_t print_sensor_enrichment(struct printbuf *kafka_line_buffer,
    const struct flowCache *flowCache) {
  assert_multi(flowCache, flowCache->sensor);

  const char *enrichment = observation_id_enrichment(flowCache->observation_id);
  if (enrichment) {
    size_t added = 0;
    added += printbuf_memappend_fast_string(kafka_line_buffer,",");
    added += printbuf_memappend_fast_string(kafka_line_buffer,enrichment);
    return added;
  } else {
    return 0;
  }
}

static const uint8_t http_host_id[] = {0x03, 0x00, 0x00, 0x50, 0x34, 0x02};


/**
 * @param kafka_line_buffer          Buffer to print result
 * @param vbuffer                    Buffer with data
 * @param real_field_len             Length of attribute
 * @param flowCache                  Flow cache
 * @param expected_identifier        Expected CISCO identifier
 * @param expected_identifier_length Expected CISCO identifier length
 */
static size_t cisco_private_decorator(struct printbuf *kafka_line_buffer,
    const void *vbuffer, const size_t real_field_len,
    struct flowCache *flowCache,
    const void *expected_identifier, size_t expected_identifier_length,
    size_t (*cb)(struct printbuf *, const void *, size_t, struct flowCache *)) {
  const char *buffer = vbuffer;
  assert_multi(kafka_line_buffer, buffer);
  (void)flowCache;

  if(real_field_len <= expected_identifier_length) {
    return 0; /* nothing to do */
  }

  if (0!=memcmp(expected_identifier,buffer, expected_identifier_length)) {
    return 0;
  }

  const char *buffer_content = buffer + expected_identifier_length;
  const size_t buffer_len = real_field_len - expected_identifier_length;
  return cb(kafka_line_buffer, buffer_content, buffer_len, flowCache);
}

static size_t cisco_private_field_append(struct printbuf *kafka_line_buffer,
    const void *vbuffer, size_t vbuffer_size, struct flowCache *flow_cache) {
  (void)flow_cache;
  const char *buffer = vbuffer;
  return append_escaped(kafka_line_buffer, buffer, vbuffer_size);
}

static size_t print_cisco_private_buffer(struct printbuf *kafka_line_buffer,
    const void *vbuffer, const size_t real_field_len,
    struct flowCache *flowCache,
    const uint8_t *expected_identifier, size_t expected_identifier_length) {
  return cisco_private_decorator(kafka_line_buffer, vbuffer, real_field_len,
    flowCache, expected_identifier,
    expected_identifier_length, cisco_private_field_append);
}

size_t print_http_url(struct printbuf *kafka_line_buffer,
  const void *buffer, const size_t real_field_len,
  struct flowCache *flowCache) {

  static const uint8_t http_url_id[] = {0x03, 0x00, 0x00, 0x50, 0x34, 0x01};
  return print_cisco_private_buffer(kafka_line_buffer, buffer,
    real_field_len, flowCache, http_url_id, sizeof(http_url_id));
}

static void save_cisco_http_private_field(const void *buffer, size_t buffer_len,
    const char **str, size_t *len) {
  *str = buffer;
  *len = buffer_len;
}

static size_t save_cisco_http_host0(struct printbuf *kafka_line_buffer,
    const void *buffer, size_t buffer_size, struct flowCache *flow_cache) {
  (void)kafka_line_buffer;
  assert_multi(buffer, flow_cache);

  /// @todo use sized_buffer
  save_cisco_http_private_field(buffer, buffer_size, &flow_cache->http_host.str,
    &flow_cache->http_host.str_size);
  return 0;
}

static size_t save_cisco_http_referer0(struct printbuf *kafka_line_buffer,
    const void *buffer, size_t buffer_size, struct flowCache *flow_cache) {
    (void)kafka_line_buffer;
  assert_multi(buffer, flow_cache);

  /// @todo use sized_buffer
  save_cisco_http_private_field(buffer, buffer_size,
    &flow_cache->http_referer.str, &flow_cache->http_referer.str_size);
  return 0;
}

static size_t save_cisco_https_common_name0(struct printbuf *kafka_line_buffer,
    const void *buffer, size_t buffer_size, struct flowCache *flow_cache) {
    (void)kafka_line_buffer;
  assert_multi(buffer, flow_cache);

  /// @todo use sized_buffer
  save_cisco_http_private_field(buffer, buffer_size,
    &flow_cache->ssl_common_name.str, &flow_cache->ssl_common_name.str_size);
  return 0;
}

size_t print_http_host(struct printbuf *kafka_line_buffer,
  const void *buffer, const size_t real_field_len,
  struct flowCache *flowCache) {

  cisco_private_decorator(kafka_line_buffer, buffer, real_field_len,
    flowCache, http_host_id, sizeof(http_host_id),
    save_cisco_http_host0);

  return print_cisco_private_buffer(kafka_line_buffer, buffer, real_field_len,
    flowCache, http_host_id, sizeof(http_host_id));
}

static bool buffer_is_ip(const char *buf, size_t bufsiz) {
  static const char *long_ipv6_example =
    "0000:0000:0000:0000:0000:0000:0000:0000";
  if (bufsiz > strlen(long_ipv6_example)) {
    return false;
  }

  char tmp_buf[bufsiz + 1];
  memcpy(tmp_buf, buf, bufsiz);
  tmp_buf[bufsiz] = 0;

  struct sockaddr_in6 sa;
  return 1 == inet_pton(AF_INET,  tmp_buf, &(sa.sin6_addr))
      || 1 == inet_pton(AF_INET6, tmp_buf, &(sa.sin6_addr));
}

/**
 * Search for first instance of a character that is not needle in the haystack.
 * Return last character (i.e, haystack+length) if not found.
 */
static const char *memcchrnul(const void *vhaystack, int needle,
    size_t length) {
  const char *haystack = vhaystack;
  const char *i = haystack;
  for (i = haystack; i < haystack + length && i[0] == needle; ++i);
  return i;
}

static size_t print_http_l2_domain(struct printbuf *kafka_line_buffer,
    const char *hostname, size_t hostname_size) {
  const char *l2_host = hostname;

  // avoid http{,s}: protocol
  static const char *skip_headers[] = {"http://", "https://"};
  size_t i;
  for (i=0; i<RD_ARRAYSIZE(skip_headers); ++i) {
    const size_t header_len = strlen(skip_headers[i]);
    if (hostname_size>=header_len &&
        0 == strncmp(skip_headers[i], hostname, header_len)) {
      const char *no_proto_domain = hostname + header_len;
      size_t no_proto_domain_len = hostname_size - header_len;
      return print_http_l2_domain(kafka_line_buffer, no_proto_domain,
        no_proto_domain_len);
    }
  }

  // avoid url on referer, now that we know we do not have https: prefix
  const char *slash = memchr(hostname, '/', hostname_size);
  if (slash) {
    size_t no_url_size = slash - hostname;
    return print_http_l2_domain(kafka_line_buffer, hostname, no_url_size);
  }

  if (buffer_is_ip(hostname, hostname_size)) {
    // Nothing more to do!
    return append_escaped(kafka_line_buffer, hostname, hostname_size);
  }

  // Now we have a clean hostname!
  const char *l1_dot = memrchr(hostname, '.', hostname_size);
  if (l1_dot) {
    const char *l2_dot = memrchr(hostname, '.',
      l1_dot - (const char *)hostname);
    if (l2_dot) {
      l2_host = l2_dot;
    }
  }

  // seek first dot(s)
  l2_host = memcchrnul(l2_host, '.',
    hostname_size - (l2_host - (const char *)hostname));

  const size_t l2_host_len = hostname_size - (l2_host - (const char *)hostname);
  return append_escaped(kafka_line_buffer, l2_host, l2_host_len);
}

static size_t print_http_host_l2_0(struct printbuf *kafka_line_buffer,
    const void *host, size_t host_size, struct flowCache *flow_cache) {
  (void)flow_cache;
  return print_http_l2_domain(kafka_line_buffer, host, host_size);
}

size_t print_http_host_l2(struct printbuf *kafka_line_buffer,
                          const void *vbuffer, const size_t real_field_len,
                          struct flowCache *flowCache) {

    return cisco_private_decorator(kafka_line_buffer, vbuffer, real_field_len,
    flowCache, http_host_id, sizeof(http_host_id), print_http_host_l2_0);

}

static void extract_flowcache_host(const struct flowCache *flow_cache,
    const char **host, size_t *host_len) {
  if (flow_cache->http_host.str) {
    *host     = flow_cache->http_host.str;
    *host_len = flow_cache->http_host.str_size;
  } else {
    *host     = flow_cache->ssl_common_name.str;
    *host_len = flow_cache->ssl_common_name.str_size;
  }
}

static void extract_flowcache_referer(const struct flowCache *flow_cache,
    const char **referer, size_t *referer_len) {
  if (flow_cache->http_referer.str) {
    *referer = flow_cache->http_referer.str;
    *referer_len = flow_cache->http_referer.str_size;
  } else {
    extract_flowcache_host(flow_cache, referer, referer_len);
  }
}

size_t print_host(struct printbuf *kafka_line_buffer,
                          const void *vbuffer, const size_t real_field_len,
                          struct flowCache *flow_cache) {
  const char *to_print = NULL;
  size_t to_print_size = 0;
  unused_params(vbuffer, real_field_len);

  extract_flowcache_host(flow_cache, &to_print, &to_print_size);
  return append_escaped(kafka_line_buffer, to_print, to_print_size);
}

size_t print_referer(struct printbuf *kafka_line_buffer,
                          const void *vbuffer, const size_t real_field_len,
                          struct flowCache *flow_cache) {
  return flow_cache->http_referer.str ?
    append_escaped(kafka_line_buffer, flow_cache->http_referer.str,
      flow_cache->http_referer.str_size) :
    print_host(kafka_line_buffer, vbuffer, real_field_len, flow_cache);
}

size_t print_host_l2(struct printbuf *kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flow_cache) {
  const char *host = NULL;
  size_t host_size = 0;
  unused_params(buffer, real_field_len);
  extract_flowcache_host(flow_cache, &host, &host_size);
  return print_http_l2_domain(kafka_line_buffer, host, host_size);
}

size_t print_referer_l2(struct printbuf *kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flow_cache) {
  const char *referer = NULL;
  size_t referer_size = 0;
  unused_params(buffer, real_field_len);
  extract_flowcache_referer(flow_cache, &referer, &referer_size);
  return print_http_l2_domain(kafka_line_buffer, referer, referer_size);
}

size_t print_http_user_agent(struct printbuf *kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flowCache) {

  static const uint8_t http_ua_id[] = {0x03, 0x00, 0x00, 0x50, 0x34, 0x03};
  return print_cisco_private_buffer(kafka_line_buffer, buffer, real_field_len,
    flowCache, http_ua_id, sizeof(http_ua_id));
}

size_t print_http_referer(struct printbuf *kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flowCache) {

  static const uint8_t http_referer_id[] = {0x03, 0x00, 0x00, 0x50, 0x34, 0x04};

  cisco_private_decorator(kafka_line_buffer, buffer, real_field_len,
    flowCache, http_referer_id, sizeof(http_referer_id),
    save_cisco_http_referer0);

  return print_cisco_private_buffer(kafka_line_buffer, buffer, real_field_len,
    flowCache, http_referer_id, sizeof(http_referer_id));
}

size_t print_https_common_name(struct printbuf *kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flowCache) {

  static const uint8_t https_common_name_nbar_id[] = {0x0d, 0x00, 0x01, 0xc5,
    0x34, 0x01};

  cisco_private_decorator(kafka_line_buffer, buffer, real_field_len,
    flowCache, https_common_name_nbar_id, sizeof(https_common_name_nbar_id),
    save_cisco_https_common_name0);

  return print_cisco_private_buffer(kafka_line_buffer, buffer,real_field_len,
    flowCache, https_common_name_nbar_id, sizeof(https_common_name_nbar_id));
}

#ifdef HAVE_UDNS

static size_t print_dns_obtained_hostname(struct printbuf *kafka_line_buffer,
  const char *string) {

  return string ? printbuf_memappend_fast_string(kafka_line_buffer,string) : 0;
}

static const char *get_direction_based_client_hostname(struct flowCache *flowCache) {
  return flowCache->address.client_name ? flowCache->address.client_name :
    flowCache->address.client_name_cache ? flowCache->address.client_name_cache->name : NULL;
}

static const char *get_direction_based_target_hostname(struct flowCache *flowCache) {
  return flowCache->address.target_name ? flowCache->address.target_name :
    flowCache->address.target_name_cache ? flowCache->address.target_name_cache->name : NULL;
}

static const uint8_t *get_src_ip(const struct flowCache *flowCache) {
  return (const uint8_t *)flowCache->address.src;
}

static const uint8_t *get_dst_ip(const struct flowCache *flowCache) {
  return (const uint8_t *)flowCache->address.dst;
}

const uint8_t *get_direction_based_client_ip(
    const struct flowCache *flow_cache) {
  assert(flow_cache);

  const uint8_t *src_ip = get_src_ip(flow_cache);
  const uint8_t *dst_ip = get_dst_ip(flow_cache);

  if (!empty_ipv6_addr(flow_cache->address.client)) {
    return flow_cache->address.client;
  }

  return GET_CLIENT_ENDPOINT(flow_cache->macs.direction, src_ip, dst_ip);
}

const uint8_t *get_direction_based_target_ip(
    const struct flowCache *flowCache) {
  const uint8_t *src_ip = get_src_ip(flowCache);
  const uint8_t *dst_ip = get_dst_ip(flowCache);

  const uint8_t *client_hostname = get_direction_based_client_ip(flowCache);
  return (client_hostname == src_ip) ?
    dst_ip : src_ip;
}

/// @TODO difference client/target src/dst
size_t print_client_name(struct printbuf *kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flowCache) {
  unused_params(buffer, real_field_len);

  return print_dns_obtained_hostname(kafka_line_buffer,
    get_direction_based_client_hostname(flowCache));
}

size_t print_target_name(struct printbuf *kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flowCache) {
  unused_params(buffer, real_field_len);

  return print_dns_obtained_hostname(kafka_line_buffer,
    get_direction_based_target_hostname(flowCache));
}

#endif /* HAVE_UDNS */

size_t printNetflowRecordWithTemplate(struct printbuf *kafka_line_buffer,
    const V9V10TemplateElementId *templateElement,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flowCache) {
  const int start_bpos = kafka_line_buffer->bpos;
  int value_ret=0;
  if(0!=strcmp(kafka_line_buffer->buf,"{")){
    printbuf_memappend_fast(kafka_line_buffer,",",strlen(","));
  }
  printbuf_memappend_fast(kafka_line_buffer,"\"",strlen("\""));
  printbuf_memappend_fast(kafka_line_buffer,templateElement->jsonElementName,
    strlen(templateElement->jsonElementName));
  printbuf_memappend_fast(kafka_line_buffer,"\":",strlen("\":"));

  if (templateElement->quote) {
    printbuf_memappend_fast(kafka_line_buffer,"\"",strlen("\""));
  }

  if (NULL!=templateElement->export_fn) {
#if WITH_PRINT_BOUND_CHECKS
    // Valgrind can watch for out of bounds reads in the heap
    const size_t copy_size = real_field_len
    uint8_t *buffer_heap_copy = malloc(copy_size);
    memcpy(buffer_heap_copy, buffer, copy_size);
#endif

    value_ret = templateElement->export_fn(kafka_line_buffer, buffer,
      real_field_len, flowCache);

#if WITH_PRINT_BOUND_CHECKS
    free(buffer_heap_copy);
#endif
  }


  /// @TODO send all this to template system
#if 0 /* SOCIAL_MEDIA */
    if(NULL==templateElement->export_fn) switch(templateElement->templateElementId)
    {
      case CISCO_HTTP_USER_AGENT_OS:
      {
        rb_keyval_list_t * iter;
        for(iter=readOnlyGlobals.rb_databases.os_name_as_list;value_ret==0 && iter;iter=iter->next)
        {
          if(strcasestr(buf,iter->val))
            value_ret = sprintbuf(kafka_line_buffer, "%s", iter->key);
        }
      }
      break;
      case CISCO_HTTP_SOCIAL_USER_FB:
        if(unlikely(strstr(buf,"akamaihd.net") || strstr(buf,"ak.fbcdn.net"))){
          size_t phid_len;
          const char * phid = extract_fb_photo_id(url,strlen(url),
                                                 buf,
                                                 &phid_len);
          if(phid)
          {
            value_ret = sprintbuf(kafka_line_buffer,"http://www.facebook.com/profile.php?id=");
            printbuf_memappend_fast(kafka_line_buffer,phid,phid_len-1);
            value_ret += phid_len - 1;
            social_user_printed = 1;
          }else
            return(0);
        }
        break;
      case CISCO_HTTP_SOCIAL_MEDIA_TT:
        if(unlikely(strstr(buf,"twitter.com") &&
                         strstr(url,"status")))
        {
          value_ret = sprintbuf(kafka_line_buffer,"%s%s",buf,url);
        }
        break;
      case CISCO_HTTP_SOCIAL_USER_TT:
        {
          // Format: *twitter.com/USER/status/###
          char * twitter_com_string = strstr(buf,"twitter.com");
          char * status_string      = strstr(url,"status");
          if(unlikely(twitter_com_string && status_string))
          {
            value_ret = sprintbuf(kafka_line_buffer,twitter_com_string + strlen("twitter.com"),status_string - twitter_com_string);
          }

          /* Format: *api.twitter.com*?screen_name=USER* */
          if(real_field_len>6)
          {
            const struct counted_string host = {buffer+real_field_len_offset+6,real_field_len-6};
            const struct counted_string counted_url  = {url,strlen(url)};

            const struct counted_string tw_user = extract_tw_user(&counted_url,&host);
            if(tw_user.string)
            {
              const size_t initial_size = kafka_line_buffer->bpos;
              printbuf_memappend_fast(kafka_line_buffer,"https://twitter.com/",strlen("https://twitter.com/"));
              printbuf_memappend_fast(kafka_line_buffer,tw_user.string,tw_user.len);
              value_ret = kafka_line_buffer->bpos - initial_size;
              //sprintf(kafka_line_buffer,tw_user.len+1,"%s",tw_user.string);
            }
          }
        }
        if(unlikely(strstr(buf,"twitter.com") && strstr(url,"status")))
        {
          value_ret = print_twitter_user(kafka_line_buffer,buf);
        }
        break;

      case CISCO_HTTP_SOCIAL_USER_YT:
        {
          /* Format: gdata.youtube.com/feeds/api/users/USERNAME */
          if(real_field_len > 6)
          {
            const struct counted_string host = {buffer+real_field_len_offset+6,real_field_len-6};
            const struct counted_string counted_url  = {url,strlen(url)};

            const struct counted_string yt_user = extract_yt_user(&host,&counted_url);
            if(yt_user.len > 0 && yt_user.string)
            {
              const size_t initial_size = kafka_line_buffer->bpos;
              printbuf_memappend_fast(kafka_line_buffer,"https://www.youtube.com/user/",strlen("https://www.youtube.com/user/"));
              printbuf_memappend_fast(kafka_line_buffer,yt_user.string,yt_user.len);
              value_ret = kafka_line_buffer->bpos - initial_size;
            }
          }
        }
        break;

      case CISCO_HTTP_SOCIAL_USER_DROPBOX:
      {
        if(real_field_len>6)
        {
          const struct counted_string host = {buffer+real_field_len_offset+6,real_field_len-6};
          const struct counted_string counted_url  = {url,strlen(url)};

          const struct counted_string dropbox_user = extract_dropbox_user(&host,&counted_url);
          if(dropbox_user.len > 0 && dropbox_user.string)
          {
            const size_t initial_size = kafka_line_buffer->bpos;
            printbuf_memappend_fast(kafka_line_buffer,"Dropbox id: ",strlen("Dropbox id:"));
            printbuf_memappend_fast(kafka_line_buffer,dropbox_user.string,dropbox_user.len);
            value_ret = kafka_line_buffer->bpos - initial_size;
          }
        }
      }
      case CISCO_HTTP_SOCIAL_USER_YT_REFERER:
        {
          /* Format: gdata.youtube.com/feeds/api/users/USERNAME */
          if(real_field_len > 6)
          {
            const struct counted_string referer = {buffer+real_field_len_offset+6,real_field_len-6};

            const struct counted_string yt_user = extract_yt_user_referer(&referer);
            if(yt_user.len > 0 && yt_user.string)
            {
              const size_t initial_size = kafka_line_buffer->bpos;
              printbuf_memappend_fast(kafka_line_buffer,"https://www.youtube.com/user/",strlen("https://www.youtube.com/user/"));
              printbuf_memappend_fast(kafka_line_buffer,yt_user.string,yt_user.len);
              value_ret = kafka_line_buffer->bpos - initial_size;
            }
          }
        }
        break;
      case CISCO_HTTP_SOCIAL_MEDIA_IG:
        if(unlikely(NULL!=strstr(buf,"instagram")) && strstr(buf,"distilleryimage"))
        {
          value_ret = sprintbuf(kafka_line_buffer,"%s%s",buf,url);
        }
        break;
      case CISCO_HTTP_SOCIAL_MEDIA_YT:
        if(unlikely(NULL!=strstr(buf,"youtube") && (NULL!=strstr(url,"watch") || NULL!=strstr(url,"embed"))))
        {
          value_ret = sprintbuf(kafka_line_buffer,"%s%s",buf,url);
        }
        break;
      default:
        if (unlikely(!templateElement->export_fn &&
                                        !templateElement->postTemplate &&
                                        readOnlyGlobals.enable_debug)) {
          traceEvent(TRACE_ERROR, "Unknown template id %s(%d).\n",
            templateElement->jsonElementName,
            templateElement->templateElementId);
        }
        break;
    };
#endif

  if(value_ret > 0) /* Some added */ {
    if(templateElement->quote) {
      value_ret+=2;
      printbuf_memappend_fast(kafka_line_buffer,"\"",strlen("\""));
    }
  } else /*if(value_ret == 0)*/ {
    kafka_line_buffer->bpos = start_bpos;
    kafka_line_buffer->buf[kafka_line_buffer->bpos] = '\0';
  }

  int i;
  for(i=0; templateElement->postTemplate != NULL
                          && templateElement->postTemplate[i] != NULL; ++i) {
        printNetflowRecordWithTemplate(kafka_line_buffer,
          templateElement->postTemplate[i], buffer, real_field_len, flowCache);
  }
  return value_ret;
}

/** Separate kafka flow message in many flows, one per minute, and distributing
  the packets and octets proportionally.
 * @param  kafka_line_buffer Current string with parameters that all flows share
 * @param  first_timestamp   First timestamp of the flow
 * @param  dSwitched         Delta time of flow.
 * @param  dInterval         Maximum intervals allowed.
 * @param  max_intervals     Maximum number of intervals to split
 * @param  bytes             Total bytes
 * @param  pkts              Total packets
 * @return                   String list with all time separated flows
 * @todo This should be in collect.c
 */
struct string_list *rb_separate_long_time_flow(
  struct printbuf *kafka_line_buffer,
  uint64_t first_timestamp, uint64_t dSwitched, const uint64_t dInterval,
  const uint64_t max_intervals, uint64_t bytes, uint64_t pkts) {

  struct string_list *kafka_buffers_list = NULL;
  assert(kafka_line_buffer);

  unsigned n_intervals_except_first = dSwitched/dInterval;
  if(n_intervals_except_first>max_intervals){
    if(unlikely(readOnlyGlobals.enable_debug))
      traceEvent(TRACE_WARNING,
        "Too many intervals to divide (%u, max: %"PRIu64"). nIntervals set to "
        "%lu",
        n_intervals_except_first, max_intervals, max_intervals-1);
    n_intervals_except_first=max_intervals-1;
  }

  /* Avoiding flows with 0 pkts/bytes */
  if(dSwitched > 0 && dSwitched % dInterval == 0)
    dSwitched--;
  const time_t first_interval_duration  = dSwitched%dInterval;
  const double first_interval_duration_percent  = dSwitched == 0 ? 1 : (double)first_interval_duration/dSwitched;

  const uint64_t first_interval_bytes  = bytes * first_interval_duration_percent;
  const uint64_t first_interval_pkts   = pkts  * first_interval_duration_percent;

  const uint64_t packets_per_interval    = n_intervals_except_first > 0 ? (pkts - first_interval_pkts)/n_intervals_except_first : 0;
  const uint64_t bytes_per_interval      = n_intervals_except_first > 0 ? (bytes - first_interval_bytes)/n_intervals_except_first : 0;
  const uint64_t packets_per_interval_sw = htonll(packets_per_interval);
  const uint64_t bytes_per_interval_sw   = htonll(bytes_per_interval);

  const uint64_t remainder_packets = pkts - first_interval_pkts - packets_per_interval*n_intervals_except_first;
  const uint64_t remainder_bytes   = bytes - first_interval_bytes - bytes_per_interval*n_intervals_except_first;

  const uint64_t first_interval_pkts_sw  = htonll(first_interval_pkts + remainder_packets);
  const uint64_t first_interval_bytes_sw = htonll(first_interval_bytes + remainder_bytes);

  uint64_t current_timestamp_s  = first_timestamp;

  const char *last_sentmsg = NULL;
  size_t last_sentmsg_useful_bpos = 0; /* bpos of last_sentmsg before timestamp -> useful*/

  while(current_timestamp_s <= first_timestamp + dSwitched){
    struct string_list *node = calloc(1,sizeof(struct string_list));
    if (unlikely(NULL==node)) {
      traceEvent(TRACE_ERROR,"Memory error");
      return kafka_buffers_list;
    }

    node->next = kafka_buffers_list?kafka_buffers_list:NULL;
    kafka_buffers_list = node;
    if(current_timestamp_s + dInterval > first_timestamp + dSwitched){
      /* Last interval -> We use the buffer passed and remainder byes */
      node->string = kafka_line_buffer;
      printNetflowRecordWithTemplate(node->string, TEMPLATE_OF(PRINT_IN_BYTES),
        (const char *)&first_interval_bytes_sw,
        sizeof(first_interval_bytes_sw), NULL);
      printNetflowRecordWithTemplate(node->string, TEMPLATE_OF(PRINT_IN_PKTS),
        (const char *)&first_interval_pkts_sw,
        sizeof(first_interval_pkts_sw), NULL);
    }else{
      /* Not last interval -> we need to clone the buffer */
      node->string = printbuf_new();
      if (unlikely(NULL == node->string)) {
        /* Can't allocate string: Return, at least, previous list */
        kafka_buffers_list = node->next;
        free(node);
        return kafka_buffers_list;
      }

      if(NULL==last_sentmsg){
        /* No cached message to copy from -> need to generate the first */
        printbuf_memappend(node->string,kafka_line_buffer->buf,kafka_line_buffer->bpos);
        printNetflowRecordWithTemplate(node->string, TEMPLATE_OF(PRINT_IN_BYTES),
          (const char *)&bytes_per_interval_sw,
          sizeof(bytes_per_interval_sw), NULL);
        printNetflowRecordWithTemplate(node->string, TEMPLATE_OF(PRINT_IN_PKTS),
          (const char *)&packets_per_interval_sw,
          sizeof(packets_per_interval_sw), NULL);
        last_sentmsg = node->string->buf;
        last_sentmsg_useful_bpos = node->string->bpos;
      }else{
        /* Cached message: We could use it to waste less CPU */
        printbuf_memappend(node->string,last_sentmsg,last_sentmsg_useful_bpos);
      }
    }

    const uint64_t interval_timestamp_sw = htonll(current_timestamp_s);
    printNetflowRecordWithTemplate(node->string, TEMPLATE_OF(PRINT_LAST_SWITCHED),
      (const char *)&interval_timestamp_sw, sizeof(interval_timestamp_sw),
      NULL);

    current_timestamp_s += dInterval;

    printbuf_memappend_fast(node->string,"}",strlen("}"));
  }/* foreach interval in nIntervals */

  return kafka_buffers_list;
}

static size_t print_observation_id_attribute(struct printbuf *kafka_line_buffer,
    const void *vbuffer, const size_t real_field_len,
    struct flowCache *flowCache,
    const char *(*observation_id_get_attribute_cb)(observation_id_t *,
      uint64_t attribute_id)) {
  const uint8_t *buffer = vbuffer;
  assert_multi(kafka_line_buffer, buffer, flowCache);
  unused_params(buffer, real_field_len);

  const uint64_t attribute_id = net2number(buffer, real_field_len);

  const char *attribute_str = observation_id_get_attribute_cb(
    flowCache->observation_id, attribute_id);

  if (attribute_str) {
    return printbuf_memappend_fast_string(kafka_line_buffer, attribute_str);
  } else {
    return printbuf_memappend_fast_n10(kafka_line_buffer, attribute_id);
  }
}

size_t print_selector_name(struct printbuf *kafka_line_buffer,
    const void *vbuffer, const size_t real_field_len,
    struct flowCache *flowCache) {
  return print_observation_id_attribute(kafka_line_buffer, vbuffer, real_field_len,
    flowCache, observation_id_selector_name);
}

static size_t process_snmp_interface(uint64_t *save,
    struct printbuf *kafka_line_buffer, const void *buffer,
    const size_t real_field_len, struct flowCache *flowCache) {
  if (readOnlyGlobals.normalize_directions) {
    *save = net2number(buffer, real_field_len);
    return 0;
  } else {
    return print_number(kafka_line_buffer, buffer, real_field_len, flowCache);
  }
}

static uint64_t get_direction_based_client_interface(
    const struct flowCache *flow_cache) {

  return GET_CLIENT_ENDPOINT(flow_cache->macs.direction,
    flow_cache->interfaces.input, flow_cache->interfaces.output);
}

static uint64_t get_direction_based_target_interface(
    const struct flowCache *flow_cache) {
  uint64_t client_interface = get_direction_based_client_interface(flow_cache);
  return (client_interface == flow_cache->interfaces.input)
    ? flow_cache->interfaces.output : flow_cache->interfaces.input;
}

size_t print_lan_interface(struct printbuf *kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flow_cache) {
  unused_params(buffer, real_field_len);

  return print_flow_cache_number(kafka_line_buffer, flow_cache,
    get_direction_based_client_interface);
}

size_t print_wan_interface(struct printbuf *kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flow_cache) {
  unused_params(buffer, real_field_len);

  return print_flow_cache_number(kafka_line_buffer, flow_cache,
    get_direction_based_target_interface);
}

size_t process_input_snmp(struct printbuf *kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flow_cache) {
  return process_snmp_interface(&flow_cache->interfaces.input,
    kafka_line_buffer, buffer, real_field_len, flow_cache);
}

size_t process_output_snmp(struct printbuf *kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flow_cache) {
  return process_snmp_interface(&flow_cache->interfaces.output,
    kafka_line_buffer, buffer, real_field_len, flow_cache);
}

// Do not check if we are normalizing directions
static size_t print_interface_name0(struct printbuf *kafka_line_buffer,
    const void *vbuffer, const size_t real_field_len,
    struct flowCache *flowCache) {
  return print_observation_id_attribute(kafka_line_buffer, vbuffer,
    real_field_len, flowCache, observation_id_interface_name);
}

size_t print_interface_name(struct printbuf *kafka_line_buffer,
    const void *vbuffer, const size_t real_field_len,
    struct flowCache *flowCache) {
  return !readOnlyGlobals.normalize_directions ?
    print_interface_name0(kafka_line_buffer, vbuffer, real_field_len,
      flowCache) : 0;
}

size_t print_interface_description(struct printbuf *kafka_line_buffer,
    const void *vbuffer, const size_t real_field_len,
    struct flowCache *flowCache) {
  return !readOnlyGlobals.normalize_directions ?
    print_observation_id_attribute(kafka_line_buffer, vbuffer, real_field_len,
      flowCache, observation_id_interface_description) : 0;
}

static size_t print_flow_cache_interface_str(struct printbuf *kafka_line_buffer,
    const struct flowCache *flow_cache,
    uint64_t (*get_number_cb)(const struct flowCache *),
    const char * (*interface_str_cb)(observation_id_t *,uint64_t)) {
  const uint64_t number = get_number_cb(flow_cache);
  observation_id_t *observation_domain_id = flow_cache->observation_id;
  const char *str = interface_str_cb(observation_domain_id, number);
  return str ? printbuf_memappend_fast_string(kafka_line_buffer, str) :
    printbuf_memappend_fast_n10(kafka_line_buffer, number);
}

size_t print_lan_interface_name(struct printbuf *kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flow_cache) {
  unused_params(buffer, real_field_len);
  return print_flow_cache_interface_str(kafka_line_buffer, flow_cache,
    get_direction_based_client_interface, observation_id_interface_name);

}
size_t print_wan_interface_name(struct printbuf *kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flow_cache) {
  unused_params(buffer, real_field_len);
  return print_flow_cache_interface_str(kafka_line_buffer, flow_cache,
    get_direction_based_target_interface, observation_id_interface_name);
}

size_t print_lan_interface_description(struct printbuf *kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flow_cache) {
  unused_params(buffer, real_field_len);
  return print_flow_cache_interface_str(kafka_line_buffer, flow_cache,
    get_direction_based_client_interface, observation_id_interface_description);

}

size_t print_wan_interface_description(struct printbuf *kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flow_cache) {
  unused_params(buffer, real_field_len);
  return print_flow_cache_interface_str(kafka_line_buffer, flow_cache,
    get_direction_based_target_interface, observation_id_interface_description);
}
