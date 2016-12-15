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

#pragma once

/* ********************** */

#define CONST_INVALIDNETMASK               -1

/* ********************************************** */

#ifdef linux
#include <sys/time.h>
#endif
#include <endian.h>

#include <librdkafka/rdkafka.h>

#include "librd/rdmem.h"
#include "librd/rdqueue.h"

#include "NumNameAssocTree.h"

#ifdef likely
#undef likely
#endif

#ifdef unlikely
#undef unlikely
#endif

#define likely(x)       __builtin_expect(!!(x),1)
#define unlikely(x)     __builtin_expect(!!(x),0)

#ifdef HAVE_ATOMICS_32_ATOMIC
// Atomic test & set
#define ATOMIC_TEST_AND_SET(PTR) __atomic_test_and_set(PTR, __ATOMIC_SEQ_CST)
#else /* HAVE_ATOMICS_32_SYNC */
#define ATOMIC_TEST_AND_SET(PTR) __sync_val_compare_and_swap(PTR, false, true)
#endif

/* ********* Packets queue ************ */
typedef struct queued_packet_s {
  uint32_t netflow_device_ip;
  uint8_t *buffer;
  ssize_t buffer_len;
  struct sensor *sensor;
  rd_kafka_message_t *original_message;
} QueuedPacket;

static inline QueuedPacket *newQueuedPacket(size_t allocated_buffer_len) {
  QueuedPacket *qpacket = calloc(1,sizeof(*qpacket) + allocated_buffer_len);

  if(qpacket)
    qpacket->buffer = (uint8_t*)&qpacket[1];
  // fprintf(stderr,"Freeing packet %p\n",packet);
  return qpacket;
}

static inline void freeQueuedPacket(QueuedPacket *packet){
  // fprintf(stderr,"Freeing packet %p\n",packet);
  if (packet->original_message) {
    rd_kafka_message_destroy(packet->original_message);
  }
  free(packet);
}

static inline void addPacketToQueue(QueuedPacket *packet,rd_fifoq_t *queue){
//  fprintf(stderr,"Push packet %p\n",packet);
  rd_fifoq_add(queue,packet);
}

static inline QueuedPacket *popPacketFromQueue_timedwait(rd_fifoq_t *queue,time_t timeout_ms){
  rd_fifoq_elm_t *fifoq_elm = rd_fifoq_pop_timedwait(queue,timeout_ms);
  if(fifoq_elm){
    QueuedPacket *packet = fifoq_elm->rfqe_ptr;
    rd_fifoq_elm_release(queue,fifoq_elm);
    // fprintf(stderr,"Pop packet %p\n",packet);
    return packet;
  }
  return NULL;
}

#define PCAP_LONG_SNAPLEN        1600
#define PCAP_DEFAULT_SNAPLEN      128

/* ********************************** */

typedef struct ipAddress {
  uint8_t ipVersion:3 /* Either 4 or 6 */,
    localHost:1, /* -L: filled up during export not before (see exportBucket()) */
    notUsed:4 /* Future use */;

  union {
    struct in6_addr ipv6;
    uint32_t ipv4; /* Host byte code */
  } ipType;
} IpAddress;

const char* _intoa(IpAddress addr, char* buf, size_t bufLen);
char* _intoaV4(unsigned int addr, char* buf, size_t bufLen);

/* Update LogEventSeverity2Str in util.c when changing the structure below */
typedef enum {
  severity_error = 0,
  severity_warning,
  severity_info
} LogEventSeverity;

/* Update LogEventType2Str in util.c when changing the structure below */
typedef enum {
  probe_started = 0,
  probe_stopped,
  packet_drop,
  flow_export_error,
  collector_connection_error,
  collector_connected,
  collector_disconnected,
  collector_too_slow
} LogEventType;

#define TRACE_ERROR     0, __FILE__, __LINE__
#define TRACE_WARNING   1, __FILE__, __LINE__
#define TRACE_NORMAL    2, __FILE__, __LINE__
#define TRACE_INFO      3, __FILE__, __LINE__

void traceEvent(const int eventTraceLevel, const char* file, const int line,
  const char * format, ...) __attribute__ ((format (printf, 4, 5)));;
void daemonize(void);

void setThreadAffinity(u_int core_id);

#ifdef HAVE_GEOIP
void readASs(const char *path);
void readCountries(const char *path);
void deleteGeoIPDatabases();
void initAS(void);
#endif /* HAVE_GEOIP */

uint32_t msTimeDiff(struct timeval *end, struct timeval *begin);
float timevalDiff(struct timeval *end, struct timeval *begin);
unsigned int ntop_sleep(unsigned int secs);
uint32_t str2addr(char *address);
char* etheraddr_string(const uint8_t *ep, char *buf);
void fixTemplateToIPFIX(void);
size_t append_escaped(struct printbuf *buffer,const char *string,size_t string_len);

void loadApplProtocols(void);
uint16_t port2ApplProtocol(uint8_t proto, uint16_t port);

#define ntohll(x) be64toh(x)
#define htonll(x) ntohll(x)

void maximize_socket_buffer(int sock_fd, int buf_type);

#ifndef min
#define min(a, b) ((a > b) ? b : a)
#endif

#ifndef max
#define max(a, b) ((a > b) ? a : b)
#endif

#ifdef linux
void setCpuAffinity(char *cpuId);
#endif

void dropPrivileges(void);
void dumpLogEvent(LogEventType event_type, LogEventSeverity severity, char *message);
uint64_t to_msec(struct timeval *tv);

char* getSystemId(void);

#ifdef HAVE_PF_RING
int forwardPacket(int rx_device_id, char *p, int p_len);
#endif

#ifndef HAVE_STRNSTR
const char* strnstr(const char *s, const char *find, size_t slen);
#endif

/* ****************************************************** */

static __inline__ ticks getticks(void) {
  ticks x __attribute__((unused));

#if defined(__i386__)
  __asm__ volatile (".byte 0x0f, 0x31" : "=A" (x));
  return x;
#elif defined(__x86_64__)
  uint32_t a, d;

  asm volatile("rdtsc" : "=a" (a), "=d" (d));
  return (((ticks)a) | (((ticks)d) << 32));

  /*
    __asm __volatile("rdtsc" : "=A" (x));
    return (x);
  */
#else
  struct timeval tv;
  gettimeofday (&tv, 0);

  return (((ticks)tv.tv_usec) + (((ticks)tv.tv_sec) * 1000000LL));
#endif
}

/* ****************************************************** */

//#define PROFILING

#if defined(PROFILING) && defined(linux)
#define PROFILING_DECLARE(n) ticks __profiling_section_start[n]; char *__profiling_section_label[n]; ticks __profiling_section_tot[n]; uint64_t __profiling_section_times[n]
#define PROFILING_INIT() memset(__profiling_section_label, 0, sizeof(__profiling_section_label)); memset(__profiling_section_tot, 0, sizeof(__profiling_section_tot)); memset(__profiling_section_times, 0, sizeof(__profiling_section_times))
#define PROFILING_SECTION_ENTER(l, i) __profiling_section_start[i] = getticks(), __profiling_section_label[i] = l
#define PROFILING_SECTION_EXIT(i)  __profiling_section_tot[i] += getticks() - __profiling_section_start[i], __profiling_section_times[i]++
#define PROFILING_SECTION_VAL(i)   __profiling_section_tot[i]
#define PROFILING_SECTION_AVG(i)   (__profiling_section_tot[i] / __profiling_section_times[i])
#define PROFILING_SECTION_CNT(i)   __profiling_section_times[i]
#define PROFILING_SECTION_LABEL(i) __profiling_section_label[i]
#else
#define PROFILING_DECLARE(n)
#define PROFILING_INIT()
#define PROFILING_SECTION_ENTER(l, i)
#define PROFILING_SECTION_EXIT(i)
#define PROFILING_SECTION_VAL(i)
#define PROFILING_SECTION_AVG(i)
#define PROFILING_SECTION_CNT(i)
#define PROFILING_SECTION_LABEL(i)
#endif

/* ****************************************************** */

/// Struct useful to avoid access like normal-integer. Please use ATOMIC_OP.
typedef struct {
  uint64_t value;
} atomic_uint64_t;

/* ****************************************************** */

int bindthread2core(pthread_t thread_id, int core_id);

typedef struct {
  uint8_t network[16];
  uint8_t networkMask[16];
  uint8_t broadcast[16];
} netAddress_t;

struct counted_string
{
    const char *string;
    size_t len;
};

/* TODO: use sys/queue functions */
/* Linked list for nets and hosts names */
typedef struct _IPNameAssoc{
  char * name;
  char * number;
  union{
    netAddress_t net_address;
    unsigned int number;
  } number_i;
  struct _IPNameAssoc * next;
} IPNameAssoc;

#include "rb_lists.h"

/* TODO pass the lines below to rb_lists.h */

typedef struct _IPNameAssoc NumNameAssoc;

bool parseAddress(const char *address, netAddress_t *netaddress);

static bool safe_parse_address(const char *addr, netAddress_t *netAddress)
                                                        __attribute__((unused));
static bool safe_parse_address(const char *addr, netAddress_t *netAddress) {
  char ipv6_buffer[INET6_ADDRSTRLEN + strlen("/128")];
  snprintf(ipv6_buffer,sizeof(ipv6_buffer),"%s",addr); // Need to copy
  return parseAddress(ipv6_buffer, netAddress);
}

static inline void apply_netmask(uint8_t dst[16], const uint8_t ip[16], const uint8_t netmask[16]){
  int i;
  for(i=0;i<16;++i)
    dst[i] = ip[i]&netmask[i];
}

static inline const IPNameAssoc * ipInList(const uint8_t ip[16],
    const IPNameAssoc * list) {
  for(;list;list=list->next){
    uint8_t _ip[16];
    apply_netmask(_ip,ip,list->number_i.net_address.networkMask);

    if(0==memcmp(_ip,list->number_i.net_address.network,sizeof(_ip)))
      break;
  }
  return list;
}

static inline const NumNameAssoc * numInList(const uint32_t num,const NumNameAssoc * list){
  for(;list;list=list->next){
    if( num == list->number_i.number )
      break;
  }
  return list;
}

static inline const NumNameAssoc * namenInList(const char *name, const NumNameAssoc *list,const size_t lenname)
{
  for(;list;list=list->next){
    if(0==strncmp(name,list->name,lenname))
      break;
  }
  return list;
}

typedef enum{HOST_ORDER,NETWORK_ORDER,APPLICATION_ORDER,ENGINE_ORDER,DOMAINS_ORDER,OS_ORDER,IFADDR_ORDER} PARSEHOSTSLIST_ORDER;
int parseHostsList_File(char * filename,PARSEHOSTSLIST_ORDER order);
void parseHostsList(char * etc_path);
void freeHostsList(IPNameAssoc * p_ip_name_list);
static inline int parseAppList(char * apps_path){return parseHostsList_File(apps_path,APPLICATION_ORDER);}
static inline int parseEngineList(char * apps_path){return parseHostsList_File(apps_path,ENGINE_ORDER);}
static inline int parseHTTPDomainsList(char * list_path){return parseHostsList_File(list_path,DOMAINS_ORDER);}
static inline int parseIfAddressList(char * list_path){return parseHostsList_File(list_path,IFADDR_ORDER);}
static inline void freeNumList(NumNameAssoc * p)
{
  NumNameAssoc * aux;
  while(p)
  {
    aux = p->next;
    free(p->name);
    free(p->number);
    free(p);
    p = aux;
  }
}

struct rb_databases{
  pthread_rwlock_t mutex;
  int reload_hosts_database;
  int reload_nets_database;
  int reload_vlans_database;
  int reload_apps_database;
  int reload_engines_database;
  int reload_domains_database;
  int reload_os_database;
  int reload_domainalias_database;
  int reload_macs_database;
  int reload_macs_vendor_database;
  int reload_geoip_database;
  IPNameAssoc *ip_name_as_list;
  IPNameAssoc *nets_name_as_list;
  NumNameAssocTree *apps_name_as_list;
  NumNameAssoc *engines_name_as_list;
  NumNameAssoc *domains_name_as_list;
  rb_keyval_list_t *os_name_as_list;
  rb_keyval_list_t *domainalias_database;
  mac_addr_list mac_name_database;
  struct mac_vendor_database *mac_vendor_database;
  char *hosts_database_path;
  char *geoip_as_database_path;
  char *geoip_country_database_path;
  char *mac_vendor_database_path;
  char *sensors_info_path;
  struct rb_sensors_db *sensors_info;
};

void load_vlan_mapping();
void unload_vlan_mapping();

/* Check if we have to reload some database */
void check_if_reload(/*const int templateElementId,*/struct rb_databases * rb_databases);

const char * rb_l1_domain(const char *url,size_t *,const NumNameAssoc *domainlist);
const char * rb_l2_domain(const char *url,const char *l1_domain, size_t *,const NumNameAssoc *domainlist);


const char * extract_fb_photo_id(const char *url,const size_t urlsize,const char *host,size_t *size);

/* input: mac => "ab:cd:ef:ab:cd:ef" */
static inline uint64_t mac_atoi(const char *number_a)
{
  uint64_t number_i = 0;
  unsigned int j;
  static const int macpos[] = {0,1,3,4,6,7,9,10,12,13,15,16}; /* Numbers positions */
  for(j=0;j<sizeof(macpos)/sizeof(macpos[0]);++j)
    number_i |= ((uint64_t)
                 ('0'<=number_a[macpos[j]] && number_a[macpos[j]]<='9' ? (number_a[macpos[j]]-'0') :
                  'A'<=number_a[macpos[j]] && number_a[macpos[j]]<='F' ? (number_a[macpos[j]]-'A'+10) :
                                                                         (number_a[macpos[j]]-'a'+10))
                )<<(4*(11-j));
  return number_i;
}

/* ******************************************************** */

FlowSetV9Ipfix * getNewTemplateNumber(const unsigned int templateId);
int saveTemplateInFile(const FlowSetV9Ipfix *template,const char * file);
int loadTemplates(const char * where);

struct counted_string extract_tw_user(const struct counted_string *url,const struct counted_string *host);
struct counted_string extract_yt_user(const struct counted_string *url,const struct counted_string *host);
struct counted_string extract_yt_user_referer(const struct counted_string *referer);
struct counted_string extract_dropbox_user(const struct counted_string *host,const struct counted_string *url);
uint64_t net2number(const void *buffer,const uint16_t real_field_len);

/* ****************************************************** */
/* End of ENEO stuffs                                     */
/* ****************************************************** */
