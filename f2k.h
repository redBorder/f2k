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

/* *************************** */

#include "rb_listener.h"
#include "config.h"
#include "netflow.h"

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

/* See http://www.redhat.com/magazine/009jul05/features/execshield/ */
#ifndef _FORTIFY_SOURCE
#define _FORTIFY_SOURCE 2
#endif

#if defined(linux) || defined(__linux__)

/*
 * This allows to hide the (minimal) differences between Linux and BSD
 */
#include <features.h>
#ifndef __FAVOR_BSD
#define __FAVOR_BSD
#endif
#ifndef _BSD_SOURCE
#define _BSD_SOURCE
#endif
#endif /* linux || __linux__ */

#include <limits.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <stdbool.h>

#include "pcap.h"

/* GeoIP */
#ifdef HAVE_GEOIP
#include "GeoIP.h"
#include "GeoIPCity.h"
#endif

#ifdef HAVE_LIBRDKAFKA
#include "librdkafka/rdkafka.h"
#endif

#ifdef HAVE_ZOOKEEPER
#include <zookeeper/zookeeper.h>
#endif

#ifdef HAVE_UDNS
#include <udns.h>
#endif

#include "template.h"

/*
 * Structure of a 10Mb/s Ethernet header.
 */
struct eth_header {
  uint8_t	ether_dhost[6];
  uint8_t	ether_shost[6];
  uint16_t	ether_type;
};


#define PREFIX             "/usr/local"

#include "collect.h"
#include "version.h"

/* ********* NETFLOW ****************** */

/*
  For more info see:

  http://www.cisco.com/warp/public/cc/pd/iosw/ioft/neflct/tech/napps_wp.htm

  ftp://ftp.net.ohio-state.edu/users/maf/cisco/
*/

/* NetFlow v9/IPFIX */

#define STANDARD_ENTERPRISE_ID                0
#define NTOP_ENTERPRISE_ID           0x00008B30 /* IANA assignment for ntop */
#define CISCO_ENTERPRISE_ID STANDARD_ENTERPRISE_ID /* TEMPORARY PEN */

#define QUOTE_OUTPUT true
#define DONT_QUOTE_OUTPUT false

#define FLOW_TEMPLATE       0
#define OPTION_TEMPLATE     1

typedef struct flow_ver9_template_field {
  const V9V10TemplateElementId *v9_template;
  uint16_t fieldId;
  uint16_t fieldLen;
} V9V10TemplateField;

typedef struct flow_ver9_ipfix_simple_template {
  uint32_t netflow_device_ip, observation_domain_id;
  /* V9TemplateDef */
  uint16_t templateId;
  uint16_t fieldCount, scope_field_len;
  bool is_option_template;
} V9IpfixSimpleTemplate;

typedef struct flowSetV9Ipfix {
  V9IpfixSimpleTemplate templateInfo;
  V9V10TemplateField *fields;
  LIST_ENTRY(flowSetV9Ipfix) entry;
} FlowSetV9Ipfix;


/* ******************************************* */

#define NETFLOW_BUFFER_LEN (16*1024)

#define ACT_NUM_PCAP_THREADS      2
#define MAX_NUM_PCAP_THREADS     32

typedef unsigned long long ticks;

/* It must stay here as it needs the definition of v9 types */
#include "util.h"

#ifdef HAVE_PF_RING
#include "pro/pf_ring.h"
#define CHECKSUM
#endif

#ifndef DARWIN
#include <getopt.h>
#endif

/* **************************************************************** */

#define MAX_NUM_COLLECTOR_THREADS  MAX_NUM_PCAP_THREADS
#define MAX_NUM_OPTIONS             128

/* ********************************************* */

struct fileList {
  char *path;
  struct fileList *next;
};

typedef struct {
  bool becomeDaemon;

  /* Expanded copy of CLI arguments */
  int argc;
  char **argv;

  size_t capture_num_packet_and_quit;
  bool promisc_mode, enableGeoIP;

  bool separate_long_flows;

  char *unprivilegedUser;
#ifdef linux
  char *cpuAffinity; /* NULL means no affinity */
#endif
  char f2kId[255+1];
  struct fileList *pcapFileList;
  char *pcapFile, *pidPath;
  pcap_t *pcapPtr;
#ifdef HAVE_NETFILTER
  struct {
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int queueId, fd;
    uint32_t nf_verdict, nf_mark;
    unsigned long thread_id;
  } nf;
#endif
#ifdef HAVE_PF_RING
  int cluster_id;
#endif
  int datalink;
  char *captureDev;
  uint16_t snaplen;
  bool do_not_drop_privileges;

  /* Logging */
  char *eventLogPath;

  /* Export Options */
  size_t numProcessThreads;

  bool useSyslog;
  int traceLevel;

  worker_t **packetProcessThread;

#ifdef HAVE_GEOIP
  /* GeoIP */
  GeoIP *geo_ip_asn_db, *geo_ip_asn_db_v6;
  GeoIP *geo_ip_city_db, *geo_ip_city_db_v6;
  GeoIP *geo_ip_country_db, *geo_ip_country_db_v6;
#endif

  /* Collector */
  listener_list listeners;

  /* Status */
  bool f2k_up; // TODO delete this!

  /* Performance test */
  bool tracePerformance;
  pthread_rwlock_t ticksLock;
  ticks decodeTicks;

  unsigned long f2kPid; /* 0 on Windows */

  bool enable_debug,
    reproduceDumpAtRealSpeed,reforgeTimestamps,dontReforgeFarTimestamp;

#ifdef HAVE_LIBRDKAFKA
  struct {
    char *broker_ip;
    char *topic;
    bool use_client_mac_partitioner;
  } kafka;
#endif

#ifdef HAVE_ZOOKEEPER
  struct {
    pthread_rwlock_t rwlock;
    zhandle_t *zh;
    char *zk_host;

    /* @TODO ZK handler will write to this log some times */
    size_t log_buffer_size;
    char *log_buffer;
    FILE *log_buffer_f;

    // Time with the last template get.
    bool need_to_reconnect;
    volatile time_t last_template_get_timestamp;
    double update_template_timeout;
    pthread_t zk_wathcher;
  } zk;
#endif

#ifdef HAVE_UDNS
  struct {
    struct dns_cache *cache;
    char *csv_dns_servers;
    struct rb_dns_info *dns_info_array;
    rd_thread_t **dns_poll_threads;
  } udns;
#endif

  struct rb_databases rb_databases;
  char templates_database_path[PATH_MAX];
} ReadOnlyGlobals;

typedef struct {
  bool shutdownInProgress, stopPacketCapture, endOfPcapReached;

#ifdef HAVE_GEOIP
  pthread_rwlock_t geoipRwLock;
#endif

#ifdef HAVE_ZOOKEEPER
  /* Collector */
  struct {
    atomic_uint64_t num_zk_templates_received;
  } collectionStats;
#endif

  bool syslog_opened;
#ifdef HAVE_PF_RING
  bool ring_enabled;
  pfring *ring;
#endif

#ifdef HAVE_LIBRDKAFKA
  struct{
    pthread_rwlock_t      rwlock;
    rd_kafka_t            *rk;
    rd_kafka_topic_t      *rkt;
  } kafka;
#endif

  /* Stats */
  uint64_t last_ps_recv, last_ps_drop;
} ReadWriteGlobals;

extern ReadOnlyGlobals  readOnlyGlobals;
extern ReadWriteGlobals *readWriteGlobals;
