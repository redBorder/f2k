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
#include "rb_kafka.h"
#include "rb_zk.h"
#include "rb_sensor.h"

#ifdef HAVE_UDNS
#include "rb_dns_cache.h"
#endif

#include "jansson.h"
#include "f2k.h"
#include <net/ethernet.h>
#include <pwd.h>
#include <syslog.h>

/* *************************************** */

static void initDefaults(void);

/* *********** Globals ******************* */

#ifdef HAVE_PF_RING
#include "pro/pf_ring.c"
#endif

/* *************************************** */

/* BSD AF_ values. */
#define BSD_AF_INET             2
#define BSD_AF_INET6_BSD        24      /* OpenBSD (and probably NetBSD), BSD/OS */
#define BSD_AF_INET6_FREEBSD    28
#define BSD_AF_INET6_DARWIN     30

#ifndef DLT_ANY
#define DLT_ANY 113
#endif

#ifndef ETHERTYPE_IP
#define ETHERTYPE_IP    0x0800  /* IP protocol */
#endif

#ifndef ETHERTYPE_IPV6
#define ETHERTYPE_IPV6    0x86DD  /* IPv6 protocol */
#endif

#ifndef ETHERTYPE_MPLS
#define ETHERTYPE_MPLS    0x8847  /* MPLS protocol */
#endif

#ifndef ETHERTYPE_PPPoE
#define ETHERTYPE_PPPoE   0x8864  /* PPP over Ethernet */
#endif

#ifndef ETHERTYPE_VLAN
#define ETHERTYPE_VLAN    0x08100
#endif

#define TRANSPORT_UDP          1
#define TRANSPORT_TCP          2
#define TRANSPORT_SCTP         3

#ifndef IPPROTO_SCTP
#define IPPROTO_SCTP         132
#endif

/* ****************************************************** */

/* Forward */
static int parseOptions(int argc, char* argv[], uint8_t reparse_options);

static int argc_;
static char **argv_;

#ifdef HAVE_OPTRESET
extern int optreset; /* defined by BSD, but not others */
#endif

typedef void *(*pthread_start_routine)(void*);

static const struct option long_options[] = {
  { "as-list",                          required_argument,       NULL, 'A' },
  { "verbose",                          required_argument,       NULL, 'b' },
  { "pid-file",                         required_argument,       NULL, 'g' },
  { "daemon-mode",                      no_argument,             NULL, 'G' },
  { "help",                             no_argument,             NULL, 'h' },
  { "hosts-path",                       required_argument,       NULL, 256 },
  { "template-cache",                   required_argument,       NULL, 257 },
  { "rb-config",                        required_argument,       NULL, 258 },
  { "separate-long-flows",              no_argument,             NULL, 260 },

  { "interface",                        required_argument,       NULL, 'i' },
  { "syslog",                           required_argument,       NULL, 'I' },
  { "num-threads",                      required_argument,       NULL, 'O' },
  { "snaplen",                          required_argument,       NULL, 's' },
  { "sample-rate",                      required_argument,       NULL, 'S' },
  { "version",                          no_argument,             NULL, 'v' },

#ifdef HAVE_PF_RING
  { "cluster-id",                       required_argument,       NULL, 'Z' },
#endif

  { "count",                            required_argument,       NULL, '2' },
  { "collector-port",                   required_argument,       NULL, '3' },
#ifdef linux
  { "cpu-affinity",                     required_argument,       NULL, '4' },
#endif
  /* Handled by the plugin */
  { "no-promisc",                       no_argument,             NULL, '6' },
  { "pcap-file-list",                   required_argument,       NULL, '$' },
  { "city-list",                        required_argument,       NULL, ',' },
  { "country-list",                     required_argument,       NULL, 259 },
  /* Some identifiers are available */
  { "dont-drop-privileges",             no_argument,             NULL, '\\' },
  { "event-log",                        required_argument,       NULL, '+'  },
#ifdef HAVE_LIBRDKAFKA
  { "kafka",                            required_argument,       NULL, 229 },
  { "rdkafka-opt",                      required_argument,       NULL, 'X' },
  { "use-kafka-random-partitioner",     no_argument,             NULL, 'p' },
#endif

#ifdef HAVE_ZOOKEEPER
  { "zk-host",                          required_argument,       NULL, 'z' },
  { "zk-timeout",                       required_argument,       NULL, 262 },
#endif

  { "dont-reforge-timestamps",          no_argument,             NULL, 235 },
  { "original-speed",                   no_argument,             NULL, 237 },

  { "unprivileged-user",                required_argument,       NULL, 244 },
  { "performance",                      no_argument,             NULL, 248 },
  { "mac-vendor-list",                  required_argument,       NULL, 249 },

  { "debug",                            no_argument,       NULL, 254 },
  { "dont-reforge-far-timestamp",       no_argument,       NULL, 261 },

#ifdef HAVE_UDNS
  { "enable-ptr-dns",                   no_argument,       NULL, 'd'},
  { "dns-cache-size-mb",                required_argument, NULL, 'c'},
  { "dns-cache-timeout-s",              required_argument, NULL, 't'},
#endif

  /* End of probe options */
  { NULL,                               no_argument,       NULL,  0 }
};

/* ****************************************************** */

static uint32_t printPcapStats(pcap_t *pcapPtr) {
  struct pcap_stat pcapStat;

  if(pcap_stats(pcapPtr, &pcapStat) >= 0) {
    uint64_t rcvd_diff, drop_diff;
    char msg[256];

    /* Some pcap implementations reset the stats at each call */
    if(pcapStat.ps_recv >= readWriteGlobals->last_ps_recv) {
      rcvd_diff = pcapStat.ps_recv - readWriteGlobals->last_ps_recv;
      drop_diff = pcapStat.ps_drop - readWriteGlobals->last_ps_drop;
    } else {
      rcvd_diff = pcapStat.ps_recv, drop_diff = pcapStat.ps_drop;
    }

    /* traceEvent(TRACE_ERROR, "[%u][%u]\n", pcapStat.ps_recv, pcapStat.ps_drop); */

    snprintf(msg, sizeof(msg), "Packet stats (pcap): "
             "%u/%u pkts rcvd/dropped [%.1f%%] [Last %lu/%lu pkts rcvd/dropped]",
             pcapStat.ps_recv, pcapStat.ps_drop,
             (pcapStat.ps_recv > 0) ? ((float)(pcapStat.ps_drop*100)/(float)pcapStat.ps_recv) : 0,
             rcvd_diff, drop_diff);

    // traceEvent(TRACE_INFO, "%s", msg);

    if(readWriteGlobals->shutdownInProgress && (pcapStat.ps_drop > 0)) {
      snprintf(msg, sizeof(msg), "Final capture stats (pcap): "
               "%u/%u pkts rcvd/dropped [%.1f%%]",
               pcapStat.ps_recv, pcapStat.ps_drop,
               (pcapStat.ps_recv > 0) ? ((float)(pcapStat.ps_drop*100)/(float)pcapStat.ps_recv) : 0);
      dumpLogEvent(packet_drop, severity_warning, msg);
    }

    readWriteGlobals->last_ps_recv = pcapStat.ps_recv, readWriteGlobals->last_ps_drop = pcapStat.ps_drop;

    return(drop_diff);
  } else {
#ifdef DEBUG
    traceEvent(TRACE_WARNING, "Unable to read pcap statistics: %s",
               pcap_geterr(pcapPtr));
#endif

    return(0 /* drop_diff */);
  }
}

/* ****************************************************** */

/* Return the number of dropped packets since last call */
static uint32_t printCaptureStats() {
#ifdef HAVE_PF_RING
  if(!readWriteGlobals->stopPacketCapture)
    return(printPfRingStats(dump_stats_on_screen));
#else
  if(readOnlyGlobals.pcapPtr != NULL)
    return(printPcapStats(readOnlyGlobals.pcapPtr));
#endif
  else
    return(0);
}

/* ****************************************************** */

static void reloadCLI(int signo) {
  traceEvent(TRACE_NORMAL, "Received signal %d: reloading CLI options", signo);
  static int reloadingCli = 0;
  if(reloadingCli++)
    return;
  parseOptions(argc_, argv_, 1);
  reloadingCli=0;
}

/* ****************************************************** */

static void cleanup(int signo __attribute__((unused))) {
  static bool statsPrinted = false;

  if(!readOnlyGlobals.f2k_up) exit(0);

  if(!statsPrinted) {
    statsPrinted = true;
    printCaptureStats();
  }

  readOnlyGlobals.f2k_up = 0;
  readWriteGlobals->shutdownInProgress = 1;
  traceEvent(TRACE_NORMAL, "Received shutdown request...");

  /* shutdown_f2k(); */
  /* exit(0); */
}

/* ****************************************************** */

static void brokenPipe(int signo __attribute__((unused))) {
#ifdef DEBUG
  traceEvent(TRACE_WARNING, "Broken pipe (socket %d closed) ?\n", currSock);
#endif
  signal(SIGPIPE, brokenPipe);
}

/* ****************************************************** */

static int isFlowPort(const uint16_t port){
  switch(port){
  case 2055:
  case 2057:
  case 6343:
  case 9999:
  case 3000:
  case 6000:
  case 9996:
  case 15003:
    return 1;
  default:
    return 0;
  }
}

static uint16_t _eth_type(const struct ether_header *ehdr){
  uint32_t null_type;

  switch(readOnlyGlobals.datalink) {
  case DLT_ANY: /* Linux 'any' device */
    return DLT_ANY;

  case DLT_RAW: /* Raw packet data */
    if(((((const uint8_t *)ehdr)[0] & 0xF0) >> 4) == 4)
      return ETHERTYPE_IP;
    else
      return ETHERTYPE_IPV6;
    break;
  case DLT_NULL: /* loopaback interface */
    memcpy(&null_type, ehdr, sizeof(uint32_t));
    //null_type = ntohl(null_type);
    /* All this crap is due to the old little/big endian story... */
    /* FIX !!!! */
    switch(null_type) {
    case BSD_AF_INET:
      return ETHERTYPE_IP;

    case BSD_AF_INET6_BSD:
    case BSD_AF_INET6_FREEBSD:
    case BSD_AF_INET6_DARWIN:
      return ETHERTYPE_IPV6;

    default:
      return DLT_NULL; /* Any other non IP protocol */
    }
    break;
  case DLT_PPP:
    break;
  default:
    assert(ehdr);
    return ntohs(ehdr->ether_type);
    break;
  };

  traceEvent(TRACE_WARNING,"Cannot find eth type");
  return 0;
}

static size_t _eth_shift(){
  switch(readOnlyGlobals.datalink) {
  case DLT_RAW: /* Raw packet data */
    return 0;

  case DLT_NULL: /* loopaback interface */
    return 4;

  case DLT_PPP:
    return 0;

  default:
    return sizeof(struct eth_header);
  };
}

// @TODO test fragment management
static void deepPacketDecode(u_short thread_id __attribute__((unused)),
                             struct pcap_pkthdr *h, QueuedPacket *qpacket) {
  size_t caplen = h->caplen, length = h->len, offset = 0;
  uint8_t proto = 0;
  uint16_t payload_shift = 0;
  int payloadLen = 0; /* Do not set it to unsigned */
  IpAddress src;
  u_short isFragmentedPacket = 0;
  ticks when=0;

#ifdef DEBUG
  traceEvent(TRACE_INFO, ".");
#endif

  // dumpPacket(h, p);

#if 0
  if(h->ts.tv_sec > (time(NULL)+1)) {
    traceEvent(TRACE_WARNING, "BAD time: h->ts.tv_sec=%u/time=%u",
               (unsigned int)h->ts.tv_sec,
               (unsigned int)time(NULL));
  }
#endif

  if(unlikely(readOnlyGlobals.tracePerformance))
    when = getticks();

  if(unlikely(readWriteGlobals->stopPacketCapture))
    return;

  if(unlikely(caplen < sizeof(struct eth_header))){
    traceEvent(TRACE_ERROR,"caplen < sizeof(struct eth_header");
    return;
  }

  size_t plen, hlen = 0, ip_len = 0;

  const uint16_t eth_type = _eth_type((const struct ether_header *)qpacket->buffer);
  const size_t   ehshift = _eth_shift(qpacket->buffer);

  switch(eth_type) {
  case ETHERTYPE_VLAN:
    traceEvent(TRACE_WARNING, "Does not processing VLAN packets.");
    return;
  case ETHERTYPE_MPLS:
    traceEvent(TRACE_WARNING, "Does not processing MPLS packets.");
    return;
  case DLT_ANY:
    traceEvent(TRACE_WARNING, "Does not processing ANY packets (use -i in tcpdump)");
    return;
  case DLT_NULL:
    traceEvent(TRACE_WARNING, "Cannot find any IPv4/IPv6 packets in LO interface");
    return;
  case ETHERTYPE_PPPoE:
    traceEvent(TRACE_WARNING, "Does not processing PPPoE packets");
    return;
  case ETHERTYPE_IP:
  case ETHERTYPE_IPV6:
  {
    size_t estimatedLen = 0;

    if(likely(eth_type == ETHERTYPE_IP)) {
      const struct ip *ip = (struct ip*)(qpacket->buffer+ehshift);
      if(ip->ip_v != 4) return; /* IP v4 only */
      const size_t ip_ip_len = htons(ip->ip_len);

      ip_len = ((size_t)ip->ip_hl * 4);
      estimatedLen = ehshift + ip_ip_len;
      hlen = ip_len;
      payloadLen = htons(ip->ip_len)-ip_len;

      if(length < h->caplen)
        h->caplen = length;

      src.ipVersion = 4;
      src.ipType.ipv4 = ntohl(ip->ip_src.s_addr);

      proto = ip->ip_p;
      const size_t off = ntohs(ip->ip_off) & 0x1fff;
      const size_t more_fragments = ntohs(ip->ip_off) & 0x2000;
      isFragmentedPacket = off || more_fragments ? 1 : 0;
    }else if(unlikely(eth_type == ETHERTYPE_IPV6)) {
      struct ip6_hdr *ipv6 = NULL;
      struct ip6_ext *ipv6ext = NULL;
      size_t ipv6_ip_len;

      ipv6 = (struct ip6_hdr*)(qpacket->buffer+ehshift);
      if(((ipv6->ip6_vfc >> 4) & 0x0f) != 6) return; /* IP v6 only */

      ipv6_ip_len = htons(ipv6->ip6_plen);
      estimatedLen = sizeof(struct ip6_hdr)+ehshift+ipv6_ip_len;

      hlen = sizeof(struct ip6_hdr);
      src.ipVersion = 6;

      proto = ipv6->ip6_nxt; /* next header (protocol) */
      payloadLen = h->caplen - ehshift - hlen;

      /* FIX: blacklist check for IPv6 */

      /* FIX: isLocalAddress doesn't work with IPv6 */
      memcpy(&src.ipType.ipv6, &ipv6->ip6_src, sizeof(struct in6_addr));

      if(proto == 0) {
        /* IPv6 hop-by-hop option */

        ipv6ext = (struct ip6_ext*)(qpacket->buffer+ehshift+40);
        hlen += (ipv6ext->ip6e_len+1)*8;
        proto = ipv6ext->ip6e_nxt;
      }
    } else {
      traceEvent(TRACE_WARNING,"Not processing non IPv4/IPv6 packet");
      return; /* Anything else that's not IPv4/v6 */
    }

    plen = length-ehshift;
    if(caplen > estimatedLen) caplen = estimatedLen;
    payloadLen -= (estimatedLen-caplen);

    offset = ehshift+hlen;

  }
    break;

  default:
    if((eth_type != 0) && (eth_type < 1500) /* Max 802.3 lenght */) {
        traceEvent(TRACE_WARNING, "We don't process 802.3 packets");
    } else {
#ifdef DEBUG
    traceEvent(TRACE_WARNING, "Unknown ethernet type: 0x%X (%d)", eth_type, eth_type);
#endif
    }
    break;
  }

  if(likely(proto==IPPROTO_UDP)){
    struct udphdr *up;
    if(unlikely(plen < (hlen+sizeof(struct udphdr)))) return; /* packet too short */
    up = (struct udphdr*)(qpacket->buffer+offset);
    const uint16_t dport = ntohs(up->uh_dport);
    if(likely(payloadLen > 0))
      payload_shift = offset+sizeof(struct udphdr);
    else {
      payloadLen    = 0;
      payload_shift = 0;
    }

    if(likely((payloadLen > 0) && (isFlowPort(dport))
      && (isFragmentedPacket == 0) /* Do not process fragmented packets */)) {
          /* traceEvent(TRACE_NORMAL, "Dissecting flow packets (%d bytes)", payloadLen); */
#if 0
          int begin = 70;

          traceEvent(TRACE_NORMAL, "%02X %02X %02X %02X %02X %02X",
                       p[payload_shift+begin] & 0xFF, p[payload_shift+begin+1] & 0xFF,
                       p[payload_shift+begin+2] & 0xFF, p[payload_shift+begin+3] & 0xFF,
                       p[payload_shift+begin+4] & 0xFF, p[payload_shift+begin+5] & 0xFF);
#endif

      if(unlikely(dport == 6343 /* sFlow (we hope) */)) {
        //struct sockaddr_in fromHostV4;
        //dissectSflow((char*)&p[payload_shift], payloadLen, &fromHostV4); /* sFlow */
      } else{
        struct sensor *sensor_object = get_sensor(
                  readOnlyGlobals.rb_databases.sensors_info, src.ipType.ipv4);
        if(NULL==sensor_object) {
          const size_t bufsize = 1024;
          char buf[bufsize];
          const int bad_sensor_added = addBadSensor(
                  readOnlyGlobals.rb_databases.sensors_info, src.ipType.ipv4);
          if(bad_sensor_added)
            traceEvent(TRACE_WARNING,"received a packet from the unknow sensor %s on port %u.",
              _intoaV4(src.ipType.ipv4,buf,bufsize), dport);
          freeQueuedPacket(qpacket);
        } else {
          qpacket->netflow_device_ip = src.ipType.ipv4;
          qpacket->buffer += payload_shift;
          qpacket->buffer_len = payloadLen - sizeof(struct udphdr);
          qpacket->sensor = sensor_object;
          worker_t *worker = sensor_worker(sensor_object);
          add_packet_to_worker(qpacket, worker);
        }
      }

      return;
    }
  }else{
    traceEvent(TRACE_WARNING,"Not processing non-UDP packets");
  }

  if(unlikely(readOnlyGlobals.tracePerformance)) {
    ticks diff = getticks() - when;

    pthread_rwlock_wrlock(&readOnlyGlobals.ticksLock);
    readOnlyGlobals.decodeTicks += diff;
    pthread_rwlock_unlock(&readOnlyGlobals.ticksLock);
  }
}

/* ****************************************************** */

static void decodePacket(u_short thread_id,
                  struct pcap_pkthdr *h, QueuedPacket *qpacket) {

  /* Sanity check */
  if(unlikely((h->ts.tv_sec < 0) || (h->ts.tv_usec < 0))) {
    static uint8_t shown_msg = 0;

    if(!shown_msg) {
      traceEvent(TRACE_WARNING, "Invalid timestamp: %lu.%lu", h->ts.tv_sec, h->ts.tv_usec);
      shown_msg = 1;
    }

    return; /* We ignore this packet */
  } else if(unlikely(h->caplen > h->len)) {
    static uint8_t shown_msg = 0;

    if(!shown_msg) {
      traceEvent(TRACE_WARNING,
        "Invalid packet length: [len=%"PRIu32"][caplen=%"PRIu32"][snaplen=%u]",
        h->len, h->caplen, readOnlyGlobals.snaplen);

      traceEvent(TRACE_WARNING, "Please disable LRO/GRO on your NIC (ethtool -k <NIC>)");
      shown_msg = 1;
    }

    h->len = readOnlyGlobals.snaplen;
    h->caplen = min(h->caplen, h->len);
  }

  deepPacketDecode(thread_id,h, qpacket);
}

/* ****************************************************** */

static void probeVersion(void) {
  printf("\nWelcome to f2k v.%s (%s) for %s\n"
         "%s\n"
         "Copyright 2002-13 by Luca Deri <deri@ntop.org>\n",
         version, f2k_revision, osName,
#ifdef HAVE_PF_RING
         "with native PF_RING acceleration.\n");
#else
  "");
#endif
}

/* ******************************************************** */

static void usage() {
  initDefaults();
  probeVersion();

  printf("\nUsage:\n");

  printf("f2k [-i <interface|dump file>][-s <snaplen>]\n"
         "              [-f <filter>] [-b <level>]"
         " [-G]"
         " [-O <# threads>]"
#ifdef HAVE_LIBRDKAFKA
         " [-X] <rdkafka option>"
#endif
         "\n              "
         "[-I <probe name>] "
         "[-v] \n"
         "\n              [-S <sample rate>] [-A <AS list>] [-g <PID file>]"
         "\n              [-2 <number>] [-3 <port>] [-4] [-5 <port>] [-6]"
         "\n              [-9 <path>] [--pcap-file-list <filename>]"
         " [--dont-drop-privileges]\n"
         "\n\n"
         );

  printf("[--interface|-i] <iface|pcap>       | Interface name from which packets are\n");
  printf("                                    | captured, or .pcap file (debug only).\n");
#ifdef HAVE_NETFILTER
  printf("                                    | For capturing from netfilter queues specify\n");
  printf("                                    | -i nf:X where X is the netfilter queue id.\n");
#endif
  printf("[--snaplen|-s] <snaplen>            | Packet capture snaplen. [default %u bytes]\n", readOnlyGlobals.snaplen);
  printf("[--verbose|-b] <level>              | Verbose output:\n"
         "                                    | 0 - No verbose logging\n"
         "                                    | 1 - Limited logging (traffic statistics)\n"
         "                                    | 2 - Full verbose logging\n");

  printf("[--daemon-mode|-G]                  | Start as daemon.\n");

  printf("[--num-threads|-O] <# threads>      | Number of packet fetcher threads\n"
         "                                    | [default=%zu]. Use 1 unless you know\n"
         "                                    | what you're doing.\n",
         readOnlyGlobals.numProcessThreads);
  printf("[--separate-long-flows]             | Separate long time flows (default no) \n");
  printf("[--f2k-version|-v]               | Prints the program version.\n");
  printf("[--help|-h]                         | Prints this help.\n");
  printf("--debug                             | Enable debugging (development only).\n");

  printf("--performance                       | Enable performance tracing (development only).\n");

  printf("[--syslog|-I] <probe name>          | Log to syslog as <probe name>\n"
         "                                    | [default=stdout]\n");


#ifdef HAVE_PF_RING
  printf("--cluster-id <cluster id>           | Specify the PF_RING clusterId on which\n"
         "                                    | incoming packets will be bound.\n");
#endif

  printf("[--sample-rate|-S] <pkt rate>:<flow rate>\n"
         "                                    | Packet capture sampling rate and flow\n"
         "                                    | sampling rate. If <pkt rate> starts with '@'\n"
         "                                    | it means that f2k will report the specified\n"
         "                                    | sampling rate but will not sample itself\n"
         "                                    | as incoming packets are already sampled\n"
         "                                    | on the specified capture device at the\n"
         "                                    | specified rate. Default: 1:1 [no sampling]\n");
  printf("[--as-list|-A] <AS list>            | GeoIP file containing the list of known ASs.\n"
         "                                    | Example: GeoIPASNum.dat\n");
  printf("--city-list <city list>             | GeoIP file containing the city/IP mapping. Note\n"
         "                                    | that nProbe will load the IPv6 file equivalent\n"
         "                                    | if present. Example: --city-list GeoLiteCity.dat\n"
         "                                    | will also attempt to load GeoLiteCityv6.dat\n");
  printf("[--pid-file|-g] <PID file>          | Put the PID in the specified file\n");
  printf("[--flow-version|-V] <version>       | NetFlow Version: 5=v5, 9=v9, 10=IPFIX\n");
  printf("[--count|-2] <number>               | Capture a specified number of packets\n"
         "                                    | and quit (debug only)\n");
  printf("[--collector-port|-3] <port>        | NetFlow/sFlow comma separated collector ports for incoming flows\n");
#ifdef linux
  printf("[--cpu-affinity|-4] <CPU/Core Id>   | Binds this process to the specified CPU/Core\n"
         "                                    | Note: the first available CPU corresponds to 0.\n");
#endif
  printf("[--no-promisc|-6]                   | Capture packets in non-promiscuous mode\n");
  printf("--pcap-file-list <filename>         | Specify a filename containing a list\n"
         "                                    | of pcap files.\n"
         "                                    | If you use this flag the -i option will be\n"
         "                                    | ignored.\n");
  printf("--dont-drop-privileges              | Do not drop privileges changing to user nobody\n");
  printf("--event-log <file>                  | Dump relevant activities into the specified log file\n");
#ifdef HAVE_LIBRDKAFKA
  printf("--kafka <broker IP>:<topic>         | Deliver flows to the specified Apache Kafka broker. Example localhost:test\n");
  printf("--use-kafka-random-partitioner      | Use random partitioning in kafka");
#endif
  printf("--hosts-path                        | Path to your own /etc/hosts, /etc/networks and vlans mapping\n");
  printf("                                    | See VLAN_MAP.txt for details\n");
  printf("--any-template                      | Print all fields in collector mode, even if not specified in template\n");
  printf("--original-speed                    | When using -i with a pcap file, instead of reading packets\n"
         "                                    | as fast as possible, the original speed is preserved (debug only)\n");
  printf("--dont-reforge-timestamps           | Disable nProbe to reforge timestamps with -i <pcap file> (debug only)\n");
  printf("--dont-reforge-far-timestamps       | Disable nProbe to reforge timestamps too far (+-1hour)\n");
  printf("--unprivileged-user <name>          | Use <name> instead of nobody when dropping privileges\n");

  printf("\nFurther plugin available command line options\n");
  printf("---------------------------------------------------\n");

  /* ************************************************ */

  printf("\n");
  printf("nProbe shut down\n");

  exit(0);
}

/* ****************************************************** */

static void printProcessingStats(void) {
  struct worker_stats all_stats = {0};

  size_t i = 0;
  uint32_t tot_pkts = 0;

  for (i=0; i<=readOnlyGlobals.numProcessThreads; ++i) {
    struct worker_stats w_stats;
    if (i < readOnlyGlobals.numProcessThreads) {
      get_worker_stats(readOnlyGlobals.packetProcessThread[i], &w_stats);
      sum_worker_stats(&all_stats, &w_stats);
    } else {
      memcpy(&w_stats, &all_stats, sizeof(w_stats));
    }

    const uint64_t num_collected_pkts = w_stats.num_packets_received;
    const double delta_seconds = difftime(w_stats.last_flow_processed_timestamp,
                                        w_stats.first_flow_processed_timestamp);
    const double flows_per_second = w_stats.num_flows_processed / delta_seconds;
    const double pkts_per_second = num_collected_pkts / delta_seconds;

    traceEvent(TRACE_NORMAL, "[W:%zu/%zu] "
      "Flow collection: [collected pkts: %"PRIu64" (%lf pkts/s)]"
      "[processed flows: %"PRIu64" (%lf flows/s)]",
      i, readOnlyGlobals.numProcessThreads,
      num_collected_pkts, pkts_per_second, w_stats.num_flows_processed,
                                                              flows_per_second);

  }


#ifdef HAVE_ZOOKEEPER
  traceEvent(TRACE_NORMAL, "[Templates received via ZooKeeper: %"PRIu64"]",
    ATOMIC_OP(add, fetch,
      &readWriteGlobals->collectionStats.num_zk_templates_received.value, 0));
#endif

  if(readOnlyGlobals.tracePerformance && (tot_pkts > 0)) {
    static unsigned long last_pkts = 0;
    ticks tot;

    pthread_rwlock_wrlock(&readOnlyGlobals.ticksLock);

    tot = readOnlyGlobals.decodeTicks;

    if(tot > 0) {
      if(last_pkts == 0) last_pkts = tot_pkts;
      last_pkts = tot_pkts - last_pkts;

      if(last_pkts > 0) {
        traceEvent(TRACE_NORMAL, "---------------------------------");
        traceEvent(TRACE_NORMAL, "Decode ticks:     %.2f ticks/pkt [%.2f %%]",
                   (float)readOnlyGlobals.decodeTicks / (float)last_pkts,
                   (float)(readOnlyGlobals.decodeTicks*100)/(float)tot);

        traceEvent(TRACE_NORMAL, "Total ticks:      %.2f ticks/pkt",
                   (float)tot / (float)last_pkts);
        traceEvent(TRACE_NORMAL, "---------------------------------");
      }

    }

    last_pkts = tot_pkts, readOnlyGlobals.decodeTicks = 0;

    pthread_rwlock_unlock(&readOnlyGlobals.ticksLock);
  }
}

/* ****************************************************** */

static void readPcapFileList(const char * filename) {
  char line[512];

  FILE *fd = fopen(filename, "r");

  if(fd != NULL) {
    struct fileList *fl, *prev;

    while(!feof(fd)) {
      size_t i;
      int bad_line;

      if(fgets(line, sizeof(line)-1, fd) == NULL) continue;
      if((line[0] == '#') || (line[0] == '\n')) continue;

      bad_line = 0;

      for(i=0; i<strlen(line); i++) {
        if(!isascii(line[i])) {
          bad_line = 1;
          break;
        }
      }

      if(bad_line) {
        traceEvent(TRACE_ERROR, "Your --pcap-file-list %s contains binary data: discarded", filename);
        fclose(fd);
        return;
      }

      while(strlen(line) && (line[strlen(line)-1] == '\n')) line[strlen(line)-1] = '\0';

      fl = (struct fileList*)malloc(sizeof(struct fileList));

      if(!fl) {
        traceEvent(TRACE_ERROR, "Not enough memory parsing --pcap-file-list argument");
        fclose(fd);
        return;
      }

      fl->path = strdup(line);

      if(!fl->path) {
        free(fl);
        traceEvent(TRACE_ERROR, "Not enough memory parsing --pcap-file-list argument");
        fclose(fd);
        return;
      }

      fl->next = NULL;

      if(readOnlyGlobals.pcapFileList) {
        prev = readOnlyGlobals.pcapFileList;
        while(prev != NULL) {
          if(prev->next)
            prev = prev->next;
          else
            break;
        }

        prev->next = fl;
      } else
        readOnlyGlobals.pcapFileList = fl;
    }

    fclose(fd);
  } else
    traceEvent(TRACE_ERROR, "Unable to open file %s", optarg);
}

/* ****************************************************** */

/**
 * Parse a port list 2055,2056,...
 */
static void parse_port_list(char *port_list, listener_list *list) {
  char *strtok_aux = NULL;
  const char *sport = NULL;

  assert(port_list);
  assert(list);

  for (sport = strtok_r(port_list, ",", &strtok_aux); sport;
       sport = strtok_r(NULL, ",", &strtok_aux)) {
    char *strtol_end = NULL;
    unsigned long lport = strtol(sport, &strtol_end, 10);
    if (*strtol_end != '\0' || lport > 0xffff) {
      traceEvent(TRACE_ERROR, "Invalid port %s, can't listen there", sport);
      continue;
    }
    struct port_collector *collector = createNetFlowListener(UDP, lport);
    listener_list_append(list, collector);
  }
}

static void initDefaults(void) {
  /* Set defaults */
#ifdef HAVE_GEOIP
  readOnlyGlobals.geo_ip_asn_db = NULL;
#endif
  readOnlyGlobals.snaplen = PCAP_DEFAULT_SNAPLEN;
  readOnlyGlobals.pcapFileList = NULL;
  readOnlyGlobals.pcapFile = NULL;
  readOnlyGlobals.unprivilegedUser = strdup("nobody");

#ifdef HAVE_PF_RING
  readOnlyGlobals.cluster_id = -1;
#endif

  pthread_rwlock_init(&readOnlyGlobals.rb_databases.mutex,0);
}

static void printArgv(int argc,char *argv[]){
  int i;
  for(i=0; i<argc; i++)
    traceEvent(TRACE_ERROR, "[%d][%s]", i, argv[i]);
}

static int parseOptions(int argc, char* argv[], uint8_t reparse_options) {
  char line[2048];
  FILE *fd;
  int opt, i, option_index;
  char *strtok_aux = NULL, *collector_ports = NULL;
#ifdef HAVE_ZOOKEEPER
  char *new_zk_host = NULL;
#endif
#ifdef HAVE_LIBRDKAFKA
  readOnlyGlobals.kafka.use_client_mac_partitioner = 1;
  char *kafka_topic=NULL,*kafka_brokers=NULL;
  rd_kafka_conf_t *rk_conf        = rd_kafka_conf_new();
  rd_kafka_topic_conf_t *rkt_conf = rd_kafka_topic_conf_new();
#endif
#ifdef HAVE_UDNS
  char *new_dns_servers = NULL;
  size_t dns_cache_size_mb = 0;
  time_t dns_cache_timeout_s = 0;
#endif

  if(!reparse_options)
    initDefaults();

  int reload_sensors_info = 0;

  optind = 0;
#ifdef HAVE_OPTRESET
  optreset = 1; /* Make sure getopt read options again */
#endif

  readOnlyGlobals.argc = 0;
  if(reparse_options && readOnlyGlobals.argv)
        free(readOnlyGlobals.argv);
  readOnlyGlobals.argv = (char**)malloc(sizeof(char*)*MAX_NUM_OPTIONS);
  memset(readOnlyGlobals.argv, 0, sizeof(char*)*MAX_NUM_OPTIONS);

  if(readOnlyGlobals.argv == NULL) return(-1);

  if((argc == 2) && (argv[1][0] != '-')) {
    char *tok, cont=1;

    fd = fopen(argv[1], "r");

    if(fd == NULL) {
      traceEvent(TRACE_ERROR, "Unable to read config. file %s", argv[1]);
      exit(-1);
    }

    readOnlyGlobals.argv[readOnlyGlobals.argc++] = strdup("f2k");

    while(cont && fgets(line, sizeof(line), fd)) {
      /* printf("line='%s'\n", line); */

      /*
        Config files accept both
        <option>=<value>
        and
        <option> <value>
      */
      i = 0;
      while(line[i] != '\0') {
        if(line[i] == '=')
          break;
        else if(line[i] == ' ') {
          line[i] = '=';
          break;
        }

        i++;
      }

      tok = strtok_r(line, "=", &strtok_aux);
      while(tok != NULL) {
        int len;
        char *argument;

        if(readOnlyGlobals.argc >= MAX_NUM_OPTIONS) {
          traceEvent(TRACE_ERROR, "Command line too long [%u arguments]", readOnlyGlobals.argc);
          printArgv(readOnlyGlobals.argc,readOnlyGlobals.argv);

          cont = 0; break;
        }

        len = strlen(tok)-1;
        if(tok[len] == '\n') tok[len] = '\0';

        if((tok[0] == '\"') && (tok[strlen(tok)-1] == '\"')) {
          tok[strlen(tok)-1] = '\0';
          argument = &tok[1];
        } else
          argument = tok;

        if(argument && (argument[0] != '\0')) {
          /* traceEvent(TRACE_NORMAL, "readOnlyGlobals.argv[%d]='%s'", readOnlyGlobals.argc, argument); */
          readOnlyGlobals.argv[readOnlyGlobals.argc++] = strdup(argument);
        }

        tok = strtok_r(NULL, "\n", &strtok_aux);
      }
    }

    fclose(fd);
  } else {
    if(reparse_options) {
      traceEvent(TRACE_WARNING, "Command line options can be reloaded only when");
      traceEvent(TRACE_WARNING, "the probe is started from a configuration file");
      traceEvent(TRACE_WARNING, "Please use f2k <configuration file>");
      return(-1);
    }

    if(argc >= MAX_NUM_OPTIONS)
      readOnlyGlobals.argc = MAX_NUM_OPTIONS-1;
    else
      readOnlyGlobals.argc = argc;

    /* Copy arguments */
    for(i=0; i<readOnlyGlobals.argc; i++) {
      readOnlyGlobals.argv[i] = strdup(argv[i]);
    }
  }

  optarg = NULL;

  // readOnlyGlobals.enable_debug = 1;

  if(unlikely(readOnlyGlobals.enable_debug)) {
    traceEvent(TRACE_NORMAL, "argc: %d", readOnlyGlobals.argc);

    for(i=0; i<readOnlyGlobals.argc; i++)
      traceEvent(TRACE_NORMAL, "%2d: %s", i, readOnlyGlobals.argv[i]);
  }

  while((opt = getopt_long(readOnlyGlobals.argc, readOnlyGlobals.argv,
                           "A:ab:B:"
                           "e:g:hi:I:"
                           "n:O:s:S:T:u:U:x:vz:"
                           "G"
#ifdef HAVE_LIBRDKAFKA
                           "X:p"
#endif
#ifdef HAVE_ZOOKEEPER
                           "Z:"
#endif
#ifdef HAVE_UDNS
                           "d:c:t:"
#endif
#if defined(linux) || defined(__linux__)
                           "4:"
#endif
                           "2:a:"
                           "6!:"
                           "$:\\"
                           "\xfc:" /* 252 */
                           ,
                           long_options,
                           &option_index
                           )) != EOF) {
    if(reparse_options) {
      bool discard_option;

      switch(opt) {
      case 'b':
      case 'l':
      case 's':
      case 'S':
      case '7':
      case '+':
      case 'A': /* as-list */
      case ',': /* city-list */
      case 259: /* country-list */
      case 229: /* kafka opts */
      case 'X': /* kafka modifiers */
      case 256: /* hosts-list options */
      case 258: /* rb-config file */
      case 'z': /* zk-host */
      case 262: /* zk-timeout */
      case '3': /* collector port */
        discard_option = false;
        break;

      default:
        discard_option = true;
      }

      if(discard_option) {
        traceEvent(TRACE_WARNING, "The %s(%d/%c) option cannot be modified at runtime: ignored",
          long_options[option_index].name, opt, isprint(opt) ? opt : '.');
        continue;
      }
    }

    switch(opt) {
    case '2':
      readOnlyGlobals.capture_num_packet_and_quit = atoi(optarg);
      break;
    case '3':
      collector_ports = strdup(optarg);
      break;
#ifdef linux
    case '4':
      readOnlyGlobals.cpuAffinity = strdup(optarg);
      break;
#endif
    case '6':
      readOnlyGlobals.promisc_mode = 0;
      break;
    case '$':
      readPcapFileList(optarg);
      break;
    case '\\':
      readOnlyGlobals.do_not_drop_privileges = 1;
      break;
    case ',':
      readOnlyGlobals.rb_databases.geoip_cities_database_path = optarg;
      if(reparse_options)
        readOnlyGlobals.rb_databases.reload_geoip_database = 1;
      break;
    case 259:
      readOnlyGlobals.rb_databases.geoip_country_database_path = optarg;
      if(reparse_options)
        readOnlyGlobals.rb_databases.reload_geoip_database = 1;
      break;

    case '+':
      {
        char *old = readOnlyGlobals.eventLogPath;

        readOnlyGlobals.eventLogPath = strdup(optarg);
        if(old == NULL) free(old);
      }
      break;

    case 'A':
      readOnlyGlobals.rb_databases.geoip_as_database_path = optarg;
      if(reparse_options)
        readOnlyGlobals.rb_databases.reload_geoip_database = 1;
      // readASs(optarg);
      break;

    case 249:
      readOnlyGlobals.rb_databases.mac_vendor_database_path = optarg;
      readOnlyGlobals.rb_databases.reload_macs_vendor_database = 1;
      break;

    case 'b':
      i = atoi(optarg);
      if(i > 2) i = 2;
      switch(i) {
      case 1:
        readOnlyGlobals.traceLevel = 5;
        break;
      case 2:
        readOnlyGlobals.traceLevel = 5;
        break;
      case 0:
      default:
        readOnlyGlobals.traceLevel = 2;
        break;
      }
      break;

    case 'g':
      readOnlyGlobals.pidPath = strdup(optarg);
      break;

    case 256:
      if(reparse_options)
        free(readOnlyGlobals.rb_databases.hosts_database_path);

      readOnlyGlobals.rb_databases.hosts_database_path = strdup(optarg);
      /* we will load databases when needed, in printRecordWithTemplate, so we avoid a
       * failure if we change this value while we are searching a value
       */
      readOnlyGlobals.rb_databases.reload_hosts_database   =
      readOnlyGlobals.rb_databases.reload_nets_database    =
      readOnlyGlobals.rb_databases.reload_vlans_database   =
      readOnlyGlobals.rb_databases.reload_apps_database    =
      readOnlyGlobals.rb_databases.reload_engines_database =
      readOnlyGlobals.rb_databases.reload_domains_database =
      readOnlyGlobals.rb_databases.reload_os_database      =
      readOnlyGlobals.rb_databases.reload_macs_database    =
      1;
      break;

    case 257:
      strncpy(readOnlyGlobals.templates_database_path,optarg,sizeof(readOnlyGlobals.templates_database_path));
      break;

    case 258: /* RB_CONFIG */
      // if(reparse_options)
      //   delete_rb_sensors_db(readOnlyGlobals.rb_databases.sensors_info);
      // readOnlyGlobals.rb_databases.sensors_info = read_rb_config(optarg);
      if(readOnlyGlobals.rb_databases.sensors_info_path)
        free(readOnlyGlobals.rb_databases.sensors_info_path);
      readOnlyGlobals.rb_databases.sensors_info_path = strdup(optarg);
      reload_sensors_info = 1;
      break;

    case 'O':
      readOnlyGlobals.numProcessThreads = atoi(optarg);
      if(readOnlyGlobals.numProcessThreads > MAX_NUM_PCAP_THREADS) {
        traceEvent(TRACE_ERROR, "You can spawn at most %d threads.",
                   MAX_NUM_PCAP_THREADS);
        readOnlyGlobals.numProcessThreads = MAX_NUM_PCAP_THREADS;
      }

      if(readOnlyGlobals.numProcessThreads <= 0) readOnlyGlobals.numProcessThreads = 1;
      break;

    case 'h':
      usage(1);
      return(-1);

    case 'i':
      {
        if(readOnlyGlobals.captureDev != NULL) free(readOnlyGlobals.captureDev);
        readOnlyGlobals.captureDev = strdup(optarg);
      }
      break;

    case 'G':
      readOnlyGlobals.becomeDaemon = true;
      break;

    case 's':
      {
        size_t snaplen = (size_t)atoi(optarg);

        if(snaplen <= 0) snaplen = SIZE_MAX; /* We set it to the maximum snaplen */

        if(snaplen < 64) {
          readOnlyGlobals.snaplen = 64;
          traceEvent(TRACE_WARNING, "The minimum snaplen is %u", readOnlyGlobals.snaplen);
        } else if(snaplen > SIZE_MAX) {
          readOnlyGlobals.snaplen = (uint16_t)-1;
          traceEvent(TRACE_WARNING, "The maximum snaplen is %u", readOnlyGlobals.snaplen);
        } else
          readOnlyGlobals.snaplen = snaplen;
      }
      break;

    case 'S':
      break; // Do nothing, at the moment

#ifdef HAVE_PF_RING
    case 'Z':
      if((readOnlyGlobals.cluster_id = atoi(optarg)) == 0) {
        readOnlyGlobals.cluster_id = 1;
        traceEvent(TRACE_WARNING, "--cluster-id must be a positive number: setting it to %d",
                   readOnlyGlobals.cluster_id);
      }
      break;
#endif

    case 'v':
      probeVersion();
      exit(0);

    case 'I':
      {
        size_t len = strlen(optarg), max_len = sizeof(readOnlyGlobals.f2kId)-1;

        if(len >= max_len) len = max_len;
        strncpy(readOnlyGlobals.f2kId, optarg, len);
        readOnlyGlobals.f2kId[len] = '\0';
        readOnlyGlobals.useSyslog = 1;
      }
      break;

#ifdef HAVE_LIBRDKAFKA
    case 'p':
      readOnlyGlobals.kafka.use_client_mac_partitioner = 0;
      break;

    case 229:
      {
        char *strtok_kafka_aux=NULL;
        char *_optarg = strdup(optarg);

        kafka_brokers = strtok_r(_optarg, "@",&strtok_kafka_aux);
        kafka_topic = strtok_r(NULL,"",&strtok_kafka_aux);

        if(kafka_brokers && kafka_topic) {
          kafka_brokers = strdup(kafka_brokers);
          kafka_topic = strdup(kafka_topic);
        } else {
          traceEvent(TRACE_ERROR, "Invalid format for --kafka parameter");
          usage(0);
          kafka_brokers = NULL;
          kafka_topic = NULL;
        }

        free(_optarg);
      }
      break;

    case 'X':
      parse_kafka_config(rk_conf,rkt_conf,optarg);
      break;

#endif /* HAVE_LIBRDKAFKA */
#ifdef HAVE_ZOOKEEPER
    case 'z':
      new_zk_host = strdup(optarg);
      break;

    case 262:
      readOnlyGlobals.zk.update_template_timeout = atoi(optarg);
      break;
#endif

#ifdef HAVE_UDNS
    case 'd':
      new_dns_servers = strdup("");
      break;

    case 'c':
      dns_cache_size_mb = atoi(optarg); /// @TODO use error safe functions
      break;

    case 't':
      dns_cache_timeout_s = atoi(optarg);
      break;
#endif

    case 235:
      readOnlyGlobals.reforgeTimestamps = 0;
      break;

    case 237:
      readOnlyGlobals.reproduceDumpAtRealSpeed = 1;
      break;

    case 244:
      free(readOnlyGlobals.unprivilegedUser);
      readOnlyGlobals.unprivilegedUser = strdup(optarg);
      break;

    case 248:
      readOnlyGlobals.tracePerformance = 1;
      break;

    case 254:
      readOnlyGlobals.enable_debug = 1;
      break;

    case 260:
      readOnlyGlobals.separate_long_flows = 1;
      break;

    case 261:
      readOnlyGlobals.dontReforgeFarTimestamp = 1;
      break;

    default:
      traceEvent(TRACE_ERROR,"Unknown parameter %c",opt);
      break;
    }
  }

  if (collector_ports) {
    listener_list new_listeners_list;
    listener_list_init(&new_listeners_list);

    parse_port_list(collector_ports, &new_listeners_list);

    mergeNetFlowListenerList(&readOnlyGlobals.listeners,&new_listeners_list);
    wakeUpListenerList(&readOnlyGlobals.listeners);
  }

#ifdef HAVE_LIBRDKAFKA
  if(kafka_brokers && kafka_topic) {
    rd_kafka_t *rk = NULL,*rk_old=NULL;
    rd_kafka_topic_t *rkt = NULL,*rkt_old=NULL;
    /* @TODO duplicated code in main function. rd_kafka_new cannot be called before daemon fork(), because
     * then the child process cannot make calls to kafka thread.
     */

    char errstr[2048];

    // @TODO workaround. Allow pass kafka parameters.
    parse_kafka_config(rk_conf, rkt_conf, "socket.keepalive.enable=true");
    parse_kafka_config(rk_conf, rkt_conf, "socket.max.fails=3");
    if(readOnlyGlobals.kafka.use_client_mac_partitioner)
      rd_kafka_topic_conf_set_partitioner_cb(rkt_conf, rb_client_mac_partitioner);
    // @TODO end of workaround


    rk = rd_kafka_new(RD_KAFKA_PRODUCER, rk_conf, errstr, sizeof(errstr));
    if(NULL == rk){
      traceEvent(TRACE_ERROR, "Unable to connect to kafka brokers %s:%s",
        kafka_brokers,errstr);
    } else {
      rk_conf = NULL;
    }

    if (rk != NULL && rd_kafka_brokers_add(rk, kafka_brokers) == 0) {
      traceEvent(TRACE_ERROR, "No valid kafka brokers specified: %s\n",kafka_brokers);
      rd_kafka_destroy(rk);
      rk = NULL;
    }

    if(rk != NULL){
      rkt = rd_kafka_topic_new(rk, kafka_topic, rkt_conf);
      if(rkt != NULL){
        rkt_conf = NULL;
      } else {
        traceEvent(TRACE_ERROR, "Unable to create a kafka topic");
        rd_kafka_destroy(rk);
        rk = NULL;
      }
    }

    rk_old = readWriteGlobals->kafka.rk;
    rkt_old = readWriteGlobals->kafka.rkt;

    /* Can't create new handlers */
    if(rk == NULL && rkt == NULL) {
      /* First running: Can't connect */
      if(NULL == rk_old && NULL == rkt_old) {
        traceEvent(TRACE_ERROR, "No valid kafka brokers specified => Can't start f2k");
        exit(-1);
      } else {
        traceEvent(TRACE_ERROR, "No valid kafka brokers specified => Using values before reload");
      }
    } else {
      pthread_rwlock_wrlock(&readWriteGlobals->kafka.rwlock);
      readWriteGlobals->kafka.rk = rk;
      readWriteGlobals->kafka.rkt = rkt;
      pthread_rwlock_unlock(&readWriteGlobals->kafka.rwlock);
    }

    if(NULL != rk_old)
      rd_kafka_destroy(rk_old);
    if(NULL != rkt_old)
      rd_kafka_topic_destroy(rkt_old);
    if(NULL != rk_conf)
      rd_kafka_conf_destroy(rk_conf);
    if(NULL != rkt_conf)
      rd_kafka_topic_conf_destroy(rkt_conf);
  }

  free(kafka_brokers);
  free(kafka_topic);
#endif

#ifdef HAVE_UDNS
  if(new_dns_servers) {
    /* Have to create a new DNS context */

    readOnlyGlobals.udns.csv_dns_servers = strdup(new_dns_servers);
    if(NULL == readOnlyGlobals.udns.csv_dns_servers) {
      traceEvent(TRACE_ERROR,"Memory error, can't strdup");
      goto udns_config_err;
    }

    dns_init(&dns_defctx,0 /* don't do_open */);

    readOnlyGlobals.udns.dns_poll_threads = calloc(readOnlyGlobals.numProcessThreads,
      sizeof(readOnlyGlobals.udns.dns_poll_threads[0]));
    if(NULL == readOnlyGlobals.udns.dns_poll_threads) {
      traceEvent(TRACE_ERROR,"Can't allocate DNS polling threads");
      free(readOnlyGlobals.udns.csv_dns_servers);
      readOnlyGlobals.udns.csv_dns_servers = NULL;
    }
    readOnlyGlobals.udns.dns_info_array = calloc(readOnlyGlobals.numProcessThreads,
      sizeof(readOnlyGlobals.udns.dns_info_array[0]));
    if(NULL == readOnlyGlobals.udns.dns_info_array) {
      traceEvent(TRACE_ERROR,"Can't allocate DNS polling threads context");
      free(readOnlyGlobals.udns.dns_poll_threads);
      free(readOnlyGlobals.udns.csv_dns_servers);
      readOnlyGlobals.udns.csv_dns_servers = NULL;
    }
    size_t dns_idx=0;
    for(dns_idx=0; NULL!=readOnlyGlobals.udns.dns_poll_threads && readOnlyGlobals.udns.dns_info_array
            && dns_idx<readOnlyGlobals.numProcessThreads;++dns_idx) {
      static const char *thread_name=NULL;
      static const pthread_attr_t *attr=NULL;

      struct rb_dns_info *info = &readOnlyGlobals.udns.dns_info_array[dns_idx];

#ifdef RB_DNS_MAGIC
      info->magic = RB_DNS_MAGIC;
#endif

      info->dns_ctx = dns_new(&dns_defctx);
      if(NULL == info->dns_ctx) {
        traceEvent(TRACE_ERROR,"Can't allocate DNS context %zu info", dns_idx);

      }

      const int thread_create_rc = rd_thread_create(&readOnlyGlobals.udns.dns_poll_threads[dns_idx],
        thread_name,attr,udns_pool_routine,info);

      if(thread_create_rc < 0) {
        char errstr[BUFSIZ];
        strerror_r(errno,errstr,sizeof(errstr));
        traceEvent(TRACE_ERROR,"Can't allocate DNS polling thread %zu: %s",
          dns_idx, errstr);
      }
    }
  }

  if(dns_cache_size_mb > 0) {
    /// @TODO reload
    readOnlyGlobals.udns.cache = dns_cache_new(dns_cache_size_mb,dns_cache_timeout_s);
    if(NULL == readOnlyGlobals.udns.cache) {
      traceEvent(TRACE_ERROR,"Can't allocate a DNS cache (out of memory?)");
    }
  }

  free(new_dns_servers);
udns_config_err:
#endif

  if (!reparse_options) {
    size_t idx = 0;
    /* Start a pool of threads */
    if((readOnlyGlobals.packetProcessThread = calloc(
                      readOnlyGlobals.numProcessThreads,
                      sizeof(readOnlyGlobals.packetProcessThread[0]))) == NULL) {
      traceEvent(TRACE_ERROR, "Not enough memory?");
      return(0);
    }

    for(idx=0;idx<readOnlyGlobals.numProcessThreads;++idx){
      readOnlyGlobals.packetProcessThread[idx] = new_collect_worker();
    }
  }

  if(reload_sensors_info == 1) {
    if(unlikely(readOnlyGlobals.enable_debug))
      traceEvent(TRACE_NORMAL,"reloading sensors info");
    pthread_rwlock_wrlock(&readOnlyGlobals.rb_databases.mutex);
    if(readOnlyGlobals.rb_databases.sensors_info)
      delete_rb_sensors_db(readOnlyGlobals.rb_databases.sensors_info);
    readOnlyGlobals.rb_databases.sensors_info = read_rb_config(
           readOnlyGlobals.rb_databases.sensors_info_path,
           readOnlyGlobals.packetProcessThread,
           readOnlyGlobals.numProcessThreads);
    reload_sensors_info = 0;
    pthread_rwlock_unlock(&readOnlyGlobals.rb_databases.mutex);
  }

#ifdef HAVE_ZOOKEEPER
  pthread_rwlock_wrlock(&readOnlyGlobals.zk.rwlock);
  if(readOnlyGlobals.zk.zk_host && (NULL == new_zk_host || 0!=strcmp(readOnlyGlobals.zk.zk_host,new_zk_host))) {
    /* Have to create a new ZK handler */
    stop_f2k_zk();
  }

  if(new_zk_host && (NULL == readOnlyGlobals.zk.zk_host)) {
    /* Exists a old zk handler, and we have changed hosts (or deleted them). Have to free */
    init_f2k_zk(new_zk_host);
  }
  pthread_rwlock_unlock(&readOnlyGlobals.zk.rwlock);
#endif

  if(reparse_options) return(0);

  if(unlikely(readOnlyGlobals.enable_debug)) {
    // readOnlyGlobals.numProcessThreads = 1;
  }

  if((readOnlyGlobals.captureDev != NULL)
     && (readOnlyGlobals.pcapFileList != NULL)) {
    traceEvent(TRACE_NORMAL, "-i is ignored as --pcap-file-list has been used");
    free(readOnlyGlobals.captureDev);
    readOnlyGlobals.captureDev = NULL;
  }

  traceEvent(TRACE_NORMAL, "Welcome to f2k v.%s (%s) for %s %s",
             version, f2k_revision, osName,
#ifdef HAVE_PF_RING
             "with native PF_RING acceleration"
#else
             ""
#endif
             );

#ifdef linux
  setCpuAffinity(readOnlyGlobals.cpuAffinity);
#endif

  return(0);
}

/* ****************************************************** */

static void stopCaptureFlushAll(void) {
  size_t i;

  readWriteGlobals->stopPacketCapture = 1;
  traceEvent(TRACE_INFO, "nProbe is shutting down...");

#ifdef HAVE_PF_RING
  if(readWriteGlobals->ring) {
    int num = 0;
    pfring_breakloop(readWriteGlobals->ring);
    traceEvent(TRACE_NORMAL, "Waiting for PF_RING termination");

    while(readWriteGlobals->ring_enabled) {
      if(++num == 3)
        break;
      else
        sleep(1);
    }

    traceEvent(TRACE_NORMAL, "PF_RING terminated");

    pfring_close(readWriteGlobals->ring);
    readWriteGlobals->ring = NULL;
  }
#endif

#ifdef HAVE_NETFILTER
  if(readOnlyGlobals.nf.h != NULL) {
    traceEvent(TRACE_NORMAL, "Terminating netfilter...");
    nfq_destroy_queue(readOnlyGlobals.nf.qh);
    nfq_close(readOnlyGlobals.nf.h);
    readOnlyGlobals.nf.fd = 0;
  }
#endif

  readWriteGlobals->shutdownInProgress = 1;

  printProcessingStats();

  for(i=0;i<readOnlyGlobals.numProcessThreads;++i) {
    collect_worker_done(readOnlyGlobals.packetProcessThread[i]);
  }
  free(readOnlyGlobals.packetProcessThread);

#ifdef HAVE_LIBRDKAFKA
  if(readWriteGlobals->kafka.rk) {
    /* Steps of librdkafka wiki */

    /* 1) Make sure all outstanding requests are transmitted and handled. */
    traceEvent(TRACE_INFO, "Flushing pending kafka messages...");
    while (rd_kafka_outq_len(readWriteGlobals->kafka.rk) > 0) {
      rd_kafka_poll(readWriteGlobals->kafka.rk, 50);
    }

    /* 2) Destroy the topic and handle objects */
    rd_kafka_topic_destroy(readWriteGlobals->kafka.rkt);
    rd_kafka_destroy(readWriteGlobals->kafka.rk);

    traceEvent(TRACE_INFO, "Disconnected from Kafka ...");
  }
#endif

  if(readOnlyGlobals.rb_databases.sensors_info)
    delete_rb_sensors_db(readOnlyGlobals.rb_databases.sensors_info);
  rb_destroy_mac_vendor_db(readOnlyGlobals.rb_databases.mac_vendor_database);

  traceEvent(TRACE_INFO, "Deleting hosts names...");
  freeHostsList(readOnlyGlobals.rb_databases.ip_name_as_list);
  freeHostsList(readOnlyGlobals.rb_databases.nets_name_as_list);
  if(readOnlyGlobals.rb_databases.apps_name_as_list)
    deleteNumNameAssocTree(readOnlyGlobals.rb_databases.apps_name_as_list);
  freeHostsList(readOnlyGlobals.rb_databases.engines_name_as_list);
  freeHostsList(readOnlyGlobals.rb_databases.domains_name_as_list);
  free(readOnlyGlobals.rb_databases.hosts_database_path);

}

/* ****************************************************** */

static void term_pcap(pcap_t **p) {
  if(p == NULL) return;

  if(readOnlyGlobals.pcapFile) {
    pcap_close(*p);
    /*
      No clue why sometimes it crashes
      so we free only when reading .pcap dump files
    */
    free(readOnlyGlobals.pcapFile);
    readOnlyGlobals.pcapFile = NULL;
  }

  *p = NULL;

  /* No unlock */
}

/* ****************************************************** */

static void shutdown_f2k(void) {
  static bool once = false;
  int i;
  size_t ui;

  if(once) return; else once = true;

  stopCaptureFlushAll();

  // ntop_sleep(1);
  traceEvent(TRACE_INFO, "Freeing memory...\n");

  unload_mappings();

  if(readOnlyGlobals.pcapPtr) {
    printPcapStats(readOnlyGlobals.pcapPtr);
    term_pcap(&readOnlyGlobals.pcapPtr);
    readOnlyGlobals.pcapPtr = NULL;
  }

  if(readOnlyGlobals.captureDev != NULL) free(readOnlyGlobals.captureDev);

  if(readOnlyGlobals.useSyslog)
    closelog();

  if(readOnlyGlobals.argv) {
    for(i=0; i<readOnlyGlobals.argc; i++)
      free(readOnlyGlobals.argv[i]);

    free(readOnlyGlobals.argv);
  }

  /* Clean globals */
  traceEvent(TRACE_INFO, "Cleaning globals");

  free(readOnlyGlobals.unprivilegedUser);

  // free(readOnlyGlobals.packetProcessThread);

  if(readOnlyGlobals.tracePerformance)
    printProcessingStats();

  if(readOnlyGlobals.pidPath) {
    const int rc = unlink(readOnlyGlobals.pidPath);
    if( rc != 0 ) {
        traceEvent(TRACE_ERROR,"Can't unlink %s: %s",
                readOnlyGlobals.pidPath,strerror(errno));
    }
  }

  traceEvent(TRACE_INFO, "nProbe terminated.");
  dumpLogEvent(probe_stopped, severity_info, "nProbe stopped");
  if(readOnlyGlobals.eventLogPath) free(readOnlyGlobals.eventLogPath);

#ifdef HAVE_GEOIP
  deleteGeoIPDatabases();
#endif

#ifdef HAVE_ZOOKEEPER
  zookeeper_close(readOnlyGlobals.zk.zh);
  pthread_rwlock_destroy(&readOnlyGlobals.zk.rwlock);
#endif

#ifdef HAVE_UDNS
  for(ui=0;NULL!=readOnlyGlobals.udns.dns_info_array
      && ui<readOnlyGlobals.numProcessThreads; ++ui) {
    dns_free(readOnlyGlobals.udns.dns_info_array[ui].dns_ctx);
  }
  free(readOnlyGlobals.udns.dns_info_array);
#endif

  free(readWriteGlobals); /* Do not move it up as it's needed for logging */

  endpwent();

  exit(0);
}

/* ******************************************* */

#ifdef HAVE_NETFILTER
static int netfilter_callback(struct nfq_q_handle *qh,
                              struct nfgenmsg *nfmsg,
                              struct nfq_data *nfa,
                              void *data) {
  char *payload;
  size_t payload_len;
  uint32_t id;
  struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
  int last_rcvd_packet_id, rc;

  last_rcvd_packet_id = ph ? ntohl(ph->packet_id) : 0;
  payload_len = nfq_get_payload(nfa, &payload);
  /* Set defaults */
  readOnlyGlobals.nf.nf_verdict = NF_ACCEPT, readOnlyGlobals.nf.nf_mark = 0;

  if((payload_len > 0) && (payload != NULL)) {
    struct pcap_pkthdr h;

    h.len = h.caplen = payload_len, gettimeofday(&h.ts, NULL);

    decodePacket(readOnlyGlobals.nf.thread_id,,
                 &h, payload,
                 0 /* Unknown sender */);

  }

  if(unlikely(readOnlyGlobals.enable_debug))
    traceEvent(TRACE_NORMAL, "[NetFilter] [packet len: %u][verdict: %u][nf_mark: %u]",
               payload_len, readOnlyGlobals.nf.nf_verdict, readOnlyGlobals.nf.nf_mark);

  rc = nfq_set_verdict_mark(readOnlyGlobals.nf.qh, last_rcvd_packet_id,
                            readOnlyGlobals.nf.nf_verdict,
                            htonl(readOnlyGlobals.nf.nf_mark), 0, NULL);

  return(rc);
}
#endif

/* ******************************************* */

static int attachToNetFilter(void) {
#ifdef HAVE_NETFILTER
  if(readOnlyGlobals.captureDev
     && (strncmp(readOnlyGlobals.captureDev, "nf:", 3) == 0)) {

    readOnlyGlobals.nf.queueId = atoi(&readOnlyGlobals.captureDev[3]);

    readOnlyGlobals.nf.h = nfq_open();
    if(readOnlyGlobals.nf.h == NULL) {
      traceEvent(TRACE_ERROR, "Error during netfilter initialization");
      exit(1);
    }

    /* Unbinding existing nf_queue handler for AF_INET (if any) */
    if(nfq_unbind_pf(readOnlyGlobals.nf.h, AF_INET) < 0) {
      traceEvent(TRACE_ERROR, "Error during nfq_unbind_pf()");
      exit(1);
    }

    /* Binding nfnetlink_queue as nf_queue handler for AF_INET */
    if(nfq_bind_pf(readOnlyGlobals.nf.h, AF_INET) < 0) {
      traceEvent(TRACE_ERROR, "Error during nfq_bind_pf()");
      exit(1);
    }

#if 0
    /* Binding nfnetlink_queue as nf_queue handler for AF_INET6 */
    if(nfq_bind_pf(readOnlyGlobals.nf.h, AF_INET6) < 0) {
      traceEvent(TRACE_ERROR, "Error during nfq_bind_pf()");
      exit(1);
    }
#endif

    /* Binding this socket to queue 'queueId' */
    readOnlyGlobals.nf.qh = nfq_create_queue(readOnlyGlobals.nf.h,
                                             readOnlyGlobals.nf.queueId,
                                             &netfilter_callback, NULL);
    if(readOnlyGlobals.nf.qh == NULL) {
      traceEvent(TRACE_ERROR, "Error during attach to queue %d: is it configured?",
                 readOnlyGlobals.nf.queueId);
      exit(1);
    }

    if(nfq_set_mode(readOnlyGlobals.nf.qh, NFQNL_COPY_PACKET,
                    readOnlyGlobals.snaplen /* IP_MAXPACKET */) < 0) {
      traceEvent(TRACE_ERROR, "Can't set packet_copy mode");
      exit(1);
    }

    readOnlyGlobals.nf.fd = nfq_fd(readOnlyGlobals.nf.h);
  } else {
    readOnlyGlobals.nf.fd = -1;
    return(-2);
  }
#else
  return(-1);
#endif
}

/* ******************************************* */

static int openDevice(char ebuf[], int printErrors, char *pcapFilePath) {
  bool open_device = true;

  traceEvent(TRACE_NORMAL, "Using packet capture length %u", readOnlyGlobals.snaplen);

  if((readOnlyGlobals.captureDev != NULL)
     && (strcmp(readOnlyGlobals.captureDev, "none") == 0)) {
    readOnlyGlobals.do_not_drop_privileges = 1;
    return(0);
  }

  if(attachToNetFilter() < 0) {
    if(readOnlyGlobals.captureDev != NULL) {
      /* Try if the passed device is instead a dump file */

      readOnlyGlobals.pcapPtr = pcap_open_offline(readOnlyGlobals.captureDev, ebuf);
      if(readOnlyGlobals.pcapPtr != NULL) {
        readOnlyGlobals.pcapFile = strdup(readOnlyGlobals.captureDev);
        readOnlyGlobals.snaplen = PCAP_LONG_SNAPLEN;
      }
    } else if(pcapFilePath != NULL) {
      if(readOnlyGlobals.pcapPtr != NULL) {
        term_pcap(&readOnlyGlobals.pcapPtr);
        readOnlyGlobals.pcapPtr = NULL;
      }

      readOnlyGlobals.pcapPtr = pcap_open_offline(pcapFilePath, ebuf);
      if(readOnlyGlobals.pcapPtr != NULL) {
        traceEvent(TRACE_NORMAL, "Processing packets from file %s", pcapFilePath);
        readOnlyGlobals.pcapFile = strdup(pcapFilePath);
        readOnlyGlobals.snaplen = PCAP_LONG_SNAPLEN;
      } else
        return(-1);
    } else
      readOnlyGlobals.pcapPtr = NULL;

    if(readOnlyGlobals.pcapPtr == NULL) {
      /* Find the default device if not specified */
      if(readOnlyGlobals.captureDev == NULL) {
        readOnlyGlobals.captureDev = pcap_lookupdev(ebuf);
        if(readOnlyGlobals.captureDev == NULL) {
          if(printErrors)
            traceEvent(TRACE_ERROR,
                       "Unable to locate default interface (%s)\n", ebuf);
          return(-1);
        } else {
          char *_captureDev = strdup(readOnlyGlobals.captureDev);
          readOnlyGlobals.captureDev = _captureDev;
        }
      }

#ifdef HAVE_PF_RING
      readWriteGlobals->ring = open_ring(readOnlyGlobals.captureDev, &open_device, 0);
#endif

      if(open_device) {
        readOnlyGlobals.pcapPtr = pcap_open_live(readOnlyGlobals.captureDev,
                                                 readOnlyGlobals.snaplen,
                                                 readOnlyGlobals.promisc_mode /* promiscuous mode */,
                                                 1000 /* ms */,
                                                 ebuf);

        if(readOnlyGlobals.pcapPtr == NULL)  {
          if(printErrors)
            traceEvent(TRACE_ERROR, "Unable to open interface %s.\n", readOnlyGlobals.captureDev);

          if((getuid () && geteuid ()) || setuid (0)) {
            if(printErrors) {
              traceEvent(TRACE_ERROR, "nProbe opens the network interface "
                         "in promiscuous mode, ");
              traceEvent(TRACE_ERROR, "so it needs root permission "
                         "to run. Quitting...");
            }
          }
          return(-1);
        }
      }
    }
  }

#ifdef HAVE_PF_RING
  if(readWriteGlobals->ring != NULL)
    readOnlyGlobals.datalink = DLT_EN10MB;
#endif
#ifdef HAVE_NETFILTER
  if(readOnlyGlobals.nf.fd >= 0) {
    readOnlyGlobals.datalink = DLT_RAW;

    if(readOnlyGlobals.netFilter != NULL) {
      free(readOnlyGlobals.netFilter);
      readOnlyGlobals.netFilter = NULL;
    }
  }
#endif

  if(readOnlyGlobals.pcapPtr != NULL)
    readOnlyGlobals.datalink = pcap_datalink(readOnlyGlobals.pcapPtr);

  return(0);
}

/* ****************************************************** */

static int restoreInterface(char ebuf[]) {
  if(readOnlyGlobals.pcapFile == NULL) {
    int rc = -1;

    if(readOnlyGlobals.pcapPtr != NULL)
      traceEvent(TRACE_INFO, "Error while capturing packets: %s", pcap_geterr(readOnlyGlobals.pcapPtr));
    traceEvent(TRACE_INFO, "Waiting until the interface comes back...");

    while(rc == -1) {
      ntop_sleep(1);
      rc = openDevice(ebuf, 0, NULL);
    }

    traceEvent(TRACE_INFO, "The interface is now available again.");
    return(rc);
  }

  return(-2);
}

/* ****************************************************** */

#ifndef HAVE_PCAP_NEXT_EX
int pcap_next_ex(pcap_t *p, struct pcap_pkthdr **pkt_header,
                 const uint8_t **pkt_data)
{
  static struct pcap_pkthdr h;

  (*pkt_data) = pcap_next(p, &h);
  (*pkt_header) = &h;
  if(*pkt_data)
    return(1);
  else
    return(0);
}
#endif

/* ****************************************************** */

static int next_pcap_packet(pcap_t *p, struct pcap_pkthdr *h,
                                                            uint8_t *pkt_data) {
  int rc;
  const u_char *pkt;
  struct pcap_pkthdr *hdr;

  // traceEvent(TRACE_NORMAL, "About to call pcap_next_ex()");

  rc = pcap_next_ex(p, &hdr, &pkt);
  if((rc > 0) && (pkt != NULL) && (hdr->caplen > 0)) {
    hdr->caplen = min(hdr->caplen, readOnlyGlobals.snaplen);
    memcpy(h, hdr, sizeof(struct pcap_pkthdr));
    memcpy(pkt_data, pkt, h->caplen);
  } else {
    h->caplen = 0, h->len = 0;
  }

#if 0
  if(rc < 0)
    traceEvent(TRACE_NORMAL, "pcap_next_ex(caplen=%d, len=%d) returned %d [demo_mode=%d][%s]",
               h->caplen, h->len, rc, readOnlyGlobals.demo_mode, pcap_geterr(readOnlyGlobals.pcapPtr));
#endif

  return(rc);
}

/* ****************************************************** */

#ifdef HAVE_NETFILTER
static void* fetchNetFilterPackets(void* _thid) {
  unsigned long thread_id = (unsigned long)_thid;
  int len;
  char pktBuf[4096] __attribute__ ((aligned));

  readOnlyGlobals.nf.thread_id = thread_id;

  while(!readWriteGlobals->shutdownInProgress) {
    if((len = recv(readOnlyGlobals.nf.fd, pktBuf, sizeof(pktBuf), 0)) > 0) {
      nfq_handle_packet(readOnlyGlobals.nf.h, pktBuf, len);
    } else {

      break;
    }
  }
}
#endif

/* ****************************************************** */

static void* fetchPcapPackets(void* _thid) {
  char ebuf[PCAP_ERRBUF_SIZE];
  struct pcap_pkthdr h;
  int rc;
  unsigned long thread_id = (unsigned long)_thid;
  unsigned num_failures = 0;

  traceEvent(TRACE_INFO, "Fetch packets thread started [thread %lu]", thread_id);

#if 0
  setThreadAffinity(thread_id % readOnlyGlobals.numProcessThreads);
#endif

  while(!readWriteGlobals->shutdownInProgress) {
    QueuedPacket *qpacket = calloc(1,sizeof(*qpacket)+readOnlyGlobals.snaplen+1);
    if(NULL == qpacket) {
      traceEvent(TRACE_ERROR,"Can't allocate a new packet (out of memory?)");
      sleep(1);
      continue;
    }
    qpacket->buffer = (uint8_t *)&qpacket[1];

    /* traceEvent(TRACE_INFO, "fetchPcapPackets(%d)", (int)notUsed); */
    rc = next_pcap_packet(readOnlyGlobals.pcapPtr, &h, qpacket->buffer);

    if(readOnlyGlobals.pcapFile && readOnlyGlobals.reproduceDumpAtRealSpeed) {
      static struct timeval lastPktProcessed = { 0, 0 }, lastPcapTime;
      struct timeval now;

      gettimeofday(&now, NULL);
      if(lastPktProcessed.tv_sec > 0) {
        uint32_t m = msTimeDiff(&h.ts, &lastPcapTime), n;

        if(m < 100000) { /* Catch wrong timestamps */
          n = msTimeDiff(&now, &lastPktProcessed);

          if(n < m) {
            usleep((m - n)*1000);
          }
        }
      }

      gettimeofday(&now, NULL);
      memcpy(&lastPcapTime, &h.ts, sizeof(struct timeval));
      memcpy(&lastPktProcessed, &now, sizeof(struct timeval));
    }

    if(readOnlyGlobals.reforgeTimestamps)
      gettimeofday(&h.ts, NULL);

    if((rc > 0) && (qpacket->buffer != NULL)){
      qpacket->buffer_len = rc;
      decodePacket(thread_id,&h, qpacket);
      // usleep(1000);
    }

    if(rc < 0) {
      if(rc == -2) {
        /* Captured file is over */
        traceEvent(TRACE_INFO, "%s(): no more packets to read (capture file over?)", __FUNCTION__);
        readWriteGlobals->endOfPcapReached = 1;
        break;
      } else if(rc == -1) {
        num_failures++;

        if(num_failures < 10) {
          /* We hope this is a temporary issue thus we try to recover first and
             if this is not possible then we have no other choice but to restart
             the network interface
          */
          usleep(100); /* We wanna wait a bit before trying again */
        } else {
          if(!readWriteGlobals->shutdownInProgress) {
            traceEvent(TRACE_ERROR, "Error while reading packets: '%s'",
                       pcap_geterr(readOnlyGlobals.pcapPtr));
            term_pcap(&readOnlyGlobals.pcapPtr);
            readOnlyGlobals.pcapPtr = NULL;
            rc = restoreInterface(ebuf);
            if(rc < 0) {
              traceEvent(TRACE_INFO, "%s(): no more packets to read", __FUNCTION__);
              break;
            }
          }
        }
      }
    } else if(rc == 0) {
      /* No more packets to read if reading from file */
      if(readOnlyGlobals.pcapFile != NULL) {
        traceEvent(TRACE_INFO, "%s(threadId=%lu): no more packets to read",
                   __FUNCTION__, thread_id);
        free(qpacket);
        break;
      }
    } else {
      num_failures = 0;
    }

    if(readOnlyGlobals.capture_num_packet_and_quit > 1)
      readOnlyGlobals.capture_num_packet_and_quit--;
    else if(readOnlyGlobals.capture_num_packet_and_quit == 1){
      readWriteGlobals->shutdownInProgress = 1;
      readWriteGlobals->endOfPcapReached   = 1;
    }
  } /* while */

  traceEvent(TRACE_INFO, "%s(threadId=%lu) terminated",
             __FUNCTION__, thread_id);

  return(NULL);
}

/* ****************************************************** */

static void init_geoip(){
  if(readOnlyGlobals.rb_databases.geoip_country_database_path)
    readCountries(readOnlyGlobals.rb_databases.geoip_country_database_path);
  if(readOnlyGlobals.rb_databases.geoip_as_database_path)
    readASs(readOnlyGlobals.rb_databases.geoip_as_database_path);
}

#ifdef HAVE_ZOOKEEPER

static void init_zookeeper() {
  pthread_rwlock_init(&readOnlyGlobals.zk.rwlock,NULL);
  readOnlyGlobals.zk.log_buffer_f = open_memstream(&readOnlyGlobals.zk.log_buffer,&readOnlyGlobals.zk.log_buffer_size);
  if(NULL == readOnlyGlobals.zk.log_buffer_f) {
    traceEvent(TRACE_ERROR,"Can't allocate ZK log buffer (out of memory?)");
  }
  readOnlyGlobals.zk.update_template_timeout = 30;
}

#endif

static void init_globals(void) {
  memset(&readOnlyGlobals, 0, sizeof(readOnlyGlobals));

  readWriteGlobals = (ReadWriteGlobals*)calloc(1, sizeof(ReadWriteGlobals));
  if(!readWriteGlobals) {
    traceEvent(TRACE_ERROR, "Not enough memory");
    exit(-1);
  }

  memset(&readOnlyGlobals, 0, sizeof(readOnlyGlobals));
  readOnlyGlobals.promisc_mode = 1;

#ifdef linux
  readOnlyGlobals.cpuAffinity = NULL; /* no affinity */
#endif

  /* Resever one core as a thread is used for packet dequeueing */
  readOnlyGlobals.numProcessThreads = 1;
  listener_list_init(&readOnlyGlobals.listeners);

  readOnlyGlobals.traceLevel = 2;
  readOnlyGlobals.pcapPtr = NULL;
  readOnlyGlobals.reforgeTimestamps = 1;

#ifdef HAVE_LIBRDKAFKA
  pthread_rwlock_init(&readWriteGlobals->kafka.rwlock,NULL);
#endif

#ifdef HAVE_ZOOKEEPER
  init_zookeeper();
#endif
}

/* ****************************************************** */

static void printCopyrights(void) {
#ifdef HAVE_GEOIP
  if(readOnlyGlobals.geo_ip_city_db != NULL)
    traceEvent(TRACE_NORMAL, "%s", GeoIP_database_info(readOnlyGlobals.geo_ip_city_db));
  if(readOnlyGlobals.geo_ip_asn_db != NULL)
    traceEvent(TRACE_NORMAL, "%s", GeoIP_database_info(readOnlyGlobals.geo_ip_asn_db));
#endif
}

/* ****************************************************** */

static void check_for_database_reloads(){
  if(unlikely(readOnlyGlobals.rb_databases.reload_geoip_database)){
    init_geoip(); // locks and reload properly
    readOnlyGlobals.rb_databases.reload_geoip_database=0;
  }

  check_if_reload(&readOnlyGlobals.rb_databases);
}

int main(int argc, char *argv[]) {
  char ebuf[PCAP_ERRBUF_SIZE] = { '\0' };

  /* Initialize to a valid value */
  readOnlyGlobals.traceLevel = 2;

  if((argc == 2) && (!strcmp(argv[1], "--f2k-version"))) {
    printf("%s\n", version);
    exit(0);
  }

  init_globals();

  setprotoent(1); setservent(1); /* Improve protocol/port lookup performance */

  argc_ = argc;
  argv_ = (char**)argv;
  if(parseOptions(argc, argv, 0) == -1) exit(0);

  traceEvent(TRACE_NORMAL, "Welcome to f2k v.%s for %s", version, osName);
  printCopyrights();

  if(readOnlyGlobals.useSyslog)
    openlog(readOnlyGlobals.f2kId, LOG_PID ,LOG_DAEMON);

  readWriteGlobals->shutdownInProgress = 0;

#ifdef HAVE_GEOIP
  pthread_rwlock_init(&readWriteGlobals->geoipRwLock, NULL);
  init_geoip();
#endif

  pthread_rwlock_init(&readOnlyGlobals.ticksLock, NULL);

  signal(SIGTERM, cleanup);
  signal(SIGINT,  cleanup);
  signal(SIGPIPE, brokenPipe);
  signal(SIGHUP,  reloadCLI);

  if(readOnlyGlobals.captureDev != NULL) {
    if((openDevice(ebuf, 1, (readOnlyGlobals.pcapFileList ? readOnlyGlobals.pcapFileList->path : NULL)) == -1)
       || ((readOnlyGlobals.pcapPtr == NULL)
           && strcmp(readOnlyGlobals.captureDev, "none")
#ifdef HAVE_PF_RING
           && (readWriteGlobals->ring == NULL)
#endif
#ifdef HAVE_NETFILTER
           && (readOnlyGlobals.nf.h == NULL)
#endif
           )) {
      traceEvent(TRACE_ERROR, "Unable to open interface %s (%s)\n",
                 readOnlyGlobals.captureDev == NULL ? "<unknown>" : readOnlyGlobals.captureDev, ebuf);
      traceEvent(TRACE_ERROR, "Try using -i none if you do not want capture from a NIC");
      exit(-1);
    }

    if(readOnlyGlobals.pcapFileList != NULL) {
      struct fileList *next = readOnlyGlobals.pcapFileList->next;

      free(readOnlyGlobals.pcapFileList->path);
      free(readOnlyGlobals.pcapFileList);
      readOnlyGlobals.pcapFileList = next;
    }
  }

#ifdef HAVE_GEOIP
  if(readOnlyGlobals.geo_ip_asn_db == NULL)
#endif
    traceEvent(TRACE_NORMAL, "Flows ASs will not be computed "
#ifndef HAVE_GEOIP
               "(missing GeoIP support)"
#endif
               );

  if((readOnlyGlobals.pcapFile == NULL)
     && (readOnlyGlobals.captureDev != NULL)) {
    if((readOnlyGlobals.pcapPtr == NULL)
#ifdef HAVE_PF_RING
       && (readWriteGlobals->ring == NULL)
#endif
#ifdef HAVE_NETFILTER
       && (readOnlyGlobals.nf.h == NULL)
#endif
       )
      traceEvent(TRACE_NORMAL, "Not capturing packet from interface (collector mode)");
    else
      traceEvent(TRACE_NORMAL, "Capturing packets from interface %s [snaplen: %u bytes]",
                 readOnlyGlobals.captureDev, readOnlyGlobals.snaplen);
  }

  readOnlyGlobals.f2k_up = 1;

  if(readOnlyGlobals.becomeDaemon)
    daemonize();

  if(readOnlyGlobals.pcapFile == NULL) {
    /* Change user-id then save the pid path */
    readOnlyGlobals.f2kPid = getpid();

    if(readOnlyGlobals.pidPath) {
      FILE *fd = fopen(readOnlyGlobals.pidPath, "w");
      if(fd != NULL) {
        fprintf(fd, "%lu\n", readOnlyGlobals.f2kPid);
        fclose(fd);
      } else
        traceEvent(TRACE_ERROR, "Unable to store PID in file %s",
                   readOnlyGlobals.pidPath);
    }
    dropPrivileges();
  }

  load_mappings();

  dumpLogEvent(probe_started, severity_info, "nProbe started");

#ifdef HAVE_ZOOKEEPER
  pthread_create(&readOnlyGlobals.zk.zk_wathcher,NULL,zk_watchers_watcher,NULL);
#endif

  check_if_reload(&readOnlyGlobals.rb_databases);
  loadTemplates(readOnlyGlobals.templates_database_path);

  if(unlikely(readOnlyGlobals.enable_debug)) {
    traceEvent(TRACE_WARNING, "*****************************************");
    traceEvent(TRACE_WARNING, "** You're running f2k in DEBUG mode **");
    traceEvent(TRACE_WARNING, "*****************************************");
  }

  if(readOnlyGlobals.pcapPtr
#ifdef HAVE_PF_RING
     || readWriteGlobals->ring
#endif
#ifdef HAVE_NETFILTER
     || readOnlyGlobals.nf.h
#endif
     || readOnlyGlobals.tracePerformance
     ) {

    if(readOnlyGlobals.pcapFileList != NULL) {
      struct fileList *fl = readOnlyGlobals.pcapFileList, *next;

      while(fl != NULL) {
        if((openDevice(ebuf, 1, fl->path) == -1) || (readOnlyGlobals.pcapPtr == NULL))
          traceEvent(TRACE_ERROR, "Unable to open file '%s' (%s)\n", fl->path, ebuf);
        else {
          if(readOnlyGlobals.pcapPtr)
            fetchPcapPackets(NULL);
        }

        next = fl->next;
        free(fl->path);
        free(fl);
        fl = next;
      }
    } else {
      if(readOnlyGlobals.pcapFile != NULL) {
        fetchPcapPackets(NULL);
      } else {
        pthread_start_routine fetcher = NULL;

#ifdef HAVE_NETFILTER
        if(readOnlyGlobals.nf.fd >= 0) fetcher = fetchNetFilterPackets;
#endif

        if(fetcher == NULL) {
#ifdef HAVE_PF_RING
          fetcher = readWriteGlobals->ring ? fetchPfRingPackets : fetchPcapPackets;
#else
          fetcher = fetchPcapPackets;
#endif
        }
      }
    }
  }

  if(readOnlyGlobals.pcapFile) {
    while(!readWriteGlobals->endOfPcapReached){
      check_for_database_reloads();
      ntop_sleep(1);
    }
    traceEvent(TRACE_INFO, "No more packets to read. Sleeping...\n");
  } else {
    while(readOnlyGlobals.f2k_up) {
      // sleep(5); break;
      check_for_database_reloads();
      rd_kafka_poll(readWriteGlobals->kafka.rk, 1000/* 1sec */);
    }
  }

  shutdown_f2k();

  return(0);
}

/* ******************************** */

