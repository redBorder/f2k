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

#include <stdint.h>

/* ********************************* */

#define FLOW_VERSION_1         1
#define V1FLOWS_PER_PAK       30

struct flow_ver1_hdr {
  uint16_t version;         /* Current version = 1*/
  uint16_t count;           /* The number of records in PDU. */
  uint32_t sysUptime;       /* Current time in msecs since router booted */
  uint32_t unix_secs;       /* Current seconds since 0000 UTC 1970 */
  uint32_t unix_nsecs;      /* Residual nanoseconds since 0000 UTC 1970 */
};

struct flow_ver1_rec {
  uint32_t srcaddr;    /* Source IP Address */
  uint32_t dstaddr;    /* Destination IP Address */
  uint32_t nexthop;    /* Next hop router's IP Address */
  uint16_t input;      /* Input interface index */
  uint16_t output;     /* Output interface index */
  uint32_t dPkts;      /* Packets sent in Duration */
  uint32_t dOctets;    /* Octets sent in Duration */
  uint32_t first;      /* SysUptime at start of flow */
  uint32_t last;       /* and of last packet of the flow */
  uint16_t srcport;    /* TCP/UDP source port number (.e.g, FTP, Telnet, etc.,or equivalent) */
  uint16_t dstport;    /* TCP/UDP destination port number (.e.g, FTP, Telnet, etc.,or equivalent) */
  uint16_t pad;        /* pad to word boundary */
  uint8_t  proto;      /* IP protocol, e.g., 6=TCP, 17=UDP, etc... */
  uint8_t  tos;        /* IP Type-of-Service */
  uint8_t  pad2[7];    /* pad to word boundary */
};

typedef struct single_flow_ver1_rec {
  struct flow_ver1_hdr flowHeader;
  struct flow_ver1_rec flowRecord[V1FLOWS_PER_PAK+1 /* safe against buffer overflows */];
} NetFlow1Record;

/* ***************************************** */

#define FLOW_VERSION_5     5
#define V5FLOWS_PER_PAK   30

struct flow_ver5_hdr {
  uint16_t version;         /* Current version=5*/
  uint16_t count;           /* The number of records in PDU. */
  uint32_t sys_uptime;       /* Current time in msecs since router booted */
  uint32_t unix_secs;       /* Current seconds since 0000 UTC 1970 */
  uint32_t unix_nsecs;      /* Residual nanoseconds since 0000 UTC 1970 */
  uint32_t flow_sequence;   /* Sequence number of total flows seen */
  uint8_t  engine_type;     /* Type of flow switching engine (RP,VIP,etc.)*/
  uint8_t  engine_id;       /* Slot number of the flow switching engine */
  uint16_t sampleRate;      /* Packet capture sample rate */
};

struct flow_ver5_rec {
  uint32_t srcaddr;    /* Source IP Address */
  uint32_t dstaddr;    /* Destination IP Address */
  uint32_t nexthop;    /* Next hop router's IP Address */
  uint16_t input;      /* Input interface index */
  uint16_t output;     /* Output interface index */
  uint32_t dPkts;      /* Packets sent in Duration (milliseconds between 1st
         & last packet in this flow)*/
  uint32_t dOctets;    /* Octets sent in Duration (milliseconds between 1st
         & last packet in  this flow)*/
  uint32_t first;      /* SysUptime at start of flow */
  uint32_t last;       /* and of last packet of the flow */
  uint16_t srcport;    /* TCP/UDP source port number (.e.g, FTP, Telnet, etc.,or equivalent) */
  uint16_t dstport;    /* TCP/UDP destination port number (.e.g, FTP, Telnet, etc.,or equivalent) */
  uint8_t pad1;        /* pad to word boundary */
  uint8_t tcp_flags;   /* Cumulative OR of tcp flags */
  uint8_t proto;        /* IP protocol, e.g., 6=TCP, 17=UDP, etc... */
  uint8_t tos;         /* IP Type-of-Service */
  uint16_t src_as;     /* source peer/origin Autonomous System */
  uint16_t dst_as;     /* dst peer/origin Autonomous System */
  uint8_t src_mask;    /* source route's mask bits */
  uint8_t dst_mask;    /* destination route's mask bits */
  uint16_t pad2;       /* pad to word boundary */
};

typedef struct single_flow_ver5_rec {
  struct flow_ver5_hdr flowHeader;
  struct flow_ver5_rec flowRecord[V5FLOWS_PER_PAK];
} NetFlow5Record;

/* ************************************ */

#define FLOW_VERSION_7        7
#define V7FLOWS_PER_PAK       28

/* ********************************* */

struct flow_ver7_hdr {
  uint16_t version;         /* Current version=7*/
  uint16_t count;           /* The number of records in PDU. */
  uint32_t sysUptime;       /* Current time in msecs since router booted */
  uint32_t unix_secs;       /* Current seconds since 0000 UTC 1970 */
  uint32_t unix_nsecs;      /* Residual nanoseconds since 0000 UTC 1970 */
  uint32_t flow_sequence;   /* Sequence number of total flows seen */
  uint32_t reserved;
};

struct flow_ver7_rec {
  uint32_t srcaddr;    /* Source IP Address */
  uint32_t dstaddr;    /* Destination IP Address */
  uint32_t nexthop;    /* Next hop router's IP Address */
  uint16_t input;      /* Input interface index */
  uint16_t output;     /* Output interface index */
  uint32_t dPkts;      /* Packets sent in Duration */
  uint32_t dOctets;    /* Octets sent in Duration */
  uint32_t first;      /* SysUptime at start of flow */
  uint32_t last;       /* and of last packet of the flow */
  uint16_t srcport;    /* TCP/UDP source port number (.e.g, FTP, Telnet, etc.,or equivalent) */
  uint16_t dstport;    /* TCP/UDP destination port number (.e.g, FTP, Telnet, etc.,or equivalent) */
  uint8_t  flags;      /* Shortcut mode(dest only,src only,full flows*/
  uint8_t  tcp_flags;  /* Cumulative OR of tcp flags */
  uint8_t  proto;      /* IP protocol, e.g., 6=TCP, 17=UDP, etc... */
  uint8_t  tos;        /* IP Type-of-Service */
  uint16_t dst_as;     /* dst peer/origin Autonomous System */
  uint16_t src_as;     /* source peer/origin Autonomous System */
  uint8_t  dst_mask;   /* destination route's mask bits */
  uint8_t  src_mask;   /* source route's mask bits */
  uint16_t pad2;       /* pad to word boundary */
  uint32_t router_sc;  /* Router which is shortcut by switch */
};

typedef struct single_flow_ver7_rec {
  struct flow_ver7_hdr flowHeader;
  struct flow_ver7_rec flowRecord[V7FLOWS_PER_PAK+1 /* safe against buffer overflows */];
} NetFlow7Record;

/* ************************************ */

typedef struct flow_ver9_hdr {
  uint16_t version;         /* Current version=9*/
  uint16_t count;           /* The number of records in PDU. */
  uint32_t sys_uptime;      /* Current time in msecs since router booted */
  uint32_t unix_secs;       /* Current seconds since 0000 UTC 1970 */
  uint32_t flow_sequence;   /* Sequence number of total flows seen */
  uint32_t source_id;       /* Source id */
} V9FlowHeader;

typedef struct flow_ver9_template_header {
  uint16_t templateFlowset; /* = 0 */
  uint16_t flowsetLen;
} V9TemplateHeader;

typedef struct flow_ver9_template_def {
  uint16_t templateId;
  uint16_t fieldCount;
} V9TemplateDef;

typedef struct flow_ver9_option_template {
  uint16_t template_id;
  uint16_t option_scope_len;
  uint16_t option_len;
} V9OptionTemplate;

typedef struct flow_ver9_flow_set {
  uint16_t templateId;
  uint16_t flowsetLen;
} V9FlowSet;

typedef struct flow_set {
  uint16_t templateId;
  uint16_t fieldCount;
} FlowSet;

/* ******************************************* */

/*
  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |       Version Number          |            Length             |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                           Export Time                         |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                       Sequence Number                         |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                    Observation Domain ID                      |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

typedef struct flow_ipfix_hdr {
  uint16_t version;        /* Current version = 10 */
  uint16_t len;            /* The length of the IPFIX PDU */
  uint32_t unix_secs;      /* Current time in msecs since router booted */
  uint32_t flow_sequence;  /* Sequence number of total flows seen */
  uint32_t observation_id; /* Source id */
} IPFIXFlowHeader;

typedef struct flow_ipfix_set {
  uint16_t set_id, set_len;
} IPFIXSet;

typedef struct flow_ipfix_option_template {
  uint16_t template_id;
  uint16_t total_field_count;
  uint16_t scope_field_count;
} IPFIXOptionsTemplate;

typedef struct flow_ipfix_field {
  uint16_t field_id, field_len;
  uint32_t enterprise_number;
} IPFIXField;
