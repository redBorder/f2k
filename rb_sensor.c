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
#include "rb_sensor.h"
#include "rb_mac.h"

#include <librd/rdavl.h>
#include <librd/rdmem.h>
#include <jansson.h>

#ifndef RD_AVL_EMPTY
#define RD_AVL_EMPTY(ravl) (NULL == (ravl)->ravl_root)
#endif


/*******************************************************************************/
/*                            RB CONFIGURATION                                 */
/*******************************************************************************/

#ifdef HAVE_UDNS
static const char *dns_ptr_client_key = "dns_ptr_client";
static const char *dns_ptr_target_key = "dns_ptr_target";
#endif

#define SENSOR_NETWORK_MAGIC 0x741258963
#define NETWORK_TREE_NODE_MAGIC 0x5683ABDEF

struct network_tree_node {
#ifdef NETWORK_TREE_NODE_MAGIC
  uint64_t magic;
#endif
  rd_avl_node_t avl_node;
  netAddress_t netAddress;
  char *name;
  char *addres_as_str;
};

static void ipv6_and(uint8_t dst[16],const uint8_t s1[16],const uint8_t s2[16]){
  /// @TODO increase unit size
  int i;
  for(i=0;i<16;++i){
    dst[i] = s1[i]&s2[i];
  }
}

static int compare_networks(const void *_network1,const void *_network2){
  const struct network_tree_node *network1 = _network1;
  const struct network_tree_node *network2 = _network2;
#ifdef NETWORK_TREE_NODE_MAGIC
  assert(NETWORK_TREE_NODE_MAGIC == network1->magic);
  assert(NETWORK_TREE_NODE_MAGIC == network2->magic);
#endif

  uint8_t _net1[16];
  uint8_t _net2[16];
  uint8_t netmask[16];

  ipv6_and(netmask,network1->netAddress.networkMask,
    network2->netAddress.networkMask);
  apply_netmask(_net1,network1->netAddress.network,netmask);
  apply_netmask(_net2,network2->netAddress.network,netmask);

  return memcmp(_net1,_net2,sizeof(_net1));
}

/* ******** */

#define MAC_ADDRESS_TREE_NODE_MAGIC 0xACADDE55EE0EA1C
struct mac_address_tree_node {
#ifdef MAC_ADDRESS_TREE_NODE_MAGIC
  uint64_t magic;
#endif
  uint64_t mac;
  rd_avl_node_t avl_node;
};

static int compare_mac_address_node(const void *_mac1,const void *_mac2) {
  const struct mac_address_tree_node *mac1 = _mac1;
  const struct mac_address_tree_node *mac2 = _mac2;

#ifdef MAC_ADDRESS_TREE_NODE_MAGIC
  assert(MAC_ADDRESS_TREE_NODE_MAGIC == mac1->magic);
  assert(MAC_ADDRESS_TREE_NODE_MAGIC == mac2->magic);
#endif

  return mac2->mac - mac1->mac;
}

/* ******** */

/// Sensor defined by a network, that have it own templates
struct sensor {
#ifndef NDEBUG
	/// Magic constant to assert coherency
#define SENSOR_MAGIC 0xABC123DEF098
	uint64_t magic; //< Magic to assert coherency
#endif

  /// network the sensor belongs to
  const struct sensors_network *network;

  /** Associated worker, so the same src sensor + dst port always goes to the
  same worker, avoiding reordering and data races */
  worker_t *worker;

  rd_avl_t routers_macs;
  rd_avl_t home_networks;
  rd_memctx_t memctx;
  char *enrichment;
  enum sensor_span_mode span_mode;
  int64_t fallback_first_switch;

#ifdef HAVE_UDNS
#define ENABLE_PTR_DNS_CLIENT 0x01
#define ENABLE_PTR_DNS_TARGET 0x02

  int dns_flags;
#endif

  // @TODO merge in one template_database struct.
  FlowSetV9Ipfix *up_to_512_templates[512]; /* Array: direct element access */
  LIST_HEAD(, flowSetV9Ipfix) over_512_templates;       /* Linked List */

  atomic_uint64_t refcnt;
};

worker_t *sensor_worker(const struct sensor *sensor) {
  return sensor->worker;
}

int sensor_has_mac_db(const struct sensor *sensor) {
  return !RD_AVL_EMPTY(&sensor->routers_macs);
}

int sensor_has_router_mac(struct sensor *sensor,const uint64_t mac) {
  assert(sensor);

  struct mac_address_tree_node dummy_mac;
  memset(&dummy_mac,0,sizeof(dummy_mac));
  dummy_mac.mac = mac;
#ifdef MAC_ADDRESS_TREE_NODE_MAGIC
  dummy_mac.magic = MAC_ADDRESS_TREE_NODE_MAGIC;
#endif

  return NULL != RD_AVL_FIND(&sensor->routers_macs,&dummy_mac);
}

#define SENSOR_PORT_TREE_NODE_MAGIC 0xE0011EE0DE

struct sensor_port_tree_node {
#ifdef SENSOR_PORT_TREE_NODE_MAGIC
  uint64_t magic;
#endif
  struct sensor *sensor;
  uint16_t port;
  SLIST_ENTRY(sensor_port_tree_node) list_node;
  rd_avl_node_t avl_node;
};

static int sensor_port_tree_node_cmp(const void *n1,const void *n2) {
  const struct sensor_port_tree_node *node1 = n1;
  const struct sensor_port_tree_node *node2 = n2;

#ifdef SENSOR_PORT_TREE_NODE_MAGIC
  assert(node1->magic == SENSOR_PORT_TREE_NODE_MAGIC);
  assert(node2->magic == SENSOR_PORT_TREE_NODE_MAGIC);
#endif

  return node1->port - node2->port;
}

static struct sensor_port_tree_node dummy_sensor_port(const uint16_t port_to_search) {
  const struct sensor_port_tree_node dummy_sensor_port_tree_node = {
#ifdef SENSOR_PORT_TREE_NODE_MAGIC
    .magic=SENSOR_PORT_TREE_NODE_MAGIC,
#endif
    .port = port_to_search,
    .avl_node = {{0}}
  };
  return dummy_sensor_port_tree_node;
}

struct sensors_network {
  #ifdef SENSOR_NETWORK_MAGIC
  uint64_t magic;
  #endif

  /* TODO use ipv6 too */
  netAddress_t ip;
  const char *ip_str;

  rd_avl_node_t avl_node;

  rd_avl_t sensors_by_port;
};

const char *sensor_ip_string(const struct sensor *sensor){
  return sensor->network->ip_str;
}

const char *sensor_ip_enrichment(const struct sensor *sensor){
  return sensor->enrichment;
}

enum sensor_span_mode is_span_sensor(const struct sensor *sensor){
  return sensor->span_mode;
}

int64_t sensor_fallback_first_switch(const struct sensor *sensor){
  return sensor->fallback_first_switch;
}

static const struct network_tree_node *network_node(struct sensor *sensor,
    const uint8_t ip[16]){
  assert(sensor);
  int i;

  struct network_tree_node dummy_network_tree_node = {
#ifdef NETWORK_TREE_NODE_MAGIC
    .magic = NETWORK_TREE_NODE_MAGIC,
#endif
    .avl_node = {{0}},
    .netAddress = {
    //  .network,
    //  .networkMask,
    //  .broadcast,
    },
    .name = NULL,
    .addres_as_str = NULL,
  };

  /* @TODO
  memcpy(dummy_network_tree_node.netAddress.network,ip,sizeof(ip));
  memset(dummy_network_tree_node.netAddress.networkMask,0xFF,sizeof(ip));
  memcpy(dummy_network_tree_node.netAddress.broadcast,ip,sizeof(ip));
  */

  for(i=0;i<16;++i){
    dummy_network_tree_node.netAddress.network[i] =
      dummy_network_tree_node.netAddress.broadcast[i] = ip[i];
    dummy_network_tree_node.netAddress.networkMask[i] = 0xff;
  }

  return RD_AVL_FIND(&sensor->home_networks,&dummy_network_tree_node);
}

const char *network_ip(struct sensor *sensor, const uint8_t ip[16]) {
  const struct network_tree_node *node = network_node(sensor, ip);
  return node?node->addres_as_str:NULL;
}

const char *network_name(struct sensor *sensor, const uint8_t ip[16]) {
  const struct network_tree_node *node = network_node(sensor, ip);
  return node?node->name:NULL;
}

#ifdef HAVE_UDNS
int sensor_want_client_dns(const struct sensor *s) {
  return s->dns_flags & ENABLE_PTR_DNS_CLIENT;
}

int sensor_want_target_dns(const struct sensor *s) {
  return s->dns_flags & ENABLE_PTR_DNS_TARGET;
}
#endif

struct bad_sensor {
  #ifdef SENSOR_NETWORK_MAGIC
  uint64_t magic;
  #endif

  uint32_t ip;

  rd_avl_node_t avl_node;
};

typedef SLIST_HEAD(, sensor_port_tree_node) sensors_list_t;

/// Sensors database
struct rb_sensors_db {
#ifndef NDEBUG
	/// Magic constant to assert coherence
#define RB_DATABASE_MAGIC 0xBDAABAEA1C
	uint64_t magic; //< Magic to assert coherence
#endif
	sensors_list_t sensors_list; //< List of sensors
	/// sensors (networks) and bad sensors db
	struct {
		rd_avl_t avl;
		rd_memctx_t memctx;
	} sensors, bad_sensors;
	listener_list new_listeners; //< Listeners that have to open
	json_t *root; //< Json data
};

static int compare_bad_sensors(const void *_s1,const void *_s2)
{
  const struct bad_sensor *s1 = _s1;
  const struct bad_sensor *s2 = _s2;

  assert(s1->magic == SENSOR_NETWORK_MAGIC);
  assert(s2->magic == SENSOR_NETWORK_MAGIC);

  return s1->ip > s2->ip ? 1 : (s2->ip==s1->ip ? 0 : -1);
}

static int compare_sensors_networks(const void *_s1,const void *_s2)
{
  const struct sensors_network *s1 = _s1;
  const struct sensors_network *s2 = _s2;

  assert(s1->magic == SENSOR_NETWORK_MAGIC);
  assert(s2->magic == SENSOR_NETWORK_MAGIC);

  uint8_t ipv6[16];
  apply_netmask(ipv6, s1->ip.network, s2->ip.networkMask);

  return memcmp(ipv6,s2->ip.network,sizeof(ipv6));
}

static struct bad_sensor *find_bad_sensor(uint64_t ip,struct rb_sensors_db *db)
{
  const struct bad_sensor proposed_sensor = {
#ifdef SENSOR_NETWORK_MAGIC
    .magic = SENSOR_NETWORK_MAGIC,
#endif

    .ip = ip,

    .avl_node = {{0}}
  };

  return RD_AVL_FIND(&db->bad_sensors.avl,&proposed_sensor);
}

int addBadSensor(struct rb_sensors_db *database,const uint64_t sensor_ip) {
  struct bad_sensor *old_sensor = find_bad_sensor(sensor_ip,database);
  if(NULL==old_sensor) {
    if(unlikely(readOnlyGlobals.enable_debug)) {
      char buf[BUFSIZ];
      traceEvent(TRACE_INFO,"%s marked as bad sensor",
                                        _intoaV4(sensor_ip, buf, sizeof(buf)));
    }

    struct bad_sensor *sensor = rd_memctx_calloc(&database->bad_sensors.memctx,
						1, sizeof(struct bad_sensor));
    #ifdef SENSOR_NETWORK_MAGIC
    sensor->magic = SENSOR_NETWORK_MAGIC;
    #endif
    sensor->ip              = sensor_ip;

    rd_avl_insert(&database->bad_sensors.avl, sensor, &sensor->avl_node);
    return 1;
  } else {
    return 0;
  }
}

/// @TODO use memctx struct calls
static bool addHomeNetToDatabase(struct sensor *sensor, json_t *json_home_net) {
  assert(sensor);
  assert(json_home_net);
  json_error_t jerr;
  const char *network=NULL,*network_name_str=NULL;

  if(!json_is_object(json_home_net)){
    traceEvent(TRACE_ERROR,"Could not get one network of sensor %s.",sensor_ip_string(sensor));
    return false;
  }

  const int unpack_rc = json_unpack_ex(json_home_net,&jerr,0,"{s:s,s:s}",
    "network_name",&network_name_str,"network",&network);

  if(unpack_rc != 0) {
    traceEvent(TRACE_ERROR,"Can't unpack home net: %s",jerr.text);
    return false;
  }

  struct network_tree_node *home_net = rd_memctx_calloc(&sensor->memctx, 1,
							sizeof(*home_net));
  if(NULL==home_net){
    traceEvent(TRACE_ERROR,"Could not allocate home net of sensor %s.",sensor_ip_string(sensor));
    return false;
  }

#ifdef NETWORK_TREE_NODE_MAGIC
  home_net->magic = NETWORK_TREE_NODE_MAGIC;
#endif

  if(!network_name_str){
    traceEvent(TRACE_ERROR,"Sensor %s has a network defined with no name.",
                                                                     sensor_ip_string(sensor));
    return false;
  }
  home_net->name = rd_memctx_strdup(&sensor->memctx, network_name_str);
  if(NULL == home_net->name){
    traceEvent(TRACE_ERROR,"Could not allocate sensor %s network name %s.",
                                    sensor_ip_string(sensor), network_name_str);
    return false;
  }

  if(!network){
    traceEvent(TRACE_ERROR,"Sensor %s has a network defined with no address.",
                                                                     sensor_ip_string(sensor));
    return false;
  }
  const bool parseAddressrc = safe_parse_address(network,&home_net->netAddress);
  if(!parseAddressrc){
    traceEvent(TRACE_ERROR,"Sensor %s has a home network with an invalid ip address (%s).",
                                                             sensor_ip_string(sensor),network);
    return false;
  }
  home_net->addres_as_str = rd_memctx_strdup(&sensor->memctx, network);

  rd_avl_insert(&sensor->home_networks,home_net,&home_net->avl_node);
  return true;
}

struct add_json_sensors_network_opaque {
#ifndef NDEBUG
#define ADD_JSON_NETWORK_OPAQUE_MAGIC 0x2468ace13579bdf
  uint64_t magic;
#endif

  struct rb_sensors_db *database;
  struct {
    worker_t **workers;
    size_t workers_size, workers_idx;
  } workers;
};

struct rb_network_port_opaque {
  struct add_json_sensors_network_opaque *add_json_opaque;
  struct sensors_network *sensors_network;
};

static bool parse_sensor_home_nets(struct sensor *sensor,
						const json_t *home_nets) {
  bool rc = true;
  if(!json_is_array(home_nets)){
      traceEvent(TRACE_ERROR,"home_nets in not an array in sensor %s.",
                                              sensor_ip_string(sensor));
  }else{
    size_t net_index;
    json_t *value;

    json_array_foreach(home_nets, net_index, value) {
      if (!rc) {
        break;
      }
      rc = addHomeNetToDatabase(sensor, value);
    }
  }

  return rc;
}

static bool parse_sensor_routers_macs(struct sensor *sensor,
					const json_t *router_mac_address) {
  if(!json_is_array(router_mac_address)) {
    traceEvent(TRACE_ERROR,"Router mac addresses is not an array in sensor %s.",
                                                      sensor_ip_string(sensor));
    return false;
  }

  const size_t router_mac_address_size = json_array_size(router_mac_address);
  size_t i=0;

  struct mac_address_tree_node *mac_address_node = rd_memctx_calloc(
	&sensor->memctx, router_mac_address_size,sizeof(mac_address_node[0]));

  if(NULL == mac_address_node) {
    traceEvent(TRACE_ERROR,"Can't allocate mac address nodes for sensor %s "
                               "(out of memory?)",sensor_ip_string(sensor));
    return false;
  }

  for(i=0;i<router_mac_address_size;++i) {
    const json_t *mac_i = json_array_get(router_mac_address,i);
    if(!json_is_string(mac_i)) {
      traceEvent(TRACE_ERROR,
        "router mac address %zu of sensor %s is not a string",
        i, sensor_ip_string(sensor));
      continue;
    }

    const char *mac_str = json_string_value(mac_i);
    if(NULL == mac_str) {
      traceEvent(TRACE_ERROR,"Can't parse router mac address %zu of sensor %s",
                            i,sensor_ip_string(sensor));
      continue;
    }

    mac_address_node[i].mac = parse_mac(mac_str);
    if(mac_address_node[i].mac == INVALID_MAC) {
      traceEvent(TRACE_ERROR,"Can't parse router mac address %s of sensor %s",
                                                mac_str,sensor_ip_string(sensor));
      continue;
    }

#ifdef MAC_ADDRESS_TREE_NODE_MAGIC
    mac_address_node[i].magic = MAC_ADDRESS_TREE_NODE_MAGIC;
#endif

    RD_AVL_INSERT(&sensor->routers_macs,&mac_address_node[i],avl_node);
  }

  return true;
}

static bool parse_sensor_enrichment(struct sensor *sensor,
						const json_t *enrichment) {
  if(!json_is_object(enrichment)) {
    traceEvent(TRACE_ERROR,"Enrichment field is not an object in sensor %s.",sensor_ip_string(sensor));
    return false;
  } else {
    char *tmp_enrichment = json_dumps(enrichment,
						JSON_COMPACT|JSON_ENSURE_ASCII);
    if(tmp_enrichment){
      // tmp_enrichment == "{\"hello\":\"world\"}". We want delete brackets.
      sensor->enrichment = rd_memctx_strdup(&sensor->memctx,
						&tmp_enrichment[1]);
      char *last_bracket = strrchr(sensor->enrichment,'}');
      if(last_bracket)
        *last_bracket = '\0';
      free(tmp_enrichment);

      if(!(strlen(sensor->enrichment)>0)) {
        /* We don't need to mantain a null buffer if enrichment == {} */
        rd_memctx_free(&sensor->memctx, sensor->enrichment);
        sensor->enrichment = NULL;
      }
    }

    return true;
  }
}

#ifdef HAVE_UDNS
static bool parse_sensor_dns0(struct sensor *sensor,const json_t *dns_ptr_value,
                                                    const char *key,int flag) {
  if(NULL != dns_ptr_value) {
    if(!json_is_boolean(dns_ptr_value)) {
      const char *sensor_name = sensor_ip_string(sensor);
      traceEvent(TRACE_ERROR,"%s is not a boolean in sensor %s, can't parse it",key,
        sensor_name);
      return false;
    } else if (json_is_true(dns_ptr_value)) {
      sensor->dns_flags |= flag;
    }
  }

  return true;
}

static true parse_sensor_dns(struct sensor *sensor,const json_t *dns_ptr_client,
                                                const json_t *dns_ptr_target) {
  return parse_sensor_dns0(sensor,dns_ptr_client,dns_ptr_client_key,
                                                       ENABLE_PTR_DNS_CLIENT)
    && parse_sensor_dns0(sensor,dns_ptr_target,dns_ptr_target_key,
                                                       ENABLE_PTR_DNS_TARGET);

}
#endif

static bool parse_sensor(struct sensor *sensor, json_t *jsensor) {
  json_error_t jerr;
  bool rc = true;
  const json_t *home_nets=NULL, *enrichment=NULL, *span_port=NULL,
    *routers_macs=NULL;
  json_int_t fallback_first_switch = 0;
#ifdef HAVE_UDNS
  const json_t *dns_ptr_client=NULL,*dns_ptr_target=NULL;
#endif

  const int unpack_rc = json_unpack_ex(jsensor, &jerr, 0,
    "{s?o,s?o,s?o,s?o,s?I}","home_nets",&home_nets,"enrichment",&enrichment,
    "span_port",&span_port,"routers_macs",&routers_macs,
    "fallback_first_switch",&fallback_first_switch);

  if(unpack_rc != 0) {
    traceEvent(TRACE_ERROR, "Can't parse sensors network %s: %s",jerr.text,
                                                  sensor_ip_string(sensor));
    return false;
  }

  if(home_nets) {
    rc = parse_sensor_home_nets(sensor,home_nets);
  }

  if(rc && enrichment) {
    rc = parse_sensor_enrichment(sensor,enrichment);
  }

  if(rc && routers_macs) {
    rc = parse_sensor_routers_macs(sensor,routers_macs);
  }

  sensor->fallback_first_switch = fallback_first_switch;

#ifdef HAVE_UDNS
  if(rc) {
    const int unpack_dns_rc = json_unpack_ex(jsensor, &jerr, 0,
      "{s?o,s?o}",dns_ptr_client_key,&dns_ptr_client,dns_ptr_target_key,&dns_ptr_target);

    if(unpack_dns_rc != 0) {
      traceEvent(TRACE_ERROR, "Can't unpack DNS attributes %s: %s",jerr.text,
                                              sensor_ip_string(sensor));
    } else {
      rc = parse_sensor_dns(sensor,dns_ptr_client,dns_ptr_target);
    }
  }
#endif

  if(NULL!=span_port){
    if(!json_is_boolean(span_port)){
      traceEvent(TRACE_ERROR,"span_port field is not a boolean in sensor %s.",
                                                    sensor_ip_string(sensor));
      return false;
    }else{
      sensor->span_mode = json_is_true(span_port);
    }
  }

  return rc;
}

static size_t tokenize_ports(char *ports_str, const char **ports,
    size_t ports_size, bool *ok){
  size_t ports_number = 0;
  char *aux=NULL,*tok=NULL;

  assert(ports_str);
  assert(ports);
  assert(ok);

  ports[ports_number++] = strtok_r(ports_str,",",&aux);
  while((ports_number < ports_size) && (tok = strtok_r(NULL,",",&aux))) {
    ports[ports_number++] = tok;
  }

  if(ports_number == ports_size) {
    traceEvent(TRACE_ERROR,"You've reached the maximum ports allowed in a string.");
    *ok = false;
  }

  return ports_number;
}

static bool addJsonSensorsNetworkPort0(
                                struct add_json_sensors_network_opaque *opaque,
                                struct sensors_network *sensors_network,
                                const char *ports_range, json_t *ports_value) {
  listener_list *listeners = &opaque->database->new_listeners;
  const size_t ports_range_len = strlen(ports_range);
  const char *ports[ports_range_len];
  char ports_aux[ports_range_len];
  char errbuf[BUFSIZ];

  size_t i=0;
  bool tokens_ok = true;
  bool rc = true;

  strcpy(ports_aux,ports_range);

  const size_t ports_number = tokenize_ports(ports_aux, ports,
                                              RD_ARRAYSIZE(ports), &tokens_ok);
  if(!tokens_ok){
    return false;
  }

  struct sensor *sensor = calloc(1, sizeof(*sensor));
  if(NULL == sensor) {
    traceEvent(TRACE_ERROR,
                  "Can't allocate sensor of network %s memory (out of memory?)",
                  sensors_network->ip_str);
    return false;
  }

#ifdef SENSOR_MAGIC
  sensor->magic = SENSOR_MAGIC;
#endif

  sensor->network = sensors_network;
  sensor->worker = opaque->workers.workers[opaque->workers.workers_idx];
  if (opaque->workers.workers_idx >= opaque->workers.workers_size) {
    opaque->workers.workers_idx = 0;
  }
  rd_avl_init(&sensor->home_networks, compare_networks, 0);
  rd_avl_init(&sensor->routers_macs, compare_mac_address_node, 0);
  rd_memctx_init(&sensor->memctx, NULL, RD_MEMCTX_F_TRACK);
  sensor->refcnt.value = 1;

  const bool parse_rc = parse_sensor(sensor,ports_value);
  if (!parse_rc) {
    return false;
  }

  struct sensor_port_tree_node *port_nodes = rd_memctx_calloc(&sensor->memctx,
					ports_number, sizeof(port_nodes[0]));

  for(i=0;rc && i<ports_number;++i) {
    errno = 0;
    char *endptr = NULL;
    const uint16_t port = strtoul(ports[i],&endptr,0);
    const int strtoul_errno = errno;

    if(port == 0 || endptr == NULL) {
      if(strtoul_errno != 0) {
        strerror_r(strtoul_errno,errbuf,sizeof(errbuf));
        traceEvent(TRACE_ERROR,"Can't parse port %s: %s",ports[i],errbuf);
      } else {
        traceEvent(TRACE_ERROR, "Can't listen on port %s",ports[i]);
      }
      rc = false;
    } else if(NULL != endptr && (!(*endptr == '\0') || isspace(*endptr))) {
      traceEvent(TRACE_ERROR,
              "Can't parse port %s: Non space extra tokens at the end of port",
              ports[i]);
      rc = false;
    }

#ifdef SENSOR_PORT_TREE_NODE_MAGIC
    port_nodes[i].magic = SENSOR_PORT_TREE_NODE_MAGIC;
#endif

    port_nodes[i].sensor = sensor;
    port_nodes[i].port = port;
    const void *old_node = rd_avl_insert(&sensors_network->sensors_by_port,
                                      &port_nodes[i], &port_nodes[i].avl_node);
    if(NULL != old_node) {
      traceEvent(TRACE_ERROR,
        "Can't parse config file: collision in port %d", port);
      return false;
    }

    SLIST_INSERT_HEAD(&opaque->database->sensors_list, &port_nodes[i],
                                                                    list_node);
    struct port_collector *collector = createNetFlowListener(UDP, port);
    listener_list_append(listeners,collector);
  }

  return rc;
}

static bool addJsonSensorsNetworkPort(const char *ports_range,
                                          json_t *ports_value, void *_opaque) {
  struct rb_network_port_opaque *opaque = _opaque;
#ifdef SENSOR_NETWORK_MAGIC
  assert(opaque->sensors_network->magic == SENSOR_NETWORK_MAGIC);
#endif
  return addJsonSensorsNetworkPort0(opaque->add_json_opaque,
                            opaque->sensors_network, ports_range, ports_value);
}

static bool json_assert_object_foreach_object_child(json_t *parent,const char *parent_name,
      bool (*child_cb)(const char *key,json_t *value, void *opaque),void *opaque){
  bool rc = true;
  const char *key = NULL;
  json_t *value = NULL;

  if(!json_is_object(parent)) {
    traceEvent(TRACE_ERROR,"%s in not an object in config file.\n",parent_name);
    rc = false;
  }

  json_object_foreach(parent,key,value) {
    if(!rc)
      break; /* Array not valid anymore */

    if(value && json_is_object(value)){
      rc = child_cb(key,value,opaque);
    } else {
      traceEvent(TRACE_ERROR,"%s is not an object in config file.\n",key);
      rc = false;
    }
  }

  return rc;
}

static bool read_rb_config_sensor_networks_ports(
                  struct add_json_sensors_network_opaque *add_json_opaque,
                  struct sensors_network *sensors_network, const char *network,
                  json_t *jsensors_network) {
  struct rb_network_port_opaque opaque = {
    .add_json_opaque = add_json_opaque,
    .sensors_network = sensors_network
  };

  char buf[BUFSIZ];
  snprintf(buf,sizeof(buf),"Network %s",network);
  return json_assert_object_foreach_object_child(jsensors_network,buf,addJsonSensorsNetworkPort,
                                                                                      &opaque);
}

static bool addJsonSensorsNetwork0(struct add_json_sensors_network_opaque *opaque,
                            const char *network, json_t *sensors_network_json) {
  struct rb_sensors_db *database = opaque->database;
  struct sensors_network *sensors_network = NULL;

  sensors_network = rd_memctx_calloc(&database->sensors.memctx, 1,
						sizeof(*sensors_network));
  if (sensors_network==NULL) {
    traceEvent(TRACE_ERROR,"Can't allocate sensor network.");
    return false;
  }

#ifdef SENSOR_NETWORK_MAGIC
  sensors_network->magic = SENSOR_NETWORK_MAGIC;
#endif

  rd_avl_init(&sensors_network->sensors_by_port,sensor_port_tree_node_cmp,0);

  const bool parse_address_rc = safe_parse_address(network, &sensors_network->ip);
  if(!parse_address_rc) {
    traceEvent(TRACE_ERROR,"Can't parse network range %s",network);
    return false;
  }
  sensors_network->ip_str = rd_memctx_strdup(&database->sensors.memctx,
								network);

  struct sensors_network *old_sensor_networks = rd_avl_insert(
            &database->sensors.avl, sensors_network,&sensors_network->avl_node);
  if(old_sensor_networks) {
    traceEvent(TRACE_ERROR,
                "Error: Network %s match with network %s. Discarding old one.",
                sensors_network->ip_str,old_sensor_networks->ip_str);
  }

  read_rb_config_sensor_networks_ports(opaque, sensors_network, network,
                                                          sensors_network_json);

  return true;
}

static bool addJsonSensorsNetwork(const char *network, json_t *network_json,
                                                                void *vopaque) {
  struct add_json_sensors_network_opaque *opaque = vopaque;
#ifdef ADD_JSON_NETWORK_OPAQUE_MAGIC
  assert(ADD_JSON_NETWORK_OPAQUE_MAGIC == opaque->magic);
#endif

  return addJsonSensorsNetwork0(opaque,network,network_json);
}


static struct rb_sensors_db *allocate_rb_sensors_db() {
  struct rb_sensors_db *database = calloc(1,sizeof(*database));
  if(NULL==database) {
    traceEvent(TRACE_ERROR, "Memory error");
  } else {
#ifdef RB_DATABASE_MAGIC
    database->magic = RB_DATABASE_MAGIC;
#endif
		listener_list_init(&database->new_listeners);
		rd_avl_init(&database->sensors.avl,compare_sensors_networks,
								RD_AVL_F_LOCKS);
		rd_memctx_init(&database->sensors.memctx, NULL,
					RD_MEMCTX_F_TRACK | RD_MEMCTX_F_LOCK);
		rd_avl_init(&database->bad_sensors.avl,compare_bad_sensors,
								RD_AVL_F_LOCKS);
		rd_memctx_init(&database->bad_sensors.memctx, NULL,
					RD_MEMCTX_F_TRACK | RD_MEMCTX_F_LOCK);
  }

  return database;
}

static bool read_rb_config_sensors_networks(struct rb_sensors_db *database,
                              json_t *sensors_networks, worker_t **worker_list,
                              size_t worker_list_size) {

  struct add_json_sensors_network_opaque opaque = {
#ifdef ADD_JSON_NETWORK_OPAQUE_MAGIC
    .magic = ADD_JSON_NETWORK_OPAQUE_MAGIC,
#endif

    .database = database,
    .workers = {
      .workers = worker_list,
      .workers_size = worker_list_size,
      .workers_idx = 0,
    }
  };

  return json_assert_object_foreach_object_child(sensors_networks,
    "sensors networks", addJsonSensorsNetwork,&opaque);
}

/* *** sensors database *** */
struct rb_sensors_db *read_rb_config(const char *json_path, listener_list *list,
                              worker_t **worker_list, size_t worker_list_size) {
  if(unlikely(readOnlyGlobals.enable_debug))
    traceEvent(TRACE_INFO,"Reading json config");

  json_error_t error;
  struct rb_sensors_db * database = allocate_rb_sensors_db();

  if(NULL == database) {
    traceEvent(TRACE_ERROR,"Invalid address");
    return NULL;
  }

  database->root = json_load_file(json_path,0,&error);
  if(NULL==database->root)
    traceEvent(TRACE_ERROR,"Could not load %s, line %d column %d: %s.",json_path,
       error.line,error.column,error.text);

  if(database && database->root) {
    json_t *sensors_networks = json_object_get(database->root, "sensors_networks");

    if(NULL==sensors_networks) {
      traceEvent(TRACE_ERROR,"Could not load %s(%d): %s.\n",json_path,error.line,error.text);
    } else {
      const bool rc = read_rb_config_sensors_networks(database, sensors_networks,
                                                worker_list, worker_list_size);
      if(!rc) {
        delete_rb_sensors_db(database);
        database = NULL;
      }
    }
  }

  if(list)
    mergeNetFlowListenerList(list,&database->new_listeners);
  else
    listener_list_done(&database->new_listeners);

  return database;
}

static struct sensors_network dummy_sensors_network(const uint64_t ip) {
  struct sensors_network _dummy_sensor;
  memset(&_dummy_sensor,0,sizeof(_dummy_sensor));
#ifdef SENSOR_NETWORK_MAGIC
  _dummy_sensor.magic = SENSOR_NETWORK_MAGIC;
#endif

  _dummy_sensor.ip.network[10] = 0xFF;
  _dummy_sensor.ip.network[11] = 0xFF;
  _dummy_sensor.ip.network[12] = ((ip & 0xFF000000) >> 24);
  _dummy_sensor.ip.network[13] = ((ip & 0x00FF0000) >> 16);
  _dummy_sensor.ip.network[14] = ((ip & 0x0000FF00) >> 8);
  _dummy_sensor.ip.network[15] = ((ip & 0x000000FF));

  memset(_dummy_sensor.ip.networkMask,0xFF,sizeof(_dummy_sensor.ip.networkMask));
  memcpy(_dummy_sensor.ip.broadcast,_dummy_sensor.ip.networkMask,sizeof(_dummy_sensor.ip.broadcast));

  return _dummy_sensor;
}

static struct flowSetV9Ipfix *find_sensor_template0(const struct sensor *sensor,
                                                       const int templateId) {
  assert(sensor);

  if(templateId < 512){
    return sensor->up_to_512_templates[templateId];
  } else {
    FlowSetV9Ipfix *template = NULL;
    LIST_FOREACH(template, &sensor->over_512_templates, entry) {
      if(template->templateInfo.templateId) {
        return template;
      }
    }
  }

  return NULL;
}

const struct flowSetV9Ipfix *find_sensor_template(const struct sensor *sensor,
                                                       const int templateId) {
  return find_sensor_template0(sensor,templateId);
}

static void free_v9_ipfix_template(struct flowSetV9Ipfix *template) {
	free(template->fields);
	free(template);
}

void saveTemplate(struct sensor *sensor,struct flowSetV9Ipfix *template)
{
  const V9IpfixSimpleTemplate * templateInfo = &template->templateInfo;
  const uint32_t netflow_device_ip = templateInfo->netflow_device_ip;
  const int template_id = templateInfo->templateId;

  struct flowSetV9Ipfix *prev_template = find_sensor_template0(sensor,
  								template_id);

  if (unlikely(readOnlyGlobals.enable_debug)) {
    char buf[BUFSIZ];
    traceEvent(TRACE_INFO, "%s [sensor=%s][id=%d]",
                        prev_template ? ">>>>> Redefined existing template " :
                                    ">>>>> Found new flow template definition",
                      _intoaV4(netflow_device_ip,buf,sizeof(buf)),template_id);
  }

  if(prev_template) {
    if(templateInfo->templateId >= 512) {
      LIST_REMOVE(prev_template, entry);
    }

    free_v9_ipfix_template(prev_template);
  }

  if(templateInfo->templateId < 512) {
    sensor->up_to_512_templates[templateInfo->templateId] = template;
  } else {
    LIST_INSERT_HEAD(&sensor->over_512_templates, template, entry);
  }

  if(unlikely(readOnlyGlobals.enable_debug))
  traceEvent(TRACE_INFO, ">>>>> Defined flow template [id=%d][flowLen=%d][fieldCount=%d]",
       template->templateInfo.templateId,
       template->flowLen, template->templateInfo.fieldCount);
}

void save_template_async(struct sensor *sensor,
                                              struct flowSetV9Ipfix *template) {
  add_template_to_worker(template, sensor, sensor->worker);
}

/// @TODO const?
struct sensor *get_sensor(struct rb_sensors_db *database, uint64_t ip,
							uint16_t dst_port) {
  assert(database);

  struct sensors_network proposed_sensors_network = dummy_sensors_network(ip);

  struct sensors_network *found_sensor_network = RD_AVL_FIND(
			&database->sensors.avl, &proposed_sensors_network);

  if (NULL == found_sensor_network)
    return NULL;

#ifdef SENSOR_NETWORK_MAGIC
  assert(SENSOR_NETWORK_MAGIC == found_sensor_network->magic);
#endif

  const struct sensor_port_tree_node _dummy_sensor_port = dummy_sensor_port(dst_port);
  struct sensor_port_tree_node *found_sensor_node
            = RD_AVL_FIND(&found_sensor_network->sensors_by_port,&_dummy_sensor_port);

  if(NULL == found_sensor_node)
    return NULL;

#ifdef SENSOR_PORT_TREE_NODE_MAGIC
  assert(SENSOR_PORT_TREE_NODE_MAGIC == found_sensor_node->magic);
#endif
  assert(found_sensor_node->sensor);
#ifdef SENSOR_MAGIC
  assert(SENSOR_MAGIC == found_sensor_node->sensor->magic);
#endif

  ATOMIC_OP(add, fetch, &found_sensor_node->sensor->refcnt.value, 1);
  return found_sensor_node->sensor;
}

static void rb_sensor_delete(struct sensor *sensor) {
	size_t i;
	struct flowSetV9Ipfix *node;

	for (i=0; i<RD_ARRAYSIZE(sensor->up_to_512_templates); ++i) {
		node = sensor->up_to_512_templates[i];
		if (node) {
			free_v9_ipfix_template(node);
		}
	}

	while(!LIST_EMPTY(&sensor->over_512_templates)) {
		node = LIST_FIRST(&sensor->over_512_templates);
		LIST_REMOVE(node, entry);
		free_v9_ipfix_template(node);
	}

	rd_memctx_freeall(&sensor->memctx);
	rd_memctx_destroy(&sensor->memctx);
	free(sensor);
}

void rb_sensor_decref(struct sensor *sensor) {
	if (ATOMIC_OP(sub, fetch, &sensor->refcnt.value, 1) == 0) {
		rb_sensor_delete(sensor);
	}
}

void delete_rb_sensors_db(struct rb_sensors_db *database) {
	assert(database);
	json_decref(database->root);

	while (!SLIST_EMPTY(&database->sensors_list)) {
		struct sensor_port_tree_node *elm =
						SLIST_FIRST(&database->sensors_list);
		SLIST_REMOVE_HEAD(&database->sensors_list, list_node);
		rb_sensor_decref(elm->sensor);
	}

	rd_avl_destroy(&database->sensors.avl);
	rd_memctx_freeall(&database->sensors.memctx);
	rd_memctx_destroy(&database->sensors.memctx);
	rd_avl_destroy(&database->bad_sensors.avl);
	rd_memctx_freeall(&database->bad_sensors.memctx);
	rd_memctx_destroy(&database->bad_sensors.memctx);
	free(database);
}
