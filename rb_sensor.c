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

/*******************************************************************************/
/*                            RB CONFIGURATION                                 */
/*******************************************************************************/

#ifdef HAVE_UDNS
static const char *dns_ptr_client_key = "dns_ptr_client";
static const char *dns_ptr_target_key = "dns_ptr_target";
#endif

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

/// Name and description of an id (application id -> application name, for
/// example)
struct id_name_description_assoc {
#ifndef NDEBUG
#define APPLICATION_ID_MAGIC 0xA1CA101DA1CA1CA1
#define SELECTOR_ID_MAGIC    0x3EC01DA1C3EC01DA
#define INTERFACE_ID_MAGIC   0x13AE1DA1C13AE1DA
  uint64_t magic; ///< Magic to assert coherency
#else
#define APPLICATION_ID_MAGIC 0
#define SELECTOR_ID_MAGIC    0
#define INTERFACE_ID_MAGIC   0
#endif
  uint64_t id; ///< Identification
  char *name; ///< id name
  char *description; ///< Id description
  rd_avl_node_t avl_node; ///< AVL node
};

/// Typedef to maintain coherency
typedef struct id_name_description_assoc application_id_t;

/**
 * Compare two (id, name, description) ids
 * @param  vnode1 Node 1
 * @param  vnode2 Node 2
 * @param  magic  Magic (if NDEBUG, the parameter is ignored)
 * @return        node2->id - node1->id
 */
static int name_id_description_cmp(const void *vnode1, const void *vnode2,
    uint64_t magic) {
  const struct id_name_description_assoc *node1 = vnode1;
  const struct id_name_description_assoc *node2 = vnode2;

#ifdef NDEBUG
  (void)magic;
#endif

  assert(node1);
  assert(node2);
  assert(node1->magic == magic);
  assert(node2->magic == magic);

  return node2->id - node1->id;
}

/**
 * Compare two application id node
 * @param  aid1 Application id 1
 * @param  aid2 Application id 2
 * @return      app_id->id name_id_description_cmp
 */
static int application_id_cmp(const void *aid1, const void *aid2) {
  return name_id_description_cmp(aid1, aid2, APPLICATION_ID_MAGIC);
}

/**
 * Compare two selector id
 * @param  aid1 Application id 1
 * @param  aid2 Application id 2
 * @return      app_id->id name_id_description_cmp
 */
static int selector_id_cmp(const void *sid1, const void *sid2) {
  return name_id_description_cmp(sid1, sid2, APPLICATION_ID_MAGIC);
}

/**
 * Compare two interfaces id
 * @param  aid1 Application id 1
 * @param  aid2 Application id 2
 * @return      app_id->id name_id_description_cmp
 */
static int interface_id_cmp(const void *iid1, const void *iid2) {
  return name_id_description_cmp(iid1, iid2, INTERFACE_ID_MAGIC);
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

/* ******** */

/// Define an observation id
struct observation_id_s {
#ifndef NDEBUG
#define OBSERVATION_ID_MAGIC 0xB53A101A1CB53A10LL
  uint64_t magic; ///< Magic constant to assert coherency
#endif
  uint32_t observation_id;

  rd_avl_t home_networks;
  rd_avl_t applications;
  rd_avl_t selectors;
  rd_avl_t interfaces;
  rd_memctx_t memctx;
  char *enrichment;

  int64_t fallback_first_switch;

#ifdef HAVE_UDNS
#define ENABLE_PTR_DNS_CLIENT 1<<0
#define ENABLE_PTR_DNS_TARGET 1<<1
#endif
#define EXPORTER_SPAN         1<<2
#define EXPORTER_IN_WAN_SIDE  1<<3
  uint8_t observation_domain_flags;

  // @TODO merge in one template_database struct.
  FlowSetV9Ipfix *up_to_512_templates[512]; /* Array: direct element access */
  LIST_HEAD(, flowSetV9Ipfix) over_512_templates;       /* Linked List */

  rd_avl_node_t avl_node;
  SLIST_ENTRY(observation_id_s) list_node;

  atomic_uint64_t refcnt;
};

#ifdef OBSERVATION_ID_MAGIC
#define assert_observation_id(X) assert(OBSERVATION_ID_MAGIC == (X)->magic)
#else
#define assert_observation_id(X)
#endif

uint32_t observation_id_num(const observation_id_t *observation_id) {
  return observation_id->observation_id;
}

static void free_v9_ipfix_template(struct flowSetV9Ipfix *template) {
	free(template);
}

static void observation_id_done(observation_id_t *observation_id) {
	size_t i;
	struct flowSetV9Ipfix *node;

	for (i=0; i<RD_ARRAYSIZE(observation_id->up_to_512_templates); ++i) {
		node = observation_id->up_to_512_templates[i];
		if (node) {
			free_v9_ipfix_template(node);
		}
	}

	while(!LIST_EMPTY(&observation_id->over_512_templates)) {
		node = LIST_FIRST(&observation_id->over_512_templates);
		LIST_REMOVE(node, entry);
		free_v9_ipfix_template(node);
	}

	rd_memctx_freeall(&observation_id->memctx);
	rd_memctx_destroy(&observation_id->memctx);
	free(observation_id);
}

void observation_id_decref(observation_id_t *observation_id) {
	if (ATOMIC_OP(sub, fetch, &observation_id->refcnt.value, 1) == 0) {
		observation_id_done(observation_id);
	}
}

static int observation_id_cmp(const void *vobs_id1, const void *vobs_id2) {
  const observation_id_t *observation_id1 = vobs_id1;
  const observation_id_t *observation_id2 = vobs_id2;

  assert_observation_id(observation_id1);
  assert_observation_id(observation_id2);

  return observation_id1->observation_id - observation_id2->observation_id;
}

/** Find a (id, name, description) tuple
 * @param  avl   AVL to find tuple
 * @param  id    Description id
 * @param  magic Expected magic (if !NDEBUG is ignored)
 * @return       Found node
 */
static struct id_name_description_assoc *find_id_description_assoc(
    rd_avl_t *avl, uint64_t id, uint64_t magic) {

#ifdef NDEBUG
  (void)magic;
#endif

  const struct id_name_description_assoc dummy = {
#ifndef NDEBUG
    .magic = magic,
#endif
    .id = id,
  };

  return RD_AVL_FIND(avl, &dummy);
}

/** Check if string is equal, checking if old string exists
 * @param  old     Old string
 * @param  new     New string
 * @param  new_len New string length
 * @return         true if equal, false in other case
 */
static bool string_equal(const char *old, const char *new, size_t new_len) {
  // We have a new string and it's different than old
  return !(new && new_len > 0 && (!old || strncmp(new, old, new_len)));
}

/** Update an id_name_description_assoc string if needed
 * @param memctx   Allocation memory context
 * @param old      Old string
 * @param new      New string
 * @param new_size New string length
 * @return         True if all ok, false if allocation fails
 */
static bool id_name_description_update_string(rd_memctx_t *memctx,
    char **old, const char *new, const size_t new_len,
    const char *memory_error_msg, const char *memory_error_field) {
  assert(old);

  if (unlikely(!string_equal(*old, new, new_len))) {
    if (*old) {
      rd_memctx_free(memctx, *old);
    }

    *old = rd_memctx_malloc(memctx, new_len + 1);
    if (unlikely(NULL == *old)) {
      traceEvent(TRACE_ERROR, "Couldn't allocate %s %s", memory_error_msg,
        memory_error_field);
      return false;
    }

    memcpy(*old, new, new_len);
    (*old)[new_len] = '\0';
  }

  return true;
}

/** Add a (id, name, description) node to an AVL
 * @param avl              AVL
 * @param memctx           Allocations memory context
 * @param id               Tuple ID
 * @param name             Tuple name
 * @param name_len         Tuple name length
 * @param description      Tuple description
 * @param description_len  Tuple description length
 * @param memory_error_msg Kind of node (for error shows purposes)
 * @param magic            Magic to assert coherency, ignored if !NDEBUG
 */
static void add_id_name_description(rd_avl_t *avl, rd_memctx_t *memctx,
    uint64_t id, const char *name, size_t name_len,
    const char *description, size_t description_len,
    const char *memory_error_msg, uint64_t magic) {
  assert(avl);

  struct id_name_description_assoc *current = find_id_description_assoc(avl, id,
    magic);

  const bool node_in_avl = current;
  if (unlikely(!node_in_avl)) {
    current = rd_memctx_calloc(memctx, 1, sizeof(*current));
    if (unlikely(NULL == current)) {
      traceEvent(TRACE_ERROR, "Couldn't allocate %s node", memory_error_msg);
      goto err;
    }

#ifndef NDEBUG
    current->magic = magic;
#else
    (void)magic;
#endif
    current->id = id;
  }

  const bool name_rc = id_name_description_update_string(memctx, &current->name,
    name, name_len, memory_error_msg, "name");
  if (unlikely(!name_rc)) {
    goto err;
  }

  const bool description_rc = id_name_description_update_string(memctx,
    &current->description, description, description_len, memory_error_msg,
    "description");
  if (unlikely(!description_rc)) {
    goto err;
  }

  if (unlikely(!node_in_avl)) {
    RD_AVL_INSERT(avl, current, avl_node);
  }

  return;

err:
  if (current) {
    if (node_in_avl) {
      RD_AVL_REMOVE_ELM(avl, current);
    }

    if (current->name) {
      rd_memctx_free(memctx, current->name);
    }

    if (current->description) {
      rd_memctx_free(memctx, current->description);
    }

    rd_memctx_free(memctx, current);
  }
}

void observation_id_add_application_id(observation_id_t *observation_id,
    uint64_t application_id, const char *application_name,
    size_t application_name_len) {

  assert(observation_id);

  add_id_name_description(&observation_id->applications,
    &observation_id->memctx, application_id, application_name,
    application_name_len, NULL, 0, "APPLICATION_ID", APPLICATION_ID_MAGIC);
}

void observation_id_add_selector_id(observation_id_t *observation_id,
    uint64_t selector_id, const char *selector_name,
    size_t selector_name_len) {

  assert(observation_id);

  add_id_name_description(&observation_id->selectors,
    &observation_id->memctx, selector_id, selector_name,
    selector_name_len, NULL, 0, "SELECTOR_ID", SELECTOR_ID_MAGIC);
}

void observation_id_add_interface(observation_id_t *observation_id,
    uint64_t interface_id, const char *interface_name,
    size_t interface_name_len, const char *interface_description,
    size_t interface_description_len) {

  assert(observation_id);

  add_id_name_description(&observation_id->interfaces,
    &observation_id->memctx, interface_id, interface_name,
    interface_name_len, interface_description, interface_description_len,
    "INTERFACE_ID", INTERFACE_ID_MAGIC);
}

/**
 * Name of a (id, name, description) record
 * @param  avl   AVL to search record
 * @param  id    Record id
 * @param  magic Magic to assert coherency (ignored if !NDEBUG)
 * @return       Tuple name
 */
static const char *id_name_description_assoc_name(rd_avl_t *avl, uint64_t id,
    uint64_t magic) {
  struct id_name_description_assoc *assoc = find_id_description_assoc(avl, id,
    magic);
  return assoc ? assoc->name : NULL;
}

/**
 * Description of a (id, name, description) record
 * @param  avl   AVL to search record
 * @param  id    Record id
 * @param  magic Magic to assert coherency (ignored if !NDEBUG)
 * @return       Tuple name
 */
static const char *id_name_description_assoc_description(rd_avl_t *avl,
  uint64_t id, uint64_t magic) {
  struct id_name_description_assoc *assoc = find_id_description_assoc(avl, id,
    magic);
  return assoc ? assoc->description : NULL;
}

const char *observation_id_application_name(observation_id_t *observation_id,
    uint64_t application_id) {
  return id_name_description_assoc_name(&observation_id->applications,
    application_id, APPLICATION_ID_MAGIC);
}

const char *observation_id_selector_name(observation_id_t *observation_id,
    uint64_t selector_id) {
  return id_name_description_assoc_name(&observation_id->selectors,
    selector_id, SELECTOR_ID_MAGIC);
}

const char *observation_id_interface_name(observation_id_t *observation_id,
    uint64_t interface_id) {
  return id_name_description_assoc_name(&observation_id->interfaces,
    interface_id, INTERFACE_ID_MAGIC);
}

const char *observation_id_interface_description(
  observation_id_t *observation_id, uint64_t interface_id) {
  return id_name_description_assoc_description(&observation_id->interfaces,
    interface_id, INTERFACE_ID_MAGIC);
}

static bool observation_id_add_home_net(observation_id_t *observation_id,
                          json_t *json_home_net, const struct sensor *sensor) {
  assert(sensor);
  assert(observation_id);
  assert(json_home_net);
  json_error_t jerr;
  const char *network=NULL, *network_name_str=NULL;

  if(!json_is_object(json_home_net)){
    traceEvent(TRACE_ERROR,
      "Could not get one network of sensor %s, observation_id%"PRIu32
      ": is not an object", sensor_ip_string(sensor),
      observation_id_num(observation_id));
    return false;
  }

  const int unpack_rc = json_unpack_ex(json_home_net,&jerr,0,"{s:s,s:s}",
    "network_name",&network_name_str,"network",&network);

  if(unpack_rc != 0) {
    traceEvent(TRACE_ERROR,"Can't unpack home net: %s",jerr.text);
    return false;
  }

  struct network_tree_node *home_net = rd_memctx_calloc(&observation_id->memctx,
    1, sizeof(*home_net));
  if(NULL==home_net){
    traceEvent(TRACE_ERROR,
      "Could not allocate home net of sensor %s observation id %"PRIu32,
      sensor_ip_string(sensor), observation_id_num(observation_id));
    return false;
  }

#ifdef NETWORK_TREE_NODE_MAGIC
  home_net->magic = NETWORK_TREE_NODE_MAGIC;
#endif

  if(!network_name_str){
    traceEvent(TRACE_ERROR,
      "Sensor %s observation id %"PRIu32" has a network defined with no name.",
      sensor_ip_string(sensor), observation_id_num(observation_id));
    return false;
  }
  home_net->name = rd_memctx_strdup(&observation_id->memctx, network_name_str);
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
  home_net->addres_as_str = rd_memctx_strdup(&observation_id->memctx, network);

  rd_avl_insert(&observation_id->home_networks, home_net, &home_net->avl_node);
  return true;
}

static bool parse_observation_id_home_nets(observation_id_t *observation_id,
    const json_t *home_nets, const struct sensor *sensor) {
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
      rc = observation_id_add_home_net(observation_id, value, sensor);
    }
  }

  return rc;
}

static bool parse_observation_id_enrichment(observation_id_t *observation_id,
    const json_t *enrichment, const struct sensor *sensor) {
  if(!json_is_object(enrichment)) {
    traceEvent(TRACE_ERROR,
      "Enrichment field is not an object in sensor %s osbervation id %"PRIu32,
      sensor_ip_string(sensor), observation_id_num(observation_id));
    return false;
  } else {
    char *tmp_enrichment = json_dumps(enrichment,
            JSON_COMPACT|JSON_ENSURE_ASCII);
    if(tmp_enrichment){
      // tmp_enrichment == "{\"hello\":\"world\"}". We want delete brackets.
      observation_id->enrichment = rd_memctx_strdup(&observation_id->memctx,
            &tmp_enrichment[1]);
      char *last_bracket = strrchr(observation_id->enrichment,'}');
      if(last_bracket)
        *last_bracket = '\0';
      free(tmp_enrichment);

      if(!(strlen(observation_id->enrichment)>0)) {
        /* We don't need to mantain a null buffer if enrichment == {} */
        rd_memctx_free(&observation_id->memctx, observation_id->enrichment);
        observation_id->enrichment = NULL;
      }
    }

    return true;
  }
}

#ifdef HAVE_UDNS

static bool parse_observation_id_dns0(observation_id_t *observation_id,
    const json_t *dns_ptr_value, const char *key, const char *sensor_name,
    int flag) {
  if(NULL != dns_ptr_value) {
    if(!json_is_boolean(dns_ptr_value)) {
      traceEvent(TRACE_ERROR, "%s is not a boolean in sensor %s observation id"
        " %"PRIu32", can't parse it", key, sensor_name,
        observation_id_num(observation_id));
      return false;
    } else if (json_is_true(dns_ptr_value)) {
      observation_id->observation_domain_flags |= flag;
    }
  }

  return true;
}

static void parse_observation_id_dns(observation_id_t *observation_id,
    const char *sensor_name, const json_t *dns_ptr_client,
    const json_t *dns_ptr_target) {
  parse_observation_id_dns0(observation_id, dns_ptr_client, dns_ptr_client_key,
    sensor_name, ENABLE_PTR_DNS_CLIENT);
  parse_observation_id_dns0(observation_id, dns_ptr_target, dns_ptr_target_key,
    sensor_name, ENABLE_PTR_DNS_TARGET);

}

#endif /* HAVE_UDNS */

static bool parse_observation_id(observation_id_t *observation_id,
    json_t *jobservation_id, uint32_t observation_id_n,
    const struct sensor *sensor) {
  json_error_t jerr;
  int span_mode = false, exporter_in_wan_side = false;
  const json_t *home_nets=NULL, *enrichment=NULL, *routers_macs=NULL;
  json_int_t fallback_first_switch = 0;
#ifdef HAVE_UDNS
  const json_t *dns_ptr_client=NULL,*dns_ptr_target=NULL;
#endif

  const int unpack_rc = json_unpack_ex(jobservation_id, &jerr, 0,
    "{s?o,s?o,s?b,s?b,s?o,s?I}",
      "home_nets", &home_nets,
      "enrichment", &enrichment,
      "span_port", &span_mode,
      "exporter_in_wan_side", &exporter_in_wan_side,
      "routers_macs", &routers_macs,
      "fallback_first_switch", &fallback_first_switch);

  if (unpack_rc != 0) {
    traceEvent(TRACE_ERROR,
      "Can't parse sensor %s observation id %"PRIu32" network: %s",
      sensor_ip_string(sensor), observation_id_n, jerr.text);
    return false;
  }

  if(home_nets) {
    parse_observation_id_home_nets(observation_id, home_nets, sensor);
  }

  if(enrichment) {
    parse_observation_id_enrichment(observation_id, enrichment, sensor);
  }

  if (routers_macs) {
    traceEvent(TRACE_ERROR,
      "Observation id's router macs support has been deprecated");
  }

  observation_id->fallback_first_switch = fallback_first_switch;

#ifdef HAVE_UDNS
  const int unpack_dns_rc = json_unpack_ex(jobservation_id, &jerr, 0,
    "{s?o,s?o}", dns_ptr_client_key, &dns_ptr_client,
    dns_ptr_target_key, &dns_ptr_target);

  if (unpack_dns_rc != 0) {
    traceEvent(TRACE_ERROR, "Can't unpack sensor %s observation id %"PRIu32
      "DNS attributes: %s", sensor_ip_string(sensor), observation_id_n,
      jerr.text);
  } else {
    parse_observation_id_dns(observation_id, sensor_ip_string(sensor),
      dns_ptr_client, dns_ptr_target);
  }
#endif

  if (span_mode) {
    observation_id->observation_domain_flags |= EXPORTER_SPAN;
  }

  if (exporter_in_wan_side) {
    observation_id->observation_domain_flags |= EXPORTER_IN_WAN_SIDE;
  }

  return observation_id;
}

static observation_id_t *observation_id_new(uint32_t observation_id,
    json_t *jobservation_id, const struct sensor *sensor) {
  observation_id_t *ret = calloc(1, sizeof(*ret));
  if (unlikely(NULL == ret)) {
    traceEvent(TRACE_ERROR,
      "Couldn't allocate observation id (out of memory?)");
    return NULL;
  }

#ifdef OBSERVATION_ID_MAGIC
  ret->magic = OBSERVATION_ID_MAGIC;
#endif
  ret->observation_id = observation_id;

  rd_avl_init(&ret->home_networks, compare_networks, 0);
  rd_avl_init(&ret->applications, application_id_cmp, 0);
  rd_avl_init(&ret->selectors, selector_id_cmp, 0);
  rd_avl_init(&ret->interfaces, interface_id_cmp, 0);

  rd_memctx_init(&ret->memctx, NULL, RD_MEMCTX_F_TRACK);
  ret->refcnt.value = 1;

  LIST_INIT(&ret->over_512_templates);

  const bool parse_oid_rc = parse_observation_id(ret,
      jobservation_id, observation_id, sensor);
  if (!parse_oid_rc) {
    observation_id_decref(ret);
    ret = NULL;
  }
  return ret;
}

/// Sensor defined by a network, that have observations ids
struct sensor {
#ifndef NDEBUG
	/// Magic constant to assert coherency
#define SENSOR_MAGIC 0xABC123DEF098
	uint64_t magic; //< Magic to assert coherency
#endif

  /// network the sensor belongs to
  struct {
    netAddress_t ip;
    const char *ip_str;
  } network;

  /** Associated worker, so the same sensor always goes to the
  same worker, avoiding reordering and data races
  @todo worker by observation id? */
  worker_t *worker;

  rd_avl_t observations_id_db; ///< Observation id database
  observation_id_t *default_observation_id; ///< default observation id
  SLIST_HEAD(,observation_id_s) observations_id_list;

  rd_avl_node_t avl_node;
  SLIST_ENTRY(sensor) list_node;

  atomic_uint64_t refcnt; ///< Reference counter
};

worker_t *sensor_worker(const struct sensor *sensor) {
  return sensor->worker;
}

static observation_id_t dummy_observation_id(uint32_t observation_id) {
  const observation_id_t ret = {
#ifdef OBSERVATION_ID_MAGIC
    .magic=OBSERVATION_ID_MAGIC,
#endif
    .observation_id = observation_id,
  };

  return ret;
}

const char *sensor_ip_string(const struct sensor *sensor){
  return sensor->network.ip_str;
}

const char *observation_id_enrichment(const observation_id_t *obs_id){
  return obs_id->enrichment;
}

bool is_span_observation_id(const observation_id_t *observation_id) {
    return observation_id->observation_domain_flags & EXPORTER_SPAN;
}

bool is_exporter_in_wan_side(const observation_id_t *observation_id) {
    return observation_id->observation_domain_flags & EXPORTER_IN_WAN_SIDE;
}

int64_t observation_id_fallback_first_switch(const observation_id_t *obs_id) {
  return obs_id->fallback_first_switch;
}

static const struct network_tree_node *network_node(
    observation_id_t *observation_id,
    const uint8_t ip[16]){
  assert(observation_id);
  int i;

  struct network_tree_node dummy_network_tree_node = {
#ifdef NETWORK_TREE_NODE_MAGIC
    .magic = NETWORK_TREE_NODE_MAGIC,
#endif
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

  return RD_AVL_FIND(&observation_id->home_networks, &dummy_network_tree_node);
}

const char *network_ip(observation_id_t *obs_id, const uint8_t ip[16]) {
  const struct network_tree_node *node = network_node(obs_id, ip);
  return node?node->addres_as_str:NULL;
}

const char *network_name(observation_id_t *obs_id, const uint8_t ip[16]) {
  const struct network_tree_node *node = network_node(obs_id, ip);
  return node?node->name:NULL;
}

#ifdef HAVE_UDNS
bool observation_id_want_client_dns(const observation_id_t *oid) {
  return oid->observation_domain_flags & ENABLE_PTR_DNS_CLIENT;
}

bool observation_id_want_target_dns(const observation_id_t *oid) {
  return oid->observation_domain_flags & ENABLE_PTR_DNS_TARGET;
}
#endif

struct bad_sensor {
#ifndef NDEBUG
#define BAD_SENSOR_MAGIC 0xBAD5350A1CBAD535
  uint64_t magic;
#endif

  uint32_t ip;

  rd_avl_node_t avl_node;
};

typedef SLIST_HEAD(, sensor) sensors_list_t;

/// Sensors database
struct rb_sensors_db {
#ifndef NDEBUG
	/// Magic constant to assert coherence
#define RB_DATABASE_MAGIC 0xBDAABAEA1C
	uint64_t magic; //< Magic to assert coherence
#endif
	sensors_list_t sensors_list; //< List of sensors
	/// sensors (networks) db
	struct {
		rd_avl_t avl;
	} sensors;
  /// bad sensors db
  struct {
    rd_avl_t avl;
    rd_memctx_t memctx;
  } bad_sensors;
	listener_list new_listeners; //< Listeners that have to open
	json_t *root; //< Json data
};

static int compare_bad_sensors(const void *_s1,const void *_s2)
{
  const struct bad_sensor *s1 = _s1;
  const struct bad_sensor *s2 = _s2;

  assert(s1->magic == BAD_SENSOR_MAGIC);
  assert(s2->magic == BAD_SENSOR_MAGIC);

  return s1->ip > s2->ip ? 1 : (s2->ip==s1->ip ? 0 : -1);
}

static int compare_sensors(const void *_s1,const void *_s2)
{
  const struct sensor *s1 = _s1;
  const struct sensor *s2 = _s2;

  assert(s1->magic == SENSOR_MAGIC);
  assert(s2->magic == SENSOR_MAGIC);

  uint8_t ipv6[16];
  apply_netmask(ipv6, s1->network.ip.network, s2->network.ip.networkMask);

  return memcmp(ipv6,&s2->network.ip,sizeof(ipv6));
}

static struct bad_sensor *find_bad_sensor(uint64_t ip,struct rb_sensors_db *db)
{
  const struct bad_sensor proposed_sensor = {
#ifdef SENSOR_NETWORK_MAGIC
    .magic = SENSOR_NETWORK_MAGIC,
#endif

    .ip = ip,

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

static uint32_t parse_observation_id_number(const char *debug_ip_str,
    const char *num, bool *ok) {
  static const uint32_t max_observation_id = 0xffffffff;
  assert(num);
  assert(ok);

  char *endptr = NULL;
  const unsigned long oid = strtoul(num, &endptr, 10);
  if ('\0' != *endptr) {
    traceEvent(TRACE_ERROR, "Couldn't parse sensor %s observation id %s"
      " number, skipping", debug_ip_str, num);
    *ok = false;
    return 0;
  }

  if (oid > max_observation_id) {
    traceEvent(TRACE_ERROR,
      "Couldn't parse sensor %s observation_id %s: Number too high %"PRIu32,
        debug_ip_str, num, max_observation_id);
    *ok = false;
  }

  *ok = true;

  return oid;
}

static struct sensor *parse_sensor(json_t *jsensor, const char *ip_str) {
  static const char observations_id_key[] = "observations_id";
  const char *observation_id_key = NULL;
  json_t *observation_id = NULL;

  if(!json_is_object(jsensor)) {
    traceEvent(TRACE_ERROR, "%s in not an object in config file.\n", ip_str);
    return NULL;
  }

  json_t *observations_id = json_object_get(jsensor, observations_id_key);
  if (!observations_id) {
    traceEvent(TRACE_ERROR, "Sensor %s has not \"%s\" property in config file",
      ip_str, observations_id_key);
    return NULL;
  }

  if (!json_is_object(observations_id)) {
    traceEvent(TRACE_ERROR, "\"%s\" property is not an object in sensor %s",
      observations_id_key, ip_str);
    return NULL;
  }

  if (0 == json_object_size(observations_id)) {
    traceEvent(TRACE_ERROR, "No \"%s\" defined in sensor %s",
      observations_id_key, ip_str);
    return NULL;
  }

  struct sensor *sensor = calloc(1, sizeof(*sensor));
  if (unlikely(NULL == sensor)) {
    traceEvent(TRACE_ERROR,
                  "Can't allocate sensor of network %s memory (out of memory?)",
                  ip_str);
    return NULL;
  }

#ifdef SENSOR_MAGIC
  sensor->magic = SENSOR_MAGIC;
#endif
  sensor->refcnt.value = 1;

  const bool parse_address_rc = safe_parse_address(ip_str, &sensor->network.ip);
  if (!parse_address_rc) {
    traceEvent(TRACE_ERROR, "Couldn't parse %s sensor address", ip_str);
    free(sensor);
    return NULL;
  }

  rd_avl_init(&sensor->observations_id_db, observation_id_cmp, 0);

  json_object_foreach(observations_id, observation_id_key, observation_id) {
    const bool parsing_default_oid = 0 == strcmp("default", observation_id_key);
    bool observation_id_ok = true;
    observation_id_t *cur_observation_id = NULL;

    const uint32_t observation_id_n = parsing_default_oid ? 0 :
      parse_observation_id_number(ip_str, observation_id_key,
        &observation_id_ok);

    if (!observation_id_ok) {
      continue;
    }

    cur_observation_id = observation_id_new(observation_id_n, observation_id,
      sensor);

    if (parsing_default_oid) {
      sensor->default_observation_id = cur_observation_id;
    } else {
      rd_avl_insert(&sensor->observations_id_db, cur_observation_id,
        &cur_observation_id->avl_node);

      SLIST_INSERT_HEAD(&sensor->observations_id_list, cur_observation_id,
        list_node);
    }
  }

  return sensor;
}

static struct rb_sensors_db *allocate_rb_sensors_db() {
	struct rb_sensors_db *database = calloc(1, sizeof(*database));
	if (NULL==database) {
		traceEvent(TRACE_ERROR, "Memory error");
		return NULL;
	}

#ifdef RB_DATABASE_MAGIC
	database->magic = RB_DATABASE_MAGIC;
#endif
	listener_list_init(&database->new_listeners);
	rd_avl_init(&database->sensors.avl, compare_sensors,
								RD_AVL_F_LOCKS);
	rd_avl_init(&database->bad_sensors.avl, compare_bad_sensors,
								RD_AVL_F_LOCKS);
	rd_memctx_init(&database->bad_sensors.memctx, NULL,
					RD_MEMCTX_F_TRACK | RD_MEMCTX_F_LOCK);

	return database;
}

static bool read_rb_config_sensors_networks(struct rb_sensors_db *database,
                              json_t *sensors_networks, worker_t **worker_list,
                              size_t worker_list_size) {

	const char *network = NULL;
	json_t *network_config = NULL;
	size_t worker_idx = 0;

	json_object_foreach(sensors_networks, network, network_config) {
		if (!json_is_object(network_config)) {
			traceEvent(TRACE_ERROR,
				"%s sensor network is not an object in config"
				" file.", network);
      			continue;
      		}

		struct sensor *sensor = parse_sensor(network_config, network);
		if (NULL == sensor) {
			continue;
		}

		sensor->worker = worker_list[worker_idx++];
		if (worker_idx >= worker_list_size) {
			worker_idx = 0;
		}

		struct sensor *old_sensor = rd_avl_insert(
			&database->sensors.avl, sensor, &sensor->avl_node);

		if (old_sensor) {
			traceEvent(TRACE_ERROR,
				"Error: Network %s match with network %s"
				". Discarding old one.",
				sensor->network.ip_str,
				old_sensor->network.ip_str);

			rb_sensor_decref(old_sensor);
		}

    SLIST_INSERT_HEAD(&database->sensors_list, sensor, list_node);
	}

	return true;
}

/* *** sensors database *** */
struct rb_sensors_db *read_rb_config(const char *json_path,
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

  return database;
}

static struct sensor dummy_sensor(const uint64_t ip) {
  struct sensor ret = {
#ifdef SENSOR_MAGIC
    .magic = SENSOR_MAGIC,
#endif

    .network.ip.network[10] = 0xFF,
    .network.ip.network[11] = 0xFF,
    .network.ip.network[12] = ((ip & 0xFF000000) >> 24),
    .network.ip.network[13] = ((ip & 0x00FF0000) >> 16),
    .network.ip.network[14] = ((ip & 0x0000FF00) >> 8),
    .network.ip.network[15] = ((ip & 0x000000FF)),
  };

  memset(ret.network.ip.networkMask, 0xFF, sizeof(ret.network.ip.networkMask));
  memset(ret.network.ip.broadcast, 0xFF, sizeof(ret.network.ip.broadcast));

  return ret;
}

static FlowSetV9Ipfix *find_observation_id_template0(
		const observation_id_t *observation_id,
		const uint16_t template_id) {
  assert(observation_id);

  if(template_id < 512){
    return observation_id->up_to_512_templates[template_id];
  } else {
    FlowSetV9Ipfix *template = NULL;
    LIST_FOREACH(template, &observation_id->over_512_templates, entry) {
      if (template->templateInfo.templateId == template_id) {
        return template;
      }
    }
  }

  return NULL;
}

const struct flowSetV9Ipfix *find_observation_id_template(
		const observation_id_t *observation_id,
		const uint16_t template_id) {
  return find_observation_id_template0(observation_id, template_id);
}

static bool template_equal(const FlowSetV9Ipfix *template1,
    const FlowSetV9Ipfix *template2) {
  const bool info_equal = template1->templateInfo.templateId ==
      template2->templateInfo.templateId &&
    template1->templateInfo.fieldCount ==
      template2->templateInfo.fieldCount &&
    template1->templateInfo.scope_field_len ==
      template2->templateInfo.scope_field_len &&
    template1->templateInfo.is_option_template ==
      template2->templateInfo.is_option_template;

  if (!info_equal) {
    return false;
  }

  size_t i;
  for (i=0; i<template1->templateInfo.fieldCount; ++i) {
    const bool field_equal =
      template1->fields[i].fieldId == template2->fields[i].fieldId &&
      template1->fields[i].fieldLen == template2->fields[i].fieldLen;

    if (!field_equal) {
      return false;
    }
  }

  return true;
}

void save_template(observation_id_t *observation_id,
		const struct flowSetV9Ipfix *template) {
	const V9IpfixSimpleTemplate *templateInfo = &template->templateInfo;
	const uint16_t template_id = templateInfo->templateId;

	struct flowSetV9Ipfix *prev_template = find_observation_id_template0(
  		observation_id, template_id);
  const bool replace_template = !prev_template ||
    !template_equal(prev_template, template);

	if (unlikely(readOnlyGlobals.enable_debug)) {
		char buf[BUFSIZ];
		const uint32_t netflow_device_ip =
				templateInfo->netflow_device_ip;

		traceEvent(TRACE_INFO, "%s [sensor=%s][observation_id=%"PRIu32
			"][id=%d]",
			replace_template ? ">>>>> Redefined existing template " :
		  prev_template ? ">>>>> Same as previous template" :
        ">>>>> Found new flow template definition",
			_intoaV4(netflow_device_ip, buf, sizeof(buf)),
			observation_id_num(observation_id), template_id);
	}

	if (!replace_template) {
		return;
	}

	if (prev_template) {
		if (templateInfo->templateId >= 512) {
			LIST_REMOVE(prev_template, entry);
		}

		free_v9_ipfix_template(prev_template);
	}

  struct flowSetV9Ipfix *new_template = NULL;
  rd_calloc_struct(&new_template, sizeof(*new_template),
    template->templateInfo.fieldCount*sizeof(template->fields[0]),
      template->fields, &new_template->fields,
    RD_MEM_END_TOKEN);

  if (unlikely(!new_template)) {
    traceEvent(TRACE_WARNING, "Not enough memory");
    return;
  }

  new_template->templateInfo.templateId = template->templateInfo.templateId;
  new_template->templateInfo.fieldCount = template->templateInfo.fieldCount;
  new_template->templateInfo.is_option_template =
    template->templateInfo.is_option_template;
  new_template->templateInfo.netflow_device_ip =
    template->templateInfo.netflow_device_ip;
  new_template->templateInfo.observation_domain_id =
    template->templateInfo.observation_domain_id;

  if (!template->templateInfo.is_option_template) {
    uint16_t fieldId;
    for (fieldId=0; fieldId<new_template->templateInfo.fieldCount; ++fieldId) {
      const uint16_t entity_id = new_template->fields[fieldId].fieldId;
      new_template->fields[fieldId].v9_template = find_template(entity_id);
    }
  }


	if (templateInfo->templateId < 512) {
		observation_id->up_to_512_templates[templateInfo->templateId]
			= new_template;
	} else {
		LIST_INSERT_HEAD(&observation_id->over_512_templates,
			new_template, entry);
	}

	if (unlikely(readOnlyGlobals.enable_debug)) {
		traceEvent(TRACE_INFO,
			">>>>> Defined flow template [id=%d][fieldCount=%d]",
			template->templateInfo.templateId,
			template->templateInfo.fieldCount);
	}
}

void save_template_async(struct sensor *sensor,
                                              struct flowSetV9Ipfix *template) {
  observation_id_t *observation_id = get_sensor_observation_id(sensor,
    template->templateInfo.observation_domain_id);

  if (observation_id) {
    add_template_to_worker(template, observation_id, sensor->worker);
  } else {
    char buf[BUFSIZ];
    traceEvent(TRACE_ERROR, "Couldn't async save template %"PRIu16" of sensor "
                    "%s observation domain %"PRIu32": Observation id not found",
      template->templateInfo.templateId,
      _intoaV4(template->templateInfo.netflow_device_ip, buf, sizeof(buf)),
      template->templateInfo.observation_domain_id);

    // @todo memory management!!
  }

  rb_sensor_decref(sensor);
}

/// @TODO const?
struct sensor *get_sensor(struct rb_sensors_db *database, uint64_t ip) {
  assert(database);

  struct sensor dummy = dummy_sensor(ip);

  rd_avl_rdlock(&database->sensors.avl);

  struct sensor *found_sensor = RD_AVL_FIND_NODE_NL(&database->sensors.avl,
    &dummy);
  if (found_sensor) {
#ifdef SENSOR_MAGIC
    assert(SENSOR_MAGIC == found_sensor->magic);
#endif
    ATOMIC_OP(add, fetch, &found_sensor->refcnt.value, 1);
  }

  rd_avl_unlock(&database->sensors.avl);

  return found_sensor;
}

/// @todo data race between end of RD_AVL_FIND and ATOMIC++, other thread could
/// decref sensor
observation_id_t *get_sensor_observation_id(struct sensor *sensor,
    uint32_t obs_id) {
  assert(sensor);

  observation_id_t dummy = dummy_observation_id(obs_id);
  observation_id_t *ret = RD_AVL_FIND_NODE_NL(&sensor->observations_id_db,
    &dummy);
  if (NULL == ret && sensor->default_observation_id) {
    ret = sensor->default_observation_id;
  }

  if (NULL == ret) {
    return NULL;
  }

  assert_observation_id(ret);
  ATOMIC_OP(add, fetch, &ret->refcnt.value, 1);
  return ret;
}

static void rb_sensor_delete(struct sensor *sensor) {
  while (!SLIST_EMPTY(&sensor->observations_id_list)) {
    observation_id_t *node = SLIST_FIRST(&sensor->observations_id_list);
    SLIST_REMOVE_HEAD(&sensor->observations_id_list, list_node);

    observation_id_decref(node);
	}

  observation_id_decref(sensor->default_observation_id);
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

  rd_avl_destroy(&database->sensors.avl);

  while (!SLIST_EMPTY(&database->sensors_list)) {
		struct sensor *node = SLIST_FIRST(&database->sensors_list);
		SLIST_REMOVE_HEAD(&database->sensors_list, list_node);
		rb_sensor_decref(node);
	}

	rd_avl_destroy(&database->bad_sensors.avl);
	rd_memctx_freeall(&database->bad_sensors.memctx);
	rd_memctx_destroy(&database->bad_sensors.memctx);
	free(database);
}
