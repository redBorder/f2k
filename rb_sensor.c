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

#include "rb_sensor.h"
#include "util.h"

#include <jansson.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

/////////////
// Private //
/////////////

#ifdef HAVE_UDNS
#define ENABLE_PTR_DNS_CLIENT 1 << 0
#define ENABLE_PTR_DNS_TARGET 1 << 1

static const char *dns_ptr_client_key = "dns_ptr_client";
static const char *dns_ptr_target_key = "dns_ptr_target";
#endif

/**
 * Parses an Observation ID id.
 *
 * @param  debug_ip_str String with the IP used for debugging purposes.
 * @param  num          The number to parse.
 * @param  ok           Success or fail.
 * @return              The parsed number.
 */
static uint32_t parse_observation_id_number(const char *debug_ip_str,
                                            const char *num, bool *ok) {
  assert(debug_ip_str);
  assert(num);

  static const uint32_t max_observation_id = 0xffffffff;
  char *endptr = NULL;
  const unsigned long oid = strtoul(num, &endptr, 10);

  if ('\0' != *endptr) {
    traceEvent(TRACE_ERROR, "Couldn't parse sensor %s observation id %s"
                            " number, skipping",
               debug_ip_str, num);
    *ok = false;
    return 0;
  }

  if (oid > max_observation_id) {
    traceEvent(
        TRACE_ERROR,
        "Couldn't parse sensor %s observation_id %s: Number too high %" PRIu32,
        debug_ip_str, num, max_observation_id);
    *ok = false;
  }

  *ok = true;

  return oid;
}

/**
 * Parses the Observation ID enrichment data.
 *
 * @param  observation_id Observation ID to store in the enrichment data.
 * @param  enrichment     JSON object with the enrichment data to parse.
 * @param  sensor         Used for debugging purposes.
 * @return                Success or fail.
 */
static bool parse_observation_id_enrichment(observation_id_t *observation_id,
                                            const json_t *enrichment,
                                            const sensor_t *sensor) {
  assert(observation_id);
  assert(enrichment);
  assert(sensor);

  if (!json_is_object(enrichment)) {
    traceEvent(TRACE_ERROR, "Enrichment field is not an object in sensor %s "
                            "osbervation id %" PRIu32,
               sensor_get_network_string(sensor),
               observation_id_get_id(observation_id));
    return false;
  }

  char *tmp_enrichment =
      json_dumps(enrichment, JSON_COMPACT | JSON_ENSURE_ASCII);
  if (tmp_enrichment) {
    char *last_bracket = strrchr(tmp_enrichment, '}');
    if (last_bracket) {
      *last_bracket = '\0';
    }

    if (strlen(tmp_enrichment) > 0) {
      observation_id_set_enrichment(observation_id, tmp_enrichment + 1);
    }

    free(tmp_enrichment);
  }

  return true;
}

/**
 * Adds a network to an Observation ID.
 *
 * @param  observation_id Observation ID to store in the network.
 * @param  json_home_net  JSON object with the network information.
 * @param  sensor         Used only with debugging purposes.
 * @return                Success or fail.
 */
static bool observation_id_add_home_net(observation_id_t *observation_id,
                                        json_t *json_home_net,
                                        const sensor_t *sensor) {
  assert(sensor);
  assert(observation_id);
  assert(json_home_net);

  json_error_t jerr;
  const char *network = NULL;
  const char *network_name_str = NULL;

  if (!json_is_object(json_home_net)) {
    traceEvent(TRACE_ERROR,
               "Could not get one network of sensor %s, observation_id%" PRIu32
               ": is not an object",
               sensor_get_network_string(sensor),
               observation_id_get_id(observation_id));

    return false;
  }

  const int unpack_rc =
      json_unpack_ex(json_home_net, &jerr, 0, "{s:s,s:s}", "network_name",
                     &network_name_str, "network", &network);

  if (unpack_rc != 0) {
    traceEvent(TRACE_ERROR, "Can't unpack home net: %s", jerr.text);

    return false;
  }

  if (!network_name_str) {
    traceEvent(TRACE_ERROR, "Sensor %s observation id %" PRIu32
                            " has a network defined with no name.",
               sensor_get_network_string(sensor),
               observation_id_get_id(observation_id));

    return false;
  }

  netAddress_t address;
  const bool parse_address_rc = safe_parse_address(network, &address);
  if (!parse_address_rc) {
    traceEvent(TRACE_ERROR,
               "Sensor %s has a home network with an invalid ip address (%s).",
               sensor_get_network_string(sensor), network);

    return false;
  }

  network_t *home_net =
      network_new(address.network, address.networkMask, network_name_str);
  if (!home_net) {
    traceEvent(
        TRACE_ERROR,
        "Could not allocate home net of sensor %s observation id %" PRIu32,
        sensor_get_network_string(sensor),
        observation_id_get_id(observation_id));

    return false;
  }

  observation_id_add_network(observation_id, home_net);

  return true;
}

/**
 * Parses the Observation ID networks.
 *
 * @param  observation_id Observation ID to store the networks.
 * @param  home_nets      JSON object with the networks data.
 * @param  sensor         Used for debugging purposes.
 * @return                Success or fail.
 */
static bool parse_observation_id_home_nets(observation_id_t *observation_id,
                                           const json_t *home_nets,
                                           const sensor_t *sensor) {
  assert(observation_id);
  assert(home_nets);
  assert(sensor);

  bool rc = true;
  if (!json_is_array(home_nets)) {
    traceEvent(TRACE_ERROR, "home_nets in not an array in sensor %s.",
               sensor_get_network_string(sensor));
  } else {
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

#ifdef HAVE_UDNS
static bool parse_observation_id_dns0(observation_id_t *observation_id,
                                      const json_t *dns_ptr_value,
                                      const char *key, const char *sensor_name,
                                      int flag) {
  assert(observation_id);
  assert(dns_ptr_value);
  assert(key);
  assert(sensor_name);

  if (NULL != dns_ptr_value) {
    if (!json_is_boolean(dns_ptr_value)) {
      traceEvent(TRACE_ERROR, "%s is not a boolean in sensor %s observation id"
                              " %" PRIu32 ", can't parse it",
                 key, sensor_name, observation_id_get_id(observation_id));
      return false;
    } else if (json_is_true(dns_ptr_value)) {
      if (flag & ENABLE_PTR_DNS_CLIENT) {
        observation_id_enable_ptr_dns_client(observation_id);
      }
      if (flag & ENABLE_PTR_DNS_TARGET) {
        observation_id_enable_ptr_dns_target(observation_id);
      }
    }
  }

  return true;
}

/**
 * Parses Observation ID DNS attributes. It's used to enable the reverse
 * name resolution for client and/or targets.
 *
 * @param observation_id Observation ID to config.
 * @param sensor_name    Used for debugging purposes.
 * @param dns_ptr_client The key used to parse the client JSON attribute.
 * @param dns_ptr_target The key used to parse the target JSON attribute.
 */
static void parse_observation_id_dns(observation_id_t *observation_id,
                                     const char *sensor_name,
                                     const json_t *dns_ptr_client,
                                     const json_t *dns_ptr_target) {
  assert(observation_id);
  assert(sensor_name);
  assert(dns_ptr_client);
  assert(dns_ptr_target);

  parse_observation_id_dns0(observation_id, dns_ptr_client, dns_ptr_client_key,
                            sensor_name, ENABLE_PTR_DNS_CLIENT);
  parse_observation_id_dns0(observation_id, dns_ptr_target, dns_ptr_target_key,
                            sensor_name, ENABLE_PTR_DNS_TARGET);
}
#endif // HAVE_UDNS

/**
 * Parses an Observation ID object to an observation_id_t.
 *
 * @param  observation_id   Observation ID to store the parsed data.
 * @param  jobservation_id  JSON object to read the data from.
 * @param  observation_id_n ID of the Observation ID to parse.
 * @param  sensor           Used for debugging purposes.
 * @return                  Success or fail.
 */
static bool parse_observation_id(observation_id_t *observation_id,
                                 json_t *jobservation_id,
                                 uint32_t observation_id_n,
                                 const sensor_t *sensor) {
  assert(observation_id);
  assert(jobservation_id);
  assert(sensor);

  int span_mode = false;
  int exporter_in_wan_side = false;
  json_error_t jerr;
  json_int_t fallback_first_switch = 0;
  const json_t *home_nets = NULL;
  const json_t *enrichment = NULL;
  const json_t *routers_macs = NULL;
#ifdef HAVE_UDNS
  const json_t *dns_ptr_client = NULL;
  const json_t *dns_ptr_target = NULL;
#endif

  const int unpack_rc = json_unpack_ex(
      jobservation_id, &jerr, 0, "{s?o,s?o,s?b,s?b,s?o,s?I}", "home_nets",
      &home_nets, "enrichment", &enrichment, "span_port", &span_mode,
      "exporter_in_wan_side", &exporter_in_wan_side, "routers_macs",
      &routers_macs, "fallback_first_switch", &fallback_first_switch);

  if (unpack_rc != 0) {
    traceEvent(TRACE_ERROR,
               "Can't parse sensor %s observation id %" PRIu32 " network: %s",
               sensor_get_network_string(sensor), observation_id_n, jerr.text);

    return false;
  }

  if (home_nets) {
    parse_observation_id_home_nets(observation_id, home_nets, sensor);
  }

  if (enrichment) {
    parse_observation_id_enrichment(observation_id, enrichment, sensor);
  }

  if (routers_macs) {
    traceEvent(TRACE_ERROR,
               "Observation id's router macs support has been deprecated");
  }

  observation_id_set_fallback_first_switch(observation_id,
                                           fallback_first_switch);

#ifdef HAVE_UDNS
  const int unpack_dns_rc =
      json_unpack_ex(jobservation_id, &jerr, 0, "{s?o,s?o}", dns_ptr_client_key,
                     &dns_ptr_client, dns_ptr_target_key, &dns_ptr_target);

  if (unpack_dns_rc != 0) {
    traceEvent(TRACE_ERROR, "Can't unpack sensor %s observation id %" PRIu32
                            "DNS attributes: %s",
               sensor_get_network_string(sensor), observation_id_n, jerr.text);
  } else {
    parse_observation_id_dns(observation_id, sensor_get_network_string(sensor),
                             dns_ptr_client, dns_ptr_target);
  }
#endif

  if (span_mode) {
    observation_id_set_span_mode(observation_id);
  }

  if (exporter_in_wan_side) {
    observation_id_set_exporter_in_wan_side(observation_id);
  }

  return observation_id;
}

/**
 * Parses a sensor configuration to a sensor_t.
 *
 * @param  jsensor JSON object with the sensor configuration.
 * @param  ip_str  Used for debugging purposes.
 * @return         The parsed sensor. NULL if fail parsing the configuration.
 */
static sensor_t *parse_sensor(json_t *jsensor, const char *ip_str) {
  assert(jsensor);
  assert(ip_str);

  static const char observations_id_key[] = "observations_id";
  const char *observation_id_key = NULL;
  json_t *observation_id = NULL;

  if (!json_is_object(jsensor)) {
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

  netAddress_t ip;
  const bool parse_address_rc = safe_parse_address(ip_str, &ip);
  if (!parse_address_rc) {
    traceEvent(TRACE_ERROR, "Couldn't parse %s sensor address", ip_str);

    return NULL;
  }

  sensor_t *sensor = sensor_new(ip.network, ip.networkMask);
  if (unlikely(NULL == sensor)) {
    traceEvent(TRACE_ERROR,
               "Can't allocate sensor of network %s memory (out of memory?)",
               ip_str);

    return NULL;
  }

  json_object_foreach(observations_id, observation_id_key, observation_id) {
    const bool parsing_default_oid = 0 == strcmp("default", observation_id_key);
    bool observation_id_ok = true;

    const uint32_t observation_id_n =
        parsing_default_oid
            ? 0
            : parse_observation_id_number(ip_str, observation_id_key,
                                          &observation_id_ok);

    if (!observation_id_ok) {
      continue;
    }

    observation_id_t *cur_observation_id = observation_id_new(observation_id_n);
    if (unlikely(NULL == cur_observation_id)) {
      traceEvent(TRACE_ERROR,
                 "Couldn't allocate observation id (out of memory?)");

      return NULL;
    }

    const bool parse_oid_rc = parse_observation_id(
        cur_observation_id, observation_id, observation_id_n, sensor);

    if (!parse_oid_rc) {
      return NULL;
    }

    if (parsing_default_oid) {
      sensor_add_default_observation_id(sensor, cur_observation_id);
    } else {
      sensor_add_observation_id(sensor, cur_observation_id);
    }
  }

  return sensor;
}

/**
 * Parses the sensors network configuration from a JSON.
 *
 * @param  database         Database to store all the parsed sensors.
 * @param  sensors_networks JSON object with the sensors data.
 * @param  worker_list      List of workers that will be bound to sensors.
 * @param  worker_list_size Size of the worker list.
 * @return                  Success or fail.
 */
static bool read_sensors_config_networks(sensors_db_t *database,
                                         json_t *sensors_networks,
                                         worker_t **worker_list,
                                         size_t worker_list_size) {
  assert(database);
  assert(sensors_networks);
  assert(worker_list);

  const char *network = NULL;
  json_t *network_config = NULL;
  size_t worker_idx = 0;

  json_object_foreach(sensors_networks, network, network_config) {
    if (!json_is_object(network_config)) {
      traceEvent(TRACE_ERROR, "%s sensor network is not an object in config"
                              " file.",
                 network);
      continue;
    }

    sensor_t *sensor = parse_sensor(network_config, network);
    if (NULL == sensor) {
      continue;
    }

    sensor_set_worker(sensor, worker_list[worker_idx++]);
    if (worker_idx >= worker_list_size) {
      worker_idx = 0;
    }

    sensors_db_add(database, sensor);
  }

  return true;
}

/**
 * Releases all the templates stored on an Observation ID.
 *
 * @param observation_id Observation ID to clean its templates.
 */
static void release_observations_id(observation_id_t *observation_id) {
  assert(observation_id);

  size_t list_length = 0;
  uint16_t *template_list =
      observation_id_list_templates(observation_id, &list_length);
  if (!template_list) {
    return;
  }

  for (size_t i = 0; i < list_length; i++) {
    struct flowSetV9Ipfix *template =
        observation_id_get_template(observation_id, template_list[i]);
    if (template) {
      free(template);
    }
  }

  dsensors_free(template_list);
}

/**
 * Releases all the templates stored on an Sensor. It will iterate the
 * Observations ID in a sensor.
 *
 * @param sensor Sensor to clean its templates.
 */
static void release_sensor_templates(sensor_t *sensor) {
  assert(sensor);

  size_t list_length = 0;
  uint32_t *observation_id_list =
      sensor_get_observation_id_list(sensor, &list_length);
  if (!observation_id_list) {
    return;
  }

  for (size_t i = 0; i < list_length; i++) {
    observation_id_t *observation_id =
        sensor_get_observation_id(sensor, observation_id_list[i]);
    if (observation_id) {
      release_observations_id(observation_id);
    }
  }

  dsensors_free(observation_id_list);
}

static void free_all_templates(sensors_db_t *database) {
  assert(database);

  size_t list_length = 0;
  sensor_t **sensor_list = sensors_db_list(database, &list_length);
  if (!sensor_list) {
    return;
  }

  for (size_t i = 0; i < list_length; i++) {
    sensor_t *sensor = sensor_list[i];
    if (sensor) {
      release_sensor_templates(sensor);
    }
  }

  dsensors_free(sensor_list);
}

////////////////
// Public API //
////////////////

void delete_rb_sensors_db(sensors_db_t *database) {
  free_all_templates(database);
  sensors_db_destroy(database);
}

sensor_t *get_sensor(sensors_db_t *database, uint64_t ip) {
  uint8_t ip_address[16] = {0};
  ip_address[10] = 0xff;
  ip_address[11] = 0xff;
  ip_address[12] = ip >> 24;
  ip_address[13] = ip >> 16;
  ip_address[14] = ip >> 8;
  ip_address[15] = ip;

  return sensors_db_get(database, ip_address);
}

const char *sensor_ip_string(const sensor_t *sensor) {
  return sensor_get_network_string(sensor);
}

observation_id_t *get_sensor_observation_id(sensor_t *sensor, uint32_t obs_id) {
  return sensor_get_observation_id(sensor, obs_id);
}

worker_t *sensor_worker(const sensor_t *sensor) {
  return sensor_get_worker(sensor);
}

int addBadSensor(sensors_db_t *database, uint64_t sensor_ip) {return 0;}

inline uint32_t observation_id_num(const observation_id_t *observation_id) {
  return observation_id_get_id(observation_id);
}

inline int64_t
observation_id_fallback_first_switch(const observation_id_t *observation_id) {
  return observation_id_get_fallback_first_switch(observation_id);
}

inline bool is_exporter_in_wan_side(const observation_id_t *observation_id) {
  return observation_id_is_exporter_in_wan_side(observation_id);
}

inline bool is_span_observation_id(const observation_id_t *observation_id) {
  return observation_id_is_span_port(observation_id);
}

inline const struct flowSetV9Ipfix *
find_observation_id_template(const observation_id_t *observation_id,
                             const uint16_t template_id) {
  return observation_id_get_template(observation_id, template_id);
}

inline const char *observation_id_enrichment(const observation_id_t *obs_id) {
  return observation_id_get_enrichment(obs_id);
}

inline const char *
observation_id_application_name(observation_id_t *observation_id,
                                uint64_t application_id) {
  const application_t *application =
      observation_id_get_application(observation_id, application_id);
  if (!application) {
    return NULL;
  }

  return application_get_name(application);
}

inline const char *
observation_id_selector_name(observation_id_t *observation_id,
                             uint64_t selector_id) {
  const selector_t *selector =
      observation_id_get_selector(observation_id, selector_id);
  if (!selector) {
    return NULL;
  }

  return selector_get_name(selector);
}

inline const char *
observation_id_interface_name(observation_id_t *observation_id,
                              uint64_t interface_id) {
  const interface_t *interface =
      observation_id_get_interface(observation_id, interface_id);
  if (!interface) {
    return NULL;
  }

  return interface_get_name(interface);
}

const char *network_name(observation_id_t *obs_id, const uint8_t ip[16]) {
  const network_t *network = observation_id_get_network(obs_id, ip);
  if (!network) {
    return NULL;
  }

  return network_get_name(network);
}

const char *network_ip(observation_id_t *obs_id, const uint8_t ip[16]) {
  const network_t *network = observation_id_get_network(obs_id, ip);
  if (!network) {
    return NULL;
  }

  return network_get_ip_str(network);
}

inline const char *
observation_id_interface_description(observation_id_t *observation_id,
                                     uint64_t interface_id) {
  const interface_t *interface =
      observation_id_get_interface(observation_id, interface_id);
  if (!interface) {
    return NULL;
  }

  return interface_get_description(interface);
}

inline void observation_id_add_application_id(observation_id_t *observation_id,
                                              uint64_t application_id,
                                              const char *application_name,
                                              size_t application_name_len) {
  application_t *application =
      application_new(application_id, application_name, application_name_len);
  if (!application) {
    return;
  }

  observation_id_add_application(observation_id, application);
}

inline void observation_id_add_selector_id(observation_id_t *observation_id,
                                           uint64_t selector_id,
                                           const char *selector_name,
                                           size_t selector_name_len) {
  selector_t *selector =
      selector_new(selector_id, selector_name, selector_name_len);
  if (!selector) {
    return;
  }

  observation_id_add_selector(observation_id, selector);
}

inline void observation_id_add_new_interface(observation_id_t *observation_id,
                                             uint64_t interface_id,
                                             const char *interface_name,
                                             size_t interface_name_len,
                                             const char *interface_description,
                                             size_t interface_description_len) {

  interface_t *interface =
      interface_new(interface_id, interface_name, interface_name_len,
                    interface_description, interface_description_len);
  if (!interface) {
    return;
  }

  observation_id_add_interface(observation_id, interface);
}

inline void save_template_async(sensor_t *sensor, struct flowSetV9Ipfix *tmpl) {
  // TODO
}

void save_template(observation_id_t *observation_id,
                   const struct flowSetV9Ipfix *template) {
  assert(observation_id);
  assert(template);

  const V9IpfixSimpleTemplate *templateInfo = &template->templateInfo;

  struct flowSetV9Ipfix *new_template = NULL;
  rd_calloc_struct(&new_template, sizeof(struct flowSetV9Ipfix),
                   template->templateInfo.fieldCount *
                       sizeof(template->fields[0]),
                   template->fields, &new_template->fields, RD_MEM_END_TOKEN);

  if (!new_template) {
    traceEvent(TRACE_ERROR, "Not enough memory");
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
    for (int fieldId = 0; fieldId < new_template->templateInfo.fieldCount;
         ++fieldId) {
      const uint16_t entity_id = new_template->fields[fieldId].fieldId;
      new_template->fields[fieldId].v9_template = find_template(entity_id);
    }
  }

  observation_id_add_template(observation_id, templateInfo->templateId,
                              new_template);
}

sensors_db_t *read_rb_config(const char *json_path, worker_t **worker_list,
                             size_t worker_list_size) {
  assert(json_path);
  assert(worker_list);

  json_error_t error;
  sensors_db_t *database = sensors_db_new();

  if (!database) {
    traceEvent(TRACE_ERROR, "Invalid address");
    return NULL;
  }

  json_t *root = json_load_file(json_path, 0, &error);
  if (!root) {
    traceEvent(TRACE_ERROR, "Could not load %s, line %d column %d: %s.",
               json_path, error.line, error.column, error.text);
  }

  if (database && root) {
    json_t *sensors_networks = json_object_get(root, "sensors_networks");

    if (!sensors_networks) {
      traceEvent(TRACE_ERROR, "Could not load %s(%d): %s.\n", json_path,
                 error.line, error.text);
    } else {
      const bool rc = read_sensors_config_networks(
          database, sensors_networks, worker_list, worker_list_size);
      if (!rc) {
        free_all_templates(database);
        sensors_db_destroy(database);
      }
    }
  }

  json_decref(root);

  return database;
}
