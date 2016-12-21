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

#include "config.h"

#include <stdbool.h>

#include "netflow.h"
#include "rb_listener.h"


#include <stdbool.h>

/* FW declarations */
struct sensor;
struct worker_s;
const char *sensor_ip_string(const struct sensor *sensor);
struct worker_s *sensor_worker(const struct sensor *sensor);

struct rb_sensors_db;

/** Creates a sensor database with a json config file
 * @param  json_path        Path to JSON config file
 * @param  worker_list      Worker list to assign to each sensor:observation
 *                          domain id
 * @param  worker_list_size Size of worker list
 * @return                  New sensors db, or NULL if error
 */
struct rb_sensors_db *read_rb_config(const char *json_path,
              struct worker_s **worker_list, size_t worker_list_size);

/** Obtains a sensor from a database.
 * @param  database Database to obtain sensor from
 * @param  ip       Sensor ip
 * @return          Obtained sensor.
 * @warning         Need to release obtained sensor with rb_sensor_decref
 */
struct sensor *get_sensor(struct rb_sensors_db *database, uint64_t ip);

/** Signal end of sensor usage
 * @param sensor Sensor that we are not going to use.
 */
void rb_sensor_decref(struct sensor *sensor);

int addBadSensor(struct rb_sensors_db *database,const uint64_t sensor_ip);

/// Sensor observation id
typedef struct observation_id_s observation_id_t;
uint32_t observation_id_num(const observation_id_t *observation_id);
void observation_id_decref(observation_id_t *observation_id);
const char *network_ip(observation_id_t *observation_id,const uint8_t ip[16]);
const char *network_name(observation_id_t *observation_id,const uint8_t ip[16]);
const char *observation_id_enrichment(const observation_id_t *obs_id);

bool is_exporter_in_wan_side(const observation_id_t *observation_id);
bool is_span_observation_id(const observation_id_t *obs_id);
#ifdef HAVE_UDNS
bool observation_id_want_client_dns(const observation_id_t *observation_id);
bool observation_id_want_target_dns(const observation_id_t *observation_id);
#endif

/**
 * Add an (application id, application name) tuple to observation id
 * @param observation_id       Observation id
 * @param application_id       Application id
 * @param application_name     Application name
 * @param application_name_len Application name length
 */
void observation_id_add_application_id(observation_id_t *observation_id,
  uint64_t application_id, const char *application_name,
  size_t application_name_len);

/**
 * Find name of a previously saved application id
 * @param  observation_id Observation id
 * @param  application_id Application id
 * @return                Found name, NULL in other case
 */
const char *observation_id_application_name(observation_id_t *observation_id,
  uint64_t application_id);

/** Add a (selector id, selector name) tuple to observation id
 * @param observation_id    Observation id
 * @param selector_id       Selector id
 * @param selector_name     Selector name
 * @param selector_name_len Selector name length
 */
void observation_id_add_selector_id(observation_id_t *observation_id,
  uint64_t selector_id, const char *selector_name,
  size_t selector_name_len);

/**
 * Get a selector name stored on an observation id from a selector id
 * @param  observation_id Observation id
 * @param  selector_id    Selector id
 * @return                Selector name if found, NULL in other case
 */
const char *observation_id_selector_name(observation_id_t *observation_id,
  uint64_t selector_id);

/** Add a (interface id, interface name) tuple to observation id
 * @param observation_id    Observation id
 * @param interface_id       interface id
 * @param interface_name     interface name
 * @param interface_name_len interface name length
 * @param interface_desc     interface description
 * @param interface_desc_len interface description length
 */
void observation_id_add_interface(observation_id_t *observation_id,
  uint64_t interface_id, const char *interface_name,
  size_t interface_name_len, const char *interface_description,
  size_t interface_description_len);

/**
 * Get a interface name stored on an observation id from a interface id
 * @param  observation_id Observation id
 * @param  interface_id   Interface id
 * @return                Interface name if found, NULL in other case
 */
const char *observation_id_interface_name(observation_id_t *observation_id,
  uint64_t interface_id);

/**
 * Get a interface description stored on an observation id from a interface id
 * @param  observation_id Observation id
 * @param  interface_id   Interface id
 * @return                Interface description if found, NULL in other case
 */
const char *observation_id_interface_description(
  observation_id_t *observation_id, uint64_t interface_id);


int64_t observation_id_fallback_first_switch(const observation_id_t *obs_id);

observation_id_t *get_sensor_observation_id(struct sensor *, uint32_t obs_id);

struct flowSetV9Ipfix;
/** Save template in sensor
 * @param observation_id Observation id to add template
 * @param template Template to save
 * @note This function is not thread safe! If you want to add a template to
 * sensor, for example via file or zookeeper, please use save_template_async
 */
void save_template(observation_id_t *observation_id,
  const struct flowSetV9Ipfix *template);

/** Save template in sensor
 * @param template Template to add
 * @param worker   Worker to add template to
 */
void save_template_async(struct sensor *sensor,
	struct flowSetV9Ipfix *template);
const struct flowSetV9Ipfix *find_observation_id_template(
  const observation_id_t *observation_id, const uint16_t template_id);

void delete_rb_sensors_db(struct rb_sensors_db *db);
