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

#include "rb_listener.h"

#include "config.h"

/* FW declarations */
struct sensor;
struct worker_s;
const char *sensor_ip_string(const struct sensor *sensor);
struct worker_s *sensor_worker(const struct sensor *sensor);
const char *network_ip(struct sensor *sensor,const char ip[16]);
const char *network_name(struct sensor *sensor,const char ip[16]);
const char *sensor_ip_enrichment(const struct sensor *sensor);
enum sensor_span_mode{NO_SPAN_MODE,SPAN_MODE};
enum sensor_span_mode is_span_sensor(const struct sensor *sensor);
int sensor_has_mac_db(const struct sensor *sensor);
int sensor_has_router_mac(struct sensor *sensor,const uint64_t mac);

int64_t sensor_fallback_first_switch(const struct sensor *sensor);

#ifdef HAVE_UDNS
int sensor_want_client_dns(const struct sensor *);
int sensor_want_target_dns(const struct sensor *);
#endif

struct rb_sensors_db;
struct rb_sensors_db *read_rb_config(const char *json_path,
          		listener_list *list, struct worker_s **worker_list,
          		size_t worker_list_size);

/** Obtains a sensor from a database.
 * @param  database Database to obtain sensor from
 * @param  ip       Sensor ip
 * @param  port     Sensor port
 * @return          Obtained sensor.
 * @warning         Need to release obtained sensor with rb_sensor_decref
 */
struct sensor *get_sensor(struct rb_sensors_db *database, uint64_t ip,
								uint16_t port);

/** Signal end of sensor usage
 * @param sensor Sensor that we are not going to use.
 */
void rb_sensor_decref(struct sensor *sensor);

int addBadSensor(struct rb_sensors_db *database,const uint64_t sensor_ip);
struct flowSetV9Ipfix; /* FW declaration */
/** Save template in sensor
 * @param sensor   Sensor to add template
 * @param template Template to save
 * @note This function is not thread safe! If you want to add a template to
 * sensor, for example via file or zookeeper, please use save_template_async
 */
void saveTemplate(struct sensor *sensor, struct flowSetV9Ipfix *template);

/** Save template in sensor
 * @param template Template to add
 * @param worker   Worker to add template to
 */
void save_template_async(struct sensor *sensor,
	struct flowSetV9Ipfix *template);
const struct flowSetV9Ipfix *find_sensor_template(const struct sensor *sensor,const int templateId);

void delete_rb_sensors_db(struct rb_sensors_db *db);
