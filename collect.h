/*
  Copyright (C) 2015 Eneo Tecnologia S.L.
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
#include <time.h>

#include "rb_sensor.h"

struct worker_stats {
  time_t first_flow_processed_timestamp, last_flow_processed_timestamp;
  uint64_t num_packets_received, num_dissected_flow_packets,
  num_flows_unknown_template,
  num_flows_processed, num_good_templates_received,
  num_known_templates, num_bad_templates_received;
};

/** a+=b in worker stats */
void sum_worker_stats(struct worker_stats *a, const struct worker_stats *b);

/** Flow worker. All flows of the same netflow probe must go to the same worker
*/
typedef struct worker_s worker_t;

/** Creates a worker */
worker_t *new_collect_worker();

/// @todo delete this FW declaration
struct queued_packet_s;
struct flowSetV9Ipfix;
struct sensor;

/** Adds a packet to worker
  @param qpacket Packet to add
  @param worker Worker queue to add
  */
void add_packet_to_worker(struct queued_packet_s *qpacket, worker_t *worker);

/** Add a template to worker sensor
 * @param template Template to add
 * @param observation_id Template observation domain id
 * @param worker   Worker to add template to
 */
void add_template_to_worker(struct flowSetV9Ipfix *template,
  observation_id_t *observation_id, worker_t *worker);

/** Get workers stats
  @param worker Worker to get stats
  @param stats where to store stats
  */
void get_worker_stats(worker_t *worker, struct worker_stats *stats);

/** Free worker's allocated resources */
void collect_worker_done(worker_t *worker, struct worker_stats *stats);
