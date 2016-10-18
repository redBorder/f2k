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

#include "config.h"

#ifdef HAVE_LIBRDKAFKA

#include <librdkafka/rdkafka.h>

int32_t rb_client_mac_partitioner (const rd_kafka_topic_t *rkt,
					 const void *key, size_t keylen,
					 int32_t partition_cnt,
					 void *rkt_opaque,
					 void *msg_opaque);

/**
* Message delivery report callback.
* Called once for each message.
* See rdkafka.h for more information.
*/
void msg_delivered (rd_kafka_t *rk,
  void *payload, size_t len,
  int error_code,
  void *opaque, void *msg_opaque);

void parse_kafka_config(rd_kafka_conf_t *rk_conf,rd_kafka_topic_conf_t *rkt_conf,
                               const char *option);

#endif
