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

#include "config.h"

#ifdef HAVE_LIBRDKAFKA

#include "rb_kafka.h"
#include "f2k.h"
#include "util.h"


int32_t rb_client_mac_partitioner (const rd_kafka_topic_t *rkt,
					 const void *key __attribute__((unused)),
           size_t keylen __attribute__((unused)),
					 int32_t partition_cnt,
					 void *rkt_opaque,
					 void *msg_opaque){
    const uint64_t client_mac = (intptr_t)msg_opaque;
    if(client_mac == 0)
    	return rd_kafka_msg_partitioner_random(rkt,NULL,0,partition_cnt,rkt_opaque,msg_opaque);
    else
    	return client_mac % partition_cnt;
}

void msg_delivered (rd_kafka_t *rk __attribute__((unused)),
  void *payload __attribute__((unused)), size_t len,
  int error_code,
  void *opaque __attribute__((unused)),
  void *msg_opaque __attribute__((unused))) {

  if (error_code)
    traceEvent(TRACE_ERROR, "Message delivery failed: %s\n",
      rd_kafka_err2str(error_code));
  else if (unlikely(readOnlyGlobals.enable_debug))
    traceEvent(TRACE_INFO, "Message delivered (%zd bytes)\n", len);
}

void parse_kafka_config(rd_kafka_conf_t *rk_conf,rd_kafka_topic_conf_t *rkt_conf,
                               const char *option){
  if(unlikely(readOnlyGlobals.enable_debug))
    traceEvent(TRACE_INFO,"Applying %s to rdkafka",option);

  char errstr[512];
  char *name, *val;
  rd_kafka_conf_res_t res;

  name = strdup(option);
  if(!name) {
    traceEvent(TRACE_ERROR, "Can't duplicate %s string",option);
    return;
  }

  if (!(val = strchr(name, '='))) {
    traceEvent(TRACE_ERROR, "rdkafka config: Expected "
      "-X/Y property=value, not %s, ",name);
    free(name);
    return;
  }

  *val = '\0';
  val++;

  res = RD_KAFKA_CONF_UNKNOWN;
  /* Try "topic." prefixed properties on topic
   * conf first, and then fall through to global if
   * it didnt match a topic configuration property. */
  if (!strncmp(name, "topic.", strlen("topic.")))
    res = rd_kafka_topic_conf_set(rkt_conf,
                name+
                strlen("topic."),
                val,
                errstr,
                sizeof(errstr));

  if (res == RD_KAFKA_CONF_UNKNOWN)
    res = rd_kafka_conf_set(rk_conf, name, val,
          errstr, sizeof(errstr));

  if (res != RD_KAFKA_CONF_OK)
    traceEvent(TRACE_ERROR,"Error parsing rdkafka option: %s", errstr);

  free(name);
}

#endif
