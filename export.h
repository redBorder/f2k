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

#include "f2k.h"
#include "printbuf.h"

struct flowCache;
struct flowCache;
struct flowCache *new_flowCache();
uint64_t flowCache_packets(const struct flowCache *);
uint64_t flowCache_octets(const struct flowCache *);
void associateSensor(struct flowCache *flowCache, struct sensor *sensor);
int guessDirection(struct flowCache *cache);
void free_flowCache(struct flowCache *cache);

/** Print string (i.e., kafka_line_buffer += buffer+real_field_len_offset)
 * @param  kafka_line_buffer     Buffer to print string into
 * @param  buffer                Buffer with string
 * @param  real_field_len        Length of string
 * @param  real_field_len_offset Offset of string in buf
 * @param  flowCache             Cache of the flow
 * @return                       Number of bytes printed
 */
size_t print_string(struct printbuf *kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    const size_t real_field_offset, struct flowCache *flowCache);

size_t print_number(struct printbuf * kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    const size_t real_field_len_offset, struct flowCache *flowCache);

size_t save_first_switched(struct printbuf *kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    const size_t real_field_offset, struct flowCache *flowCache);

size_t save_last_switched(struct printbuf *kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    const size_t real_field_offset, struct flowCache *flowCache);

size_t save_first_second(struct printbuf *kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    const size_t real_field_offset, struct flowCache *flowCache);

size_t save_first_msecond(struct printbuf *kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    const size_t real_field_offset, struct flowCache *flowCache);

size_t save_last_second(struct printbuf *kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    const size_t real_field_offset, struct flowCache *flowCache);

size_t save_last_msecond(struct printbuf *kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    const size_t real_field_offset, struct flowCache *flowCache);

size_t save_flow_bytes(struct printbuf *kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    const size_t real_field_offset, struct flowCache *flowCache);

size_t save_flow_pkts(struct printbuf *kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    const size_t real_field_offset, struct flowCache *flowCache);

size_t print_tcp_flags(struct printbuf * kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    const size_t real_field_len_offset, struct flowCache *flowCache);

size_t print_netflow_type(struct printbuf * kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    const size_t real_field_len_offset, struct flowCache *flowCache);

size_t print_flow_end_reason(struct printbuf * kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    const size_t real_field_len_offset, struct flowCache *flowCache);

size_t print_biflow_direction(struct printbuf * kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    const size_t real_field_len_offset, struct flowCache *flowCache);

size_t print_direction(struct printbuf *kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    const size_t real_field_len_offset, struct flowCache *flowCache);

size_t save_direction(struct printbuf *kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    const size_t real_field_len_offset, struct flowCache *flowCache);

size_t save_src_mac(struct printbuf *kafka_line_buffer, const void *buffer, const size_t real_field_len,
    const size_t real_field_len_offset, struct flowCache *flowCache);

size_t save_dst_mac(struct printbuf *kafka_line_buffer, const void *buffer, const size_t real_field_len,
    const size_t real_field_len_offset, struct flowCache *flowCache);

size_t save_post_src_mac(struct printbuf *kafka_line_buffer, const void *buffer, const size_t real_field_len,
    const size_t real_field_len_offset, struct flowCache *flowCache);

size_t save_post_dst_mac(struct printbuf *kafka_line_buffer, const void *buffer, const size_t real_field_len,
    const size_t real_field_len_offset, struct flowCache *flowCache);

size_t print_direction_based_client_mac(struct printbuf *kafka_line_buffer, const void *buffer, const size_t real_field_len,
  const size_t real_field_len_offset, struct flowCache *flowCache);

size_t print_client_mac(struct printbuf *kafka_line_buffer, const void *buffer, const size_t real_field_len,
  const size_t real_field_len_offset, struct flowCache *flowCache);

size_t print_direction_based_client_mac_vendor(struct printbuf *kafka_line_buffer, const void *buffer, const size_t real_field_len,
    const size_t real_field_len_offset, struct flowCache *flowCache);

size_t print_net(struct printbuf * kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    const size_t real_field_len_offset, struct flowCache *flowCache);

size_t print_net_name(struct printbuf * kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    const size_t real_field_len_offset, struct flowCache *flowCache);

size_t print_net_v6(struct printbuf * kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    const size_t real_field_len_offset, struct flowCache *flowCache);

size_t print_net_name_v6(struct printbuf * kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    const size_t real_field_len_offset, struct flowCache *flowCache);

size_t print_ipv4_src_addr(struct printbuf * kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    const size_t real_field_len_offset, struct flowCache *flowCache);

size_t print_ipv4_dst_addr(struct printbuf * kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    const size_t real_field_len_offset, struct flowCache *flowCache);

size_t print_proto_name(struct printbuf * kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    const size_t real_field_len_offset, struct flowCache *flowCache);

size_t print_engine_id(struct printbuf * kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    const size_t real_field_len_offset, struct flowCache *flowCache);

size_t print_engine_id_name(struct printbuf * kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    const size_t real_field_len_offset, struct flowCache *flowCache);

size_t print_application_id(struct printbuf * kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    const size_t real_field_len_offset, struct flowCache *flowCache);

size_t print_application_id_name(struct printbuf * kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    const size_t real_field_len_offset, struct flowCache *flowCache);

size_t print_src_port(struct printbuf * kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    const size_t real_field_len_offset, struct flowCache *flowCache);

size_t print_dst_port(struct printbuf * kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    const size_t real_field_len_offset, struct flowCache *flowCache);

size_t print_srv_port(struct printbuf * kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    const size_t real_field_len_offset, struct flowCache *flowCache);

size_t print_ipv6_src_addr(struct printbuf * kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    const size_t real_field_len_offset, struct flowCache *flowCache);

size_t print_ipv6_dst_addr(struct printbuf * kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    const size_t real_field_len_offset, struct flowCache *flowCache);

size_t print_ssid_name(struct printbuf * kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    const size_t real_field_len_offset, struct flowCache *flowCache);

size_t print_mac(struct printbuf *kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    const size_t real_field_len_offset, struct flowCache *flowCache);

size_t print_mac_map(struct printbuf *kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    const size_t real_field_len_offset, struct flowCache *flowCache);

size_t print_mac_vendor(struct printbuf *kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    const size_t real_field_len_offset, struct flowCache *flowCache);

#ifdef HAVE_GEOIP

size_t print_AS_ipv4(struct printbuf * kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    const size_t real_field_len_offset, struct flowCache *flowCache);

size_t print_country_code(struct printbuf * kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    const size_t real_field_len_offset, struct flowCache *flowCache);

size_t print_AS_ipv4_name(struct printbuf * kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    const size_t real_field_len_offset, struct flowCache *flowCache);

size_t print_AS6_name(struct printbuf * kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    const size_t real_field_len_offset, struct flowCache *flowCache);

size_t print_AS6(struct printbuf *kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    const size_t real_field_len_offset, struct flowCache *flowCache);

size_t print_country6_code(struct printbuf *kafka_line_buffer,
  const void *buffer, const size_t real_field_len,
  const size_t real_field_len_offset,struct flowCache *flowCache);

size_t print_sensor_enrichment(struct printbuf *kafka_line_buffer,
    const struct flowCache *flowCache);

#endif /* HAVE_GEOIP */

#ifdef HAVE_CISCO_URL

size_t print_http_url(struct printbuf *kafka_line_buffer,
  const void *buffer, const size_t real_field_len,
  const size_t real_field_len_offset,struct flowCache *flowCache);
size_t print_http_host(struct printbuf *kafka_line_buffer,
  const void *buffer, const size_t real_field_len,
  const size_t real_field_len_offset,struct flowCache *flowCache);
size_t print_http_user_agent(struct printbuf *kafka_line_buffer,
  const void *buffer, const size_t real_field_len,
  const size_t real_field_len_offset,struct flowCache *flowCache);
size_t print_http_referer(struct printbuf *kafka_line_buffer,
  const void *buffer, const size_t real_field_len,
  const size_t real_field_len_offset,struct flowCache *flowCache);

size_t print_https_common_name(struct printbuf *kafka_line_buffer,
  const void *buffer, const size_t real_field_len,
  const size_t real_field_len_offset,struct flowCache *flowCache);

#endif /* CISCO_URL */

#ifdef HAVE_UDNS

const uint8_t *get_direction_based_client_ip(struct flowCache *flowCache);
const uint8_t *get_direction_based_target_ip(struct flowCache *flowCache);

size_t print_client_name(struct printbuf *kafka_line_buffer,
  const void *buffer, const size_t real_field_len,
  const size_t real_field_len_offset,struct flowCache *flowCache);

size_t print_target_name(struct printbuf *kafka_line_buffer,
  const void *buffer, const size_t real_field_len,
  const size_t real_field_len_offset,struct flowCache *flowCache);

#endif
