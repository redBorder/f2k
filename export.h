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

#include "rb_sensor.h"
#include "f2k.h"
#include "printbuf.h"

struct flowCache {
  uint64_t client_mac;
  struct {
    uint64_t input,output;
  } interfaces;

  struct{
    uint8_t client_mac[6];
    uint8_t src_mac[6];
    uint8_t dst_mac[6];
    uint8_t post_src_mac[6];
    uint8_t post_dst_mac[6];
    uint8_t direction;
  }macs;

  struct{
    uint8_t proto;
    uint16_t src,dst;
  }ports;

  struct {
    size_t str_size;
    const char *str;
  } http_referer, http_host, ssl_common_name;

  struct{
    uint8_t client[16],src[16],dst[16];
#ifdef HAVE_UDNS
    /// @TODO use a memory context. Join both cases!!
    /// In case that we do not have a cache
    char *client_name,*target_name;
    struct dns_cache_elm *client_name_cache,*target_name_cache;
#endif
  }address;

  /// Sensor associated
  const struct sensor *sensor;
  observation_id_t *observation_id;

  /// Flow time related information
  struct {
    uint64_t export_timestamp_s;      ///< Flow export timestamp (seconds)
    uint64_t sys_uptime_s;            ///< Seconds since probe device boot (s)
    uint64_t first_switched_uptime_s; ///< First switched uptime in flow
    uint64_t last_switched_uptime_s;  ///< Last switched uptime in flow
    uint64_t first_timestamp_s;       ///< First timestamp in flow (s)
    uint64_t last_timestamp_s;        ///< Last timestamp in flow (s)
  } time;
  uint64_t bytes;              ///< Flow bytes
  uint64_t packets;            ///< Flow packets
};

struct flowCache *new_flowCache();
uint64_t flowCache_packets(const struct flowCache *);
uint64_t flowCache_octets(const struct flowCache *);
void associateSensor(struct flowCache *flowCache, struct sensor *sensor);
bool guessDirection(struct flowCache *cache);
void free_flowCache(struct flowCache *cache);

/** Prints a netflow entity value with a given template
 * @param  kafka_line_buffer     Buffer to print entity.
 * @param  templateElement       Expected element in buffer
 * @param  buffer                Flow element
 * @param  real_field_len        Length of element
 * @param  flowCache             Flow cache
 * @return                       Number of bytes written
 */
size_t printNetflowRecordWithTemplate(struct printbuf *kafka_line_buffer,
  const V9V10TemplateElementId *templateElement, const void* buffer,
  const size_t real_field_len,
  struct flowCache *flowCache);
struct string_list *rb_separate_long_time_flow(
  struct printbuf *kafka_line_buffer,
  uint64_t export_timestamp, uint64_t dSwitched, uint64_t dInterval,
  uint64_t max_intervals, uint64_t bytes, uint64_t pkts);

/** Print string (i.e., kafka_line_buffer += buffer+real_field_len_offset)
 * @param  kafka_line_buffer     Buffer to print string into
 * @param  buffer                Buffer with string
 * @param  real_field_len        Length of string
 * @param  flowCache             Cache of the flow
 * @return                       Number of bytes printed
 */
size_t print_string(struct printbuf *kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flowCache);

size_t print_number(struct printbuf * kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flowCache);

size_t save_first_switched(struct printbuf *kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flowCache);

size_t save_last_switched(struct printbuf *kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flowCache);

size_t save_first_second(struct printbuf *kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flowCache);

size_t save_first_msecond(struct printbuf *kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flowCache);

size_t save_last_second(struct printbuf *kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flowCache);

size_t save_last_msecond(struct printbuf *kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flowCache);

size_t save_flow_bytes(struct printbuf *kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flowCache);

size_t save_flow_pkts(struct printbuf *kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flowCache);

size_t print_tcp_flags(struct printbuf * kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flowCache);

size_t print_netflow_type(struct printbuf * kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flowCache);

size_t print_flow_end_reason(struct printbuf * kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flowCache);

size_t print_biflow_direction(struct printbuf * kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flowCache);

size_t print_flow_cache_direction(struct printbuf *kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flowCache);

size_t process_direction(struct printbuf *kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flowCache);

size_t process_src_mac(struct printbuf *kafka_line_buffer,
  const void *buffer, const size_t real_field_len,
  struct flowCache *flowCache);

size_t process_dst_mac(struct printbuf *kafka_line_buffer,
  const void *buffer, const size_t real_field_len,
  struct flowCache *flowCache);

size_t process_post_src_mac(struct printbuf *kafka_line_buffer,
  const void *buffer, const size_t real_field_len,
  struct flowCache *flowCache);

size_t process_post_dst_mac(struct printbuf *kafka_line_buffer,
  const void *buffer, const size_t real_field_len,
  struct flowCache *flowCache);

size_t print_direction_based_client_mac(struct printbuf *kafka_line_buffer, const void *buffer, const size_t real_field_len,
  struct flowCache *flowCache);

size_t print_client_mac(struct printbuf *kafka_line_buffer, const void *buffer, const size_t real_field_len,
  struct flowCache *flowCache);

size_t print_direction_based_client_mac_vendor(struct printbuf *kafka_line_buffer, const void *buffer, const size_t real_field_len,
    struct flowCache *flowCache);

size_t print_net(struct printbuf * kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flowCache);

size_t print_net_name(struct printbuf * kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flowCache);

size_t print_net_v6(struct printbuf * kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flowCache);

size_t print_net_name_v6(struct printbuf * kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flowCache);

size_t print_ipv4_src_addr(struct printbuf * kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flowCache);

size_t print_ipv4_dst_addr(struct printbuf * kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flowCache);

size_t process_input_snmp(struct printbuf *kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flowCache);

size_t process_output_snmp(struct printbuf *kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flowCache);

size_t print_lan_interface(struct printbuf *kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flowCache);

size_t print_wan_interface(struct printbuf *kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flowCache);

size_t print_sta_ipv4_address(struct printbuf *kafka_line_buffer,
                              const void *buffer, const size_t real_field_len,
                              struct flowCache *flow_cache);

size_t print_lan_addr(struct printbuf * kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flowCache);

size_t print_wan_addr(struct printbuf * kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flowCache);

size_t print_lan_addr_net(struct printbuf *kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flowCache);

size_t print_lan_addr_net_name(struct printbuf *kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flowCache);

size_t print_wan_addr_net(struct printbuf *kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flowCache);

size_t print_wan_addr_net_name(struct printbuf *kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flowCache);

size_t print_proto_name(struct printbuf * kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flowCache);

size_t print_engine_id_name(struct printbuf * kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flowCache);

size_t print_application_id(struct printbuf * kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flowCache);

size_t print_application_id_name(struct printbuf * kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flowCache);

size_t process_src_port(struct printbuf * kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flowCache);

size_t process_dst_port(struct printbuf * kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flowCache);

size_t print_lan_port(struct printbuf *kafka_line_buffer, const void *buffer,
                      const size_t real_field_len,
                      struct flowCache *flowCache);

size_t print_wan_port(struct printbuf *kafka_line_buffer, const void *buffer,
                      const size_t real_field_len,
                      struct flowCache *flowCache);

size_t print_ipv6_src_addr(struct printbuf * kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flowCache);

size_t print_ipv6_dst_addr(struct printbuf * kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flowCache);

size_t print_ssid_name(struct printbuf * kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flowCache);

size_t print_mac(struct printbuf *kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flowCache);

size_t print_mac_map(struct printbuf *kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flowCache);

size_t print_mac_vendor(struct printbuf *kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flowCache);

#ifdef HAVE_GEOIP

size_t print_AS_ipv4(struct printbuf * kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flowCache);

size_t print_country_code(struct printbuf * kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flowCache);

size_t print_AS_ipv4_name(struct printbuf * kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flowCache);

size_t print_AS6_name(struct printbuf * kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flowCache);

size_t print_AS6(struct printbuf *kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flowCache);

size_t print_country6_code(struct printbuf *kafka_line_buffer,
  const void *buffer, const size_t real_field_len,
  struct flowCache *flowCache);

size_t print_lan_country_code(struct printbuf *kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flow_cache);

size_t print_wan_country_code(struct printbuf *kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flow_cache);

size_t print_lan_AS_name(struct printbuf *kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flow_cache);
size_t print_wan_AS_name(struct printbuf *kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flow_cache);

#endif /* HAVE_GEOIP */

size_t print_selector_name(struct printbuf *kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flowCache);

size_t print_interface_name(struct printbuf *kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flowCache);

size_t print_lan_interface_name(struct printbuf *kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flow_cache);

size_t print_wan_interface_name(struct printbuf *kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flow_cache);

size_t print_lan_interface_description(struct printbuf *kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flow_cache);

size_t print_wan_interface_description(struct printbuf *kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flow_cache);

size_t print_interface_description(struct printbuf *kafka_line_buffer,
    const void *buffer, const size_t real_field_len,
    struct flowCache *flowCache);

size_t print_sensor_enrichment(struct printbuf *kafka_line_buffer,
    const struct flowCache *flowCache);

size_t print_http_url(struct printbuf *kafka_line_buffer,
  const void *buffer, const size_t real_field_len,
  struct flowCache *flowCache);
size_t print_http_host(struct printbuf *kafka_line_buffer,
  const void *buffer, const size_t real_field_len,
  struct flowCache *flowCache);
size_t print_http_host_l2(struct printbuf *kafka_line_buffer,
  const void *buffer, const size_t real_field_len,
  struct flowCache *flowCache);
size_t print_http_user_agent(struct printbuf *kafka_line_buffer,
  const void *buffer, const size_t real_field_len,
  struct flowCache *flowCache);
size_t print_http_referer(struct printbuf *kafka_line_buffer,
  const void *buffer, const size_t real_field_len,
  struct flowCache *flowCache);

size_t print_https_common_name(struct printbuf *kafka_line_buffer,
  const void *buffer, const size_t real_field_len,
  struct flowCache *flowCache);

size_t print_host(struct printbuf *kafka_line_buffer,
  const void *vbuffer, const size_t real_field_len,
  struct flowCache *flowCache);
size_t print_referer(struct printbuf *kafka_line_buffer,
  const void *vbuffer, const size_t real_field_len,
  struct flowCache *flow_cache);

size_t print_host_l2(struct printbuf *kafka_line_buffer,
  const void *vbuffer, const size_t real_field_len,
  struct flowCache *flowCache);
size_t print_referer_l2(struct printbuf *kafka_line_buffer,
  const void *vbuffer, const size_t real_field_len,
  struct flowCache *flow_cache);

#ifdef HAVE_UDNS

const uint8_t *get_direction_based_client_ip(const struct flowCache *flowCache);
const uint8_t *get_direction_based_target_ip(const struct flowCache *flowCache);

size_t print_client_name(struct printbuf *kafka_line_buffer,
  const void *buffer, const size_t real_field_len, struct flowCache *flowCache);

size_t print_target_name(struct printbuf *kafka_line_buffer,
  const void *buffer, const size_t real_field_len, struct flowCache *flowCache);

#endif
