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

#ifdef HAVE_UDNS

#include <udns.h>
#include <librd/rdavl.h>
#include <librd/rdsysqueue.h>
#include <librd/rdmem.h>
#include <stdint.h>
#include <stdint.h>

#ifndef NDEBUG
#define RB_DNS_MAGIC 0xBA1CBA1CBA1CBA1CL
#define RB_DNS_OPAQUE 0xB0A3B0A3B0A3B0A3L
#endif

struct dns_cache_elm {
	uint8_t addr[16];
	size_t name_len;
	const char *name;
};

struct dns_cache;

struct dns_cache *dns_cache_new(size_t maxmem_m, time_t timeout_s);
void dns_cache_done(struct dns_cache *cache);

/// Get an element from cache. If success (return not null), must do a dns_cache_decref_elm at the end.
struct dns_cache_elm *dns_cache_get_elm(struct dns_cache *cache,const uint8_t *addr,time_t now);
void dns_cache_decref_elm(struct dns_cache_elm *);
struct dns_cache_elm *dns_cache_save_elm(struct dns_cache *cache,const uint8_t *addr,const char *name,size_t name_len,time_t now);

struct rb_dns_info {
#ifdef RB_DNS_MAGIC
	uint64_t magic;
#endif
	struct dns_ctx *dns_ctx;
};

void *udns_pool_routine(void *);

#endif /* HAVE_UDNS */
