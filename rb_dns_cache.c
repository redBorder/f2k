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

#include "rb_dns_cache.h"

#ifdef HAVE_UDNS

#include "f2k.h"
#include "util.h"

#include <librd/rdio.h>
#include <librd/rdthread.h>

#include <stddef.h>
#include <assert.h>

static const int MAX_DNS_TIMEOUT_MS = 500;
static const int MAX_DNS_TIMEOUT_S  = 0;
static const int UDNS_GUESS_TIME    = 0;


#ifndef NDEBUG
#define DNS_CACHE_ENTRY_MAGIC 0xDCACEEA1CL
#endif

struct dns_cache_entry {
	/* Private API - Do not use directly */
#ifdef DNS_CACHE_ENTRY_MAGIC
	uint64_t magic;
#endif

	/// cache from where node was allocated
	struct dns_cache *cache;

	struct dns_cache_elm elm;

	time_t last_checked;

	/// It's possible to use node after delete it from database.
	uint32_t refcnt;
	rd_avl_node_t avl_elm;
	TAILQ_ENTRY(dns_cache_entry) lru_entry;
};

typedef TAILQ_HEAD(lru_element_head,dns_cache_entry) lru_t;
#define lru_init(lru)       TAILQ_INIT(lru)
#define lru_empty(lru)      TAILQ_EMPTY(lru)
#define lru_push(lru,elm)   TAILQ_INSERT_HEAD(lru,elm,lru_entry)
#define lru_remove(lru,elm) do{ \
		TAILQ_REMOVE(lru,elm,lru_entry); \
		memset(&(elm)->lru_entry,0,sizeof((elm)->lru_entry)); \
	}while(0)

static struct dns_cache_entry *lru_pop_nl(lru_t *lru) {
	struct dns_cache_entry *e = TAILQ_LAST(lru,lru_element_head);
	lru_remove(lru,e);
	return e;
}

/// @TODO register match/failures/recycled/etc.
/// @NOTE: When a ntry is deleted from database, it's deleted from lru,
/// but it will not be freed until you drop to 0 refcnt.
struct dns_cache {
	/// Maximum memory that cache can hold
	size_t max_mem_b;

	/// Timeout in what entry is not valid anymore
	time_t timeout_s;

	pthread_mutex_t mutex;
	rd_memctx_t memctx;
	rd_avl_t avl;
	lru_t lru;
};

static size_t real_entry_size(struct dns_cache_entry *entry) {
	return sizeof(*entry) + entry->elm.name_len + 1;
}

static void dns_cache_memctx_free(struct dns_cache_entry *entry) {
	rd_memctx_freesz(&entry->cache->memctx,entry,real_entry_size(entry));
}

static int dns_cache_entry_cmp(const void *_e1,const void *_e2) {
	const struct dns_cache_entry *e1 = _e1;
	const struct dns_cache_entry *e2 = _e2;

#ifdef DNS_CACHE_ENTRY_MAGIC
	assert(DNS_CACHE_ENTRY_MAGIC == e1->magic);
	assert(DNS_CACHE_ENTRY_MAGIC == e2->magic);
#endif

	return memcmp(e1->elm.addr,e2->elm.addr,sizeof(e1->elm.addr));
}

struct dns_cache *dns_cache_new(size_t maxmem_m, time_t timeout_s) {
	struct dns_cache *ret = calloc(1,sizeof(ret[0]));
	if(NULL == ret) {
		traceEvent(TRACE_ERROR, "Can't allocate DNS cache (out of memory?)");
		return NULL;
	}

	ret->max_mem_b = maxmem_m * 1024 * 1024;
	ret->timeout_s = timeout_s;

	pthread_mutex_init(&ret->mutex,NULL);
	rd_memctx_init(&ret->memctx,NULL /* name */,RD_MEMCTX_F_TRACK);
	rd_avl_init(&ret->avl,dns_cache_entry_cmp,0);
	lru_init(&ret->lru);

	return ret;
}

void dns_cache_done(struct dns_cache *cache) {
	rd_memctx_freeall(&cache->memctx);
	rd_avl_destroy(&cache->avl);
	rd_memctx_destroy(&cache->memctx);
	pthread_mutex_destroy(&cache->mutex);
}

static void dns_cache_decref_elm0(struct dns_cache_elm *elm,int do_lock) {
	int freed = 0;
	rd_memctx_stats_t stats = {0};
	uint8_t *ptr_elm = (uint8_t *)elm;
	uint8_t *ptr_entry = ptr_elm - offsetof(struct dns_cache_entry, elm);
	struct dns_cache_entry *entry = (struct dns_cache_entry *)ptr_entry;
	struct dns_cache *cache = entry->cache;

#ifdef DNS_CACHE_ENTRY_MAGIC
	assert(DNS_CACHE_ENTRY_MAGIC == entry->magic);
#endif

	if(do_lock) {
		pthread_mutex_lock(&cache->mutex);
	}

	if(0 == --entry->refcnt) {
		dns_cache_memctx_free(entry);
		if(unlikely(readOnlyGlobals.enable_debug)) {
			freed = 1;
			rd_memctx_stats(&cache->memctx,&stats);
		}
	}

	if(do_lock) {
		pthread_mutex_unlock(&cache->mutex);
	}

	if(unlikely(readOnlyGlobals.enable_debug) && freed) {
		traceEvent(TRACE_NORMAL,
			"DNS cache node %p freed. Current stats: "
			"%d allocations, %zu bytes",
			entry,stats.out, stats.bytes_out);
	}
}

/// Internal reference decrement, use if you have already locked cache.
static void dns_cache_decref_elm_nl(struct dns_cache_elm *elm) {
	dns_cache_decref_elm0(elm,0 /* no lock */);
}

void dns_cache_decref_elm(struct dns_cache_elm *elm) {
	dns_cache_decref_elm0(elm,1 /* lock */);
}

struct dns_cache_elm * dns_cache_save_elm(struct dns_cache *cache,
		const uint8_t *addr, const char *name, size_t name_len,
		time_t now) {
	struct dns_cache_entry *entry = NULL;
	rd_memctx_stats_t stats;
	const size_t needed_size = sizeof(*entry) + name_len + 1;
	// Can't trust in that bytes_out have been reduced because of refcounting system.
	size_t freed_size = 0;

	pthread_mutex_lock(&cache->mutex);

	rd_memctx_stats(&cache->memctx,&stats);
	while(stats.bytes_out + needed_size > cache->max_mem_b + freed_size) {
		if(unlikely(lru_empty(&cache->lru))) {
			traceEvent(TRACE_ERROR,"Can't allocate DNs cache element because cache limit.");
			traceEvent(TRACE_ERROR,"Please consider increase it.");
			pthread_mutex_unlock(&cache->mutex);
			return NULL;
		}

		struct dns_cache_entry *old_entry = lru_pop_nl(&cache->lru);
		freed_size += real_entry_size(old_entry);

		if(unlikely(readOnlyGlobals.enable_debug)) {
			traceEvent(TRACE_NORMAL,"Freeing entry %p, of size %zu",
				old_entry, real_entry_size(old_entry));
		}

		RD_AVL_REMOVE_ELM(&cache->avl,old_entry);
		dns_cache_decref_elm_nl(&old_entry->elm);
	}

	entry = rd_memctx_calloc(&cache->memctx, 1, needed_size);
	if(NULL != entry) {
#ifdef DNS_CACHE_ENTRY_MAGIC
		entry->magic = DNS_CACHE_ENTRY_MAGIC;
#endif

		/// cache from where node was allocated
		entry->cache = cache;

		memcpy(entry->elm.addr,addr,sizeof(entry->elm.addr));
		entry->elm.name = memcpy((void *)&entry[1],name,name_len);
		entry->elm.name_len = name_len;

		entry->last_checked = now;
		entry->refcnt = 2; /* database & returned */

		lru_push(&cache->lru,entry);
		struct dns_cache_entry *oldentry = RD_AVL_INSERT(&cache->avl,entry,avl_elm);
		if(oldentry) {
			/* Another one inserted it's element first! we will make it dissapear */
			lru_remove(&cache->lru,oldentry);
			memset(&oldentry->lru_entry,0,sizeof(oldentry->lru_entry));
			dns_cache_decref_elm_nl(&oldentry->elm);
		}
	}
	pthread_mutex_unlock(&cache->mutex);

	return &entry->elm;
}

struct dns_cache_elm *dns_cache_get_elm(struct dns_cache *cache,const uint8_t *addr,time_t now) {
	struct dns_cache_entry entry;
	struct dns_cache_entry *ret = NULL;
	memset(&entry,0,sizeof(entry));
#ifdef DNS_CACHE_ENTRY_MAGIC
	entry.magic = DNS_CACHE_ENTRY_MAGIC;
#endif
	memcpy(entry.elm.addr,addr,sizeof(entry.elm.addr));

	pthread_mutex_lock(&cache->mutex);
	ret = RD_AVL_FIND(&cache->avl,&entry);

	if(ret) {
		lru_remove(&cache->lru,ret);

		const double age = difftime(now,ret->last_checked);
		if(age > cache->timeout_s) {
			/// Invalidate -> please, call again.
			if(unlikely(readOnlyGlobals.enable_debug)) {
				traceEvent(TRACE_NORMAL,"Invalidating %p entry (age = %lf > %tu)",
					ret,age,cache->timeout_s);
			}

			RD_AVL_REMOVE_ELM(&cache->avl,ret);
			dns_cache_decref_elm_nl(&ret->elm);
			ret = NULL;
		} else {
			// Re-ordering lru
			lru_push(&cache->lru,ret);

			ret->refcnt++;
		}
	}
	pthread_mutex_unlock(&cache->mutex);

	return ret ? &ret->elm : NULL;

}

void *udns_pool_routine(void *_dns_info) {
	struct rb_dns_info *dns_info = _dns_info;

	assert(dns_info);
#ifdef RB_DNS_MAGIC
	assert(dns_info->magic == RB_DNS_MAGIC);
#endif
	assert(dns_info->dns_ctx);

	dns_open(dns_info->dns_ctx);

	int dns_socket_fd = dns_sock(dns_info->dns_ctx);

	while(rd_currthread->rdt_state == RD_THREAD_S_RUNNING) {
		dns_ioevent(dns_info->dns_ctx,UDNS_GUESS_TIME);
		dns_timeouts(dns_info->dns_ctx,MAX_DNS_TIMEOUT_S,UDNS_GUESS_TIME);
		rd_thread_poll(0); // Consume all events created in ioevent
		rd_io_poll_single(dns_socket_fd,POLLIN,MAX_DNS_TIMEOUT_MS);
	}

	/* Cleanup */
	rd_thread_cleanup();

	return NULL;
}

#endif /* HAVE_UDNS */
