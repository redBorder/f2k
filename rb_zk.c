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
#include "f2k.h"
#include "rb_zk.h"
#include "rb_sensor.h"
#include "util.h"

#include <librd/rdthread.h>

#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <pthread.h>

#ifdef HAVE_ZOOKEEPER

// Needed because of ZK API
static void *not_const_cast(const void *p) {
  void *r;
  memcpy(&r, &p, sizeof(r));
  return r;
}

struct zk_template_ls_root_completed_data {
#ifndef NDEBUG
#define ZK_TEMPLATE_LS_ROOT_COMPLETED_DATA_MAGIC 0x3A3500333A350033
  uint64_t magic;
#endif

  zhandle_t *zh; ///< Zookeeper handler
  const char *root_path; ///< ZK path to save templates

  // in the initial call, we stall until we get all templates
  size_t pending_childs; ///< Pending childs templates
  pthread_cond_t cv; ///< Condition variable to stall
  pthread_mutex_t mtx; ///< cv mutex
  bool path_initialized; ///< /f2k/nprobe initialized
  bool initialized; ///< First call, have to wait all templates
};

#define assert_zk_template_get_completed_data(data) \
              assert(ZK_TEMPLATE_LS_ROOT_COMPLETED_DATA_MAGIC == (data)->magic)

static void zk_template_get_completed(int rc, const char *value, int value_len,
  const struct Stat *zk_stat __attribute__((unused)), const void *_data) {
  char buf[BUFSIZ];

  struct zk_template_ls_root_completed_data *data = not_const_cast(_data);
  assert_zk_template_get_completed_data(data);
  readOnlyGlobals.zk.last_template_get_timestamp = time(NULL);

  if(rc != ZOK) {
    traceEvent(TRACE_ERROR,"ZooKeeper can't complete GET template: %s",zerror(rc));
    return;
  }

  struct flowSetV9Ipfix *new_template = deserialize_template(value,value_len);
  if(new_template) {
    ATOMIC_OP(add, fetch,
      &readWriteGlobals->collectionStats.num_zk_templates_received.value, 1);
    struct sensor *s = get_sensor(readOnlyGlobals.rb_databases.sensors_info,
      new_template->templateInfo.netflow_device_ip);
    if(NULL == s) {
      traceEvent(TRACE_NORMAL,"Received template from ZK of unknown sensor "
        "[device %s][Observation domain id %"PRIu32"][Template id %"PRIu16"]",
        _intoaV4(new_template->templateInfo.netflow_device_ip, buf, sizeof(buf)),
        new_template->templateInfo.observation_domain_id,
        new_template->templateInfo.templateId);
      return;
    }
    save_template_async(s,new_template);
    traceEvent(TRACE_NORMAL,"Added template from ZK [device "
      "%s][observation domain id %"PRIu32"][template id %"PRIu16"]",
      _intoaV4(new_template->templateInfo.netflow_device_ip, buf, sizeof(buf)),
      new_template->templateInfo.observation_domain_id,
      new_template->templateInfo.templateId);
  }

  pthread_mutex_lock(&data->mtx);
  if (data->pending_childs > 0 && 0 == --data->pending_childs) {
    // We were the last child to retrieve
    pthread_cond_signal(&data->cv);
  }
  pthread_mutex_unlock(&data->mtx);
}

static void zk_template_watcher(zhandle_t *zh,int type,int state,
                                const char *path,
                                void *ctx __attribute__((unused))) {
  if(type == ZOO_CHANGED_EVENT) {
    /* The only good case */
  } else if (type == ZOO_NOTWATCHING_EVENT) {
    traceEvent(TRACE_WARNING,"Template watcher removed by ZK server. Re-trying.");
  } else if (type == ZOO_SESSION_EVENT) {
    traceEvent(TRACE_WARNING,"ZK Session change.");
  } else {
    traceEvent(TRACE_ERROR,"Event type %d (%s) received in child watcher. Can't do anything.",type,type2String(type));
    return;
  }

  if(state != ZOO_CONNECTED_STATE) {
    traceEvent(TRACE_ERROR,"Called with zh state %d",state);
    return;
  }

  zoo_awget(zh,path,zk_template_watcher,NULL,zk_template_get_completed,zoo_get_context(zh));
  return;
}

#define assert_zk_template_ls_root_completed_data(data) \
  assert(ZK_TEMPLATE_LS_ROOT_COMPLETED_DATA_MAGIC == (data)->magic)

static void zk_template_root_completed(int rc,const struct String_vector *strings, const void *_data) {
  assert(_data);

  struct zk_template_ls_root_completed_data *data = not_const_cast(_data);
  int i;

  assert_zk_template_ls_root_completed_data(data);

  if(rc != ZOK) {
    traceEvent(TRACE_ERROR,"Error while getting template root: %s",zerror(rc));
    return;
  }

  if(NULL == strings) {
    traceEvent(TRACE_ERROR, "strings == NULL, can't list childrens");
    return;
  }

  if (!ATOMIC_TEST_AND_SET(&data->initialized)) {
    // First call to function, the caller is still waiting to us to signal
    // continue, so we should answer
    pthread_mutex_lock(&data->mtx);
    if (strings->count == 0) {
      pthread_cond_signal(&data->cv);
    } else {
      data->pending_childs = strings->count;
    }
    pthread_mutex_unlock(&data->mtx);
  }

  for(i=0;i<strings->count;++i) {
    char buf[BUFSIZ];
    const int printf_rc = snprintf(buf,sizeof(buf),"%s/%s",data->root_path,strings->data[i]);
    if(printf_rc < 0 || (size_t)printf_rc > sizeof(buf)) {
      traceEvent(TRACE_ERROR,"Bad printf output");
    } else {
      zoo_awget(data->zh,buf,zk_template_watcher,NULL,zk_template_get_completed,data);
    }
  }
}

/**
  Wrapper around zk_awget_children that prints error code (if any)
  */
static int verbose_zoo_awget_children(zhandle_t *zh, const char *path,
        watcher_fn zk_template_root_watcher,
        void* watcherCtx __attribute__((unused)),
        strings_completion_t zk_template_root_completed_cb,
        const void *context __attribute__((unused))) {

  const int get_children_rc = zoo_awget_children(zh,path,
    zk_template_root_watcher,NULL,zk_template_root_completed_cb,zoo_get_context(zh));

  switch(get_children_rc) {
  case ZNONODE:
    traceEvent(TRACE_ERROR,"the node %s does not exist.",path);
    break;
  case ZNOAUTH:
    traceEvent(TRACE_ERROR,"the client does not have permission over node %s.",
      path);
    break;
  case ZBADARGUMENTS:
    traceEvent(TRACE_ERROR,"invalid input parameters");
    break;
  case ZINVALIDSTATE:
    /* We will try next time */
    break;
  case ZMARSHALLINGERROR:
    traceEvent(TRACE_ERROR,"ZK failed to marshall a getchildren request;"
      " possibly, out of memory");
    break;
  case ZOK:
  default:
    /* All ok, do nothing */
    break;
  };

  return get_children_rc;
}

static void zk_template_root_watcher(zhandle_t *zh, int type, int state,
  const char *path, void *watcherCtx __attribute__((unused))) {
  if(type == ZOO_CHILD_EVENT){
    /* The only good case */
  } else if (type == ZOO_NOTWATCHING_EVENT) {
    traceEvent(TRACE_WARNING,"Template root watcher removed by ZK server. Re-trying.");
  } else if (type == ZOO_SESSION_EVENT) {
    traceEvent(TRACE_WARNING,"ZK Session change.");
  } else {
    traceEvent(TRACE_ERROR,"Event type %d (%s) received in child watcher. Can't do anything.",type,type2String(type));
    return;
  }

  if(state != ZOO_CONNECTED_STATE) {
    traceEvent(TRACE_ERROR,"Called with zh state %d",state);
    return;
  }

  if(path == NULL) {
    traceEvent(TRACE_ERROR,"Called with NULL path");
    return;
  }

  verbose_zoo_awget_children(zh,path,
    zk_template_root_watcher,NULL,
    zk_template_root_completed, zoo_get_context(zh));
}

static void load_all_templates_from_zk(zhandle_t *zh,const char *f2k_zk_path) {
  verbose_zoo_awget_children(zh,f2k_zk_path,
    zk_template_root_watcher,NULL,zk_template_root_completed,zoo_get_context(zh));
}

/* Prepare zookeeper structure */
static bool zk_prepare(zhandle_t *zh) {
  char aux_buf[sizeof(ZOOKEEPER_PATH)];
  strcpy(aux_buf,ZOOKEEPER_PATH);
  int last_path_printed = 0;

  char *cursor = aux_buf+1;

  /* Have to create path recursively */
  cursor = strchr(cursor,'/');
  while(cursor || !last_path_printed) {
    if(cursor)
      *cursor = '\0';
    const int create_rc = zoo_create(zh,aux_buf,
      NULL /* Value */,
      0 /* Valuelen*/,
      &ZOO_OPEN_ACL_UNSAFE /* ACL */,
      0 /* flags */,
      NULL /* result path buffer */,
      0 /* result path buffer lenth */);

    if(create_rc != ZOK && create_rc != ZNODEEXISTS) {
      traceEvent(TRACE_ERROR,"Can't create zookeeper path [%s]: %s",ZOOKEEPER_PATH,zerror(create_rc));
      return false;
    }

    if(cursor) {
      *cursor = '/';
      cursor = strchr(cursor+1,'/');
    } else {
      last_path_printed = 1;
    }
  }

  return true;
}

static void zk_watcher(zhandle_t *zh, int type, int state,
            const char *path __attribute__((unused)),
            void* watcherCtx)
{
  struct zk_template_ls_root_completed_data *data = watcherCtx;
  assert_zk_template_ls_root_completed_data(data);
  const bool initializing = !ATOMIC_TEST_AND_SET(&data->path_initialized);

  if (initializing) {
    data->zh = zh;
  }

  if(type == ZOO_SESSION_EVENT && state == ZOO_CONNECTED_STATE){
    if (initializing) {
      zk_prepare(zh);
    }
    load_all_templates_from_zk(zh,ZOOKEEPER_PATH);
  } else {
    traceEvent(TRACE_ERROR,"Can't connect to ZK: [type: %d (%s)][state: %d (%s)]",
      type,type2String(type),state,state2String(state));
    if(type == ZOO_SESSION_EVENT && state == ZOO_EXPIRED_SESSION_STATE) {
      traceEvent(TRACE_ERROR,"Trying to reconnect");
      readOnlyGlobals.zk.need_to_reconnect = 1;
    }
  }

  zoo_set_watcher(zh,zk_watcher);
}

void init_f2k_zk(const char *new_zk_host) {
  static const int cond_timeout_ms = 3*1000;

  struct zk_template_ls_root_completed_data *data = NULL;
  rd_calloc_struct(&data,sizeof(*data),
    -1,ZOOKEEPER_PATH,&data->root_path,
    RD_MEM_END_TOKEN);

  if(NULL == data) {
    traceEvent(TRACE_ERROR,"Can't allocate data (out of memory?)");
  } else {
#ifndef NDEBUG
    data->magic = ZK_TEMPLATE_LS_ROOT_COMPLETED_DATA_MAGIC;
#endif
    pthread_mutex_init(&data->mtx, NULL);
    pthread_cond_init(&data->cv, NULL);

    readOnlyGlobals.zk.zk_host = strdup(new_zk_host);
    new_zk_host = NULL;
    traceEvent(TRACE_INFO,"Init Zookeeper handler to %s",new_zk_host);
    assert(readOnlyGlobals.zk.zk_host);
    const int zk_read_timeout = 30000;
    pthread_mutex_lock(&data->mtx);
    readOnlyGlobals.zk.zh = zookeeper_init(readOnlyGlobals.zk.zk_host, zk_watcher, zk_read_timeout, 0, data, 0);
    if(NULL == readOnlyGlobals.zk.zh) {
      char strerror_buf[BUFSIZ];
      strerror_r(errno,strerror_buf,sizeof(strerror_buf));
      traceEvent(TRACE_ERROR,"Can't init zookeeper: [%s]. ZK says: [%s]",strerror_buf,readOnlyGlobals.zk.log_buffer);
    } else {
      traceEvent(TRACE_NORMAL,"Connected to ZooKeeper %s",readOnlyGlobals.zk.zk_host);
    }

    rd_cond_timedwait_ms(&data->cv, &data->mtx, cond_timeout_ms);
    pthread_mutex_unlock(&data->mtx);
  }
}

static void destroy_zk_handler(zhandle_t *zh) {
  struct zk_template_ls_root_completed_data *data = not_const_cast(zoo_get_context(zh));
  zookeeper_close(zh);

  pthread_cond_destroy(&data->cv);
  pthread_mutex_destroy(&data->mtx);
  free(data);
}

void stop_f2k_zk() {
  traceEvent(TRACE_INFO,"Closing Zookeeper handler to %s",readOnlyGlobals.zk.zk_host);
  if (readOnlyGlobals.zk.zh) {
    destroy_zk_handler(readOnlyGlobals.zk.zh);
    readOnlyGlobals.zk.zh = NULL;
  }
  free(readOnlyGlobals.zk.zk_host);
  readOnlyGlobals.zk.zk_host=NULL;
  if(readOnlyGlobals.zk.log_buffer_f)
    fclose(readOnlyGlobals.zk.log_buffer_f);
  readOnlyGlobals.zk.log_buffer_f = NULL;
  free(readOnlyGlobals.zk.log_buffer);
  readOnlyGlobals.zk.log_buffer = NULL;
}

void *zk_watchers_watcher(void *a __attribute__((unused))) {
  while(readOnlyGlobals.f2k_up) {
    sleep(1);

    if(readOnlyGlobals.zk.need_to_reconnect) {
      pthread_rwlock_wrlock(&readOnlyGlobals.zk.rwlock);
      char *zk_host = readOnlyGlobals.zk.zk_host; /* backup */
      readOnlyGlobals.zk.zk_host = NULL;
      zookeeper_close(readOnlyGlobals.zk.zh);
      init_f2k_zk(zk_host);
      free(zk_host);
      pthread_rwlock_unlock(&readOnlyGlobals.zk.rwlock);
      readOnlyGlobals.zk.need_to_reconnect = 0;
    }

    if(readOnlyGlobals.zk.update_template_timeout < 1)
      continue;

    time_t now;

    time(&now);
    const double dseconds = difftime(now,
      readOnlyGlobals.zk.last_template_get_timestamp);
    if( readOnlyGlobals.zk.zh
        && dseconds > readOnlyGlobals.zk.update_template_timeout ) {
      /* Timeout: Force an update */
      load_all_templates_from_zk(readOnlyGlobals.zk.zh,ZOOKEEPER_PATH);
    }
  }

  return NULL;
}

#endif
