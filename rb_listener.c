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

#include "rb_listener.h"
#include "rb_sensor.h"

#include "f2k.h"
#include "util.h"

#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define PORT_COLLECTOR_MAGIC 0xE0A1CL

struct port_collector{
#ifdef PORT_COLLECTOR_MAGIC
  uint64_t magic;
#endif
  int af_version;
  int run;
  enum transport_proto proto;
  uint16_t port;
  pthread_t listener;
  int socket;
  TAILQ_ENTRY(port_collector) list_entry;
};

void listener_list_append(listener_list *l1, struct port_collector *collector) {
  assert(l1);
  assert(collector);
  TAILQ_INSERT_TAIL(l1,collector,list_entry);
}

#define listener_list_foreach(var,head) TAILQ_FOREACH(var,head,list_entry)
#define listener_list_head(list) TAILQ_FIRST(list)
#define listener_list_next(elm) TAILQ_NEXT(elm,list_entry)
#define listener_list_remove(head,elm) TAILQ_REMOVE(head,elm,list_entry)
#define listener_list_concat(list1,list2) TAILQ_CONCAT(list1,list2,list_entry)

static void* netFlowCollectLoop0(struct port_collector *collector) {
  QueuedPacket *qpacket=NULL;
  static const size_t allocated_buffer_len = NETFLOW_BUFFER_LEN- sizeof(*qpacket);
  struct sockaddr_in fromHostV4;
  memset(&fromHostV4,0,sizeof(fromHostV4));

  /* traceEvent(TRACE_NORMAL, "netFlowMainLoop(%u) thread...", thread_id); */
  readOnlyGlobals.datalink = DLT_EN10MB;

  while(!readWriteGlobals->shutdownInProgress) {
    socklen_t socklen = sizeof(fromHostV4);
    if(NULL==qpacket){
        qpacket = newQueuedPacket(allocated_buffer_len);
    }

    errno = 0;
    qpacket->buffer_len = recvfrom(collector->socket,
                      qpacket->buffer, allocated_buffer_len,
                      0, (struct sockaddr*)&fromHostV4, &socklen);

    if(qpacket->buffer_len < 0 && errno != EAGAIN){
      traceEvent(TRACE_ERROR,"Error in recvfrom: %s",strerror(errno));
    } else if(qpacket->buffer_len > 0){
#ifdef DEBUG_FLOWS
      if(unlikely(readOnlyGlobals.enable_debug))
        traceEvent(TRACE_INFO,
          "NETFLOW_DEBUG: Received sFlow/NetFlow packet(len=%d)",
          qpacket->buffer_len);
#endif
      qpacket->netflow_device_ip = ntohl(fromHostV4.sin_addr.s_addr);
      qpacket->sensor = get_sensor(
        readOnlyGlobals.rb_databases.sensors_info, qpacket->netflow_device_ip);
      if(NULL==qpacket->sensor) {
        const size_t bufsize = 1024;
        char buf[bufsize];
        const int bad_sensor_added = addBadSensor(
        readOnlyGlobals.rb_databases.sensors_info, qpacket->netflow_device_ip);
        if(bad_sensor_added) {
          traceEvent(TRACE_WARNING,
            "Received a packet from the unknow sensor %s on port %u.",
                      _intoaV4(qpacket->netflow_device_ip,buf,bufsize),
                      collector->port);
        }
      } else {
        worker_t *worker = sensor_worker(qpacket->sensor);
        add_packet_to_worker(qpacket, worker);
        qpacket = NULL;
      }
    } else {
      /* EAGAIN. Let's poll */
      fd_set netflowMask;
      FD_ZERO(&netflowMask);
      FD_SET(collector->socket, &netflowMask);
      struct timeval tv = {.tv_sec=0,.tv_usec=500000};

      select(collector->socket+1, &netflowMask, NULL, NULL, &tv);
    }
  }

  return(NULL);
}

static void *netFlowCollectLoop(void* _port_collector) {
  struct port_collector *collector = _port_collector;

  #ifdef PORT_COLLECTOR_MAGIC
  assert(collector->magic == PORT_COLLECTOR_MAGIC);
  #endif

  netFlowCollectLoop0(collector);
  return NULL;
}

void closeNetFlowListener(struct port_collector *collector) {
  assert(collector);

  if(collector->socket > 0){
    traceEvent(TRACE_NORMAL,"Closing socket UPD port %u",collector->port);
    close(collector->socket);
  }
  free(collector);
}

static int wakeUpListener(struct port_collector *listener) {
  char errbuf[BUFSIZ];
  int sockopt = 1;
  struct sockaddr_in sockInV4;
  traceEvent(TRACE_NORMAL,"Creating listening socket in port %d",listener->port);

  errno = 0;
  switch(listener->proto){
  case UDP:
    listener->socket = socket(AF_INET, SOCK_DGRAM, 0);
    break;
  default:
    traceEvent(TRACE_ERROR,"Unknown protocol %d, can't create socket",listener->proto);
    goto free_listener;
  };

  if( listener->socket < 0 ) {
    const int _errno = errno;
    strerror_r(_errno,errbuf,sizeof(errbuf));
    traceEvent(TRACE_INFO, "Unable to create a UDPv4 socket - returned %d, error is '%s'(%d)",
        listener->socket, errbuf, _errno);
    goto free_listener;
  }

  maximize_socket_buffer(listener->socket, SO_RCVBUF);

  setsockopt(listener->socket, SOL_SOCKET, SO_REUSEADDR, (char *)&sockopt, sizeof(sockopt));

  sockInV4.sin_family            = AF_INET;
  sockInV4.sin_port              = (int)htons(listener->port);
  sockInV4.sin_addr.s_addr       = INADDR_ANY;
  const int bind_rc = bind(listener->socket,
    (struct sockaddr *)&sockInV4, sizeof(sockInV4));

  if(bind_rc < 0) {
    const int _errno = errno;
    strerror_r(_errno,errbuf,sizeof(errbuf));
    traceEvent(TRACE_ERROR,
      "Flow listener UDP port %d already in use ? [%s/%d]",
      listener->port, errbuf, _errno);
    goto close_socket;
  }

  if(listener->socket > 0)
    pthread_create(&listener->listener, NULL, netFlowCollectLoop, listener);

  return 0;

close_socket:
  closeNetFlowListener(listener);
  listener = NULL;

free_listener:
  free(listener);
  return -1;
}

void wakeUpListenerList(listener_list *list) {
  struct port_collector *i = NULL;
  listener_list_foreach(i,list)
    wakeUpListener(i);
}

struct port_collector *createNetFlowListener(enum transport_proto proto,uint16_t collectorInPort){
  struct port_collector *collector = calloc(1,sizeof(*collector));
  if(NULL == collector) {
    traceEvent(TRACE_ERROR,"Invalid address");
    return NULL;
  }

#ifdef PORT_COLLECTOR_MAGIC
  collector->magic = PORT_COLLECTOR_MAGIC;
#endif

  collector->port = collectorInPort;
  collector->proto = proto;

  collector->socket = -1;

  return collector;
}

static int is_present(const struct port_collector *collector,const listener_list *list) {
  const struct port_collector *i = NULL;

  listener_list_foreach(i,list) {
    if(i->proto == collector->proto && i->port == collector->port)
      return 1;
  }

  return 0;
}

/* Close all listener in 'original' not present in 'compare' */
enum purge_type {present,not_present};
static void purgeListeners(listener_list *original,listener_list *compare,
                                                   enum purge_type type) {
  assert(original);
  assert(compare);

  struct port_collector *i = listener_list_head(original);
  while(i) {
    struct port_collector *next = listener_list_next(i);

    if((type==not_present && !is_present(i,compare))
       || (type==present && is_present(i,compare))) {
      listener_list_remove(original,i);
      closeNetFlowListener(i);
    }

    i = next;
  }
}

static void purgeListenersPresentIn(listener_list *original,listener_list *compare) {
  purgeListeners(original,compare,present);
}

static void purgeListenersNotPresentIn(listener_list *original,listener_list *compare) {
  purgeListeners(original,compare,not_present);
}

void listener_list_done(listener_list *l) {
  listener_list empty;
  listener_list_init(&empty);

  purgeListenersNotPresentIn(l,&empty);
}

void mergeNetFlowListenerList(listener_list *l1,listener_list *l2) {
  // Close sockets that are not needed anymore
  purgeListenersNotPresentIn(l1,l2);

  // Delete already opened sockets from new list
  purgeListenersPresentIn(l2,l1);

  listener_list_concat(l1,l2);
}
