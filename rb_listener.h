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

#include <sys/queue.h>
#include <stdint.h>
#include <pthread.h>

enum transport_proto {
	UDP
};

struct port_collector;

typedef TAILQ_HEAD(,port_collector) listener_list;
#define listener_list_init(list) TAILQ_INIT(list)
void listener_list_done(listener_list *l);
void listener_list_append(listener_list *l1,struct port_collector *collector);
#define listener_list_empty(list) TAILQ_EMPTY(list)

/* Let l1 previous list:
	* It will close all listener present in l1 and not present in l2
	* It will create all listener present in l2 and not present in l1
	* l2 will be empty
*/
void mergeNetFlowListenerList(listener_list *l1,listener_list *l2);
struct port_collector *createNetFlowListener(enum transport_proto proto,uint16_t collectorInPort);
void closeNetFlowListener(struct port_collector *);
void wakeUpListenerList(listener_list *l1);
