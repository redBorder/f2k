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

#ifndef RB_LISTS_H
#define RB_LISTS_H

#include "rb_listener.h"

#include <sys/queue.h>
#include "printbuf.h"
#include <librd/rdmem.h>
#include <time.h>

/// @todo use this to iterate over host/network file?
#ifdef HAVE_GDBM
#include <gdbm.h>
#endif


#ifdef HAVE_RB_MAC_VENDORS
#include "rb_mac_vendors.h"
#endif

/*********     char * (strings) lists     ************/
struct string_list{
  struct printbuf *string;
  uint64_t client_mac;
  struct string_list *next;
  //SLIST_ENTRY(string_list) next;
};

static void string_list_concat(struct string_list **s1,struct string_list *s2) __attribute__((unused));
static void string_list_concat(struct string_list **s1,struct string_list *s2){
  assert(s1);
  struct string_list *node = *s1;
  if(s2==NULL){
    return; // The result will be the same
  }
  if(node==NULL){
    (*s1) = s2;
  }else{
    while(node->next)
      node = node->next;
    node->next = s2;
  }
}

/*********     number char * lists         ***********/

struct number64_string_list_node{
  uint64_t number_i; /* plain number */
  char *   number_a; /* number as string */
  char *   name;
  STAILQ_ENTRY(number64_string_list_node) next;
};

typedef STAILQ_HEAD(,number64_string_list_node) number_string_list;

typedef number_string_list mac_addr_list;
typedef struct number64_string_list_node mac_addr_list_node;
static inline void freeIfAddressList(mac_addr_list * list){
  mac_addr_list_node * node = NULL;
  while((node = STAILQ_FIRST(list)))
  {
    STAILQ_REMOVE_HEAD(list,next);
    free(node->number_a);
    free(node->name);
    free(node);
  }

  STAILQ_INIT(list);
}

static inline const char * find_mac_name(const uint64_t mac,const mac_addr_list *list)
{
  mac_addr_list_node * node=NULL;
  STAILQ_FOREACH(node,list,next)
  {
    if(node->number_i == mac)
      return node->name;
  }
  return NULL;
}

/********* char * key, char * value lists ************/

typedef struct rb_keyval_list_s{
  char * key;
  char * val;
  struct rb_keyval_list_s * next;
}rb_keyval_list_t;

static inline void freeCharCharNode(rb_keyval_list_t * node)
{
  free(node->key);free(node->val);
}

#define RB_FREE_LIST(TYPE,list,freeitem)                            \
do{                                                                 \
  TYPE *item,*tmpitem;                                              \
  for(item=*list ; item && (tmpitem = item->next); item = tmpitem){ \
		freeitem(item);free(item);                                      \
	}                                                                 \
	*list=NULL;                                                       \
}while(0)

int parseCharCharList_File(rb_keyval_list_t ** list,char * filename);

static inline void freeOSList(rb_keyval_list_t **list){
  RB_FREE_LIST(rb_keyval_list_t,list,freeCharCharNode);
}

#endif // RB_LISTS_H
