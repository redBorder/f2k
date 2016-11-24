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


#include "NumNameAssocTree.h"

#include "librd/rdavl.h"
#include "librd/rdmem.h"

#define NUMNAMEASSOCNODE_MAGIC 0x4376bafc

struct NumNameAssoc_s{
	rd_rwlock_t lock;
	rd_avl_t avl;
	rd_memctx_t memctx;
};

struct NumNameAssoc_node{
#ifdef NUMNAMEASSOCNODE_MAGIC
	uint64_t magic;
#endif
	uint64_t number;
	char *string;

	/* private */
	rd_avl_node_t avl_node;
};

static int node_cmp(const void *_node1,const void *_node2){
	const struct NumNameAssoc_node *node1 = (const struct NumNameAssoc_node *)_node1;
	const struct NumNameAssoc_node *node2 = (const struct NumNameAssoc_node *)_node2;

#ifdef NUMNAMEASSOCNODE_MAGIC
	assert(node1->magic == NUMNAMEASSOCNODE_MAGIC);
	assert(node2->magic == NUMNAMEASSOCNODE_MAGIC);
#endif

	return node1->number - node2->number;
}

void deleteNumNameAssocTree(NumNameAssocTree *tree){
	pthread_rwlock_destroy(&tree->lock);
	rd_avl_destroy(&tree->avl);
	rd_memctx_freeall(&tree->memctx);
	rd_memctx_destroy(&tree->memctx);
	free(tree);
}


NumNameAssocTree *newNumNameAssocTree(char *errbuf,size_t errbuf_size){
	NumNameAssocTree *ret = calloc(1,sizeof(*ret));
	if(NULL==ret)
		return NULL;

	const int rwlock_init_rc = pthread_rwlock_init(&ret->lock,NULL);
	if(rwlock_init_rc != 0){
		snprintf(errbuf,errbuf_size,"Can't initialize rwlock: %s",strerror(rwlock_init_rc));
		goto error;
	}

	rd_avl_t *avl = rd_avl_init(&ret->avl,node_cmp,0);
	if(NULL==avl){
		snprintf(errbuf,errbuf_size,"Can't initialize avl");
		goto avl_error;
	}

	rd_memctx_init(&ret->memctx,NULL,RD_MEMCTX_F_TRACK); /* No error code provided */

	return ret; /* All ok */

avl_error:
	pthread_rwlock_destroy(&ret->lock);

error:
	free(ret);
	return NULL;
}

// 0-> fail, 1->success
int addNumNameAssocToTree(NumNameAssocTree *tree,uint64_t number,const char *str,char *err,size_t err_size){
	const int wrlock_rc = pthread_rwlock_wrlock(&tree->lock);
	if(wrlock_rc != 0){
		snprintf(err,err_size,"Can't acquire write lock: %s",strerror(wrlock_rc));
		return 0;
	}

	struct NumNameAssoc_node *node = rd_memctx_calloc(&tree->memctx,1,sizeof(*node));
	if(NULL==node){
		snprintf(err,err_size,"Can't allocate node: %s",strerror(wrlock_rc));
		goto error;
	}

#ifdef NUMNAMEASSOCNODE_MAGIC
	node->magic = NUMNAMEASSOCNODE_MAGIC;
#endif
	node->number = number;
	node->string = rd_memctx_strdup(&tree->memctx,str);
	if(node->string == NULL){
		snprintf(err,err_size,"Can't strdup (not enough memory?)");
		goto strdup_error;
	}


	rd_avl_insert(&tree->avl,node,&node->avl_node);
	/* Forget about the previous node. Memory managed by memctx */

	pthread_rwlock_unlock(&tree->lock);
	return 1;

strdup_error:
	/* @TODO: rd_memctx_free(&tree->memctx,node); */
error:
	pthread_rwlock_unlock(&tree->lock);
	return 0;
}

const char *searchNameAssociatedInTree(NumNameAssocTree *tree,uint64_t searched_number,char *err,size_t err_size){
	const struct NumNameAssoc_node dummy_node = {
#ifdef NUMNAMEASSOCNODE_MAGIC
		.magic = NUMNAMEASSOCNODE_MAGIC,
#endif
		.number = searched_number,
	};

	const int wrlock_rc = pthread_rwlock_rdlock(&tree->lock);
	if(wrlock_rc != 0){
		snprintf(err,err_size,"Can't acquire read lock: %s",strerror(wrlock_rc));
		return NULL;
	}

	const struct NumNameAssoc_node *ret_node = RD_AVL_FIND(&tree->avl,&dummy_node);
	pthread_rwlock_unlock(&tree->lock);

	return ret_node?ret_node->string:NULL;
}
