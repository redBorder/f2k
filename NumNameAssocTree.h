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

#pragma once

#include <stdint.h>
#include <string.h>

typedef struct NumNameAssoc_s NumNameAssocTree;

NumNameAssocTree *newNumNameAssocTree();
void deleteNumNameAssocTree(NumNameAssocTree *tree);
int addNumNameAssocToTree(NumNameAssocTree *tree,uint64_t number,const char *str,char *err,size_t err_size);
const char *searchNameAssociatedInTree(NumNameAssocTree *tree,uint64_t searched_number,char *err,size_t err_size);
