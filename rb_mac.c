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

#include "rb_mac.h"
#include <string.h>

static int ishexchar(const char x) {
	return ('0' <= x && x <= '9') || ('a' <= x && x <= 'f') || ('A' <= x && x <= 'F');
}

static uint64_t hexchar(const char x) {
	return ('0' <= x && x <= '9') ? x - '0' :
	       ('a' <= x && x <= 'f') ? x - 'a' + 10 :
	       x - 'A' +10;
}

static int validmac(const char *a) {
	return
		ishexchar(a[ 0]) && ishexchar(a[ 1]) &&
		ishexchar(a[ 3]) && ishexchar(a[ 4]) &&
		ishexchar(a[ 6]) && ishexchar(a[ 7]) &&
		ishexchar(a[ 9]) && ishexchar(a[10]) &&
		ishexchar(a[12]) && ishexchar(a[13]) &&
		ishexchar(a[15]) && ishexchar(a[16]) &&
		a[2]  == ':' && a[5] == ':' && a[8] == ':' &&
		a[11] == ':' && a[14] == ':';
}

uint64_t parse_mac(const char *mac) {
	if(strlen(mac) != strlen("00:00:00:00:00:00"))
		return 0xFFFFFFFFFFFFFFFFL;

	if(!validmac(mac))
		return 0xFFFFFFFFFFFFFFFFL;

	return 0L +
		(hexchar(mac[16])<<0)+
		(hexchar(mac[15])<<4)+
		(hexchar(mac[13])<<8)+
		(hexchar(mac[12])<<12)+
		(hexchar(mac[10])<<16)+
		(hexchar(mac[ 9])<<20)+
		(hexchar(mac[ 7])<<24)+
		(hexchar(mac[ 6])<<28)+
		(hexchar(mac[ 4])<<32)+
		(hexchar(mac[ 3])<<36)+
		(hexchar(mac[ 1])<<40)+
		(hexchar(mac[ 0])<<44);
}
