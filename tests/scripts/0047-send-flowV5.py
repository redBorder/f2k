# Copyright (C) 2016 Eneo Tecnologia S.L.
# Authors:
# Diego Fernández Barrera <dieferbar@redborder.com>
# Eugenio Perez <eupm90@gmail.com>
# Ana Rey <anarey@redborder.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import datetime
import netflowV5_data as nfv5

from scapy.all import IP, UDP

IP_DST = "localhost"
PORT_SRC = int(2056)
PORT_DST = int(2055)

nf5_pkt = nfv5.NetflowHeaderV5(
    sysUptime=0x3e80,
    unixSecs=(datetime.datetime.utcnow() -
              datetime.datetime(1970, 1, 1)).seconds,
    unixNanoSeconds=0x04bdb6f0,
    flowSequence=48,
    engineType=0,
    engineID=0,
    samplingInterval=0,
    pduList=nfv5.records,
)

data = IP(dst=IP_DST) / UDP(dport=PORT_DST, sport=PORT_SRC) / nf5_pkt
