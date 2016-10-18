/*
 *  Copyright (C) 2007-11 Luca Deri <deri@ntop.org>
 *
 *  		       http://www.ntop.org/
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifdef HAVE_PF_RING

//#include "pf_ring.h"

/* ************************************* */

static char* sec2dhms(uint32_t input_seconds, char *buf, size_t buf_len) {
  const uint32_t hours_in_day = 24;
  const uint32_t mins_in_hour = 60;
  const uint32_t secs_to_min = 60;
  uint32_t seconds = input_seconds % secs_to_min;
  uint32_t minutes = (input_seconds / secs_to_min) % mins_in_hour;
  uint32_t hours = (input_seconds / (secs_to_min*mins_in_hour)) % hours_in_day;
  uint32_t days = input_seconds / (secs_to_min * mins_in_hour * hours_in_day);

  snprintf(buf, buf_len, "%u:%02u:%02u:%02u", days, hours, minutes, seconds);

  return(buf);
}

/* ****************************************************** */

inline void processPfringPktHdr(struct pfring_pkthdr *hdr,
				char *packet, long thread_id,
				uint32_t packet_hash,
				uint8_t direction /* 1=RX, 0=TX */) {
  if(likely((!readWriteGlobals->shutdownInProgress)
	    && (!readWriteGlobals->stopPacketCapture)))
    decodePacket(thread_id,
		 hdr->extended_hdr.if_index,
		 (struct pcap_pkthdr*)hdr, packet,
		 0 /* sampledPacket */, direction,
		 1, NO_INTERFACE_INDEX, NO_INTERFACE_INDEX,
		 0 /* flow_sender_ip */,
		 packet_hash);
}

/* ****************************************************** */

uint32_t printPfRingStats(uint8_t dump_stats_on_screen) {
  pfring_stat stats;
  static uint32_t last_drop = 0;
  uint32_t diff = 0;

  if(readWriteGlobals->ring == NULL) return(0);

  if((pfring_stats(readWriteGlobals->ring, &stats) >= 0)
     && (stats.recv > 0)) {
    char buf[512];
    static struct timeval start_time = { 0 };
    static pfring_stat prev_stats    = { 0, 0 };
    struct timeval time_now;
    char timeBuffer[128];
    uint64_t ms;
    float f = ((float)stats.drop*100)/(float)stats.recv;

    if(dump_stats_on_screen) {
      snprintf(buf, sizeof(buf),
	       "PF_RING stats (Average): %u/%u [%.1f %%] pkts rcvd/dropped",
	       (unsigned int)stats.recv, (unsigned int)stats.drop, f);

      traceEvent(TRACE_INFO, "%s", buf);

      if(prev_stats.recv > 0) {
	f = ((float)(stats.drop-prev_stats.drop)*100)/(float)(stats.recv-prev_stats.recv);

	snprintf(buf, sizeof(buf),
		 "PF_RING stats (Current): %u/%u [%.1f %%] pkts rcvd/dropped",
		 (unsigned int)(stats.recv-prev_stats.recv),
		 (unsigned int)(stats.drop-prev_stats.drop),
		 f);

	traceEvent(TRACE_INFO, "%s", buf);
      }

      memcpy(&prev_stats, &stats, sizeof(pfring_stat));
    }

    gettimeofday(&time_now, NULL);
    if (start_time.tv_sec == 0)
      start_time.tv_sec = time_now.tv_sec, start_time.tv_usec = time_now.tv_usec;
    ms = to_msec(&time_now) - to_msec(&start_time);

    snprintf(buf, sizeof(buf),
	     "Duration: %s\n"
	     "Packets:  %lu\n"
	     "Dropped:  %lu\n",
	     sec2dhms((ms/1000), timeBuffer, sizeof(timeBuffer)),
	     (long unsigned int) stats.recv,
	     (long unsigned int) stats.drop);

    pfring_set_application_stats(readWriteGlobals->ring, buf);

    diff = stats.drop - last_drop;
    last_drop = stats.drop;
  }

  return(diff);
}

/* ****************************************************** */

static time_t my_time;

void timealarm(int sig) {
  my_time = time(NULL);

  if((!readWriteGlobals->shutdownInProgress)
     && (!readWriteGlobals->stopPacketCapture)) {
    alarm(1);
    signal(SIGALRM, timealarm);
  }
}


/* ****************************************************** */

void* fetchPfRingPackets(void* notUsed) {
  unsigned long thread_id = (unsigned long)notUsed;
  struct pfring_pkthdr hdr;
  uint8_t use_pkt_reference;
  uint8_t *packet;
  int rc, allocate_buffer = 0;
  struct pcap_pkthdr h;
  size_t numPkts;
  int input_index, output_index;

  readWriteGlobals->ring_enabled = 1;

  if((readOnlyGlobals.numProcessThreads > 1)
     || (readOnlyGlobals.num_active_plugins > 0) /* Just to be safe */
     || readOnlyGlobals.enable_l7_protocol_discovery /* It's not reentrant */)
    allocate_buffer = 1;
  else
    allocate_buffer = 0;

  traceEvent(TRACE_NORMAL,
	     "[PF_RING] Reading packets in %d copy mode",
	     allocate_buffer);

#if 0
  setThreadAffinity(thread_id % readOnlyGlobals.numProcessThreads);
#endif

  if(allocate_buffer) {
    packet = malloc(readOnlyGlobals.snaplen+1);

    if(packet == NULL) {
      traceEvent(TRACE_WARNING, "Not enough memory!");
      readWriteGlobals->ring_enabled = 0;
      return(NULL);
    }
  }

  if(readOnlyGlobals.pktSampleRate > 1)
    rc = pfring_set_sampling_rate(readWriteGlobals->ring,
				  readOnlyGlobals.pktSampleRate);

  memset(&hdr, 0, sizeof(hdr));

  if(readOnlyGlobals.quick_mode)
    timealarm(SIGALRM);

  while((!readWriteGlobals->shutdownInProgress)
	&& (!readWriteGlobals->stopPacketCapture)) {

    while(!pfring_is_pkt_available(readWriteGlobals->ring)) {
      usleep(1);
      if(readWriteGlobals->shutdownInProgress
	 || readWriteGlobals->stopPacketCapture)
	break;

      /* In multithreaded probe each fetcher calls idleThreadTask() */
      if(readOnlyGlobals.numProcessThreads == 1)
	idleThreadTask(thread_id, 7); /* Run some idle task */
    }

    if(readWriteGlobals->shutdownInProgress
       || readWriteGlobals->stopPacketCapture)
      break;

    rc = pfring_recv(readWriteGlobals->ring,
		     &packet,
		     allocate_buffer ? readOnlyGlobals.snaplen : 0,
		     &hdr, 1 /* wait_for_incoming_packet */);

    if(rc > 0) {
      if(unlikely((hdr.ts.tv_sec < 0) || (hdr.ts.tv_usec < 0))) {
	traceEvent(TRACE_WARNING, "Invalid timestamp: %lu.%lu", hdr.ts.tv_sec, hdr.ts.tv_usec);
	continue;
      } else if(unlikely((hdr.caplen > hdr.len) || (hdr.len > 16384))) {
	traceEvent(TRACE_WARNING, "Invalid packet length: [len=%lu][caplen=%lu]", hdr.len, hdr.caplen);
	traceEvent(TRACE_WARNING, "Please disable LRO/GRO on your NIC (ethtool -k <NIC>)");
	continue;
      }
    }

    if(rc > 0) {
      ticks when, diff;

      if(unlikely(readOnlyGlobals.tracePerformance)) when = getticks();
      if(hdr.ts.tv_sec == 0) {
	if(readOnlyGlobals.quick_mode)
	  hdr.ts.tv_sec = my_time;
	else
	  gettimeofday((struct timeval*)&hdr.ts, NULL);
      }

      /*
	if(unlikely(readOnlyGlobals.enable_debug))
	traceEvent(TRACE_NORMAL, "Hash: %u", hdr.extended_hdr.pkt_hash);
      */

      //if(readOnlyGlobals.tunnel_mode) hdr.extended_hdr.pkt_hash = 0;

      hdr.extended_hdr.pkt_hash = 0;
      packet[hdr.caplen] = 0;

      processPfringPktHdr(&hdr, packet, thread_id, hdr.extended_hdr.pkt_hash,
			  hdr.extended_hdr.rx_direction /* 1=RX, 0=TX */);

      if(unlikely(readOnlyGlobals.tracePerformance)) {
	diff = getticks() - when;
	if(readOnlyGlobals.numProcessThreads > 1) pthread_rwlock_wrlock(&readOnlyGlobals.ticksLock);
	readOnlyGlobals.allInclusiveTicks += diff;
	if(readOnlyGlobals.numProcessThreads > 1) pthread_rwlock_unlock(&readOnlyGlobals.ticksLock);
      }
    }

    /* In multithreaded probe each fetcher calls idleThreadTask() */
    if(readOnlyGlobals.numProcessThreads == 1)
      idleThreadTask(thread_id, 8);
  }

  if(allocate_buffer)
    free(packet);

  readWriteGlobals->ring_enabled = 0;

  traceEvent(TRACE_NORMAL, "Terminated PF_RING packet processing");

  return(NULL);
}

/* ********************************************* */

pfring* open_ring(char *dev, bool *open_device, u_short thread_id) {
  pfring* the_ring = NULL;
  uint32_t flags = 0;

  /*
    We disable promiscuous mode when using NFlite as we will capture
    just packets sent to use and not those that belong to other
    host (thus that are not interesting for us)
  */
  if(readOnlyGlobals.nfLitePluginEnabled)
    readOnlyGlobals.promisc_mode = 0, readOnlyGlobals.snaplen = 256;

  if(readOnlyGlobals.numProcessThreads > 1) flags |= PF_RING_REENTRANT;
  if(readOnlyGlobals.promisc_mode)          flags |= PF_RING_PROMISC;
  flags |= PF_RING_LONG_HEADER;
  flags |= PF_RING_DNA_SYMMETRIC_RSS;  /* Note that symmetric RSS is ignored by non-DNA drivers */
  flags |= PF_RING_DO_NOT_PARSE;

  if((the_ring = pfring_open(dev, readOnlyGlobals.snaplen, flags)) != NULL) {
    uint32_t version;
    int rc;

    rc = pfring_version(the_ring, &version);

    if((rc == -1) || (version < 0x030502)) {
      traceEvent(TRACE_WARNING,
		 "nProbe requires PF_RING v.3.9.3 or above (you have v.%d.%d.%d)",
		 (version & 0xFFFF0000) >> 16,
		 (version & 0x0000FF00) >> 8,
		 version & 0x000000FF);
      pfring_close(the_ring);
      the_ring = NULL;
    } else {
      char path[256] = { 0 };

      if(thread_id == 0)
	traceEvent(TRACE_INFO, "Successfully open PF_RING v.%d.%d.%d on device %s [snaplen=%u]\n",
		   (version & 0xFFFF0000) >> 16, (version & 0x0000FF00) >> 8,
		   (version & 0x000000FF),
		   readOnlyGlobals.captureDev, readOnlyGlobals.snaplen);
      *open_device = false;
      readOnlyGlobals.datalink = DLT_EN10MB;
      pfring_set_application_name(the_ring, "nProbe");

      if(thread_id == 0)
	traceEvent(TRACE_NORMAL, "Using PF_RING in-kernel accelerated packet parsing");

      pfring_set_application_stats(the_ring, "Statistics not yet computed: please try again...");
      if(pfring_get_appl_stats_file_name(the_ring, path, sizeof(path)) != NULL)
	traceEvent(TRACE_NORMAL, "Dumping traffic statistics on %s", path);

      if(readOnlyGlobals.nfLitePluginEnabled) {
	filtering_rule rule;

	pfring_toggle_filtering_policy(the_ring, 0); /* Default to drop */

	memset(&rule, 0, sizeof(rule));

	rule.rule_id = 1;
	rule.rule_action = execute_action_and_stop_rule_evaluation;
	rule.plugin_action.plugin_id = 13 /* NFLITE_PLUGIN_ID */;
	rule.core_fields.proto       = 17; /* UDP */
	rule.core_fields.dport_low   = readOnlyGlobals.nfLitePluginLowPort;
	rule.core_fields.dport_high  = readOnlyGlobals.nfLitePluginLowPort + readOnlyGlobals.nfLitePluginNumPorts;

	if(pfring_add_filtering_rule(the_ring, &rule) < 0) {
	  traceEvent(TRACE_WARNING, "[NFLite] Unable to add PF_RING NFLite rule: quitting");
	  traceEvent(TRACE_WARNING, "[NFLite] Did you 'modprobe nflite_plugin' ?");
	  exit(-1);
	} else
	  traceEvent(TRACE_INFO, "[NFLite] PF_RING NFLite rule added successfully [UDP ports %d:%d]",
		     readOnlyGlobals.nfLitePluginLowPort,
		     readOnlyGlobals.nfLitePluginLowPort + readOnlyGlobals.nfLitePluginNumPorts);

	pfring_set_direction(the_ring, rx_only_direction);
      }

      if(readOnlyGlobals.netFilter != NULL) {
	errno = 0;
	if((rc = pfring_set_bpf_filter(the_ring, readOnlyGlobals.netFilter)) != 0)
	  traceEvent(TRACE_WARNING, "[PF_RING] Unable to set PF_RING filter '%s' [rc=%d/%s]",
		     readOnlyGlobals.netFilter, rc, strerror(errno));
	else
	  traceEvent(TRACE_INFO, "Successfully set PF_RING filter '%s'",
                     readOnlyGlobals.netFilter);
      }

      if(readOnlyGlobals.cluster_id != -1) {
	rc = pfring_set_cluster(the_ring, readOnlyGlobals.cluster_id, cluster_per_flow_5_tuple);

	if(rc < 0)
	  traceEvent(TRACE_WARNING, "[PF_RING] Unable to set PF_RING cluster %d [rc=%d]",
		     readOnlyGlobals.cluster_id, rc);
	else
	  traceEvent(TRACE_INFO, "Successfully bound to PF_RING cluster %d", readOnlyGlobals.cluster_id );
      }

      if(readOnlyGlobals.enableL7BridgePlugin) {
	pfring_set_poll_watermark(the_ring, 1);
	pfring_set_direction(the_ring, rx_only_direction);
      } else {
	pfring_set_poll_watermark(the_ring, 8);
      }

      pfring_enable_ring(the_ring);
    }
  }

  return(the_ring);
}

#endif /* HAVE_PF_RING */
