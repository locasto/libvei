/***************************************************************************
 *  Virtual Network Event Injector Service (VEI)
 *  Copyright (C) 2010-2011 Michael Locasto <locasto@ucalgary.ca>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful, but
 *  WITHOUT ANY WARRANTY; without even the implied warranty of 
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU 
 *  General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the:
 *	 Free Software Foundation, Inc.
 *	 59 Temple Place, Suite 330 
 *	 Boston, MA  02111-1307  USA
 *
 * $Id$
 **************************************************************************/

#ifndef __VEI_H_
#define __VEI_H_

#include <stdio.h>

#define  LIB_NOT_INITIALIZED        98 //not in the initialized state
#define  LIB_NOT_TRANSCRIBING       99 //not in the transcription state
#define  BAD_BTRACE_FILE           100
#define  BAD_OTRACE_FILE           200
#define  BAD_THREAD_INIT           300
#define  THREAD_KICKOFF_FAILED     400
#define  FAILED_TO_BUFFER          500 //failed to queue injected packets
#define  BAD_EVENT_TYPE            600 //unrecognized event to inject

/** Inject HTTP HEAD request for www.cs.gmu.edu */
#define  EVENT_HTTP_HEAD_CONVERSATION                  7890

/** Inject DNS lookup of objectvideo.com (equiv to `dig objectvideo.com')*/
#define  EVENT_DNS_LOOKUP_CONVERSATION                 7891

/** Inject HTTP request/response for DHS_DailyWord twitter profile */
#define  EVENT_TWITTER_DHS_DW_FETCH_CONVERSATION       7892

/** Inject twitter post to http://twitter.com/#!/libvei */
#define  EVENT_TWITTER_LIBVEI_POST_CONVERSATION        7893

/** simulate an nmap syn scan and OS guest of a local host*/
#define  EVENT_NMAP_SYN_SCAN                           7894

/** inject SMTP (port 25) packets */
#define  EVENT_SMTP_CONVERSATION                       7895

/** inject HTTP/RSS fetch packets */
#define  EVENT_RSSFEED_CONVERSATION                    7896

/** inject SIP setup handshake for VoIP call */
#define  EVENT_SIP_SETUP_CONVERSATION                  7897

/** inject HTTP POST of a JPG */
#define  EVENT_POST_PICTURE                            7898

/** inject an SSH connection */
#define  EVENT_SSH_SESSION                             7899

/** inject an SSL connection */
#define  EVENT_SSL_SESSION                             7900

/** inject an ICMP traceroute to ober.cs.columbia.edu */
#define  EVENT_TRACEROUTE_ICMP                         7901

/** inject an single ICMP echo reply to www.cpsc.ucalgary.ca */
#define  EVENT_PING_ICMP                               7902

//////////////////////////////////////////////////////////////////

/**
 * Clients should use these constants with the `inject_event()'
 * function, e.g., 
 * 
 *  int result = inject_event(VEI_SMTP);
 *
 */
typedef enum _vei_event_type
{
  VEI_HTTP_HEAD=EVENT_HTTP_HEAD_CONVERSATION,
  VEI_DNS_LOOKUP=EVENT_DNS_LOOKUP_CONVERSATION,
  VEI_TWITTER_DHS=EVENT_TWITTER_DHS_DW_FETCH_CONVERSATION,
  VEI_TWITTER_LIBVEIPOST=EVENT_TWITTER_LIBVEI_POST_CONVERSATION,
  VEI_NMAP=EVENT_NMAP_SYN_SCAN,
  VEI_SMTP=EVENT_SMTP_CONVERSATION,
  VEI_RSS_FETCH=EVENT_RSSFEED_CONVERSATION,
  VEI_SIP=EVENT_SIP_SETUP_CONVERSATION,
  VEI_POST_JPG=EVENT_POST_PICTURE,
  VEI_SSH_SESSION=EVENT_SSH_SESSION,
  VEI_SSL_SESSION=EVENT_SSL_SESSION,
  VEI_TRACEROUTE=EVENT_TRACEROUTE_ICMP,
  VEI_PING=EVENT_PING_ICMP
} VEI_EVENT_TYPE;

/**
 * Initialize the library by telling it to write packets to the named
 * output_trace file. The background_trace file must exist and should
 * contain libpcap/tcpdump formatted data. Internally, the library
 * will use a separate thread to replay packets from the
 * background_trace file at the rate they were previously recorded.
 * 
 * Clients of the library will then use the `inject_event' function
 * call. The library will send the packets corresponding to the events
 * listed above onto the target interface. Internally, the
 * `inject_event' function will coordinate via pthread to serialize
 * writes to the output_trace file.
 *
 * The output_trace file can be consumed by a network anomaly sensor.
 * 
 * This function MUST be called. If not, the library will not work
 * (i.e., subsequent calls to `inject_event' will return an error
 * code).
 * 
 *
 *
 * This function returns the following error codes:
 *  -BAD_BTRACE_FILE failed to open background_trace
 *  -BAD_OTRACE_FILE failed to open output_trace
 *  -BAD_THREAD_INIT failed to set up threading properly
 *
 *
 * On success, this function returns 0. 
 */
int
initialize_vei_library(FILE* background_trace, //pcap file to replay
		       FILE* output_trace);    //"merged" output file


/**
 * Trigger the replay thread in the library to start reading
 * packets from background_trace and writing them to output_trace
 * in "real time" (as defined by the intervals in background_trace).
 * 
 * This function exists so that initialization can happen independently
 * from playback/replay. If `initialize_vei_library' did not previously
 * return 0, this function will have no effect.
 *
 *
 * An important architectural note related to initialization and the
 * start of transcription, and how these activities relate to inject_event:
 * `start_vei_transcription' will not "return" in a timely manner; it
 * basically kicks off pcap's pcap_loop() function, which consumes
 * packets from the background file and asks VEI to replay them to the
 * output file.
 * 
 * For this reason, the thread calling `start_vei_transcription' should
 * NOT be the thread you intend to use to call `inject_event', since 
 * this thread would only get around to calling `inject_event' after
 * all background trace packets have already been "played" to the output.
 * 
 * Step 1: Thread1: call `initialize_vei_library'
 * Step 2: create Thread2 for issuing calls to `inject_event'
 * Step 3: Thread1: call `start_vei_transcription'
 *
 * VEI will internally buffer any packets that arrive via
 * `inject_packet' before `start_vei_transcription' has started.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 * 
 */
int
start_vei_transcription(void);

/**
 * Inject the named event. See the enum VEI_EVENT_TYPE
 * for the list of possible events.
 *
 * This function will not work unless start_vei_transcription() has
 * already been called (and by implication, initialize_vei_library
 * must also have been called).
 * 
 * On success, returns the number of packets injected.
 * Returns -1 on failure.
 *
 *
 */
int
inject_event(VEI_EVENT_TYPE event);

/**
 * Called when library should be cleaned up.
 * See implementation file for semantics.
 */
void
vei_finish(void);

/**
 * Placeholder. Asynchronous call to apply a filter that will
 * modify the packets from background_trace in some standard
 * way. 
 */
//int apply_filter(VEI_FILTER_TYPE filter);

#endif
