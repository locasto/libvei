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

#include <stdlib.h>
#include <stdio.h>
#include <pcap.h> //for capture/reading "background" traffic
#include <dnet.h> //for packet formulation
#include <pthread.h> //for coordinating over writes to the output file
#include <string.h>
#include <time.h> //required for timestamp manipulation from pcap file
#include <unistd.h>
#include <assert.h>
#include <sched.h> //sched_yield()

#include "vei.h"

/**
 * The VEI API and implementation provide *programmable* functionality
 * not present in things like mergecap, pcapmerge, editcap, and
 * tcpreplay.
 *
 * Two key issues occur:
 *  - replaying to a virtual interface (need OS kernel module for
 *    handling these types of "devices")
 *  - merging a la mergecap fails b/c mergecap relies on
 *    chronological order
 * 
 * What we want is something that reads and replays a background
 * packet capture *at speed* (i.e., in realtime at the rate it was
 * captured) and periodically injects new packets into the output
 * driven by some scripted or interactive environment (such as
 * ObjectVideo's VVT or a video game engine environment).
 */

/***************************************************************/

/** 
 * Define default/max length for buffering packets. Essentially means
 * that VEI is willing to maintain a list of 100000 pointers to actual
 * packets (actually VEI_PACKET_ENTRY structures).
 */
#define VEI_PACKET_BUF_LENGTH       100000

/** parameter controlling "progress bar" output when replaying packets */
#define PACKET_PROGRESS_INTERVAL     200

#define VEI_PING_SIZE                 46
#define VEI_PING_PACKETS               1

//need about 2666 packets to send 4000000 bytes over packets of 1.5KB each
//this should be a nicely anomalous TCP flow
#define VEI_JPEG_PACKETS            7165 //VEI_POST_JPG (from PCAP trace)

//EVENT_POST_PICTURE
// read in ./resources/santorini-deck.JPG
//static char* e_post_picture = NULL; //need to create dynamically
//this set of packets (multiple VEI_PACKET_ENTRY objects) will look
//like:
// [Ether][IP][TCP dst 80][HTTP Header][HTTP Body]
// where HTTP Body will be split over multiple IP packets
// because the POST upload is 4.1 MB and typical fragmentation
// is ~1500 bytes for max packet size

//EVENT_PING_ICMP
//need to determine if stored in network or host order. Definitely looks
//like not host order (i.e., "DEADBEEF" at the end is readable, rather than being EDDA EBFE, as it would be stored in IA-32 memory)
const char e_ping_icmp[] = "\x00\x50\x56\xe7\xaa\xf8\x00\x0c"
                           "\x29\xe3\x2d\x82\x08\x00\x45\x00"
                           "\x00\x20\x02\x50\x00\x00\xff\x7c"
                           "\x47\xb9\x7f\x15\x61\x77\x80\x3b"
                           "\x10\x91\x00\x00\x00\x00\x44\x45"
                           "\x41\x44\x42\x45\x45\x46";

static int m_initialized = 0; //FALSE
static int m_transcribing = 0; //FALSE
static int m_first_packet = 1; //TRUE

static long configured_for_pthreads = -1;

static pcap_t* btrace_handle = NULL;        //background trace
static pcap_t* o_handle = NULL;             //output trace
static pcap_dumper_t* otrace_handle = NULL; //output trace dump() handle
static pcap_t* sctrace_handle = NULL;       //injection src trace handle

static char m_errbuf[PCAP_ERRBUF_SIZE];

typedef struct _vei_packet_entry
{
  VEI_EVENT_TYPE ve_type;
  u_char* packet;
  //struct pcap_pkthdr contains:
  //struct timeval ts; //get from m_last_time (from replaying packets timeline)
  //bpf_u_int32 caplen; /* length of portion present */
  //bpf_u_int32 len; /* length this packet (off wire) */
  struct pcap_pkthdr header;
} VEI_PACKET_ENTRY;

//static u_char* m_packet_buffer[VEI_PACKET_BUF_LENGTH];
static VEI_PACKET_ENTRY* m_packet_buffer[VEI_PACKET_BUF_LENGTH];
/** number of items currently in the array (position of highest entry) */
static long int m_pbuffer_length = 0;

static FILE* btracefile = NULL;
static FILE* otracefile = NULL;

/** timestamp of previous background packet. important. */
static struct timeval m_last_time;

/** Some summary stats */

static long long m_packets_copied = 0;
static long long m_total_packets_injected = 0;
static long long m_total_seconds_slept = 0;
static long long m_longest_sleep_interval = 0;
static long long m_num_scripted_packets_injected = 0;

/** inject new packets by reading m_packet_buffer and sending to pcap_dump() */
static pthread_t injecter; 

/** support for internal thread_sleep routine (since non exists in pthread) */
pthread_mutex_t fake_mutex = PTHREAD_MUTEX_INITIALIZER;
/** support for internal pthread_sleep rtn */
pthread_cond_t fake_cond = PTHREAD_COND_INITIALIZER;

/**
 * replayer thread (i.e., packet handler callback function) must own
 * this before emitting a packet (writing to ofile). Does not need to
 * own this before reading from btracefile, since libpcap will use
 * pcap_loop() to read btracefile
 *
 * injecter thread must own this before injecting a packet to
 * otracefile
 */
static pthread_mutex_t ofile_lock = PTHREAD_MUTEX_INITIALIZER;

/**
 * `inject_event' calling thread must own this (transparently)
 * before asking for bytes to be put into the buffer
 *
 * injecter thread must own this before reading from injection buffer
 * and removing successfully injected packets
 *
 * replayer thread has nothing to do with this lock
 */
static pthread_mutex_t buffer_lock = PTHREAD_MUTEX_INITIALIZER;

/** The injecter thread worker routine. */
void * empty_buffer(void*);

/** The callback for the replayer "thread" */
void   bg_packet_handler(u_char*,
			 const struct pcap_pkthdr*,
			 const u_char*);

/** The callback for injecting pre-recorded conversations */
void   inj_packet_handler(u_char *args,
			  const struct pcap_pkthdr *header,
			  const u_char *packet);

/** 
 * Insert bytes into a slot in m_packet_buffer, if possible.
 * Also increments m_pbuffer_length by 1. Recall that all we
 * are inserting here is a single pointer into a list of
 * pointers, not actual data bytes.
 * 
 * Returns -1 if insert failed, 0 on success.
 */
static int 
pbuf_insert(VEI_PACKET_ENTRY* entry)
{
  if(m_pbuffer_length<VEI_PACKET_BUF_LENGTH)
  {
    //assume the supplied data structure is CORRECT...trust relationship
    m_packet_buffer[m_pbuffer_length] = entry;
    m_pbuffer_length++; //possible integer overflow or off by one error
    return 0;
  }else{
    return -1;
  }
}

/**
 * Inject the supplied packets into the internal buffer
 * by creating VEI_PACKET_ENTRY object and inserting
 * (with proper locks held)
 *
 * NB: the resulting traffic stream may or may not be
 * strictly "valid", but serves to illustrate our
 * main idea.
 */
void
inj_packet_handler(u_char *args, //use this to report num_packets_injected
		   const struct pcap_pkthdr *header,
		   const u_char *packet)
{
  u_char* bytes = NULL;
  VEI_PACKET_ENTRY* v = NULL;
  int iresult = 0;   //result of pbuf_insert() call; 0==success, -1==failure

  v = (VEI_PACKET_ENTRY*)calloc(1, 
				sizeof(VEI_PACKET_ENTRY));
  bytes = (u_char*)calloc((header->caplen), //bytes
			  sizeof(u_char));
  if(NULL==bytes || NULL==v)
  {
    free(bytes);
    free(v);
    bytes = NULL;
    v = NULL;
  }else{
    memcpy(bytes, packet, (header->caplen));
    v->ve_type = VEI_POST_JPG;
    //set sizes based on ve_type
    v->header.caplen = header->caplen; //full capture, caplen==len
    v->header.len = header->len; //full capture
    v->header.ts.tv_sec = 0; //will be overwritten by injecter thread
    v->header.ts.tv_usec = 0; //will be overwritten by injecter thread
    v->packet = bytes;
    iresult = pbuf_insert(v);
    if(0==iresult)
    {
      m_num_scripted_packets_injected++;
    }else{
      //
    }
  }
  return;
}

/**
 * Ask libpcap to open_offline and replay JPEG capture file;
 * the packet handler callback function for this will 
 * place the VEI_PACKET_ENTRY objects into the buffer 
 *
 * Be careful about potential deadlock here, as we are
 * essentially asking libpcap to spawn another thread to
 * write to the m_packet_buffer data structure (via
 * asynchronous calls to inj_packet_handler()) WITH the
 * locks on that already held by the caller of this
 * function, inject_event...we solved this by moving the
 * locking statements within inject_event to wrap only
 * certain of the switch..case cases...and in this case,
 * by NOT acquiring that mutex. Instead, inj_packet_handler
 * must acquire it when servicing an asynchronous event
 * from libpcap.
 */
static long long
replay_jpeg_capture()
{
  int rval = 0;

  memset(m_errbuf, 0, PCAP_ERRBUF_SIZE);  
  sctrace_handle = pcap_open_offline("../resources/JPEG.packets.cap",
				     m_errbuf);
  if(NULL==sctrace_handle)
  {
    fprintf(stderr,
	    "[vei]: problem opening scripted trace file: %s\n",
	    m_errbuf);
    return -BAD_BTRACE_FILE;
  }

  //won't return until playback is complete, and we
  //already have the appropriate locks from our parent caller...
  //so no need to reacquire locks in inj_packet_handler
  rval = pcap_loop(sctrace_handle,     //pcap handle 
		   -1,                 //#pkts to loop, <0 means "until error"
		   inj_packet_handler, //callback function pointer
		   NULL);              //args to pass to callback

  if(-1==rval)
  {
    pcap_perror(sctrace_handle, "[vei] error buffering scripted trace");
  }else if(-2==rval){
    fprintf(stderr,
	    "[vei] a call to pcap_breakloop() occurred\n");
  }else if(0==rval){
    fprintf(stdout,
	    "[vei] no more packets to snarf from scripted trace\n");
  }else{
    fprintf(stderr,
	    "[vei] pcap_loop() returned value %d\n",
	    rval);
  }

  fprintf(stdout,
	  "[vei] buffered %lld scripted packets\n",
	  m_num_scripted_packets_injected);

  if(NULL!=sctrace_handle)
  {
    pcap_close(sctrace_handle);
    //fclose(sctracefile); //DON'T do this. potential double-free problem.
    fprintf(stdout,
	    "[vei] pcap closed sctrace_handle\n");
    fflush(stdout);
  }

  return m_num_scripted_packets_injected;
}

/**
 * A way to get individual threads to sleep via libpthread rather than
 * asking the whole process to sleep(3) or sched_yield(2)
 *
 * From:
 * http://somethingswhichidintknow.blogspot.com/2009/09/sleep-in-pthread.html 
 *
 * The unit of the `time' argument is seconds, as time_t indicates
 */
static void 
vei_pthread_sleep(time_t s_time)
{
  struct timespec wait_time;
  struct timeval now;
  int rt;

  gettimeofday(&now, NULL);

  wait_time.tv_sec = now.tv_sec + s_time;
  wait_time.tv_nsec = now.tv_usec*1000; //XXX check this

  pthread_mutex_lock(&fake_mutex);
  rt = pthread_cond_timedwait(&fake_cond, &fake_mutex, &wait_time);
  pthread_mutex_unlock(&fake_mutex);
  return;
}

/** 
 * The pcap callback for emitting a background packet to the output
 * trace file needs to play nicely with the injector. We can dispense
 * with a separate `replayer' thread for now.
 *
 * The basic strategy here is to sleep every second or so when we
 * detect that all the packets within that second-granularity
 * timestamp have been played. In cases where long stretches of time
 * (e.g., 45 seconds) elapse, libpcap is still transmitting packets
 * as fast as it can read them from the file, so we will detect the
 * 45 second difference and sleep for 45 seconds.
 */
void
bg_packet_handler(u_char *args,
		  const struct pcap_pkthdr *header,
		  const u_char *packet)
{
  time_t diff_seconds = 0;
  
  //check for initialization and transcription
  if(1!=m_initialized)
    return;
  if(1!=m_transcribing)
    return;

  /**
   * struct timeval =
   * long int tv_sec //whole seconds of elapsed time 1 Jan 1970
   * long int tv_usec //microseconds from tv_sec to next tv_sec 
   */
  /*
  fprintf(stdout,
	  "timestamp [%ld].[%ld]\n",
	  header->ts.tv_sec,
	  header->ts.tv_usec);
  */

  //if first packet (so we don't have a nonsensical subtraction
  //and resulting long sleep on the first packet comparing with the
  //non-existent 0th packet)
  if(1==m_first_packet)
  {
    m_first_packet = 0;
  }else{
    //extract timestamp from 'header'
    //subtract current timestamp from m_last_time
    diff_seconds = header->ts.tv_sec - m_last_time.tv_sec;
    /*
    fprintf(stdout,
	    "%d seconds elapsed since last packet\n",
	    ((int)diff_seconds));
    */
    if(diff_seconds > 0)
    {
      //is sleep a spinlock? hot CPU and fans...
      sleep(diff_seconds);
      m_total_seconds_slept+=diff_seconds;
      if(diff_seconds > m_longest_sleep_interval)
      {
	m_longest_sleep_interval = diff_seconds;
      }
    }
  }

  pthread_mutex_lock(&ofile_lock);
  //write packet to otracefile via pcap
  //note that "user" args (first param) must be the
  //pcap_dumper_t handle, not "NULL" as in a user-supplied
  //packet handler (e.g., bg_packet_handler)
  pcap_dump(((u_char*)otrace_handle),
	    header,
	    packet);
  pthread_mutex_unlock(&ofile_lock);
  m_packets_copied++;
  if(0==(m_packets_copied % PACKET_PROGRESS_INTERVAL))
  {
    fprintf(stdout,
	    "|");
    fflush(stdout);
  }
  m_last_time.tv_sec = header->ts.tv_sec;
  m_last_time.tv_usec = header->ts.tv_usec;
  
  return;
}


/**
 * Initialize the library by telling it to write packets to the named
 * output_trace file. The background_trace file must exist and should
 * contain libpcap/tcpdump formatted data. Internally, the library
 * will use a separate thread to replay packets from the
 * background_trace file at the rate they were previously recorded.
 *
 * This function assumes that the client has opened both files
 * properly. It will use
 * 
 *   pcap_t *pcap_fopen_offline(FILE *fp, char *errbuf)
 *
 * internally to actually ask libpcap to read the opened file.
 *
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
 * This function returns the following error codes:
 *  -BAD_BTRACE_FILE failed to open background_trace
 *  -BAD_OTRACE_FILE failed to open output_trace
 *  -BAD_THREAD_INIT failed to set up threading properly
 *
 *
 * On success, this function returns 0. NB that this function will not
 * return until libpcap has replayed all packets in the background
 * trace or if libpcap has encountered an error reading the background
 * trace file.
 */
int
initialize_vei_library(FILE* background_trace, //pcap file to replay
		       FILE* output_trace)     //"merged" output file
{
  if(NULL==background_trace)
  {
    return -BAD_BTRACE_FILE;
  }else if(NULL==output_trace){
    return -BAD_OTRACE_FILE;
  }else{
    btracefile = background_trace;
    otracefile = output_trace;
  }

  memset(m_errbuf, 0, PCAP_ERRBUF_SIZE);
  
  //pcap_t *pcap_fopen_offline(FILE *fp, char *errbuf)
  btrace_handle = pcap_fopen_offline(btracefile,
				     m_errbuf);
  if(NULL==btrace_handle)
  {
    fprintf(stderr,
	    "initialize_vei_library(): problem opening background file: %s\n",
	    m_errbuf);
    return -BAD_BTRACE_FILE;
  }

  o_handle = pcap_open_dead(DLT_EN10MB, //`linktype'; see pcap_datalink()
			    65535);     //`snaplen'
  if(NULL==o_handle)
  {
    fprintf(stderr,
	    "initialize_vei_library(): problem getting `dead' handle: %s\n",
	    m_errbuf);
    return -BAD_OTRACE_FILE;
  }

  otrace_handle = pcap_dump_fopen(o_handle,
				  otracefile);
  if(NULL==otrace_handle)
  {
    fprintf(stderr,
	    "initialize_vei_library(): problem opening dump file: \n");
    return -BAD_OTRACE_FILE;
  }    

  /** A compile-time test */
#ifndef _POSIX_THREADS
   fprintf(stderr,
           "POSIX threads are not available\n");
   fflush(stderr);
   exit(-2);
#endif

   //runtime test for pthreads
  configured_for_pthreads = sysconf(_SC_THREADS);
  if(-1==configured_for_pthreads)
  {
    fprintf(stderr,
	    "libpthread unavailable, clients should exit(2)...\n");
    return -BAD_THREAD_INIT;
  }

  fprintf(stdout,
	  "[vei] initialization finished\n");
  m_initialized = 1;
  return 0;
}

/**
 * Trigger the replay thread in the library to start reading
 * packets from background_trace and writing them to output_trace
 * in "real time" (as defined by the intervals in background_trace).
 * 
 * This function exists so that initialization can happen independently
 * from playback/replay. If `initialize_vei_library' did not previously
 * return 0, this function will have no effect.
 *
 * Returns 0 on success.
 * Returns -THREAD_KICKOFF_FAILED for general errors here
 * Returns -LIB_NOT_INITIALIZED if initialize_vei_library did not successfully 
 *  execute
 *
 */
int
start_vei_transcription()
{
  int err = 0;
  int rval = 0;

  if(1!=m_initialized)
  {
    return -LIB_NOT_INITIALIZED;
  }

  err = pthread_create(&injecter,
		       NULL,
		       empty_buffer,
		       NULL);
  if(0!=err)
  {
    fprintf(stderr,
	    "[vei] failed to create internal injecter service thread: %s\n",
	    strerror(err));
    return -BAD_THREAD_INIT;
  }else{
    fprintf(stdout,
	    "[vei] created internal injecter service thread\n");
    fflush(stdout);
  }

  //fprintf(stdout,
  //	  "[vei] about to set m_transcribing flag...\n");
  //fflush(stdout);

  m_transcribing = 1;

  //fprintf(stdout,
  //  "[vei] about to call pcap_loop()...\n");
  //fflush(stdout);

  assert(NULL!=btrace_handle);

  fprintf(stdout, 
	  "[vei] replay packet progress: |");
  fflush(stdout);
  //returns only if pcap_loop() times out or fails to grab more packets
  rval = pcap_loop(btrace_handle,     //pcap handle 
		   -1,                //#pkts to loop, <0 means "until error"
		   bg_packet_handler, //callback function pointer
		   NULL);             //args to pass to callback
  fprintf(stdout, "\n"); //finished progress bar, print newline

  if(-1==rval)
  {
    pcap_perror(btrace_handle, "[vei] error transcribing");
    return rval;
  }else if(-2==rval){
    fprintf(stderr,
	    "[vei] a call to pcap_breakloop() occurred\n");
    return rval;
  }else if(0==rval){
    fprintf(stdout,
	    "[vei] no more packets to snarf\n");
    fprintf(stdout,
	    "[vei] copied %lld packets\n",
	    m_packets_copied);
    fprintf(stdout,
	    "[vei] injected %lld packets\n",
	    m_total_packets_injected);
    fprintf(stdout,
	    "[vei] slept for %lld (s); longest sleep interval = %lld (s)\n",
	    m_total_seconds_slept,
	    m_longest_sleep_interval);
    return 0;
  }else{
    fprintf(stderr,
	    "[vei] pcap_loop() returned value %d\n",
	    rval);
    return rval;
  }
  return 0;
}

/**
 * Inject the named event by telling the library to insert the
 * corresponding entry into an internal buffer. See the enum
 * VEI_EVENT_TYPE in `vei.h' for the list of possible precooked canned
 * events. An internal thread then writes this buffer to the outfile
 * when it has time.
 * 
 * On success, returns the number of packets injected.  
 * 
 * Internally, this function simply inserts the requisite set of
 * bytes (i.e., pre-formed packets) into an internal buffer that
 * is occasionally read by the thread `injecter'
 * 
 * Place packets corresponding to named event on an internal buffer.
 * The internal buffer is a set of pointers to structures that contain
 * these fields:
 *  VEI_EVENT_TYPE ve_type;
 *  u_char* packet;
 *  struct pcap_pkthdr header;
 *
 * While internally, placing packets on the queue/buffer is
 * thread-safe, this routine itself IS NOT thread-safe. If multiple
 * threads call this function, they will step on each other.
 * NB: if multiple actor threads exist (e.g., in a game-style environment),
 * they should use thread coordination mechanisms amongst themselves
 * for the right to call this function, or we should make this function
 * re-entrant in a future release.
 *
 */
int
inject_event(VEI_EVENT_TYPE event)
{
  long long num_packets_injected = 0; //this invocation
  u_char* bytes = NULL;
  VEI_PACKET_ENTRY* v = NULL;
  int iresult = 0;   //result of pbuf_insert() call; 0==success, -1==failure

  if(1!=m_initialized)
    return -LIB_NOT_INITIALIZED;

  /*
    this code should NOT be here. its absence is NOT a bug.
    the `empty_buffer' routine will use a pthread method for
    telling the injection thread to sleep for a couple of seconds
    if we aren't transcribing. In the meanwhile, it is OK to
    buffer packets (after all, that is what a buffer is for)
  if(1!=m_transcribing)
    return -LIB_NOT_TRANSCRIBING;
  */

  /** 
   * Yes, a big critical section, but necessary to avoid
   * complicated control flow (e.g., error handling) and
   * conflicts on shared resources (like bytes, iresult, etc.).
   */
  pthread_mutex_lock(&buffer_lock);

  switch(event)
  {
  case VEI_HTTP_HEAD:
    break;
  case VEI_DNS_LOOKUP:
    break;
  case VEI_TWITTER_DHS:
    break;
  case VEI_TWITTER_LIBVEIPOST:
    break;
  case VEI_NMAP:
    break;
  case VEI_SMTP:
    break;
  case VEI_RSS_FETCH:
    break;
  case VEI_SIP:
    break;
  case VEI_POST_JPG:
    fprintf(stdout,
	    "[vei] VEI_POST_JPG\n");
    num_packets_injected = replay_jpeg_capture();
    m_num_scripted_packets_injected = 0;
    break;
  case VEI_SSH_SESSION:
    break;
  case VEI_SSL_SESSION:
    break;
  case VEI_TRACEROUTE:
    break;
  case VEI_PING:
    fprintf(stdout,
	    "[vei] VEI_PING\n");
    v = (VEI_PACKET_ENTRY*)calloc(1, 
				  sizeof(VEI_PACKET_ENTRY));
    bytes = (u_char*)calloc(VEI_PING_SIZE, //in bytes
			    sizeof(u_char));
    if(NULL==bytes || NULL==v)
    {
      num_packets_injected = -FAILED_TO_BUFFER;
      free(bytes);
      free(v);
      bytes = NULL;
      v = NULL;
    }else{
      memcpy(bytes, e_ping_icmp, VEI_PING_SIZE);
      v->ve_type = VEI_PING;
      //set sizes based on ve_type
      v->header.caplen = VEI_PING_SIZE; //full capture, caplen==len
      v->header.len = VEI_PING_SIZE; //full capture
      v->header.ts.tv_sec = 0; //will be overwritten by injecter thread
      v->header.ts.tv_usec = 0; //will be overwritten by injecter thread
      v->packet = bytes;
      iresult = pbuf_insert(v);
      if(0==iresult)
      {
	num_packets_injected = VEI_PING_PACKETS;
      }else{
	num_packets_injected = -FAILED_TO_BUFFER;
      }
    }
    break;
  default:
    return -BAD_EVENT_TYPE;
  };

  if(num_packets_injected>0)
  {
    //only add a "positive" number of packets b/c
    //`num_packets_injected' might hold -FAILED_TO_BUFFER
    m_total_packets_injected+=num_packets_injected;
  }else{
    //dead code, but makes error case of -FAILED_TO_BUFFER clearer in source
    m_total_packets_injected+=0;
  }

  pthread_mutex_unlock(&buffer_lock);

  return num_packets_injected;
}

/**
 * Called when library should be cleaned up.
 * See implementation file for semantics.
 *
 * It is safe to enter this function from anywhere.
 * It doesn't care if what combination of m_transcribing and
 * m_initialized we have.
 */
void
vei_finish()
{
  m_transcribing = 0;
  m_initialized = 0;

  fprintf(stdout,
	  "[vei] entering vei_finish()\n");
  fprintf(stdout,
	  "[vei] m_packet_buffer has %ld entries\n",
	  m_pbuffer_length);
  fflush(stdout);

  //pcap_stats() not supported on savefiles
  //stop threads
  
  if(NULL!=otrace_handle)
  {
    pcap_dump_flush(otrace_handle);
    pcap_dump_close(otrace_handle);
  //having this call here causes
  //*** glibc detected *** ./nech0: double free or corruption (!prev): 0x083b0170 ***
  //fclose(otracefile);
  //pcap_close(o_handle);
    otrace_handle = NULL;
    fprintf(stdout,
	    "[vei] pcap dump flushed and closed otrace_handle\n");
    fflush(stdout);
    otracefile = NULL;
  }

  if(NULL!=btrace_handle)
  {
    pcap_close(btrace_handle);
    //fclose(btracefile); //DON'T do this. potential double-free problem.
    btracefile = NULL;
    fprintf(stdout,
	    "[vei] pcap closed btrace_handle\n");
    fflush(stdout);
  }

  return;
}

////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////

/**
 * Injecter thread body.
 *
 * Should use pcap_inject() for outputting to an iface
 *   -  int pcap_inject(pcap_t *p, const void *buf, size_t size)
 *   -  int pcap_sendpacket(pcap_t *p, const u_char *buf, int size)
 * Should use pcap_dump() for outputting to a capture file
 */
void *
empty_buffer(void *arg)
{
  pthread_t myself;
  int num_slots = 0; // entries in m_packet_buffer to read and inject
  int i = 0; // iterator, empty m_packet_buffer from front (0) to num_slots
  VEI_PACKET_ENTRY* v = NULL;
  struct pcap_pkthdr* header = NULL;
  u_char* packet = NULL;

  myself = pthread_self();

  //should only get executed once.
  fprintf(stdout,
	  "[vei.injecter] thread[@0x%x] reporting for duty\n",
	  ((int)myself));

  //thread invoking start_vei_transcription() will call pthread_join()
  // (inside of start_vei_transcription() body)
  for(;;)
  {
    if(1!=m_initialized)
    {
      vei_pthread_sleep(2);
      //sched_yield();
      continue; //skip loop iteration
    }

    if(1!=m_transcribing)
    {
      vei_pthread_sleep(2);
      //sched_yield();
      continue; //skip loop iteration
    }

    pthread_mutex_lock(&buffer_lock);
    //read m_packet_buffer, empty 0 to m_pbuffer_length
    assert(m_pbuffer_length < VEI_PACKET_BUF_LENGTH);
    num_slots = m_pbuffer_length;
    assert(0 <= num_slots);
    i = 0;
    if(0!=num_slots)
    {
      fprintf(stdout,
	      "\n[vei.injecter] injecting %d packets in position %lld\n",
	      num_slots,
	      m_packets_copied);
      fflush(stdout);
    }
    for(i=0;i<num_slots;i++)
    {
      v = m_packet_buffer[i];
      header = &(v->header);
      packet = v->packet;
      //luckily, we are already saving the "now" in m_last_time :)
      v->header.ts.tv_sec = m_last_time.tv_sec;
      v->header.ts.tv_usec = m_last_time.tv_usec;
      pthread_mutex_lock(&ofile_lock);
      //write packets to otracefile
      pcap_dump(((u_char*)otrace_handle),
		header,
		packet);
      pthread_mutex_unlock(&ofile_lock);
      free(v->packet);
      v->packet=NULL;
      free(v);
      v=NULL;
    }
    m_pbuffer_length = 0; //all buffered packets have been injected
    pthread_mutex_unlock(&buffer_lock);
    //as an alternative to vei_pthread_yield(), ask OS scheduler to
    //put us to bed...may affect whole process rather than individual
    //thread
    sched_yield();
  }
}
