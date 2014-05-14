/***************************************************************************
 *  Virtual Network Event Injector Service (VEI)
 *  nr0xy: network actor proxy, example client for libvei
 *  Copyright (C) 2011 Michael Locasto <locasto@ucalgary.ca>
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
#define _FILE_OFFSET_BITS   64  //required to open pcap files >2GB
//#define _LARGEFILE64_SOURCE

#include <features.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <pcap.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include "vei.h"

/**
 * This thread calls `inject_event', which simply
 * buffers packets if the VEI library has been
 * initialized. The VEI library contains a separate
 * thread for actually consuming the injection buffer
 * and writing it to the target output file if the
 * VEI library is transcribing.
 */
static pthread_t i_thread;

static void
create_net_proxy(int port)
{
  return;
}


static void
listen_loop()
{
  for(;;)
  {
    //wait on message from OVVT.
    //if message content is VEI_POST_JPG,
    //then call inject_even(VEI_POST_JPG);
    break;
  }
  return;
}

/**
 * Helper routine (swappable body) for injector thread. 
 */
static void
test_one_packet()
{
  int injection_result = 0;
  injection_result = inject_event(VEI_POST_JPG);
  if(injection_result<0)
  {
    fprintf(stdout, 
	    "[nroxy] injection request failed with code %d\n", 
	    injection_result);
  }else{
    fprintf(stdout, 
	    "[nroxy] buffered %d packets\n", 
	    injection_result);
  }
  return;
}

/**
 * Inject one VEI_PING every second, forever. 
 */
/*
static void
test_loop_one_packet()
{
  int injection_result = 0;
  for(;;)
  {
    injection_result = inject_event(VEI_PING);
    if(injection_result<0)
    {
      fprintf(stdout, "injection failed with code %d\n", injection_result);
    }else{
      fprintf(stdout, "injected %d packets\n", injection_result);
    }
    sleep(1);
  }

  return;
}
*/

/**
 * i_thread action routine.
 *
 */
void*
do_injection_script(void* arg)
{
  //give transcriber time to set up
  //sleep(2);
  sched_yield();

  //load script file here, tells us which actions to take
  fprintf(stdout,
	  //"\n[nroxy.i_thread] calling test_one_packet()...\n");
	  "\n[nroxy.i_thread] calling listen_loop()...\n");
  fflush(stdout);

  //can swap out test functions here
  test_one_packet();
  //listen_loop();

  return ((void*)0);
}

/////////////////////////////////////////////////////////////////////////

static void 
do_work(char* src,
	char* dst,
	int port)
{
  int err = 0; //thread creation result
  int init_result = 0;
  int kickoff_result = 0;

  FILE* btrace = NULL;
  FILE* otrace = NULL;

  btrace = fopen(src, "r");
  if(NULL==btrace)
  {
    perror("dowork(): opening input file");
    exit(-10); //if we don't do this, we fall through to vei_finish()
  }

  //'b' ignored on POSIX-conforming systems including linux
  otrace = fopen(dst, "wb");
  if(NULL==otrace)
  {
    perror("dowork(): opening output file");
    exit(-20);
  }

  //create and bind socket, listen
  //"actor thread" will do the task of listening to
  //the network and then passing the command on, so
  //no need to create a separate "server" thread
  create_net_proxy(port);

  init_result = initialize_vei_library(btrace,
				       otrace);
  if(0==init_result)
  {
    fprintf(stdout, "[nroxy] initialized OK\n");
  }else{
    fprintf(stdout, "initialization failed with code %d\n", init_result);
    exit(-30);
  }

  //need to create a thread that does injection because
  //start_vei_transcription() won't return until it has
  //echoed all packets from the background file to the
  //destination output file.
  fprintf(stdout,
	  "[nroxy] creating actor thread...\n");
  err = pthread_create(&i_thread,
		       NULL,
		       do_injection_script,
		       NULL); //possibly filename of script/injctn timeline
  if(0!=err)
  {
    fprintf(stderr,
	    "[nroxy] failed to create actor thread: %s\n",
	    strerror(err));
    exit(-40);
  }else{
    fprintf(stdout,
	    "[nroxy] created actor thread\n");
    fflush(stdout);
  }

  fprintf(stdout,
	  "[nroxy] invoking start_vei_transcription...\n");
  kickoff_result = start_vei_transcription();
  if(0!=kickoff_result)
  {
    fprintf(stderr,
	    "failed to start transcription with error code %d\n",
	    kickoff_result);
    fflush(stderr);
    exit(-40);
  }

  return;
}

/** 
 * Tell library to cleanly shut down.
 */
void
shutdown()
{
  vei_finish();
  return;
}

/**
 * Network Actor Proxy (nroxy)
 * nroxy src.cap dst.cap -p port
 * 
 * - open src (must exist)
 * - open and create dst
 * - bind port and listen for VEI_EVENT names
 */
int main(int argc,
	 char* argv[])
{
  if(5==argc && (0==strncmp("-p",argv[3],2)))
  {
    const char* ver = pcap_lib_version();
    fprintf(stdout,
	    "nroxy is using %s\n",
	    ver);

    fprintf(stdout,
	    "playing [%s] to [%s] and listening to %d\n",
	    argv[1],
	    argv[2],
	    atoi(argv[4]));

    /**
     * initialize libvei
     * create actor thread
     * create network port listener thread
     * tell libvei to start transcribing / copying background packets
     */
    do_work(argv[1],
	    argv[2],
	    atoi(argv[4]));

    fprintf(stdout,
	    "[nroxy] calling shutdown()...\n");
    fflush(stdout);
    shutdown();

  }else{
    fprintf(stderr,
	    "nroxy srcfile.cap dstfile.cap -p port\n");
    return -1;
  }

  return 0;
}
