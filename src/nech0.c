/***************************************************************************
 *  Virtual Network Event Injector Service (VEI)
 *  Nech0: Network Ech0, an example client of the VEI library
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

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <features.h>
#include "vei.h"

static void 
do_work(char* src,
	char* dst)
{
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

  init_result = initialize_vei_library(btrace,
				       otrace);
  if(0==init_result)
  {
    fprintf(stdout, "[nech0] initialized OK\n");
  }else{
    fprintf(stdout, "initialization failed with code %d\n", init_result);
    exit(-30);
  }

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
 * Network Ech0 (nech0)
 * necho src.cap dst.cap
 * 
 * open src (must exist)
 * open and create dst
 */
int main(int argc,
	 char* argv[])
{
  if(3==argc)
  {
    const char* ver = pcap_lib_version();
    fprintf(stdout,
	    "nech0 is using %s\n",
	    ver);

    fprintf(stdout,
	    "echoing [%s] to [%s]\n",
	    argv[1],
	    argv[2]);

    do_work(argv[1],
	    argv[2]);

    fprintf(stdout,
	    "[nech0] calling shutdown()...\n");
    shutdown();

  }else{
    fprintf(stderr,
	    "nech0 srcfile.cap dstfile.cap\n");
    return -1;
  }

  return 0;
}
