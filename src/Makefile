LDFLAGS=-L../lib -L/usr/lib
INCLUDES=-I/usr/include -I../include 
LIBS=-lpcap -ldnet -lpthread -lvei
#OPTS=-Wall -g -pg
OPTS=-Wall -g
ECHO_TOOLOUT=nech0
ECHO_TOOLSRC=nech0.c
ACT_TOOLOUT=nact
ACT_TOOLSRC=n4ct.c
P_TOOLOUT=nroxy
P_TOOLSRC=nr0xy.c


all:	vei library tools

static:
	gcc $(OPTS) $(INCLUDES) -c vei.c 
	ar rc libvei.a vei.o
	mkdir -p ../lib
	mv libvei.a ../lib
	gcc $(OPTS) $(LDFLAGS) $(INCLUDES) -o $(ECHO_TOOLOUT) objects/*.o $(ECHO_TOOLSRC) -static -lvei
	mv $(ECHO_TOOLOUT) ../bin/
	gcc $(OPTS) $(LDFLAGS) $(INCLUDES) -o $(ACT_TOOLOUT) objects/*.o $(ACT_TOOLSRC) -static -lvei
	mv $(ACT_TOOLOUT) ../bin/

library: libvei.a

libvei.a: vei.o
	ar rc $@ vei.o
	mkdir -p ../lib
	mv libvei.a ../lib

vei: vei.c ../include/vei.h
	gcc $(OPTS) $(INCLUDES) -c vei.c

tools:	nech0 n4ct nr0xy

nech0:	nech0.c
	gcc $(OPTS) $(LDFLAGS) $(INCLUDES) -o $(ECHO_TOOLOUT) $(ECHO_TOOLSRC) $(LIBS)
	mv $(ECHO_TOOLOUT) ../bin/

n4ct:	n4ct.c
	gcc $(OPTS) $(LDFLAGS) $(INCLUDES) -o $(ACT_TOOLOUT) $(ACT_TOOLSRC) $(LIBS)
	mv $(ACT_TOOLOUT) ../bin/

nr0xy:	nr0xy.c
	gcc $(OPTS) $(LDFLAGS) $(INCLUDES) -o $(P_TOOLOUT) $(P_TOOLSRC) $(LIBS)
	mv $(P_TOOLOUT) ../bin/

clean:
	@/bin/rm -f *~ *.o *.a $(ECHO_TOOLOUT) $(ACT_TOOLOUT) $(P_TOOLOUT)
	@/bin/rm -f ../include/*~
	@/bin/rm -f ../lib/*.a
	@/bin/rm -f ../bin/$(ECHO_TOOLOUT)
	@/bin/rm -f ../bin/$(ACT_TOOLOUT)
	@/bin/rm -f ../bin/$(P_TOOLOUT)
	@/bin/rm -f ../*~