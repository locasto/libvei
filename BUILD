[michael@proton src]$ make clean
[michael@proton src]$ ls
Makefile  n4ct.c  nech0.c  vei.c
[michael@proton src]$ make
gcc -Wall -g -I/usr/include -I../include  -c vei.c
ar rc libvei.a vei.o
mkdir -p ../lib
mv libvei.a ../lib
gcc -Wall -g -L../lib -L/usr/lib -I/usr/include -I../include  -o nech0 nech0.c -lpcap -ldnet -lpthread -lvei
mv nech0 ../bin/
gcc -Wall -g -L../lib -L/usr/lib -I/usr/include -I../include  -o nact n4ct.c -lpcap -ldnet -lpthread -lvei
mv nact ../bin/
[michael@proton src]$ ls ../bin
nact  nech0
[michael@proton src]$ 
