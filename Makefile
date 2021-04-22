
all:
	$(CC) -m32 -Wall -Wextra -fPIC -g -O2 -c ssdis.c ssdis.h
	$(AR) -rsc libssdis.a ssdis.o
	#Note: libudis86 must be compiled for the correct architecture
	#$(CC) -m32 -Wall -Wextra -g driver.c libssdis.a ssdis.h /usr/local/lib/libudis86.a /usr/local/lib/libpagealloc.a -o driver

all64:
	$(CC) -Wall -Wextra -g -c ssdis.c ssdis.h
	$(AR) -rsc libssdis-64.a ssdis.o
	$(CC) -Wall -Wextra -g driver64.c libssdis-64.a ssdis.h /usr/local/lib/libudis86-64.a /usr/local/lib/libpagealloc-64.a -o driver64

install: all
	cp ssdis.h /usr/local/include/ssdis.h
	cp libssdis.a /usr/local/lib/libssdis.a

install64: all64
	cp ssdis.h /usr/local/include/ssdis-64.h
	cp libssdis-64.a /usr/local/lib/libssdis-64.a

clean:
	rm -f driver driver64 *.gch *.a *.o
