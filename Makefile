
all:
	$(CC) -g -c ssdis.c ssdis.h
	$(AR) -rsc libssdis.a ssdis.o
	$(CC) -g driver.c libssdis.a ssdis.h /usr/local/lib/libudis86.a -o driver

all32:
	$(CC) -m32 -fPIC -g -c ssdis.c ssdis.h
	$(AR) -rsc libssdis.a ssdis.o
	#Note: libudis86 must be compiled for the correct architecture
	$(CC) -m32 -g driver32.c libssdis.a ssdis.h /usr/local/lib/libudis86.a /usr/local/lib/libpagealloc.a -o driver32

install32: all32
	cp ssdis.h /usr/local/include/ssdis32.h
	cp libssdis.a /usr/local/lib/libssdis32.a

install: all
	cp ssdis.h /usr/local/include/ssdis.h
	cp libssdis.a /usr/local/lib/libssdis.a

clean:
	rm -f driver *.gch *.a *.o
