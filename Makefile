
all:
	$(CC) -g -c ssdis.c ssdis.h
	$(AR) -rsc libssdis.a ssdis.o
	$(CC) -g driver.c libssdis.a ssdis.h /usr/lib/libcapstone.a -o driver

all32:
	$(CC) -m32 -g -c ssdis.c ssdis.h
	$(AR) -rsc libssdis.a ssdis.o
	#libcapstone32.a is NOT installed by capstone!
	#This is custom named to allow concurrent 64 and 32 bit installations!
	$(CC) -m32 -g driver32.c libssdis.a ssdis.h /usr/lib/libcapstone32.a -o driver32

install32: all32
	cp ssdis.h /usr/local/include/ssdis32.h
	cp libssdis.a /usr/local/lib/libssdis32.a

install: all
	cp ssdis.h /usr/local/include/ssdis.h
	cp libssdis.a /usr/local/lib/libssdis.a

clean:
	rm -f driver *.gch *.a *.o
