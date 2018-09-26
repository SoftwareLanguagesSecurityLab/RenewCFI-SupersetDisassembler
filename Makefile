
all:
	$(CC) -g -c ssdis.c ssdis.h
	$(AR) -rsc libssdis.a ssdis.o
	$(CC) -g driver.c libssdis.a ssdis.h /usr/lib/libcapstone.a -o driver

install: all
	cp ssdis.h /usr/local/include/ssdis.h
	cp libssdis.a /usr/local/lib/libssdis.a

clean:
	rm -f driver *.gch *.a *.o
