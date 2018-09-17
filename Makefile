
all:
	$(CC) driver.c ssdis.c ssdis.h /usr/lib/libcapstone.a -o driver

clean:
	rm driver
