#Makefile
all: pcap-test

pcap-test: main.c
	gcc main.c -lpcap -o pcap-test

clean:
	rm -f pcap-test
