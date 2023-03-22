#Makefile
all: pcap-test

pcap-test: main.o
       g++ -o pcap-test main.o

main.o:  libnet-headers.h main.cpp

clean:
	rm -f pcap-test
	rm -f *.o
