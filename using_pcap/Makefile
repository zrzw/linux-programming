CC = clang++ -Wall -g -std=c++14
LIBS = /usr/lib/x86_64-linux-gnu/libpcap.so

simple_pcap: main.o
	$(CC) -o simple_pcap main.o $(LIBS)

main.o: src/main.cpp
	$(CC) -c src/main.cpp

clean:
	rm *.o
