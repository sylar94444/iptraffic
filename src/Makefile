#PCAP
#CFLAGS = -UENABLE_STAT_ONLY -UENABLE_LIBNET_LINK -UENABLE_MAC_SPECIFIED -UHAVE_UDPGRE_HEADER -UENABLE_DEBUG -Wall -O2
#LDFLAGS = -L/usr/lib -L/usr/lib64/ -lpcap -lnet

#PFRING
CFLAGS = -DHAVE_PF_RING -UENABLE_STAT_ONLY -UENABLE_LIBNET_LINK -UENABLE_MAC_SPECIFIED -UHAVE_UDPGRE_HEADER -UENABLE_DEBUG -Wall -O2
LDFLAGS = -L/usr/lib -L/usr/lib64/ -L/usr/local/lib/ /usr/local/lib/libpcap.a  /usr/local/lib/libpfring.a -lnet -lrt

TARGET=iptrafficd
OBJS=iptraffic.o capture.o log.o util.o hash.o list.o process.o transmit.o

$(TARGET):$(OBJS)
	gcc  -o $(TARGET) $(OBJS) $(LDFLAGS)
.c.o:
	gcc -c -o $*.o $(CFLAGS) $<
clean:
	rm -rf $(TARGET) $(OBJS)
install:
	cp $(TARGET) /etc/$(TARGET)

