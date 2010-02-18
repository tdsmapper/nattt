
CC =    gcc
CXX =    g++
CFLAGS =  -g -O2  -DHAVE_CONFIG_H -DNAT3_TAP
LDFLAGS =  -lpthread 
DEFINES = -D_POSIX_THREADS -DHAVE_CONFIG_H
DNS = dns_a.o dns_compression.o dns_header.o dns_name.o dns_nat3.o dns_packet.o dns_query.o dns_rr.o
OBJS = $(DNS) tun_mgr.o tun_device.o tun_queue.o resolver.o tun_in_ent.o tun_out_ent.o tun_ent.o mutex_helper.o config_file.o functions.o linux_tun_mgr.o

TEST_DRIVERS = test_tun_mgr 
PROG = nat3d nat3ping

CFLAGS += -Wall -Werror -D_REENTRANT
CFLAGS += -g

CXXFLAGS += $(CFLAGS)

.cc.o:
	$(CXX) $(CXXFLAGS) $(DEFINES) -c $<

.c.o:
	$(CC) $(CFLAGS) $(DEFINES) -c $<

all: $(PROG) $(TEST_DRIVERS)

$(PROG): $(OBJS)
	$(CXX) $(CXXFLAGS) $(DEFINES) $(LDFLAGS) -o ../bin/$@ $@.cc $(OBJS)

$(TEST_DRIVERS): $(OBJS)
	$(CXX) $(CXXFLAGS) $(DEFINES) $(LDFLAGS) -o ../bin/$@ $@.cc $(OBJS)

clean:
	rm -f $(PROG) $(OBJS)
