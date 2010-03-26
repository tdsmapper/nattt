PROG = nat3d

CC =    gcc
CXX =    g++
CFLAGS =  -g -O2  -DHAVE_CONFIG_H
LDFLAGS =  
DEFINES = -DHAVE_CONFIG_H

CFLAGS += -Wall -Werror -D_REENTRANT
CFLAGS += -g

CXXFLAGS += $(CFLAGS)

all:
	-( mkdir -p bin )
	$(MAKE) -C src

$(PROG): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $(OBJS) $(LDFLAGS)

clean:
	$(MAKE) clean -C src
