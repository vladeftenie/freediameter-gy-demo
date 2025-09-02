FD_INC = ../freeDiameter/include ../freeDiameter/build/include
FD_LIB = ../freeDiameter/build/freeDiameterd

CFLAGS = -Wall -fPIC -shared $(addprefix -I,$(FD_INC)) -pthread
LDFLAGS = -L$(FD_LIB) -lfdcore -lfdproto -lpthread -lgnutls

TARGETS = server.fdx client.fdx

all: $(TARGETS)

server.fdx: server.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

client.fdx: client.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(TARGETS)
