OUTPUT=nethostfs
OBJS=main.o
CFLAGS=-Wall -I.
LDFLAGS=-L. -lpthread
STRIP=strip

all: $(OUTPUT)

clean:
	rm -f $(OUTPUT) *.o

$(OUTPUT): $(OBJS)
	$(LINK.c) $(LDFLAGS) -o $@ $^ $(LIBS)
	$(STRIP) $@
