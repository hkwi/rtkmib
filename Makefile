CFLAGS := -s -Wall -c -Os $(CFLAGS)
LDFLAGS = -s -Wall


CFLAGS  += -ffunction-sections -fdata-sections
LDFLAGS += --static -s -Wl,--gc-sections

default: all
all: rtkmib

rtkmib:	rtkmib.o
	$(CC) $(LDFLAGS) -o rtkmib rtkmib.o

rtkmib.o: rtkmib.c
	$(CC) $(CFLAGS) -o rtkmib.o rtkmib.c

clean:
	rm -f *.o
	rm -f rtkmib
