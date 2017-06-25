CC		= gcc
LD		= $(CC)
OPT 		= -I./includes/ -march=armv8-a+crypto+crc+lse -O2 -std=c11 -pthread -Wunused-variable 
CFLAGS 		= -D_POSIX_SOURCE -D_GNU_SOURCE $(OPT)
LDFLAGS		= $(OPT)
LIBS		= -ljansson -pthread
OBJS		= crypto/c_blake256.o \
		crypto/c_groestl.o crypto/c_keccak.o crypto/c_jh.o crypto/c_skein.o \
		cryptonight.o log.o net.o minerutils.o main.o

all: $(OBJS)
	$(LD) $(LDFLAGS) -o miner $(OBJS) $(LIBS)

clean:
	rm -f *.o crypto/*.o miner
