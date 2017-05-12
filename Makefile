CC		= gcc
LD		= gcc
OPT 	= -O2 -s -I/home/wolf/miners/sgminer-builds/sgminer-lin64/include/ -L/home/wolf/miners/sgminer-builds/sgminer-lin64/lib
AES	= -maes
CFLAGS 	= -D_POSIX_SOURCE -D_GNU_SOURCE $(OPT) -c -std=c11
LDFLAGS	= -DPTW32_STATIC_LIB $(OPT)
LIBS	= -ljansson -lOpenCL -lpthread -ldl

OBJS = crypto/aesb.o crypto/aesb-x86-impl.o crypto/c_blake256.o \
	crypto/c_groestl.o crypto/c_keccak.o crypto/c_jh.o crypto/c_skein.o \
	crypto/oaes_lib.o cryptonight.o log.o net.o minerutils.o gpu.o main.o

all: $(OBJS)
	$(LD) -o miner $(OBJS) $(LIBS)

cryptonight.o:	cryptonight.c
	$(CC) $(CFLAGS) $(AES)	$? -o $@

clean:
	rm -f *.o crypto/*.o miner
