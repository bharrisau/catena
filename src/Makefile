CC=gcc
HDIR=./blake2
CFLAGS=-fomit-frame-pointer -O3 -std=c99 -fgnu89-inline -s -m64 -msse4.2 -W -Wall  -L$(HDIR) -I$(HDIR)

HASH=$(HDIR)/blake2b.c
HASHs=$(HDIR)/blake2s.c

all: blake2b sha512

blake2b: catena-blake2b-test catena-blake2b-test_vectors 
sha512: catena-sha512-test catena-sha512-test_vectors

catena-blake2b-test:
	$(CC) $(CFLAGS) -o $@ test-catena.c catena.c catena-blake2b.c $(HASH)


catena-blake2b-test_vectors:
	$(CC) $(CFLAGS) -o $@ catena_test_vectors.c catena.c catena-blake2b.c $(HASH)

catena-blake2b-util:
	$(CC) $(CFLAGS) -o $@ util-catena.c catena.c catena-blake2b.c $(HASH)

catena-blake2s-util:
	$(CC) $(CFLAGS) -o $@ util-catena.c catena.c catena-blake2s.c $(HASHs) -DH_LEN=32

catena-sha512-test:
	$(CC) $(CFLAGS) -o $@ test-catena.c catena.c catena-sha512.c -lssl -lcrypto


catena-sha512-test_vectors:
	$(CC) $(CFLAGS) -o $@ catena_test_vectors.c catena.c catena-sha512.c -lssl -lcrypto

catena:
	$(CC) $(CFLAGS) -c $@.c $(HASH)


clean:
	rm -f  *~ *.o catena-blake2b-test catena-blake2b-test_vectors catena-sha512-test catena-sha512-test_vectors catena-blake2b-opt-test
