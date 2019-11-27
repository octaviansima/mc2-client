TGT=encrypt-file
cc=g++
CFLAGS ?=-O3 -g

$(TGT): encrypt-file.cc Makefile
	$(cc) $(CFLAGS) -o $(TGT) encrypt-file.cc -lmbedtls -lmbedcrypto $(LDFLAGS)

