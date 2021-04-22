TARGET  := bitpeer.exe
INCS = -I ../network -I ../utils
LIBS = -L ../utils -lutils -L ../network -lnetwork -Wl,-Bstatic -lev -lhiredis -ljansson -lssl -lcrypto -Wl,-Bdynamic -lcurl -ldl -lm -lpthread -lz
include ../makefile.inc
