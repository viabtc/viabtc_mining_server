TARGET  := mineragent.exe
INCS = -I ../network -I ../utils
LIBS = -L ../utils -lutils -L ../network -lnetwork -Wl,-Bstatic -lev -lhiredis -ljansson -lssl -lcrypto -Wl,-Bdynamic -lcurl -lm
include ../makefile.inc
