CFLAGS += -I/usr/include/jwt
MODLIB += rvi
LIBS_rvi := -lssl -lcrypto -ljansson -ljwt
INCLUDE_rvi := src/btree.o src/rvi_list.o src/rvi.o
