CFLAGS += -Ilibjwt/include/ 
LDFLAGS += -L. -L$(CURDIR)/libjwt/lib -Wl,-rpath $(CURDIR)/libjwt/lib/ 
MODLIB += rvi
LIBS_rvi := -lssl -lcrypto -ljansson -ljwt
INCLUDE_rvi := src/btree.o src/rvi_list.o src/rvi.o
