# Copyright (C) 2016, Jaguar Land Rover. All Rights Reserved.
#
# This Source Code Form is subject to the terms of the Mozilla Public 
# License, v 2.0. If a copy of the MPL was not distributed with this 
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

CFLAGS +=		\
	-std=gnu11	\
	-g			\
	-Wall		\
	-fPIC		\

JWTDIR = /media/tjamison/b2a03dd8-91cc-4c25-acc8-c7016244a589/tjamison/work/git/libjwt

JWTINC = -I$(JWTDIR)/include -Wl,-rpath $(JWTDIR)/lib

LDFLAGS+=		\
	-L.			\
	-L./../src	\

LIBRARIES+=		\
	-lssl		\
	-lcrypto	\
	-ljansson	\
	-lrvi		\
#	-ljwt		\

INCLUDES=		\

all: interactive

# Sample application that uses the API.
interactive: $(INCLUDES) interactive.c
	echo "Rebuilding the interactive executable..."
	gcc $(CFLAGS) -o interactive interactive.c $(LDFLAGS) -Wl,-rpath $(CURDIR) \
	-Wl,-rpath -I./../src/ -Wl,-rpath ./../src/librvi.so $(LIBRARIES) 

clean distclean:
	echo "Deleting all derived files..."
	rm -rf *.o *~ interactive
