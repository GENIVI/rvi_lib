# Copyright (C) 2016, Jaguar Land Rover. All Rights Reserved.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

CFLAGS+=		\
	-std=gnu11 	\
	-g 			\
	-Wall 		\
	-fPIC		\

## TEMPORARY
JWTDIR = /media/tjamison/b2a03dd8-91cc-4c25-acc8-c7016244a589/tjamison/work/git/libjwt

JWTINC = -I$(JWTDIR)/include/ -Wl,-rpath $(JWTDIR)/lib/

LDFLAGS+=		\
	-L.			\
	-L$(JWTDIR)/lib \

LIBRARIES= 		\
	-lssl		\
	-lcrypto	\
	-ljwt		\
	-ljansson	\

INCLUDES=		\
	btree.h     \
	rvi.h		\
	rvi_list.h	\

TARGETS=		\
	librvi.so 	\

#
#	Define extra files to be included in a tar output file.
#
EXTRA_FILES=	\
	Makefile	\
	README.md	\

#
#	Allow make to run compiles/links in parallel
#
MAKEFLAGS += j

#
#	Suppress all of the automatic command echoing
#

#.SILENT:

default: all

all: $(TARGETS)

rvi.o : btree.o rvi_list.o $(INCLUDES)
	gcc -c $(CFLAGS) -o rvi.o rvi.c btree.o rvi_list.o $(LDFLAGS) $(JWTINC) $(LIBRARIES)

# Target for building the RVI library.
librvi.so: btree.o rvi_list.o rvi.o
	echo "Linking the $@ library..."
	gcc $(CFLAGS) -shared -o $@ btree.o rvi_list.o rvi.o $(LDFLAGS) $(JWTINC) $(LIBRARIES)

# Build the user-facing documentation.
docs: Doxyfile $(INCLUDES)
	echo "Rebuilding the RVI documentation..."
	doxygen ./Doxyfile

clean distclean:
	echo "Deleting all derived files..."
	rm -rf *.o *~ librvi.so 
