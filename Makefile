#
# Copyright (C) 2016, Jaguar Land Rover. All Rights Reserved.
#
# This Source Code Form is subject to the terms of the Mozilla Public 
# License, v. 2.0. If a copy of the MPL was not distributed with this file, 
# You can obtain one at http://mozilla.org/MPL/2.0/.
#

#
#	Top level Remote Vehicle Interface build rules.
#

MODULES = src examples

# Look for include files in each of the modules 
CFLAGS += $(patsubst %,-I%, $(MODULES)) \
		  -fPIC -g -Wall -std=gnu99

#MAKEFLAGS += j

# Modules may add to this
LDFLAGS := -L.
SRC := 
MODLIB :=

LLIBDIR := $(CURDIR)/build/lib
LBINDIR := $(CURDIR)/build/bin

INSTALL_PATH ?= /usr

# Specify default target before including any other files

default: libs

# Include the description for each module
include $(patsubst %,%/module.mk,$(MODULES))

# Define shared libraries for each library module
SHAREDLIBS := $(foreach var,$(MODLIB),$(LLIBDIR)/lib$(var).so)

# Additional libraries and local path
LIBS := 
LDFLAGS += -I. -Wl,-rpath $(LLIBDIR)

# Determine the object files
OBJ := \
	$(patsubst %.c,%.o, $(filter %.c,$(SRC))) \
	$(patsubst %.y,%.o, $(filter %.y,$(SRC))) \

all: libs $(TARGET) 

examples: $(TARGET)

.SILENT:
# Build the shared libraries
libs: $(foreach var,$(MODLIB),$(INCLUDE_$(var))) jwt
	echo "Building library in" $(LLIBDIR) "..."; \
	mkdir -p $(LLIBDIR); \
	$(foreach var,$(MODLIB),$(CC) $(CFLAGS) -shared \
		-o $(LLIBDIR)/lib$(var).so $(INCLUDE_$(var)) \
		$(LDFLAGS) $(LIBS_$(var));)

# Build jwt
jwt: 
	git submodule init; git submodule update; cd libjwt; cmake .; make jwt;

# Link the program
$(TARGET): $(OBJ) libs
	echo "Building the executable in" $(LBINDIR) "..."; \
	mkdir -p $(LBINDIR); \
	$(CC) -o $@ $(OBJ) $(CFLAGS) $(LDFLAGS)  $(LIBS) \
		$(SHAREDLIBS)

install: jwt libs 
	cd libjwt; make install; cd ..; \
		echo -- Installing: $(INSTALL_PATH)/lib/librvi.so;\
		cp $(LLIBDIR)/librvi.so $(INSTALL_PATH)/lib;\
		echo -- Installing: $(INSTALL_PATH)/include/rvi.h;\
		cp -p $(CURDIR)/src/rvi.h $(INSTALL_PATH)/include;\

docs: Doxyfile $(INCLUDES)
	echo "Rebuilding the RVI documentation..."; \
	doxygen ./Doxyfile

clean distclean:
	rm -rf *.o */*.o *~ build docs; cd libjwt; make clean;
