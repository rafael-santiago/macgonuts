#
# Copyright (c) 2023, Rafael Santiago
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.
OBJDIR = .o
LIBDIR = ../lib
BINARY = libmacgonuts.a
INCS = .
LIBS = -Llibs/accacia/lib
AR = ar
NATIVE_SRC = $(shell uname -s | tr '[:upper:]' '[:lower:]')

LDFLAGS=-lpthread -laccacia
CFLAGS=-Ilibs/accacia/src -I.

SOURCES := $(wildcard *.c)
SOURCES += $(wildcard unix/*.c)
SOURCES += $(wildcard $(NATIVE_SRC)/*.c)
OBJECTS := $(patsubst %.c, $(OBJDIR)/%.o, $(SOURCES))

all: setup build_accacia $(BINARY)
	cd cmd && $(MAKE)

setup:
	@mkdir -p .o

build_accacia:
	cd libs/accacia/src && $(CC) -I. -c accacia.c && mkdir -p ../lib &&\
 $(AR) -r ../lib/libaccacia.a accacia.o && rm accacia.o && cd ../../..

$(BINARY): $(OBJDIR)/$(OBJECTS)
	@$(AR) -r $(LIBDIR)/$(BINARY) $(OBJECTS) > /dev/null 2>&1
	@echo ____
	@echo libmacgonuts.a created at $(LIBDIR)/$(BINARY)

$(OBJDIR)/%.o: %.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	@rm -rf .o
	@rm $(LIBDIR)/$(BINARY)
