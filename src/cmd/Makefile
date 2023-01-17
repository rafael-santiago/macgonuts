#
# Copyright (c) 2023, Rafael Santiago
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.
OBJDIR = .o
BINDIR = ../../bin
BINARY = macgonuts
INCS = .
LIBS = -L../libs/accacia/lib -L../../lib

LDFLAGS=-lpthread -laccacia -lmacgonuts
CFLAGS=-I../libs/accacia/src -I../ -I.

SOURCES := $(wildcard *.c)
SOURCES += $(wildcard hooks/*.c)
OBJECTS := $(patsubst %.c, $(OBJDIR)/%.o, $(SOURCES))

all: setup $(BINARY)

setup:
	@mkdir -p .o

$(BINARY): $(OBJDIR)/$(OBJECTS)
	@$(CC) $(LIBS) -o $(BINDIR)/$(BINARY) $(OBJECTS) $(LDFLAGS)
	@echo ____
	@echo macgonuts created at $(BINDIR)/$(BINARY)

$(OBJDIR)/%.o: %.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	@rm -rf .o
	@rm $(BINDIR)/$(BINARY)
