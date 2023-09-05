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

LIBACCACIA_CFLAGS=

ifdef with-pybind
    CFLAGS += -fPIC
    LIBACCACIA_CFLAGS += -fPIC
endif

CURR_GOBIND_VERSION = v1

SOURCES := $(wildcard *.c)
SOURCES += $(wildcard unix/*.c)
SOURCES += $(wildcard $(NATIVE_SRC)/*.c)
OBJECTS := $(patsubst %.c, $(OBJDIR)/%.o, $(SOURCES))

MACGONUTS_SHARE_DIR = /usr/local/share/macgonuts

all: setup build_accacia $(BINARY)
	cd cmd && $(MAKE)
ifdef with-pybind
	ar -r $(LIBDIR)/libmacgonutssock.a
	cd binds/py && rm -rf build && rm -f macgonuts.c && python setup.py build_ext --inplace
endif
ifdef with-gobind
	cd binds/go/$(CURR_GOBIND_VERSION) && go build
endif

setup:
	@mkdir -p .o

build_accacia:
	cd libs/accacia/src && $(CC) -I. -c accacia.c $(LIBACCACIA_CFLAGS) && mkdir -p ../lib &&\
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
	@rm -f $(LIBDIR)/$(BINARY)

install:
	@mkdir -p /usr/local/bin && cp ../bin/macgonuts /usr/local/bin &&\
 mkdir -p /usr/local/man/man1 && cp ../doc/man1/macgonuts.1 /usr/local/man/man1/macgonuts.1 &&\
 mkdir -p $(MACGONUTS_SHARE_DIR)/etc && cp ../etc/hoax $(MACGONUTS_SHARE_DIR)/etc/hoax &&\
 cp ../etc/oui $(MACGONUTS_SHARE_DIR)/etc/oui
	@echo installed.

uninstall:
	@rm /usr/local/bin/macgonuts && rm /usr/local/man/man1/macgonuts.1 && rm -rf $(MACGONUTS_SHARE_DIR)
	@echo uninstalled.

deb:
	@mkdir -p ../deb
	@dpkg-buildpackage -uc -us --pre-clean -j1
	@mv ../macgonuts*.* ../deb
