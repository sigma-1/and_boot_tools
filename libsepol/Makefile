# Authors:  Yannik Sembritzki
#           Vidir Alexander Jonsson <valex@valex.is>
# License:  GPLv2

OS = $(shell uname)

ifeq ($(OS), Darwin)
CC ?= /usr/bin/clang
AR ?= /usr/bin/ar
else ifeq ($(OS), Linux))
CC ?= gcc
AR ?= ar
endif

LIBA=libsepol.a
ifeq ($(OS), Darwin)
LIBSO=libsepol.dylib
else
LIBSO=libsepol.so
endif

SRCS = $(wildcard *.c)
OBJS = $(patsubst %.c,%.o,$(sort $(SRCS)))
LOBJS = $(patsubst %.c,%.lo,$(sort $(SRCS)))
CFLAGS ?= -I . -I../include -Werror -Wall -W -Wundef -Wshadow -Wmissing-format-attribute -O2

override CFLAGS += -I. -D_GNU_SOURCE

ifeq ($(OS), Darwin)
LDFLAGS ?= -Bdynamic -dynamiclib -undefined dynamic_lookup -flat_namespace -Bstatic
else ifeq ($(OS), Linux)
LDFLAGS ?= -undefined dynamic_lookup -flat_namespace -static
endif

.PHONY: all clean build indent

all: $(LIBA) $(LIBSO)

$(LIBA): $(OBJS)
	@$(AR) rcs $@ $^
	@echo "$^" | xargs -n1 | ts "AR"
	@echo "AR $@"

$(LIBSO): $(LOBJS)
	@$(CC) $(CFLAGS) -fPIC $(LDFLAGS) -o $@ $(LOBJS)
	@echo "$@" | xargs -n1 | ts "CC"
	$(POSTCOMPILE)

%.o:  %.c 
	@$(CC) $(CFLAGS) -fPIC -c -o $@ $<
	@echo "$@" | xargs -n1 | ts "CC"

%.lo:  %.c
	@$(CC) $(CFLAGS) -fPIC -DSHARED -c -o $@ $<
	@echo "$@" | xargs -n1 | ts "CC"

clean:
	@rm -f $(OBJS)
	@echo "$(OBJS)" | xargs -n1 | ts "clean"
	@rm -f $(LOBJS)
	@echo "$(LOBJS)" | xargs -n1 | ts "clean"
	@rm -f $(LIBA)
	@echo "$(LIBA)" | xargs -n1 | ts "clean"
	@rm -f $(LIBSO)
	@echo "$(LIBA)" | xargs -n1 | ts "clean"

indent:
	../scripts/Lindent $(wildcard *.[ch])
