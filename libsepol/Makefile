# Authors:  Yannik Sembritzki
#           Vidir Alexander Jonsson <valex@valex.is>
# License:  GPLv2

OS = $(shell uname)

ifeq ($(OS), Darwin)
CC ?= /usr/bin/clang
AR ?= /usr/bin/ar
RANLIB  ?= /usr/bin/ranlib
else ifeq ($(OS), Linux))
CC ?= gcc
AR ?= ar
RANLIB ?= ranlib
endif

LIBA = libsepol.a

SRCS = $(wildcard *.c) 
OBJS = $(patsubst %.c,%.o,$(sort $(SRCS)))
DEPS = $(SRCS:.c=.d)

DEPFLAGS = -MT $@ -MMD -MP -MF $*.Td
POSTCOMPILE = @mv -f $*.Td $*.d

CFLAGS ?= -I . -Werror -Wall -W -Wundef -Wshadow -Wmissing-format-attribute -O2
LDFLAGS ?= -static

.PHONY: all clean indent

all: $(LIBA)

$(LIBA): $(OBJS)
	@$(AR) rcs $@ $^
	@echo "$^" | xargs -n1 | ts "AR"
	@echo "AR $@"
	@$(RANLIB) $@
	@echo "ranlib $@"
	chmod 644 $@

$(OBJS): $(SRCS) $(DEPS)
	@$(CC) $(DEPFLAGS) $(CFLAGS) -fPIC $(LDFLAGS) -c -o $@ $<
	@echo "CC $@"
	$(POSTCOMPILE)

$(DEPS): ;

clean:
	@rm -f $(OBJS)
	@echo "$(OBJS)" | xargs -n1 | ts "clean"
	@rm -f $(DEPS)
	@echo "$(DEPS)" | xargs -n1 | ts "clean"
	@rm -f $(LIBA)
	@echo "$(LIBA)" | xargs -n1 | ts "clean"

indent:
	../scripts/Lindent $(wildcard *.[ch])
