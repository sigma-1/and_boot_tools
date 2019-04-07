# Authors:  Yannik Sembritzki
#           Vidir Alexander Jonsson <valex@valex.is>
# License:  GPLv2

OS = $(shell uname)

ifeq ($(OS), Darwin)
CC ?= /usr/bin/clang
else ifeq ($(OS), Linux))
CC ?= gcc
endif

SRCS = $(wildcard *.c)
OBJS = $(patsubst %.c,%.o,$(sort $(SRCS)))
DEPS = $(patsubst %.c,%.d,$(sort $(SRCS)))
LIBS = $(wildcard libs/*.a)

ifeq ($(OS), Darwin)
LIBSCP := $(shell mkdir -p libs && cp ../libsepol/*.a libs && \
			cp ../libinotify-kqueue/.libs/*.a libs)
else ifeq ($(OS), Linux))
LIBSCP := $(shell mkdir -p libs && cp ../libsepol/*.a)
endif

ifeq ($(OS), Darwin)
CFLAGS += -I../libinotify-kqueue -I../libsepol -I../include \
		  -ffunction-sections -fdata-sections \
		  -Wno-deprecated-declarations -Wno-address-of-packed-member \
		  -O3 --sysroot=$(SYSROOT)
else ifeq ($(OS), Linux))
CFLAGS += -I../libinotify-kqueue -I../libsepol -I../include \
		  -ffunction-sections -fdata-sections \
		  -O3 --sysroot=$(SYSROOT)
endif

ifeq ($(OS), Darwin)
LDFLAGS += -Wl, -dead_strip -Llibs -Bstatic
else ifeq ($(OS), Linux))
LDFLAGS += -Wl,--gc-sections -Llibs -static
endif

DEPFLAGS = -MT $@ -MMD -MP -MF $*.Td
POSTCOMPILE = @mv -f $*.Td $*.d

.PHONY: all clean build indent

all: bootimg

bootimg: $(OBJS)
	$(LIBSCP)
	@$(CC) -o bootimg $(CFLAGS) -fPIC $(OBJS) $(LDFLAGS) $(LIBS)
	@echo "$@" | xargs -n1

%.o: %.c %.d
	@$(CC) -c $(DEPFLAGS) $(CFLAGS) -fPIC $< -o $@
	@echo "$@" | xargs -n1 | ts "CC"
	$(POSTCOMPILE)

%.d: ;

clean:
	@rm -rf libs
	@echo "$(LIBS)" | xargs -n1 | ts "clean"
	@rm -f *.o
	@echo "$(OBJS)" | xargs -n1 | ts "clean"
	@rm -f *.d
	@echo "$(DEPS)" | xargs -n1 | ts "clean"
	@rm -f bootimg
	@echo "bootimg" | xargs -n1 | ts "clean"


indent:
	../scripts/Lindent $(wildcard *.[ch])

-include $(DEPS)
