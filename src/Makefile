# Authors:  Yannik Sembritzki
#           Vidir Alexander Jonsson <valex@valex.is>
# License:  GPLv2

OS = $(shell uname)
CC ?= /usr/bin/clang

SRCS = $(wildcard *.c)
OBJS = $(patsubst %.c,%.o,$(sort $(SRCS)))
DEPS = $(patsubst %.c,%.d,$(sort $(SRCS)))
LIBS = $(wildcard libs/*.a)

LIBSCP := $(shell mkdir -p libs && cp ../libs/libsepol/*.a libs && \
			cp ../libs/libmincrypt/*.a libs && cp ../libs/libinotify/*.a libs)

CFLAGS += -I../include -I../libs/include/sepol -I../libs/include/mincrypt \
		  -I../libs/include/inotify -ffunction-sections -fdata-sections -O3

ifeq ($(OS), Darwin)
LDFLAGS += -Wl, -dead_strip
else ifeq ($(OS), Linux))
LDFLAGS += -Wl,--gc-sections
endif

DEPFLAGS = -MT $@ -MMD -MP -MF $*.Td
POSTCOMPILE = @mv -f $*.Td $*.d

.PHONY: all clean indent

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
