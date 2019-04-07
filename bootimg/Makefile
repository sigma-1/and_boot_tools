# Author: Yannik Sembritzki
# License: GPLv2

# dependency generation loosely based on http://make.mad-scientist.net/papers/advanced-auto-dependency-generation
CFLAGS+=-I ../libsepol -I ../include --sysroot=$(SYSROOT)
LIBS="../libsepol/libsepol.a"
SRCS = $(wildcard *.c)
OBJS=$(SRCS:.c=.o)
DEPS=$(SRCS:.c=.d)
DEPFLAGS = -MT $@ -MMD -MP -MF $*.Td
POSTCOMPILE = @mv -f $*.Td $*.d
.PHONY: all clean build

all: bootimg

bootimg: $(OBJS)
	$(CC) -o bootimg $(CFLAGS) $(OBJS) -static $(LIBS)

%.o: %.c %.d 
	$(CC) -c $(DEPFLAGS) $(CFLAGS) $< -o $@
	$(POSTCOMPILE)

%.d: ;

clean:
	rm -f *.o *.d bootimg

-include $(DEPS)
