# Authors:  Yannik Sembritzki
#           Vidir Alexander Jonsson <valex@valex.is>
# License:  GPLv2

rwildcard=$(foreach d,$(wildcard $1*),$(call rwildcard,$d/,$2) $(filter $(subst *,%,$2),$d))

OS = $(shell uname)
CC ?= /usr/bin/clang

SRCS = $(wildcard *.c)
OBJS = $(patsubst %.c,%.o,$(sort $(SRCS)))
DEPS = $(patsubst %.c,%.d,$(sort $(SRCS)))
LIBS = $(wildcard ../libs/*/*.a)

INC 	 += -I../include
LIBS_INC += -I../libs/include

CFLAGS += $(INC) $(LIBS_INC) -O3 -Wall \
		  -ffunction-sections -fdata-sections \
		  -Bstatic -fPIC -fPIE -std=c99

ifeq ($(OS), Darwin)
LDFLAGS += -Wl, -dead_strip -lcrypto
else ifeq ($(OS), Linux)
LDFLAGS += -Wl,--gc-sections -lcrypto
endif

DEPFLAGS = -MT $@ -MMD -MP -MF $*.Td
POSTCOMPILE = @mv -f $*.Td $*.d

.PHONY: all clean indent

all: bootimg

bootimg: $(OBJS)
	@$(CC) -o bootimg $(CFLAGS) $(OBJS) $(LDFLAGS) $(LIBS)
	@echo "$@" | xargs -n1

%.o: %.c %.d
	@$(CC) -c $(DEPFLAGS) $(CFLAGS) $< -o $@
	@echo "$@" | xargs -n1 | ts "CC"
	$(POSTCOMPILE)

%.d: ;

clean:
	@rm -f *.o
	@echo "$(OBJS)" | xargs -n1 | ts "clean"
	@rm -f *.d
	@echo "$(DEPS)" | xargs -n1 | ts "clean"
	@rm -f bootimg
	@echo "bootimg" | xargs -n1 | ts "clean"

indent:
	../scripts/Lindent $(wildcard *.[ch])

-include $(DEPS)
