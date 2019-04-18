CC ?= /usr/bin/clang
AR ?= /usr/bin/ar  -frs
RM ?= rm -f

CFLAGS = -Wall -O3 -ffunction-sections -fdata-sections -Bstatic -fPIC -fPIE -std=c99
EXT = a
LIB = libmincrypt.$(EXT)
SRCS = $(wildcard *.c)
LIB_OBJS = $(patsubst %.c,%.o,$(sort $(SRCS)))
INC  =  -I../include/mincrypt

all: $(LIB)

clean:
	@$(RM) $(LIB_OBJS) $(LIB)
	@echo "$(LIB_OBJS)" | xargs -n1 | ts "clean"

$(LIB):$(LIB_OBJS)
	@$(AR) rcs $@ $^
	@echo "$^" | xargs -n1 | ts "AR"
	@echo "AR $@"

%.o:%.c
	@$(CC) -o $@ $(CFLAGS) -fPIC -fPIE -c $< $(INC)
	@echo "$@" | xargs -n1 | ts "CC"
