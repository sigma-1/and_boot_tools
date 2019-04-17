CC ?= /usr/bin/clang
AR ?= /usr/bin/ar
RM ?= rm -f

CFLAGS = -ffunction-sections -fdata-sections -O3
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
	@$(CC) -o $@ $(CFLAGS) -fPIC -c $< $(INC)
	@echo "$@" | xargs -n1 | ts "CC"
