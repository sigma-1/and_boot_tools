OS = $(shell uname)

ifeq ($(OS), Darwin)
CC ?= /usr/bin/clang
AR ?= /usr/bin/ar
else ifeq ($(OS), Linux))
CC ?= gcc
AR ?= ar
endif

ifeq ($(windir),)
RM = rm -f
else
RM = del
endif

CFLAGS = -I../include -ffunction-sections -O3
EXT = a
LIB = libmincrypt.$(EXT)
LIB_OBJS = dsa_sig.o p256.o p256_ec.o p256_ecdsa.o rsa.o sha.o sha256.o
INC  = -I../include

all: $(LIB)

clean:
	@$(RM) $(LIB_OBJS) $(LIB)
	@echo "$(LIB_OBJS)" | xargs -n1 | ts "clean"

$(LIB):$(LIB_OBJS)
	@$(AR) rcs $@ $^
	@echo "$^" | xargs -n1 | ts "AR"
	@echo "AR $@"

%.o:%.c
	@$(CC) -o $@ $(CFLAGS) -c $< $(INC)
	@echo "$@" | xargs -n1 | ts "CC"
