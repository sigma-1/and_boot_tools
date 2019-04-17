PREFIX ?= /usr/local/bin

.PHONY: all clean install

all:
	$(MAKE) -C libs
	$(MAKE) -C src

clean:
	$(MAKE) -C libs clean
	$(MAKE) -C src clean

install:
	cp src/bootimg $(PREFIX)
