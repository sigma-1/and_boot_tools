OS = $(shell uname)

ifeq ($(OS), Darwin)
LIBINOTIFY_CONFIG = $(shell . libinotify/autogen.sh \
					&& . libinotify/configure)
endif

ifeq ($(OS), Darwin)
all:
	$(LIBINOTIFY_CONFIG)
	$(MAKE) -C libinotify
	$(MAKE) -C libsepol
	$(MAKE) -C libmincrypt
	$(MAKE) -C bootimg
else ifeq ($OS), Linux)
all:
	$(MAKE) -C libsepol
	$(MAKE) -C libmincrypt
	$(MAKE) -C bootimg
endif

ifeq ($(OS), Darwin)
clean:
	$(MAKE) -C libinotify clean
	$(MAKE) -C libsepol clean
	$(MAKE) -C libmincrypt clean
	$(MAKE) -C bootimg clean
else ifeq ($OS), Linux)
clean:
	$(MAKE) -C libsepol clean
	$(MAKE) -C libmincrypt clean
	$(MAKE) -C bootimg clean
endif

indent:
	$(MAKE) -C libsepol $@
	$(MAKE) -C bootimg $@

