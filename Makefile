OS = $(shell uname)

ifeq ($(OS), Darwin)
LIBINOTIFY_CONFIG = $(shell . libinotify-kqueue/autogen.sh && . libinotify-kqueue/configure)
endif

ifeq ($(OS), Darwin)
all:
	$(LIBINOTIFY_CONFIG)
	$(MAKE) -C libinotify-kqueue
	$(MAKE) -C libsepol
	$(MAKE) -C bootimg
else ifeq ($OS), Linux)
all:
	$(MAKE) -C libsepol
	$(MAKE) -C bootimg
endif

ifeq ($(OS), Darwin)
clean:
	$(MAKE) -C libinotify-kqueue clean
	$(MAKE) -C libsepol clean
	$(MAKE) -C bootimg clean
else ifeq ($OS), Linux)
clean:
	$(MAKE) -C libsepol clean
	$(MAKE) -C bootimg clean
endif

indent:
	$(MAKE) -C libsepol $@
	$(MAKE) -C bootimg $@

