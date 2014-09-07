CFLAGS ?= -O2 -g -Wall
LIBS_UDEV = $(shell pkg-config --libs libudev)
LIBS_BLKID = $(shell pkg-config --libs blkid)
ifdef USE_LIBPIPELINE
LIBS_PIPELINE = $(shell pkg-config --libs libpipeline)
CFLAGS += -DUSE_LIBPIPELINE
endif
PROGS = fll_fstab_generator fll_blockdev_detect

all: $(PROGS)

fll_fstab_cmdline.c: fll_fstab_generator.ggo
	gengetopt --input=$< --file-name=fll_fstab_cmdline \
		  --unamed-opts=DEVICES

fll_fstab_cmdline.o: fll_fstab_cmdline.c
	$(CC) $(CFLAGS) $(CPPFLAGS) $(CXXFLAGS) $(LDFLAGS) -c -o $@ $<

fll_fstab_generator: fll_fstab_cmdline.o
	$(CC) $(CFLAGS) $(CPPFLAGS) $(CXXFLAGS) $(LDFLAGS) $< -o $@ $@.c $(LIBS_UDEV) $(LIBS_BLKID)

fll_blockdev_cmdline.c: fll_blockdev_detect.ggo
	gengetopt --input=$< --file-name=fll_blockdev_cmdline \
		  --unamed-opts=ARGS

fll_blockdev_cmdline.o: fll_blockdev_cmdline.c
	$(CC) $(CFLAGS) $(CPPFLAGS) $(CXXFLAGS) $(LDFLAGS) -c -o $@ $<

fll_blockdev_detect: fll_blockdev_cmdline.o
	$(CC) $(CFLAGS) $(CPPFLAGS) $(CXXFLAGS) $(LDFLAGS) $< -o $@ $@.c $(LIBS_UDEV) $(LIBS_PIPELINE)

clean:
	$(RM) $(PROGS) *_cmdline.*
