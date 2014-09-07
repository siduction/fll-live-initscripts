DIRS := bin man
INIT := $(notdir $(wildcard debian/*.init))

all: $(DIRS:%=all-%)
all-%:
	$(MAKE) -C $* all

clean: $(DIRS:%=clean-%)
clean-%:
	$(MAKE) -C $* clean

distclean: clean

test: $(INIT:%=test-%)
test-%:
	$(info checking $* ...)
	@dash -n debian/$*
	@checkbashisms -p debian/$*
