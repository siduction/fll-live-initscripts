DIRS := bin man

all: $(DIRS:%=all-%)
all-%:
	$(MAKE) -C $* all

clean: $(DIRS:%=clean-%)
clean-%:
	$(MAKE) -C $* clean

distclean: clean

test: 
test-%:
	$(info checking $* ...)
	@dash -n debian/$*
	@checkbashisms -p debian/$*
