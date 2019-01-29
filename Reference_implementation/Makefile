SUBDIR = qTesla_I qTesla_III_size qTesla_III_speed qTesla_p_I qTesla_p_III


BUILDSUBDIR = $(SUBDIR:%=build-%)
CLEANSUBDIR = $(SUBDIR:%=clean-%)

.PHONY: clean $(SUBDIR) $(CLEANSUBDIR) $(BUILDSUBDIR) test

all: $(BUILDSUBDIR)

clean: $(CLEANSUBDIR)

test:
	for folder in $(SUBDIR); do \
        echo "===>" $$folder; \
		./$$folder/mytest_sign ; \
        echo "<===" $$folder; \
    done

$(BUILDSUBDIR):
	@echo "===>" $@
		$(MAKE) -C $(@:build-%=%)
	@echo "<===" $@

$(CLEANSUBDIR):
	@echo "===>" $@
		$(MAKE) -C $(@:clean-%=%) clean -i
	@echo "<===" $@
