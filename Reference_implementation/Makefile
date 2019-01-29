SUBDIR = qTesla_I qTesla_III_size qTesla_III_speed qTesla_p_I qTesla_p_III


CLEANSUBDIR = $(SUBDIR:%=clean-%)

.PHONY: clean $(SUBDIR) $(CLEANSUBDIR)

clean: $(CLEANSUBDIR)

$(CLEANSUBDIR):
	@echo "===>" $@
		$(MAKE) -C $(@:clean-%=%) clean -i
	@echo "<===" $@
