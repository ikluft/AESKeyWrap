# AES KeyWrap (RFC3394/RFC5649) implementation on Crypto++
# test directory makefile
# by Ian Kluft
# Copyright (c) 2016 Security Together Corporation http://www.securitytogether.com/
# Contributed to Open Source Crypto++ project by Security Together
# This is Open Source code licensed under the terms of the Boost Software
# License 1.0 (like the rest of Crypto++)
# http://www.boost.org/users/license.html

EXTRADEBUG=-DEXTRADEBUG=0
include $(abspath ..)/makefile-common

CPPLEVELS = 98 03 11 14
TESTDIRS = $(foreach level, $(CPPLEVELS), cpp$(level) cpp$(level)-debug)
TESTMAKEFILES = $(foreach dir, $(TESTDIRS), $(dir)/Makefile)

.PHONY : all
all: $(TESTMAKEFILES)
	for level in $(CPPLEVELS); do \
		$(MAKE) BUILDMODE=prod CPPLEVEL=--std=c++$$level VPATH=$(VPATH):$(CURDIR) -C cpp$$level all; \
		$(MAKE) CPPLEVEL=--std=c++$$level VPATH=$(VPATH):$(CURDIR) -C cpp$$level-debug all; \
	done

.PHONY : test
test: all
	prove --exec /usr/bin/env $(wildcard $(TESTDIRS)/*.t)

.PHONY : clean
clean: $(TESTMAKEFILES)
	-for dir in $(TESTDIRS); do make VPATH=$(VPATH):$(CURDIR) -C $$dir clean; done

.PHONY : spotless
spotless:
ifneq "$(strip $(TESTDIRS))" ""
	-rm -rf $(TESTDIRS)
endif

# test directory dependencies: all permutations of C++ standard level and debug/prod
$(TESTMAKEFILES): makefile-aeskw-testdir
	@[ \! -d $(dir $@) ] && mkdir $(dir $@)
	@cp makefile-aeskw-testdir $@
	@echo "created $@"
