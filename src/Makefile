# AES KeyWrap (RFC3394/RFC5649) implementation on Crypto++
# src directory makefile
# by Ian Kluft
# Copyright (c) 2016 Security Together Corporation http://www.securitytogether.com/
# Contributed to Open Source Crypto++ project by Security Together
# This is Open Source code licensed under the terms of the Boost Software
# License 1.0 (like the rest of Crypto++)
# http://www.boost.org/users/license.html

# set parameters by build mode (debug/prod)
ifeq "$(BUILDMODE)" "prod"
BUILDMACROS=-DNDEBUG
BUILDOPTS=-O2
else
BUILDMACROS=-UNDEBUG
BUILDOPTS=-g2
endif
export BUILDMODE BUILDMACROS BUILDOPTS

# common compilation and linking settings
CPPLEVEL ?= --std=c++14
CXXFLAGS = -I${SRCDIR}/include $(CPPLEVEL) -Wall -Wextra $(BUILDMACROS) $(BUILDOPTS) 
LDFLAGS = $(CPPLEVEL) $(BUILDOPTS)
LDLIBS = -lcryptopp -lstdc++ 

.PHONY : all
all: debug prod

debug/Makefile: makefile-builddir
	[ -d debug ] || mkdir debug
	cp makefile-builddir $@
prod/Makefile: makefile-builddir
	[ -d prod ] || mkdir prod
	cp makefile-builddir $@

.PHONY : debug
debug: debug/Makefile
	$(MAKE) -C debug all

.PHONY : prod
prod: prod/Makefile
	$(MAKE) BUILDMODE=prod -C prod all

.PHONY : clean
clean: debug/Makefile prod/Makefile
	[ -d debug ] || make -C debug clean
	[ -d prod ] || make -C prod clean

.PHONY : spotless
spotless:
	-rm -rf debug prod

