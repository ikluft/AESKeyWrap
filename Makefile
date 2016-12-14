# AES KeyWrap (RFC3394/RFC5649) implementation on Crypto++
# Makefile for AES KeyWrap for Crypto++
# by Ian Kluft
# Copyright (c) 2016 Security Together Corporation http://www.securitytogether.com/
# Contributed to Open Source Crypto++ project by Security Together
# This is Open Source code licensed under the terms of the Boost Software
# License 1.0 (like the rest of Crypto++)
# http://www.boost.org/users/license.html

# build library from source
.PHONY : all
all: 
	$(MAKE) -C src all

# run tests
.PHONY : test
test: all
	$(MAKE) -C test test

# clean out generated files
.PHONY : clean
clean:
	make -C src clean
	make -C test clean

# remove all generated files including generated makefiles and generated subdirectories
.PHONY : spotless
spotless:
	make -C src spotless
	make -C test spotless

