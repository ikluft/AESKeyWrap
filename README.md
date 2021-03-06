# AESKeyWrap
AES KeyWrap (RFC3394/RFC5649) implementation for Crypto++ library

Copyright 2016 by Security Together Corporation. This was written by Ian Kluft.
It was released as Open Source by Security Together for contribution to the
Crypto++ library. It is licensed under the same Open Source conditions as
Crypto++, currently the Boost License 1.0.
http://www.boost.org/users/license.html

This is an implementation of the AES (Advanced Encryption Standard) Key Wrap
algorithm defined by the US NIST (National Institute of Standards and
Technology). It is also defined by IETF RFCs 3394 and 5649.

Briefly, AES Key Wrap uses the AES encryption standard to encapsulate some
short information which should be an encryption key and perhaps related
encryption parameters. It has advantages of not needing to consume system
entropy for a random number generator. It has a disadvantage that it is less
efficient and therefore should only be used for a small amount of data. Its
intended use case is to have a key encryption key (KEK), usually a user's
password or passphrase unlock a larger set of encryption parameters which are
then used with a more efficient algorithm to decrypt the rest of a data set.

The technical details can be found as follows:
* NIST AES Key Wrap Specification http://csrc.nist.gov/groups/ST/toolkit/documents/kms/key-wrap.pdf
* RFC 3394 Advanced Encryption Standard (AES) Key Wrap Algorithm http://www.ietf.org/rfc/rfc3394.txt
* RFC 5649 Advanced Encryption Standard (AES) Key Wrap with Padding Algorithm http://www.ietf.org/rfc/rfc5649.txt
* Crypto++ is a C++ cryptography library at https://cryptopp.com/

## Building AESKeyWrap
This is a temporary directory structure for the AESKeyWrap code for evaluation
or actual use until it is (hopefully) accepted and integrated into Crypto++.

It has been tested so far on Linux (Fedora 25 and Ubuntu 16.04) with GNU Make
and the g++ compiler with Crypto++ 5.6.5. To build the debug and production
versions, enter "make" at the top level or the src directory. Use "make debug"
to make only the debug version. Use "make prod" to build only the production
(non-debug) version.

There are known problems compiling this on Crypto++ 5.6.3 due to an error
in an assertion which was fixed in 5.6.4.

## Running tests
The tests from the NIST AES Key Wrap Specification and from RFC3394/RFC5649
have been included for verification of proper operation of the algorithm.
Run "make test" at the top level or in the test directory to run the tests.
It will make multiple subdirectories under the test directory to run the tests
under C++99, C++03, C++11 and C++14.  It also makes separate runs for debug
and prod (production/non-debug) builds.

The tests use /usr/bin/prove which is provided by Perl's Test::Harness, in
order to process TAP (Test Anything Protocol) results from the tests.

A successful test run looked like this. However changes will happen - look
for "PASS" at the bottom.
> prove --exec /usr/bin/env cpp98 cpp98-debug cpp03 cpp03-debug cpp11 cpp11-debug cpp14 cpp14-debug/AesKeyWrapTest.t
> cpp98/AesKeyWrapTest.t ........ ok     
> cpp98-debug/AesKeyWrapTest.t .. ok     
> cpp03/AesKeyWrapTest.t ........ ok     
> cpp03-debug/AesKeyWrapTest.t .. ok     
> cpp11/AesKeyWrapTest.t ........ ok     
> cpp11-debug/AesKeyWrapTest.t .. ok     
> cpp14/AesKeyWrapTest.t ........ ok     
> cpp14-debug/AesKeyWrapTest.t .. ok     
> All tests successful.
> Files=8, Tests=168,  0 wallclock secs ( 0.03 usr  0.01 sys +  0.01 cusr  0.00 csys =  0.05 CPU)
> Result: PASS
