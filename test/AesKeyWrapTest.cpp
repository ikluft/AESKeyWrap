// AesKeyWrapTest.cpp - tests for AES KeyWrap (RFC3394/RFC5649) implementation on Crypto++
// by Ian Kluft
// Copyright (c) 2016 Security Together Corporation http://www.securitytogether.com/
// This is Open Source code licensed under the terms of the Boost Software License 1.0
// (like the rest of Crypto++) http://www.boost.org/users/license.html 

#include <iostream>
#include <sstream>
#include <string>
#include <cctype>
#include <exception>
#if !defined(NDEBUG)
#include <cstdio>
#endif
#include <cryptopp/cryptlib.h>
#include <cryptopp/secblock.h>
#include <cryptopp/aes.h>
#include "AesKeyWrap.h"
using namespace AesKeyWrap;
using namespace CryptoPP;

// AesKeyWrap is written to use Crypto++ ( https://cryptopp.com/ )
static bool use_tap = true;

// test exception handling
class TestException : std::exception {
	public:
	TestException(std::string r) { reason = r; };
	TestException(char *s) { reason = std::string(s); };
	virtual ~TestException() throw() {};

	const char* what() const throw() {return reason.c_str();}

	private:
	std::string reason;
};

class TestAesKw {
	public:
	TestAesKw(const std::string nameIn, const std::string keyIn, const std::string kekIn, const std::string expectIn, const KeyWrap::KWSpec specIn)
		{name=nameIn; key=keyIn; kek=kekIn; expect=expectIn; spec=specIn;};
	TestAesKw(const TestAesKw& in)
		{name=in.name; key=in.key; kek=in.kek; expect=in.expect; spec=in.spec;};

	std::string	name, key, kek, expect;
	KeyWrap::KWSpec spec;
};

// main() for tests
int main (int argc, char *argv[])
{
	// quick command-line check for TAP (Test Anything Protocol) setting
	if (argc==2) {
		if (strncmp(argv[1],"--notap",7)==0) {
			use_tap = true;
		}
	}
	try {
		// tests defined in RFC3394
		std::vector<TestAesKw> tests;
		tests.push_back(TestAesKw("RFC3394 test case 1", "00112233445566778899AABBCCDDEEFF", "000102030405060708090A0B0C0D0E0F", "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5", KeyWrap::RFC3394));
		tests.push_back(TestAesKw("RFC3394 test case 2", "00112233445566778899AABBCCDDEEFF", "000102030405060708090A0B0C0D0E0F1011121314151617", "96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D", KeyWrap::RFC3394));
		tests.push_back(TestAesKw("RFC3394 test case 3", "00112233445566778899AABBCCDDEEFF", "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7", KeyWrap::RFC3394));
		tests.push_back(TestAesKw("RFC3394 test case 4", "00112233445566778899AABBCCDDEEFF0001020304050607", "000102030405060708090A0B0C0D0E0F1011121314151617", "031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2", KeyWrap::RFC3394));
		tests.push_back(TestAesKw("RFC3394 test case 5", "00112233445566778899AABBCCDDEEFF0001020304050607", "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1", KeyWrap::RFC3394));

		// tests defined in RFC5649
		tests.push_back(TestAesKw("RFC3394 test case 1", "C37B7E6492584340BED12207808941155068F738", "5840DF6E29B02AF1AB493B705BF16EA1AE8338F4DCC176A8", "138BDEAA9B8FA7FC61F97742E72248EE5AE6AE5360D1AE6A5F54F373FA543B6A", KeyWrap::RFC5649));
		tests.push_back(TestAesKw("RFC3394 test case 2", "466F7250617369", "5840DF6E29B02AF1AB493B705BF16EA1AE8338F4DCC176A8", "AFBEB0F07DFBF5419200F2CCB50BB24F", KeyWrap::RFC5649));

		// TAP header
		if (use_tap) {
			std::cout << "1.." << tests.size()*3 << std::endl;
		}

		std::vector<TestAesKw>::iterator	test;
		int testNum=1;
		int passes = 0;
		for (test=tests.begin(); test!=tests.end(); ++test) {
			// initialize
			SecByteBlock keydata(KeyWrap::hex2sbb(test->key));
			SecByteBlock kek(KeyWrap::hex2sbb(test->kek));
			std::string expect(test->expect);
			SecByteBlock wrapped;

			// wrap key
			KeyWrap::wrap(keydata, kek, wrapped, test->spec);

			// print encryption test status
			bool result;
			std::string wrappedstr = KeyWrap::sbb2hex(wrapped);
			result = ( wrappedstr == expect );
			if (result) {
				passes++;
			}
			if (use_tap) {
				std::cout << (result ? "ok" : "not ok") << " " << testNum << " " << test->name << " encryption" << std::endl;
			} else {
				std::cerr << (result ? "PASS" : "FAIL") << " ";
				std::cerr << "key:" << KeyWrap::sbb2hex(keydata) << " (" << keydata.size() << ")" << " ";
				std::cerr << "kek:" << KeyWrap::sbb2hex(kek) << " (" << kek.size() << ")" << " ";
				std::cerr << "wrapped:" << wrappedstr << " (" << wrapped.size() << ")" << std::endl;
			}
			testNum++;

			// unwrap key
			SecByteBlock unwrapped;
			KeyWrap::unwrap(wrapped, kek, unwrapped, test->spec);

			// print decryption test status
			std::string unwrappedstr = KeyWrap::sbb2hex(unwrapped);
			result = (unwrappedstr == test->key);
			if (result) {
				passes++;
			}
			if (use_tap) {
				std::cout << (result ? "ok" : "not ok") << " " << testNum << " " << test->name << " decryption" << std::endl;
			} else {
				std::cerr << (result ? "PASS" : "FAIL") << " ";
				std::cerr << "kek:" << KeyWrap::sbb2hex(kek) << " (" << kek.size() << ")" << " ";
				std::cerr << "unwrapped:" << unwrappedstr << " (" << unwrapped.size() << ")" << std::endl;
			}
			testNum++;

			// test fail-as-expected scenario: reject incorrect cipher
			bool failedAsExpected = false;
			try {
				// modify 1 bit in wrapped cipher SecByteBlock
				wrapped.data()[wrapped.size()-1] ^= 1;

				// this time the decrypt should throw an exception - which we'll catch and mark as passed test
				KeyWrap::unwrap(wrapped, kek, unwrapped, test->spec);

			} catch (CryptoPP::Exception& e) {
				if (e.what() == std::string("key unwrap failed")) {
					failedAsExpected = true;
				} else {
					throw; // not an exception we expected here - send it up the chain
				}
			}
			if (failedAsExpected) {
				passes++;
			}
			if (use_tap) {
				std::cout << (failedAsExpected ? "ok" : "not ok") << " " << testNum << " " << test->name << " reject bad cipher" <<  std::endl;
			} else {
				std::cerr << (failedAsExpected ? "PASS" : "FAIL") << " rejection of modified cipher" << std::endl;
			}
			testNum++;
		}
		return ((passes == testNum-1) ? 0 : (testNum-passes-1));
	} catch (std::exception& e) {
		std::cout.flush();
		std::cerr.flush();
		std::cerr << "exception caught: " << e.what() << std::endl;
		return 1;
	}
}
