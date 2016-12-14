// AesKeyWrap.cpp - AES KeyWrap (RFC3394/RFC5649) implementation on Crypto++
// by Ian Kluft
// Copyright (c) 2016 Security Together Corporation http://www.securitytogether.com/
// Contributed to Open Source Crypto++ project by Security Together
// This is Open Source code licensed under the terms of the Boost Software License 1.0
// (like the rest of Crypto++) http://www.boost.org/users/license.html 

#include <iostream>
#include <sstream>
#include <cryptopp/cryptlib.h>
#include <cryptopp/secblock.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include "AesKeyWrap.h"

namespace AesKeyWrap {
// using namespace CryptoPP;

// constants for initial value in primary (RFC3394) and extended (RFC5649) definition
static const char* initialValue3394 = "A6A6A6A6A6A6A6A6";	// from RFC3394 Section 2.2.3.1
static const char* initialValue5649 = "A65959A6"; // from RFC5649 Section 3
// the extended initial value LSB is the message length on octets - not a constant, therefore omitted here

// See the AES Key Wrap definition RFC and update
// * RFC3394 "Advanced Encryption Standard (AES) Key Wrap Algorithm"
//   https://tools.ietf.org/html/rfc3394.html
//   (algorithm outlined in comments below)
// * RFC 5649 "Advanced Encryption Standard (AES) Key Wrap with Padding Algorithm"
//   https://tools.ietf.org/html/rfc5649.html
//   (algorithm not repeated here, relatively minor additions)
//
// algorithm notations from RFC3394:
// AES(K, W)      Encrypt W using the AES codebook with key K
// AES-1(K, W)    Decrypt W using the AES codebook with key K
// MSB(j, W)      Return the most significant j bits of W
// LSB(j, W)      Return the least significant j bits of W
// B1 ^ B2        The bitwise exclusive or (XOR) of B1 and B2
// B1 | B2        Concatenate B1 and B2
// K              The key-encryption key K
// n              The number of 64-bit key data blocks
// s              The number of steps in the wrapping process, s = 6n
// P[i]           The ith plaintext key data block
// C[i]           The ith ciphertext data block
// A              The 64-bit integrity check register
// R[i]           An array of 64-bit registers where i = 0, 1, 2, ..., n
// A[t], R[i][t]  The contents of registers A and R[i] after encryption step t.
// IV             The 64-bit initial value used during the wrapping process.
// 
// RFC5649 adds the following:
// ENC(K,W)       encrypt - synonym for AES(K,W)
// DEC(K,W)       decrypt - synonym for AES-1(K,W)
// m              The number of octets in the key data
// Q[i]           The ith plaintext octet in the key data

// RFC3394 defined the AES KeyWrap encryption (wrap) process as follows (2nd method):
// Inputs:  Plaintext, n 64-bit values {P1, P2, ..., Pn}, and
//             Key, K (the KEK).
//    Outputs: Ciphertext, (n+1) 64-bit values {C0, C1, ..., Cn}.
//    1) Initialize variables.
//        Set A = IV, an initial value (see 2.2.3)
//        For i = 1 to n
//            R[i] = P[i]
//    2) Calculate intermediate values.
//        For j = 0 to 5
//            For i=1 to n
//                B = AES(K, A | R[i])
//                A = MSB(64, B) ^ t where t = (n*j)+i
//                R[i] = LSB(64, B)
//    3) Output the results.
//        Set C[0] = A
//        For i = 1 to n
//            C[i] = R[i]

// RFC3394/RFC5649 key wrap
// inputs: message plain text, key encryption key
// outputs: cipher text
// throws CryptoPP::Exception for errors
void KeyWrap::wrap (
	SecByteBlock plainTextIn,
	SecByteBlock keyEncKeyIn,
	SecByteBlock& cipherOut,
	KeyWrap::KWSpec spec )
{
	// check parameters

	if (spec==KeyWrap::RFC3394) {
		// under RFC3394 plainTextIn must be a multiple of 8 bytes (64-bit blocks)
		if (plainTextIn.size() % 8 != 0) {
			throw CryptoPP::Exception(Exception::INVALID_ARGUMENT,
				"key must be a multiple of 64-bit (8 byte) blocks");
		}
	}
	unsigned long m = plainTextIn.size();
	unsigned long n = m/8;
	if (spec==KeyWrap::RFC5649) {
		// under RFC5649 padding is added to make a multiple of 8 bytes (64-bit blocks)
		if (m%8 != 0) {
			// add 1 block for the missing fraction that was rounded down
			n++;

			// add padding with zero values in unused bytes at end of last block
			SecByteBlock padding(8 - m%8);
			unsigned p;
			for (p=0; p<padding.size(); p++) {
				padding.data()[p] = 0;
			}
			plainTextIn += padding;
			if (plainTextIn.size() % 8 != 0) {
				throw Exception(Exception::OTHER_ERROR,
					"plain text input with padding should be multiple of 8");
			}
		}
	}

	// KEK must be 128, 192 or 256 bits
	if (keyEncKeyIn.size() != 16 && keyEncKeyIn.size() != 24 && keyEncKeyIn.size() != 32) {
		throw CryptoPP::Exception(Exception::INVALID_ARGUMENT,
			"KEK must be 128, 192 or 256 bits (16, 24 or 32 bytes)");
	}

	// step 1: iniatialize algorithm

	// set A = IV (initial value)
	SecByteBlock a;
	if (spec==KeyWrap::RFC3394) {
		// RFC3394 initial value: 64-bit fixed value
		a = hex2sbb(std::string(initialValue3394));
	} else {
		// RFC5649 initial value: 32-bit fixed + 32-bit length
		a = hex2sbb(std::string(initialValue5649))+word2sbb(m);
	}

	// encrypt - either RFC5649 1-block special case or common normal case
	if (spec==KeyWrap::RFC5649 && n==1) {
		// RFC5649 special case for 1-block key
		// steps 2 & 3 abbreviated: C[0] | C[1] = ENC(K, A | P[1])
#if !defined(NDEBUG) && EXTRADEBUG>1
		std::cerr << "enc in : A:" << sbb2hex(a) << " P:" << sbb2hex(plainTextIn) << std::endl;
#endif
		encryptAES(keyEncKeyIn, a+plainTextIn, cipherOut);
#if !defined(NDEBUG) && EXTRADEBUG>1
		std::cerr << "enc out: C:" << sbb2hex(cipherOut) << std::endl;
#endif
	} else {
		// encryption - RFC3394 (all cases) and RFC5649 (more than 1 block key)

		// loop: set R[i] = P[i]
		std::vector<SecByteBlock> r;	// r[] starts from 0 so use i-1 index compared with R[] in algorithm
		r.reserve(n);
		unsigned long i;
		for (i=1; i<=n; i++) { 
#ifdef CRYPTOPP_CXX11
			r.emplace_back(plainTextIn.data()+(i-1)*8, 8);
#else
			r.push_back(SecByteBlock(plainTextIn.data()+(i-1)*8, 8));
#endif
		}

		// step 2: calculate intermediate values
		int j;
		for (j=0; j<=5; j++) {
			for (i=1; i<=n; i++) {
				unsigned long t = n*j+i;	// encryption stage number

#if !defined(NDEBUG) && EXTRADEBUG>=1
				// output A & R for tracking calculation at initial point in each stage
				std::cerr << "enc stage " << t << " A:" << sbb2hex(a) << " R:";
				unsigned k;
				for (k=1; k<=n; k++) { 
					std::cerr << sbb2hex(r[k-1]) << " ";
				}
				std::cerr << std::endl;
#endif

				// B = AES(K, A | R[i])
				SecByteBlock b;
#if !defined(NDEBUG) && EXTRADEBUG>1
				std::cerr << "enc in : A:" << sbb2hex(a) << " R[" << i << "]:" << sbb2hex(r[i-1]) << std::endl;
#endif
				encryptAES(keyEncKeyIn, a+r[i-1], b);
#if !defined(NDEBUG) && EXTRADEBUG>1
				std::cerr << "enc out: B:" << sbb2hex(b) << std::endl;
#endif

				// A = MSB(64, B) ^ t where t = (n*j)+i
				unsigned nbyte;
				for (nbyte=0; nbyte<8; nbyte++) {
					a.data()[nbyte] = b.data()[nbyte]; // MSB of B to A
				}
				// XOR 32-bit integer t into 64-bit A (last 4 bytes)
				a[4] ^= (byte)((t>>24)&255);
				a[5] ^= (byte)((t>>16)&255);
				a[6] ^= (byte)((t>>8)&255);
				a[7] ^= (byte)(t&255);

				// R[i] = LSB(64, B)
				for (nbyte=0; nbyte<8; nbyte++) {
					r[i-1].data()[nbyte] = b.data()[nbyte+8]; // LSB of B to result array
				}
			}
		}

		// step 3: output results
		// Using vector<SecByteBlock> for R in Step 2 reduces the number of copies in the algorithm overall.
		// But it requires some here to assemble the result into one SecByteBlock.

		// Set C[0] = A
		cipherOut = a; // set the result starting with the 
		// For i = 1 to n { C[i] = R[i] }
		for (i=1; i<=n; i++ ) {
			cipherOut += r[i-1]; // append to the result SecByteBlock
		}
	}
}

// RFC3394 defined the AES KeyWrap decryption (unwrap) process as follows (2nd method):
// Inputs:  Ciphertext, (n+1) 64-bit values {C0, C1, ..., Cn}, and
//             Key, K (the KEK).
//    Outputs: Plaintext, n 64-bit values {P0, P1, K, Pn}.
//    1) Initialize variables.
//        Set A = C[0]
//        For i = 1 to n
//            R[i] = C[i]
//    2) Compute intermediate values.
//        For j = 5 to 0
//            For i = n to 1
//                B = AES-1(K, (A ^ t) | R[i]) where t = n*j+i
//                A = MSB(64, B)
//                R[i] = LSB(64, B)
//    3) Output results.
//    If A is an appropriate initial value (see 2.2.3),
//    Then
//        For i = 1 to n
//            P[i] = R[i]
//    Else
//        Return an error

// Note that this code does not err on the side of convenience.
// The correct wrapping spec (KeyWrap::RFC3394 or KeyWrap::RFC5649) must be used to correctly decrypt a wrapped key.
// Though it is possible for the code to offer some help by recognizing the initial value and selecting the correct
// algorithm, that may give too much information to a potential attacker. No such convenience is offered here.

// RFC3394/RFC5649 key unwrap
// inputs: cipher text, key encryption key
// outputs: message plain text
// throws CryptoPP::Exception for errors
void KeyWrap::unwrap (
	SecByteBlock cipherTextIn,
	SecByteBlock keyEncKeyIn,
	SecByteBlock& plainTextOut,
	KeyWrap::KWSpec spec )
{
	// check parameters

	// cipherTextIn must be a multiple of 8 bytes (64-bit blocks)
	if (cipherTextIn.size()%8 != 0) {
		throw CryptoPP::Exception(Exception::INVALID_ARGUMENT,
			"wrapped key must be a multiple of 64-bit (8 byte) blocks");
	}
	unsigned long n = cipherTextIn.size()/8 - 1;	// subtract 1 because A register will be removed from front

	// KEK must be 128, 192 or 256 bits
	if (keyEncKeyIn.size()!=16 && keyEncKeyIn.size()!=24 && keyEncKeyIn.size()!=32) {
		throw CryptoPP::Exception(Exception::INVALID_ARGUMENT,
			"KEK must be 128, 192 or 256 bits (16, 24 or 32 bytes)");
	}

	// decrypt - either RFC5649 1-block special case or common normal case
	SecByteBlock	a;
	std::vector<SecByteBlock>	r;	// r[] starts from 0 so use i-1 index compared with R[] in algorithm
	if (spec==KeyWrap::RFC5649 && n==1) {
		// RFC5649 special case for 1-block key
		// abbreviated steps 2 & 3: A | P[1] = DEC(K, C[0] | C[1])
		SecByteBlock	p;
#if !defined(NDEBUG) && EXTRADEBUG>1
		std::cerr << "dec in : C:" << sbb2hex(cipherTextIn) << std::endl;
#endif
		decryptAES(keyEncKeyIn, cipherTextIn, p);
#if !defined(NDEBUG) && EXTRADEBUG>1
		std::cerr << "dec out: P:" << sbb2hex(p) << std::endl;
		std::cerr.flush();
#endif
		a = SecByteBlock(p.data(), 8);
#ifdef CRYPTOPP_CXX11
		r.emplace_back(p.data()+8, 8);
#else
		r.push_back(SecByteBlock(p.data()+8, 8));
#endif

	} else {
		// decryption - RFC3394 (all cases) and RFC5649 (more than 1 block key)

		// 1) Initialize variables.
		// Set A = C[0]
		a = SecByteBlock(cipherTextIn.data(),8);

		// For i = 1 to n
		//   R[i] = C[i]
		r.reserve(n);
		unsigned long i;
		for (i=1; i<=n; i++) {
#ifdef CRYPTOPP_CXX11
			r.emplace_back(cipherTextIn.data()+(i)*8, 8);
#else
			r.push_back(SecByteBlock(cipherTextIn.data()+(i)*8, 8));
#endif
		}

		// 2) Compute intermediate values.
		// For j = 5 to 0
		int j;
		for (j=5; j>=0; j--) {
			// For i = n to 1
			for (i=n; i>=1; i--) {
				unsigned long t = n*j+i;	// decryption stage number

#if !defined(NDEBUG) && EXTRADEBUG>=1
				// output A & R for tracking calculation at initial point in each stage
				std::cerr << "dec stage " << t << " A:" << sbb2hex(a) << " R:";
				unsigned k;
				for (k=1; k<=n; k++) { 
					std::cerr << sbb2hex(r[k-1]) << " ";
				}
				std::cerr << std::endl;
#endif

				// B = AES-1(K, (A ^ t) | R[i]) where t = n*j+i
				// XOR 32-bit integer t into 64-bit A (last 4 bytes)
				a[4] ^= (byte)((t>>24)&255);
				a[5] ^= (byte)((t>>16)&255);
				a[6] ^= (byte)((t>>8)&255);
				a[7] ^= (byte)(t&255);
				SecByteBlock	b;
#if !defined(NDEBUG) && EXTRADEBUG>1
				std::cerr << "dec in : A:" << sbb2hex(a) << " R[" << i << "]:" << sbb2hex(r[i-1]) << std::endl;
#endif
				decryptAES(keyEncKeyIn, a+r[i-1], b);
#if !defined(NDEBUG) && EXTRADEBUG>1
				std::cerr << "dec out: B:" << sbb2hex(b) << std::endl;
				std::cerr.flush();
#endif

				// A = MSB(64, B)
				//a = SecByteBlock(b.data(), 8);
				unsigned nbyte;
				for (nbyte=0; nbyte<8; nbyte++) {
					a.data()[nbyte] = b.data()[nbyte]; // MSB of B to A
				}

				// R[i] = LSB(64, B)
				//r[i-1] = SecByteBlock(b.data()+8, 8);
				for (nbyte=0; nbyte<8; nbyte++) {
					r[i-1].data()[nbyte] = b.data()[nbyte+8]; // LSB of B to result array
				}
			}
		}
	}

	//    3) Output results.
	//    If A is an appropriate initial value (see 2.2.3),
	//    Then
	//        For i = 1 to n
	//            P[i] = R[i]
	//    Else
	//        Return an error

	// extract initial value from A
	// RFC3394 uses fixed 64-bit value; RFC5649 uses fixed 32-bit value and 32-bit length
	std::string aHex;
	unsigned long length = 0;
	if (spec==KeyWrap::RFC3394) {
		aHex = sbb2hex(a);
	} else {
		aHex = sbb2hex(SecByteBlock(a.data(), 4));
		length = a.data()[7] + (a.data()[6]<<8) + (a.data()[5]<<16) + (a.data()[4]<<24);
	}
#if !defined(NDEBUG) && EXTRADEBUG>0
		std::cerr << "aHex = " << aHex << std::endl;
#endif

	// throw exception if integrity check failed (wrong KEK)
	if ((spec==KeyWrap::RFC3394 && aHex!=initialValue3394)
		|| (spec==KeyWrap::RFC5649 && aHex!=initialValue5649))
	{
		// throw exception
		// note: by definition no decryption results are returned on failure - see RFC3394 or AES-KW spec
		throw CryptoPP::Exception(Exception::DATA_INTEGRITY_CHECK_FAILED, "key unwrap failed");
	}

	// for RFC5649, check message length is valid (fits within received cipher length)
	if (spec==KeyWrap::RFC5649) {
		if ( length > n*8) {
			throw CryptoPP::Exception(Exception::DATA_INTEGRITY_CHECK_FAILED, "message too long");
		}
#if !defined(NDEBUG) && EXTRADEBUG>0
		std::cerr << "length = " << length << std::endl;
#endif
	}

	// if it gets here, key unwrap succeeded - return the result
	plainTextOut.resize(0);
	unsigned i;
	for (i=1; i<=n; i++ ) {
		plainTextOut += r[i-1]; // append to the result SecByteBlock
	}
	if (spec==KeyWrap::RFC5649) {
		// resize buffer to the specified message length
		plainTextOut.resize(length);
	}
}

// convert a 32-bit integer to a SecByteBlock
SecByteBlock KeyWrap::word2sbb(word64 wordIn)
{
	SecByteBlock result(4);
	byte	*ptr = result.data();
	ptr[0] = (byte)((wordIn>>24)&255);
	ptr[1] = (byte)((wordIn>>16)&255);
	ptr[2] = (byte)((wordIn>>8)&255);
	ptr[3] = (byte)(wordIn&255);
	return result;
}

// AES electronic codebook (ECB) encryption
void KeyWrap::encryptAES(SecByteBlock key, SecByteBlock plainIn, SecByteBlock &cipherOut )
{
	ECB_Mode< AES >::Encryption e;
    e.SetKey(key, key.size());
	cipherOut.resize(plainIn.size());
	e.ProcessData(cipherOut.data(), plainIn.data(), plainIn.size());
}

// AES electronic codebook (ECB) decryption
void KeyWrap::decryptAES(SecByteBlock key, SecByteBlock cipherIn, SecByteBlock &plainOut )
{
	ECB_Mode< AES >::Decryption e;
    e.SetKey(key, key.size());
	plainOut.resize(cipherIn.size());
	e.ProcessData(plainOut.data(), cipherIn.data(), cipherIn.size());
}

// convert hex digit to 4-bit integer
// for testing and debug output
int KeyWrap::hexdigit2int(char hexdigit)
{
	if (hexdigit>='0' && hexdigit<='9') {
		return hexdigit - '0';
	} else if (hexdigit>='A' && hexdigit<='F') {
		return hexdigit - 'A' + 10;
	} else if (hexdigit>='a' && hexdigit<='f') {
		return hexdigit - 'a'+10;
	}
	// shouldn't happen if we were given a valid hexadecimal digit character
	// should already have checked with isxdigit() before calling here
	throw CryptoPP::Exception(Exception::INVALID_ARGUMENT, "hexdigit2int: bad hex digit");
}

// convert a string of hexadecimal digits to a SecByteBlock to feed the tests
// for testing and debug output
SecByteBlock KeyWrap::hex2sbb(const std::string &hex)
{
	int length = hex.size();
	if (length%2 != 0) {
		throw CryptoPP::Exception(Exception::INVALID_ARGUMENT, "hex2sbb: odd number of hex digits");
	}
	SecByteBlock	buf(length/2);
	int i;
	for (i=0; i<length/2; i++) {
		std::string hexbytes(hex.substr(i*2,2));
		if (!isxdigit(hexbytes[0]) || !isxdigit(hexbytes[1])) {
			std::ostringstream oss;
			oss << "hex2sbb: non-hexdigit '" << hexbytes << "' in input";
			throw CryptoPP::Exception(Exception::INVALID_ARGUMENT, oss.str());
		}
		buf.data()[i] = (hexdigit2int(hexbytes[0])<<4) + hexdigit2int(hexbytes[1]);
	}
	return buf;
}

// convert a SecByteBlock to a string of hexadecimal digits to check test results
// for testing and debug output
std::string KeyWrap::sbb2hex(const SecByteBlock &sbb)
{
	static const std::string hexdigits = "0123456789ABCDEF";
	std::string result;
	unsigned i;
	for (i=0; i<sbb.size(); i++ ) {
		result += hexdigits[(sbb[i]>>4)&15];
		result += hexdigits[sbb[i]&15];
	}
	return result;
}

} // namespace AesKeyWrap
