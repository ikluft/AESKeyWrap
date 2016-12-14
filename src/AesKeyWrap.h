// AesKeyWrap.h - AES KeyWrap (RFC3394/RFC5649) implementation on Crypto++
// by Ian Kluft
// Copyright (c) 2016 Security Together Corporation http://www.securitytogether.com/
// Contributed to Open Source Crypto++ project by Security Together
// This is Open Source code licensed under the terms of the Boost Software License 1.0
// (like the rest of Crypto++) http://www.boost.org/users/license.html 

#ifndef AESKEYWRAP_H
#define AESKEYWRAP_H

// AesKeyWrap is written to use Crypto++ ( https://cryptopp.com/ )

#include <cryptopp/cryptlib.h>	// base Crypto++ header
#include <cryptopp/aes.h>		// AES encryption
#include <cryptopp/stdcpp.h>	// includes C++ library headers
#include <cryptopp/secblock.h>	// secure memory allocations & buffers
#include <cryptopp/modes.h>		// for ECB_MODE electronic codebook mode of AES

namespace AesKeyWrap {
using namespace CryptoPP;

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

// KeyWrap class contains wrapping/unwrapping and related utility functions
class KeyWrap : public Algorithm {
	public:
	// Crypto++ library algorithm declaration
	std::string AlgorithmName() const {return "AES-KW";}

	// enumeration of AES KeyWrap RFC specification
	enum KWSpec {RFC3394, RFC5649};

	// key wrap/unwrap functions

	// RFC3394 key wrap
	// inputs: message plain text, key encryption key
	// outputs: cipher text
	// throws CryptoPP::Exception for errors
	static void wrap (
		SecByteBlock plainTextIn,
		SecByteBlock keyEncKeyIn,
		SecByteBlock& cipherTextOut,
		KWSpec spec = RFC5649 );

	// RFC3394 key unwrap
	// inputs: cipher text, key encryption key
	// outputs: message plain text
	// throws CryptoPP::Exception for errors
	static void unwrap (
		SecByteBlock cipherTextIn,
		SecByteBlock keyEncKeyIn,
		SecByteBlock& plainTextOut,
		KWSpec spec = RFC5649 );

	// utility functions

	// convert a 32-bit integer to a SecByteBlock
	static SecByteBlock word2sbb(word64 wordIn);

	// convert hex digit to 4-bit integer - for test/debug
	static int hexdigit2int(char hexdigit);

	// convert a string of hexadecimal digits to a SecByteBlock to feed the tests - for test/debug
	static SecByteBlock hex2sbb(const std::string &hex);

	// convert a SecByteBlock to a string of hexadecimal digits to check test results - for test/debug
	static std::string sbb2hex(const SecByteBlock &sbb);



	private:
	// AES encryption/decryption functions

	// AES encryption/decryption
	static void encryptAES(SecByteBlock key, SecByteBlock plainIn, SecByteBlock &CipherOut );
	static void decryptAES(SecByteBlock key, SecByteBlock cipherIn, SecByteBlock &PlainOut );
};

} // namespace AesKeyWrap
#endif // AESKEYWRAP_H
