#ifndef UTILS_HPP
#define UTILS_HPP

#include "upsi/crypto/context.h"
#include "upsi/crypto/elgamal.h"
#include "upsi/crypto/ec_commutative_cipher.h"
#include "upsi/crypto/paillier.h"
#include "emp-sh2pc/emp-sh2pc.h"

#include <algorithm>
#include <bitset>
#include <chrono>
#include <cmath>
#include <iostream>
#include <iterator>
#include <memory>
#include <ostream>
#include <random>
#include <set>
#include <sstream>
#include <string>
#include <tuple>
#include <utility>
#include <vector>
#include <emmintrin.h>

// for printing to the command line in colors
#define RED    "\033[0;31m"
#define GREEN  "\033[0;32m"
#define YELLOW "\033[0;33m"
#define BLUE   "\033[0;34m"
#define CYAN   "\033[0;36m"
#define WHITE  "\033[0;37m"
#define RESET  "\033[0m"

namespace upsi {

    #define CURVE_ID NID_X9_62_prime256v1
	#define DEFAULT_NODE_SIZE 4

    #define ELEMENT_STR_LENGTH 16

	#define DEBUG 1
	
	#define GC_P0 emp::BOB //ALICE
	#define GC_P1 emp::ALICE //BOB

    // type of elements in each party's sets
	typedef BigNum Element;


    // type of an element with its associated payload
    typedef std::pair<Element, BigNum> ElementAndPayload;

    // type of an encrypted element with its (also encrypted) associated payload
    typedef std::pair<BigNum, BigNum> CiphertextAndPayload;

    // protocol functionality options
    enum Functionality { PSI, CA, SUM, SS };

    // these allow us to have a Functionality command line flag
    bool AbslParseFlag(absl::string_view text, Functionality* func, std::string* err);
    std::string AbslUnparseFlag(Functionality func);


	typedef std::string BinaryHash;

    StatusOr<std::vector<CiphertextAndPayload>> DeserializeCiphertextAndPayloads(
        const google::protobuf::RepeatedPtrField<EncryptedElement> serialized,
        Context* ctx,
        ECGroup* group
    );
    
    StatusOr<std::vector<Element>> DeserializeElement(
		const EncryptedSet serialized,
		Context* ctx,
		ECGroup* group
    );

	std::string Byte2Binary(const std::string &byte_hash);
	
	void PadBytes(std::string& str, int len);
	
	void BigNum2block(BigNum x, emp::block* bl, int cnt_block);
	BigNum block2BigNum(emp::block* bl, int cnt_block, Context* ctx);

	template<typename T>
	BinaryHash computeBinaryHash(T &elem);


	template<typename T>
	T elementCopy(const T &elem);
	
	uint64_t bytes2uint64(const std::string& str);
	
	uint64_t generateRandom64bits();
	
	uint64_t BigNum2uint64(const BigNum &x); //mod 2^64

	BinaryHash generateRandomHash();

	void generateRandomHash(int cnt, std::vector<std::string> &hsh);

	StatusOr<elgamal::Ciphertext> elgamalEncrypt(const ECGroup* ec_group, std::unique_ptr<elgamal::PublicKey> public_key, const BigNum& elem);

	//int64_t NumericString2uint(const std::string &str);
	//long long NumericString2ll(const std::string &str);

	std::string GetRandomNumericString(size_t length, bool padding);
    std::string GetRandomSetElement();
    Element GetRandomPadElement(Context* ctx);

    /**
     * class to unify time benchmarking
     */
    class Timer {
        public:
            Timer(std::string msg, std::string color = WHITE);
            void stop();
            void lap();
            void print();
        private:
            std::string message;
            std::string color;
            std::chrono::time_point<std::chrono::high_resolution_clock> start;
            std::vector<std::chrono::duration<float>> laps;
            bool using_laps = false;
    };
}

#endif
