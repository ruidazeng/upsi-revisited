#ifndef upsi_CRYPTO_THRESHOLD_PAILLIER_H_
#define upsi_CRYPTO_THRESHOLD_PAILLIER_H_

#endif  // upsi_CRYPTO_PAILLIER_H_

#include <tuple>

#include "upsi/crypto/big_num.h"
#include "upsi/crypto/context.h"
#include "upsi/crypto/paillier.pb.h"
#include "upsi/util/status.inc"

namespace upsi {

struct ThresholdPaillierPrivateKey {
  BigNum n;
  BigNum share;
};

StatusOr<
    std::pair<ThresholdPaillierPrivateKey, ThresholdPaillierPrivateKey>
> GenerateThresholdPaillierKeys(Context* ctx, int32_t modulus_length, int32_t statistical_param);

class ThresholdPaillier {
    public:
    // Creates a ThresholdPaillier equivalent to the original Paillier cryptosystem
    // (i.e., s = 1) n is the plaintext size and n^2 is the ciphertext size.
    ThresholdPaillier(Context* ctx, const BigNum& n, const BigNum& share);
    ThresholdPaillier(Context* ctx, const ThresholdPaillierPrivateKey& key);


    // ThresholdPaillier is neither copyable nor movable.
    ThresholdPaillier(const ThresholdPaillier&) = delete;
    ThresholdPaillier& operator=(const ThresholdPaillier&) = delete;

    ~ThresholdPaillier();


    // Encrypts the message and returns the ciphertext.
    // Returns INVALID_ARGUMENT status when the message is < 0 or >= n^s.
    StatusOr<BigNum> Encrypt(const BigNum& message) const;

    // partially decrypts the ciphertext with our share and
    //   returns the partial ciphertext as a BigNum
    //
    // Returns INVALID_ARGUMENT status when the ciphertext is < 0 or >= n^(s+1).
    StatusOr<BigNum> PartialDecrypt(const BigNum& ciphertext) const;

    // fully decrypts a ciphertext given the other party's partial ciphertext
    //
    // Returns INVALID_ARGUMENT status when the ciphertext is < 0 or >= n^(s+1).
    StatusOr<BigNum> Decrypt(const BigNum& ciphertext, const BigNum& partial_ciphertext) const;

    private:
    Context* const ctx_;
    const BigNum n_;
    const BigNum share_;
    const BigNum n_squared_;
};
}
