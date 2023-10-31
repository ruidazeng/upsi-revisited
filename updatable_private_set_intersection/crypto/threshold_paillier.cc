#include "updatable_private_set_intersection/crypto/threshold_paillier.h"

#include "updatable_private_set_intersection/crypto/big_num.h"
#include "updatable_private_set_intersection/crypto/context.h"
#include "updatable_private_set_intersection/crypto/paillier.h"
#include "updatable_private_set_intersection/util/status.inc"

namespace updatable_private_set_intersection {

StatusOr<
    std::pair<ThresholdPaillierPrivateKey, ThresholdPaillierPrivateKey>
> GenerateThresholdPaillierKeys(
    Context* ctx,
    int32_t modulus_length,
    int32_t statistical_param
) {
    // factorization of our modulus
    BigNum p = ctx->GenerateSafePrime(modulus_length / 2);
    BigNum q = ctx->GenerateSafePrime(modulus_length / 2);

    // rsa modulus
    BigNum n = p * q;

    // euclid's totient of our modulus
    BigNum phi = n - p - q + ctx->One();

    // randomness to generate the decryption
    BigNum r1 = ctx->GenerateRandLessThan(n);
    BigNum r2 = ctx->GenerateRandLessThan(
        ctx->One().Lshift(modulus_length + statistical_param)
    );

    BigNum r0 = phi * r1 + n * r2;
    BigNum r0_inverse = *(r0.ModInverse(n));

    BigNum d = r1 * phi * r0_inverse;

    if (!d.Mod(phi).IsZero()) {
        return InvalidArgumentError("d != 0 mod phi(n) ");
    }

    if (!d.Mod(n).IsOne()) {
        return InvalidArgumentError("d != 1 mod n ");
    }

    // secret keys
    BigNum sk1 = ctx->GenerateRandLessThan(d);
    BigNum sk2 = d - sk1;

    if (sk1 + sk2 != d) {
        return InvalidArgumentError("Secret keys aren't correctly an additive share of d.");
    }

    ThresholdPaillierPrivateKey key_one = {n, sk1};
    ThresholdPaillierPrivateKey key_two = {n, sk2};

    return std::make_pair(std::move(key_one), std::move(key_two));
}

ThresholdPaillier::~ThresholdPaillier() = default;

ThresholdPaillier::ThresholdPaillier(Context* ctx, const BigNum& n, const BigNum& share)
    : ctx_(ctx), n_(n), share_(share), n_squared_(n * n) { }

ThresholdPaillier::ThresholdPaillier(Context* ctx, const ThresholdPaillierPrivateKey& key)
    : ctx_(ctx), n_(key.n), share_(key.share), n_squared_(key.n * key.n) { }

StatusOr<BigNum> ThresholdPaillier::Encrypt(const BigNum& message) const {
    return PublicPaillier(ctx_, n_).Encrypt(message);
}

StatusOr<BigNum> ThresholdPaillier::PartialDecrypt(const BigNum& c) const {

  if (!c.IsNonNegative()) {
    return InvalidArgumentError(
        "ThresholdPaillier::PartialDecrypt() - Cannot decrypt negative number."
    );
  }
  if (c >= n_squared_) {
    return InvalidArgumentError(
        "ThresholdPaillier::PartialDecrypt() - Ciphertext not smaller than n^(s+1)."
    );
  }

  return c.ModExp(share_, n_squared_);
}
StatusOr<BigNum> ThresholdPaillier::Decrypt(
    const BigNum& c,
    const BigNum& partial
) const {
  if (!c.IsNonNegative()) {
    return InvalidArgumentError(
        "ThresholdPaillier::Decrypt() - Cannot decrypt negative number."
    );
  }
  if (!partial.IsNonNegative()) {
    return InvalidArgumentError(
        "ThresholdPaillier::Decrypt() - Cannot decrypt with negative partial."
    );
  }
  if (c >= n_squared_) {
    return InvalidArgumentError(
        "ThresholdPaillier::Decrypt() - Ciphertext not smaller than n^(s+1)."
    );
  }
  if (partial >= n_squared_) {
    return InvalidArgumentError(
        "ThresholdPaillier::Decrypt() - Partial ciphertext not smaller than n^(s+1)."
    );
  }

  auto ours = PartialDecrypt(c);
  if (ours.ok()) {
      return (partial.ModMul(*ours, n_squared_) - ctx_->One()) / n_;
  } else {
      return ours.status();
  }
}

}
