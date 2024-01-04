#include "upsi/crypto/threshold_paillier.h"

#include "upsi/crypto/big_num.h"
#include "upsi/crypto/context.h"
#include "upsi/crypto/paillier.h"
#include "upsi/util/proto_util.h"
#include "upsi/util/status.inc"

namespace upsi {

StatusOr<
    std::pair<ThresholdPaillierKey, ThresholdPaillierKey>
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

        ThresholdPaillierKey key_one;
        key_one.set_n(n.ToBytes());
        key_one.set_share(sk1.ToBytes());

        ThresholdPaillierKey key_two;
        key_two.set_n(n.ToBytes());
        key_two.set_share(sk2.ToBytes());

        return std::make_pair(std::move(key_one), std::move(key_two));
    }

Status GenerateThresholdPaillierKeys(
    Context* ctx,
    int32_t modulus_length,
    int32_t statistical_param,
    std::string key_zero_fn,
    std::string key_one_fn
) {
    ASSIGN_OR_RETURN(
        auto keys,
        GenerateThresholdPaillierKeys(ctx, modulus_length, statistical_param)
    );
    RETURN_IF_ERROR(ProtoUtils::WriteProtoToFile(std::get<0>(keys), key_zero_fn));
    RETURN_IF_ERROR(ProtoUtils::WriteProtoToFile(std::get<1>(keys), key_one_fn));
    return OkStatus();
}

ThresholdPaillier::~ThresholdPaillier() = default;

ThresholdPaillier::ThresholdPaillier(Context* ctx, const BigNum& n, const BigNum& share)
    : n(n), n_squared_(n * n), ctx_(ctx), share_(share) {
    paillier = std::make_unique<PublicPaillier>(this->ctx_, this->n);
}

ThresholdPaillier::ThresholdPaillier(Context* ctx, const ThresholdPaillierKey& key)
    : ThresholdPaillier(ctx, ctx->CreateBigNum(key.n()), ctx->CreateBigNum(key.share())) { }

StatusOr<BigNum> ThresholdPaillier::Encrypt(const BigNum& message) const {
    return paillier->Encrypt(message);
}


StatusOr<BigNum> ThresholdPaillier::ReRand(const BigNum& ciphertext) const {
    return paillier->ReRand(ciphertext);
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
        return (partial.ModMul(*ours, n_squared_) - ctx_->One()) / n;
    } else {
        return ours.status();
    }
}

BigNum ThresholdPaillier::Add(
    const BigNum& ciphertext1,
    const BigNum& ciphertext2
) const {
  return ciphertext1.ModMul(ciphertext2, n_squared_);
}

}
