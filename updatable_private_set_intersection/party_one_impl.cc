/*
 * Copyright 2019 Google LLC.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "updatable_private_set_intersection/party_one_impl.h"

#include <algorithm>
#include <iterator>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/memory/memory.h"
#include "updatable_private_set_intersection/crypto/ec_commutative_cipher.h"
#include "updatable_private_set_intersection/crypto/paillier.h"
#include "updatable_private_set_intersection/util/status.inc"

using ::updatable_private_set_intersection::BigNum;
using ::updatable_private_set_intersection::ECCommutativeCipher;

namespace updatable_private_set_intersection {

PrivateIntersectionSumProtocolPartyOneImpl::
    PrivateIntersectionSumProtocolPartyOneImpl(Context* ctx, int32_t modulus_size) {
        // Assign context
        this->ctx_ = ctx;
        // Use curve_id and context to create EC_Group for ElGamal
        const int kTestCurveId = NID_X9_62_prime256v1;
        auto ec_group = ECGroup::Create(kTestCurveId, &ctx);
        // ElGamal key pairs
        auto elgamal_key_pair = elgamal::GenerateKeyPair(ec_group);
        auto elgamal_public_key_struct = std::move(elgamal_key_pair.first);
        auto elgamal_private_key_struct = std::move(elgamal_key_pair.second);
        this->g_ = elgamal_public_key_struct->g;
        this->y_ = elgamal_public_key_struct->y;
        this->x_ = elgamal_private_key_struct->x;
        // Paillier Key Pairs
        BigNum p = ctx->GenerateSafePrime(modulus_length / 2);
        BigNum q = ctx->GenerateSafePrime(modulus_length / 2);
        while (p == q) {
            q = ctx->GenerateSafePrime(modulus_length / 2);
        }
        BigNum n = p * q;
        this->p_ = p;
        this->q_ = q;
        this->n_ = n;
}

}  // namespace updatable_private_set_intersection
