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

namespace updatable_private_set_intersection {

PrivateIntersectionProtocolPartyOneImpl::
    PrivateIntersectionProtocolPartyOneImpl(
        Context* ctx, const std::vector<std::string>& elements,
        const std::vector<BigNum>& payloads, int32_t modulus_size)  {
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
            // Elements and payloads assignments
            this->elements_ = elements;
            this->new_elements_ = elements;
            this->payloads_ = payloads;
            this->new_payloads_ = payloads;
}

void PrivateIntersectionProtocolPartyOneImpl::UpdateElements(std::vector<std::string> new_elements) {
  this->new_elements_ = new_elements;
  this->elements_.insert(this->elements_.end(), new_elements.begin(), new_elements.end());
}

void PrivateIntersectionProtocolPartyOneImpl::UpdatePayload(std::vector<BigNum> new_payloads) {
  this->new_payloads_ = new_payloads;
  this->payloads_.insert(this->payloads_.end(), new_payloads.begin(), new_payloads.end());
}

Status PrivateIntersectionProtocolPartyOneImpl::Handle(
    const ClientMessage& request,
    MessageSink<ServerMessage>* server_message_sink) {
  if (protocol_finished()) {
    return InvalidArgumentError(
        "PrivateIntersectionSumProtocolServerImpl: Protocol is already "
        "complete.");
  }

  return server_message_sink->Send(server_message);
}

}  // namespace updatable_private_set_intersection
