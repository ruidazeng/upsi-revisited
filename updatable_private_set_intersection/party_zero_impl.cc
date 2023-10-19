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

#include "updatable_private_set_intersection/party_zero_impl.h"

#include <algorithm>
#include <iostream>
#include <iterator>
#include <memory>
#include <ostream>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "absl/memory/memory.h"

namespace updatable_private_set_intersection {

PrivateIntersectionProtocolPartyZeroImpl::
    PrivateIntersectionProtocolPartyZeroImpl(
      Context* ctx, const std::vector<std::string>& elements,
      const std::vector<BigNum>& payloads, int32_t modulus_size) {
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

void PrivateIntersectionProtocolPartyZeroImpl::UpdateElements(std::vector<std::string> new_elements) {
  this->new_elements_ = new_elements;
  this->elements_.insert(this->elements_.end(), new_elements.begin(), new_elements.end());
}

void PrivateIntersectionProtocolPartyZeroImpl::UpdatePayload(std::vector<BigNum> new_payloads) {
  this->new_payloads_ = new_payloads;
  this->payloads_.insert(this->payloads_.end(), new_payloads.begin(), new_payloads.end());
}

Status PrivateIntersectionProtocolPartyZeroImpl::StartProtocol(
    MessageSink<ClientMessage>* client_message_sink) {
  ClientMessage client_message;
  *(client_message.mutable_private_intersection_client_message()
        ->mutable_start_protocol_request()) =
      PrivateIntersectionSumMessage::StartProtocolRequest();
  return client_message_sink->Send(client_message);
}

// StatusOr<std::unique_ptr<PublicKey>> GeneratePublicKeyFromShares(
//     const std::vector<std::unique_ptr<elgamal::PublicKey>>& shares);

Status PrivateIntersectionProtocolPartyZeroImpl::Handle(
    const ServerMessage& server_message,
    MessageSink<ClientMessage>* client_message_sink) {
  if (protocol_finished()) {
    return InvalidArgumentError(
        "PrivateIntersectionSumProtocolClientImpl: Protocol is already "
        "complete.");
  }

}

}  // namespace updatable_private_set_intersection
