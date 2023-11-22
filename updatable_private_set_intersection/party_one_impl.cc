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
        int32_t modulus_size, int32_t statistical_param)  {
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
            // Threshold Paillier Key & Object
            // auto threshold_paillier_keys = GenerateThresholdPaillierKeys(&ctx, modulus_length, statistical_param);
            // ThresholdPaillier party_one(&ctx, std::get<1>(keys));
            // this->threshold_paillier = party_one;
            // Elements assignments
            this->elements_ = elements;
            this->new_elements_ = elements;
}

void PrivateIntersectionProtocolPartyOneImpl::UpdateElements(std::vector<std::string> new_elements) {
  this->new_elements_ = new_elements;
  this->elements_.insert(this->elements_.end(), new_elements.begin(), new_elements.end());
}

StatusOr<PrivateIntersectionServerMessage::ServerKeyExchange>
PrivateIntersectionProtocolPartyOneImpl::ServerKeyExchange(const PrivateIntersectionClientMessage::StartProtocolRequest&
                        client_message) {
  // 1. Retrieve P_0's (g, y)
  BigNum client_g = this->ctx_->CreateBigNum(client_message.elgamal_g());
  BigNum client_y = this->ctx_->CreateBigNum(client_message.elgamal_y());
  // 2. Generate Threshold ElGamal public key from shares, save it to P_1's member variable
  elgamal::PublicKey client_public_key;
  elgamal::PublicKey my_public_key;
  std::vector<std::unique_ptr<elgamal::PublicKey>> key_shares;
  key_shares.reserve(2);
  key_shares.push_back(std::move(client_public_key));
  key_shares.push_back(std::move(my_public_key));
  elgamal::PublicKey shared_public_key = elgamal::GeneratePublicKeyFromShares(key_shares);
  this->shared_g_ = shared_public_key->g;
  this->shared_y_ = shared_public_key->y;
  // 3. Generate ServerKeyExchange message using P_1's (g, y)
  PrivateIntersectionSumClientMessage::ServerKeyExchange result;
  *result.mutable_elgamal_g() = this->g_.ToBytes();
  *result.mutable_elgamal_y() = this->y_.ToBytes();
  return result;
}

StatusOr<PrivateIntersectionServerMessage::ServerRoundOne>
PrivateIntersectionProtocolPartyOneImpl::ServerProcessing(const PrivateIntersectionClientMessage::ClientRoundOne&
                        client_message) {
  return null;
}

Status PrivateIntersectionProtocolPartyOneImpl::Handle(
    const ClientMessage& request,
    MessageSink<ServerMessage>* server_message_sink) {
  if (protocol_finished()) {
    return InvalidArgumentError(
        "PrivateIntersectionProtocolServerImpl: Protocol is already "
        "complete.");
  }
   // Check that the message is a PrivateIntersection protocol message.
  if (!request.has_private_intersection_client_message()) {
    return InvalidArgumentError(
        "PrivateIntersectionProtocolServerImpl: Received a message for the "
        "wrong protocol type");
  }
  const PrivateIntersectionClientMessage& client_message =
      request.private_intersection_client_message();

  ServerMessage server_message;

  if (client_message.has_start_protocol_request()) {
    // Handle a protocol start message.
    auto maybe_server_key_exchange = ServerKeyExchange();
    if (!maybe_server_key_exchange.ok()) {
      return maybe_server_key_exchange.status();
    }
    *(server_message.mutable_private_intersection_server_message()
          ->mutable_server_key_exchange()) =
        std::move(maybe_server_key_exchange.value());
  } else if (client_message.has_client_round_one()) {
    // Handle the client round 1 message.
    auto maybe_server_round_two =
        ComputeIntersection(client_message.client_round_one());
    if (!maybe_server_round_two.ok()) {
      return maybe_server_round_two.status();
    }
    *(server_message.mutable_private_intersection_server_message()
          ->mutable_server_round_two()) =
        std::move(maybe_server_round_two.value());
    // Mark the protocol as finished here.
    protocol_finished_ = true;
  } else {
    return InvalidArgumentError(
        "PrivateIntersectionProtocolServerImpl: Received a client message "
        "of an unknown type.");
  }

  return server_message_sink->Send(server_message);
}

}  // namespace updatable_private_set_intersection
