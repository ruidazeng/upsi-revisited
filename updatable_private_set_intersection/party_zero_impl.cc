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
      const std::vector<BigNum>& payloads, int32_t modulus_size, int32_t statistical_param) {
        // Assign context
        this->ctx_ = ctx;
        // Use curve_id and context to create EC_Group for ElGamal
        const int kTestCurveId = NID_X9_62_prime256v1;
        auto ec_group = ECGroup::Create(kTestCurveId, &ctx);
        // ElGamal key pairs
        auto elgamal_key_pair = elgamal::GenerateKeyPair(ec_group);
        auto elgamal_public_key_struct = std::move(elgamal_key_pair.first);
        auto elgamal_private_key_struct = std::move(elgamal_key_pair.second);
        this->elgamal_public_key = elgamal_public_key_struct;
        this->elgamal_private_key = elgamal_private_key_struct;
        // Threshold Paillier Key & Object
        // auto threshold_paillier_keys = GenerateThresholdPaillierKeys(&ctx, modulus_length, statistical_param);
        // ThresholdPaillier party_zero(&ctx, std::get<0>(keys));
        // this->threshold_paillier = party_zero;
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
  PrivateIntersectionSumClientMessage::StartProtocolRequest start_protocol_request;
  *start_protocol_request.mutable_elgamal_g() = this->g_.ToBytes();
  *start_protocol_request.mutable_elgamal_y() = this->y_.ToBytes();
  *(client_message.mutable_private_intersection_client_message()
        ->mutable_start_protocol_request()) =
      std::move(start_protocol_request.value());
  return client_message_sink->Send(client_message);
}

// StatusOr<std::unique_ptr<PublicKey>> GeneratePublicKeyFromShares(
//     const std::vector<std::unique_ptr<elgamal::PublicKey>>& shares);

Status PrivateIntersectionProtocolPartyZeroImpl::Handle(
    const ServerMessage& server_message,
    MessageSink<ClientMessage>* client_message_sink) {
  if (protocol_finished()) {
    return InvalidArgumentError(
        "PrivateIntersectionProtocolClientImpl: Protocol is already "
        "complete.");
        
  }
   // Check that the message is a PrivateIntersection protocol message.
  if (!server_message.has_private_intersection_server_message()) {
    return InvalidArgumentError(
        "PrivateIntersectionProtocolClientImpl: Received a message for the "
        "wrong protocol type");
  }

  if (server_message.private_intersection_server_message().
          .has_server_key_exchange()) {
    // Handle the server key exchange message.           
  
  } else if (server_message.private_intersection_server_message()
          .has_server_round_one()) {
    // Handle the server round one message.
    ClientMessage client_message;

    auto maybe_client_round_one =
        ReEncryptSet(server_message.private_intersection_server_message()
                         .server_round_one());
    if (!maybe_client_round_one.ok()) {
      return maybe_client_round_one.status();
    }
    *(client_message.mutable_private_intersection_client_message()
          ->mutable_client_round_one()) =
        std::move(maybe_client_round_one.value());
    return client_message_sink->Send(client_message);
  } else if (server_message.private_intersection_server_message()
                 .has_server_round_two()) {
    // Handle the server round two message.
    auto maybe_result =
        DecryptSum(server_message.private_intersection_server_message()
                       .server_round_two());
    if (!maybe_result.ok()) {
      return maybe_result.status();
    }
    std::tie(intersection_size_, intersection_sum_) =
        std::move(maybe_result.value());
    // Mark the protocol as finished here.
    protocol_finished_ = true;
    return OkStatus();
  }
  // If none of the previous cases matched, we received the wrong kind of
  // message.
  return InvalidArgumentError(
      "PrivateIntersectionProtocolClientImpl: Received a server message "
      "of an unknown type.");

}

}  // namespace updatable_private_set_intersection
