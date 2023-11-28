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
        this->ec_group = ec_group.value();
        // ElGamal key pairs
        auto elgamal_key_pair = elgamal::GenerateKeyPair(ec_group).value();
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
  *start_protocol_request.mutable_elgamal_g() = this->elgamal_public_key->g.ToBytesCompressed();
  *start_protocol_request.mutable_elgamal_y() = this->elgamal_public_key->y.ToBytesCompressed();
  *(client_message.mutable_private_intersection_client_message()
        ->mutable_start_protocol_request()) =
      std::move(start_protocol_request.value());
  return client_message_sink->Send(client_message);
}

  Status PrivateIntersectionProtocolPartyZeroImpl::ClientExchange(
    const PrivateIntersectionClientMessage::ServerKeyExchange&server_message) {
  // 1. Retrieve P_1's (g, y)
  ASSIGN_OR_RETURN(ECPoint server_g, this->ec_group->CreateECPoint(server_message.elgamal_g()));
  ASSIGN_OR_RETURN(ECPoint server_y, this->ec_group->CreateECPoint(server_message.elgamal_y()));
  // 2. Generate Threshold ElGamal public key from shares, save it to P_0's member variable
  elgamal::PublicKey server_public_key = absl::WrapUnique(new elgamal::PublicKey(
    {std::move(server_g), std::move(server_y)}));
  std::vector<std::unique_ptr<elgamal::PublicKey>> key_shares;
  key_shares.reserve(2);
  key_shares.push_back(std::move(server_public_key));
  key_shares.push_back(std::move(absl::WrapUnique(this->elgamal_public_key)));
  ASSIGN_OR_RETURN(auto shared_public_key, elgamal::GeneratePublicKeyFromShares(key_shares));
  this->shared_elgamal_public_key = std::move(shared_public_key);
}

  // Start client side processing (for a new day of UPSI)
  StatusOr<PrivateIntersectionClientMessage::ClientRoundOne> 
   PrivateIntersectionProtocolPartyZeroImpl::ClientPreProcessing(std::vector<std::string> elements) {
    // 1. Insert into my own tree
    this->my_crypto_tree.insert(elements);
    // 2. Generate {Path_i}_i
    // 3. ElGamal Encryptor for elements, Threshold Paillier Encryptor for payloads 
    // elements(vector of strings) -> vector of Enc(m) - elgamal Ciphertext instead of ECPoint
    std::vector<elgamal::Ciphertext> encrypted_elements;
    int cnt = elements.size();
    std::unique_ptr<encrypter> key_ptr(new elgamal::PublicKey(this->shared_elgamal_public_key));
    ASSIGN_OR_RETURN(ElGamalEncrypter encrypter, ElGamalEncrypter(this->ec_group, std::move(key_ptr)));
    for (int i = 0; i < cnt; ++i) {
        absl::string_view str = elements[i];
        ASSIGN_OR_RETURN(ECPoint m, this->ec_group->CreateECPoint(str));
        ASSIGN_OR_RETURN(ECPoint g_to_m, this->shared_elgamal_public_key.g.Mul(m)); //g^m
        ASSIGN_OR_RETURN(elgamal::Ciphertext now, encrypter.Encrypt(g_to_m));
        encrypted_elements.push_back(now);
    }
    // 4. Generate Client Round One message (Party 0) to send to Party 1
    PrivateIntersectionSumClientMessage::ClientRoundOne result;
    for (size_t i = 0; i < encrypted_elements.size(); i++) {
      EncryptedElement* element = result.mutable_encrypted_set()->add_elements();
      elgamal::Ciphertext encrypted = encrypted_elements[i];
      // Ciphertext -> Bytes Compressed
      *element->mutable_elgamal_u() = encrypted->u.ToBytesCompressed(); // Ciphertext -> Bytes Compressed
      *element->mutable_elgamal_e() = encrypted->e.ToBytesCompressed(); 
      // TODO: Payload - Paillier
      // StatusOr<BigNum> value = private_paillier_->Encrypt(values_[i]);
      // if (!value.ok()) {
      //   return value.status();
      // }
      // *element->mutable_associated_data() = value.value().ToBytes();
    }

    return result;
  }

  // Complete client side processing (for the same day of UPSI)
  // 1. Partial decryption (ElGamal/Paillier)
  // 2. Update P0's tree
  // 3. Update P1's tree
  // 4. Payload Processing
  Status PrivateInterClientPostProcessing(
    const PrivateIntersectionClientMessage::ServerRoundOne& server_message) {
      // 1. Reconstruct ElGamal ciphertext
      std::vector<elgamal::Ciphertext> partially_decrypted_element;
      for (const EncryptedElement& element :
      server_message.encrypted_set().elements()) {
        ASSIGN_OR_RETURN(ECPoint u, this->ec_group->CreateECPoint(element.elgamal_u()));
        ASSIGN_OR_RETURN(ECPoint e, this->ec_group->CreateECPoint(element.elgamal_e()));
        elgamal::Ciphertext partial_element;
        partial_element->u = u;
        partial_element->e = e;
        partially_decrypted_element.push_back(partial_element);
      }
      // 1. Full decryption on a partial decryption (ElGamal/Paillier)
      std::unique_ptr<encrypter> key_ptr(new elgamal::PrivateKey(this->elgamal_private_key));
      ASSIGN_OR_RETURN(ElGamalEncrypter decrypter, ElGamalDecrypter(this->ec_group, std::move(key_ptr)));
      std::vector<ECPoint> decrypted_element;
      for (size_t i = 0; i < partially_decrypted_element.size(); i++) {
        ASSIGN_OR_RETURN(ECPoint decrypted_ct, decrypter->Decrypt(partially_decrypted_element));
        decrypted_element.push_back(partial_ct);
      }
      // Check if decrypted_element = 0
      // 2. Update P0's treet
      this->my_crypto_tree.insert(decrypted_element);
      // 3. Update P1's tree
      this->other_crypto_tree.replaceNodes(decrypted_element);
      // 4. Payload Processing - TODO
      return OkStatus();
  }


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
    auto maybe_client_key_exchange = ClientKeyExchange(server_message.server_key_exchange());
    if (!maybe_server_key_exchange.ok()) {
      return maybe_server_key_exchange.status();
    }
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
    // TODO: new "protocol_finished" condition based on the number of days n for updatable
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
