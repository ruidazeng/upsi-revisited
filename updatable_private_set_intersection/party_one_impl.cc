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
        int32_t modulus_size, int32_t statistical_param,
        int total_days)  {
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
            // ThresholdPaillier party_one(&ctx, std::get<1>(keys));
            // this->threshold_paillier = party_one;
            // Elements assignments
            this->elements_ = elements;
            this->new_elements_ = elements;
            // Total days and current day
            this->total_days = total_days;
}

void PrivateIntersectionProtocolPartyOneImpl::UpdateElements(std::vector<std::string> new_elements) {
  this->new_elements_ = new_elements;
  this->elements_.insert(this->elements_.end(), new_elements.begin(), new_elements.end());
}

StatusOr<PrivateIntersectionServerMessage::ServerExchange>
PrivateIntersectionProtocolPartyOneImpl::ServerExchange(const PrivateIntersectionClientMessage::StartProtocolRequest&
                        client_message) {
  // 1. Retrieve P_0's (g, y)
  ASSIGN_OR_RETURN(ECPoint client_g, this->ec_group->CreateECPoint(client_message.elgamal_g()));
  ASSIGN_OR_RETURN(ECPoint client_y, this->ec_group->CreateECPoint(client_message.elgamal_y()));
  // 2. Generate Threshold ElGamal public key from shares, save it to P_1's member variable
  elgamal::PublicKey client_public_key = absl::WrapUnique(new elgamal::PublicKey(
    {std::move(client_g), std::move(client_y)}));
  std::vector<std::unique_ptr<elgamal::PublicKey>> key_shares;
  key_shares.reserve(2);
  key_shares.push_back(std::move(client_public_key));
  key_shares.push_back(std::move(absl::WrapUnique(this->elgamal_public_key)));
  ASSIGN_OR_RETURN(auto shared_public_key, elgamal::GeneratePublicKeyFromShares(key_shares));
  this->shared_elgamal_public_key = std::move(shared_public_key);
  // 3. Generate ServerKeyExchange message using P_1's (g, y)
  PrivateIntersectionClientMessage::ServerKeyExchange result;
  *result.mutable_elgamal_g() = this->elgamal_public_key->g.ToBytesCompressed();
  *result.mutable_elgamal_y() = this->elgamal_public_key->y.ToBytesCompressed();
  return result;
}

// Complete server side processing:
StatusOr<PrivateIntersectionServerMessage::ServerRoundOne>
PrivateIntersectionProtocolPartyOneImpl::ServerProcessing(const PrivateIntersectionClientMessage::ClientRoundOne&
                        client_message, std::vector<std::string> server_elements) {
    // A NEW DAY - update
    this->current_day += 1;
    // 1. Reconstruct encrypted elements (vector of Enc(m), ECPoint)
    std::vector<elgamal::Ciphertext> encrypted_element;
    for (const EncryptedElement& element :
      client_message.encrypted_set().elements()) {
      ASSIGN_OR_RETURN(ECPoint u, this->ec_group->CreateECPoint(element.elgamal_u()));
      ASSIGN_OR_RETURN(ECPoint e, this->ec_group->CreateECPoint(element.elgamal_e()));
      elgamal::Ciphertext enc_element;
      enc_element->u = u;
      enc_element->e = e;
      encrypted_element.push_back(enc_element);
    }
    // 2. Shuffle
    std::random_device rd;
    std::mt19937 gen(rd());
    std::shuffle(encrypted_element.begin(), encrypted_element.end(), gen);
    // 3. Mask with a random exponent
    std::vector<elgamal::Ciphertext> masked_encrypted_element;
    for (size_t i = 0; i < encrypted_element.size(); i++) {
      BigNum a = this->ec_group_->GeneratePrivateKey();  // generate a random exponent
      ASSIGN_OR_RETURN(elgamal::Ciphertext masked_ct, elgamal::Mul(encrypted_element[i], a));
      mask_encrypted_element.push_back(masked_ct);
    }
    // 4. Partial decryption (ElGamal/Paillier)
    std::unique_ptr<encrypter> key_ptr(new elgamal::PrivateKey(this->elgamal_private_key));
    ASSIGN_OR_RETURN(ElGamalEncrypter decrypter, ElGamalDecrypter(this->ec_group, std::move(key_ptr)));
    std::vector<elgamal::Ciphertext> partially_decrypted_element;
    for (size_t i = 0; i < masked_encrypted_element.size(); i++) {
      ASSIGN_OR_RETURN(elgamal::Ciphertext partial_ct, decrypter->PartialDecrypt(masked_encrypted_element[i]));
      partially_decrypted_element.push_back(partial_ct);
    }
    // 5. Update P0's tree
    this->other_crypto_tree.replace_nodes(encrypted_elements);
    // 6. Update P1's tree
    this->my_crypto_tree.insert(server_elements);
    // 7. Generate {Path_i}_i
    // 8. Generate ServerRoundOne back to client
    // Note: maybe need to do the subtraction/comparisions with tree first with input: server_encrypted_element
    PrivateIntersectionServerMessage::ServerRoundOne result;
    for (size_t i = 0; i < partially_decrypted_element.size(); i++) {
      EncryptedElement* partial_element = result.mutable_encrypted_set()->add_elements();
      elgamal::Ciphertext partially_decrypted = partially_decrypted_elements[i];
      // Ciphertext -> Bytes Compressed
      *partial_element->mutable_elgamal_u() = partially_decrypted->u.ToBytesCompressed();
      *partial_element->mutable_elgamal_e() = partially_decrypted->e.ToBytesCompressed();
    }
  return result;
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
    // Handle a protocol start message (with client key exchange).
    auto maybe_server_key_exchange = ServerExchange(client_message.client_key_exchange());
    if (!maybe_server_key_exchange.ok()) {
      return maybe_server_key_exchange.status();
    }
    *(server_message.mutable_private_intersection_server_message()
          ->mutable_server_key_exchange()) =
        std::move(maybe_server_key_exchange.value());
  } else if (client_message.has_client_round_one()) {
    // Handle the client round 1 message.
    auto maybe_server_round_one =
        ServerProcessing(client_message.client_round_one());
    if (!maybe_server_round_one.ok()) {
      return maybe_server_round_two.status();
    }
    *(server_message.mutable_private_intersection_server_message()
          ->mutable_server_round_one()) =
        std::move(maybe_server_round_one.value());
    // Mark the protocol as finished here.
    // change protocol_finished condition for updatable
    if (current_day >= total_days) {
      this->protocol_finished_ = true;
    }
  } else {
    return InvalidArgumentError(
        "PrivateIntersectionProtocolServerImpl: Received a client message "
        "of an unknown type.");
  }

  return server_message_sink->Send(server_message);
}

}  // namespace updatable_private_set_intersection
