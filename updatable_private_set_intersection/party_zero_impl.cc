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

#include "updatable_private_set_intersection/utils.h"

#include "absl/memory/memory.h"

namespace updatable_private_set_intersection {

PrivateIntersectionProtocolPartyZeroImpl::
    PrivateIntersectionProtocolPartyZeroImpl(
      Context* ctx, const std::vector<std::string>& elements,
      const std::vector<BigNum>& payloads, int32_t modulus_size, int32_t statistical_param,
      int total_days) {
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
        // Total days and current day
        this->total_days = total_days;
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
  PrivateIntersectionClientMessage::StartProtocolRequest start_protocol_request;
  // Put P_0's ElGamal public key (g, y) into a message and send it to P_1
  *start_protocol_request.mutable_elgamal_g() = this->elgamal_public_key->g.ToBytesCompressed();
  *start_protocol_request.mutable_elgamal_y() = this->elgamal_public_key->y.ToBytesCompressed();
  *(client_message.mutable_private_intersection_client_message()
        ->mutable_start_protocol_request()) =
      std::move(start_protocol_request.value());
  return client_message_sink->Send(client_message);
}

Status PrivateIntersectionProtocolPartyZeroImpl::ClientSendRoundOne(
  MessageSink<ClientMessage>* client_message_sink) {
    // A NEW DAY - update
    this->current_day += 1;
    ClientMessage client_message;
    PrivateIntersectionClientMessage::ClientRoundOne client_round_one = ClientPreProcessing(this->elements);
    if (!client_round_one.ok()) {
      return client_round_one.status();
    }
    return client_message_sink->Send(client_message);
}


Status PrivateIntersectionProtocolPartyZeroImpl::ClientExchange(
    const PrivateIntersectionServerMessage::ServerExchange&server_message) {
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
    std::vector<BinaryHash> hsh;
    std::vector<CryptoNode<std::string> > plaintxt_nodes = this->my_crypto_tree.insert(elements, hsh);
    
    std::vector<elgamal::Ciphertext > encrypted_nodes;
    int node_cnt = plaintxt_nodes.size();
    for (int i = 0; i < node_cnt; ++i) {
    	int cur_node_size = plaintxt_nodes[i].nodes.size();
    	assert(cur_node_size == plaintxt_nodes[i].node_size);
    	CryptoNode<elgamal::Ciphertext> new_node(cur_node_size);
    	for (int j = 0; j < cur_node_size; ++j) {
    		std::string cur_elem = plaintxt_nodes[i].nodes[j];
    		ASSIGN_OR_RETURN(elgamal::Ciphertext cur_encrypted, 
    			elgamalEncrypt(this->ec_group, this->shared_elgamal_public_key, cur_elem));
    		new_node.addElement(cur_encrypted);
    	}
    	encrypted_nodes.push_back(new_node);
    }
    
    PrivateIntersectionClientMessage::ClientRoundOne result;
    
   	for (const BinaryHash &cur_hsh : hsh) {
   		result.mutable_hash_set().add_elements(hsh[i]);
   	}
   	/*TODO
    for (int i = 0; i < node_cnt; ++i) {
    	strstream ss;
    	std::string cur_node_string;
    	ss << encrypted_nodes[i];
    	ss >> cur_node_string;
    	result.mutable_encrypted_nodes()->add_nodes(cur_node_string);
    }
   	*/
    // 2. Generate {Path_i}_i
    // 3. ElGamal Encryptor for elements, Threshold Paillier Encryptor for payloads 
    
    int new_elements_cnt = elements.size();
    
    for (int i = 0; i < new_elements_cnt; ++i) {
    	std::vector<elgamal::Ciphertext> cur_path = std::move(this->other_crypto_tree.getPath(elements[i]));
    	int cur_cnt = cur_path.size();
    	BigNum cur_x = CreateBigNum; //TODO: -elements[i]
    	for (int j = 0; j < cur_cnt; ++j) {
    		elgamal::Ciphertext cur_y = std::move(cur_path[j]);
    		ASSIGN_OR_RETURN(elgamal::Ciphertext y_minus_x, elgamal::Mul(cur_y, cur_x)); // TODO
    		EncryptedElement* element = result.mutable_encrypted_set()->add_elements();
    		*element->mutable_elgamal_u() = encrypted->u.ToBytesCompressed(); // Ciphertext -> Bytes Compressed
      		*element->mutable_elgamal_e() = encrypted->e.ToBytesCompressed();
    	}
    }
	
    return result;
  }

  // Complete client side processing (for the same day of UPSI)
  // 1. Partial decryption (ElGamal/Paillier)
  // 2. Update P0's tree
  // 3. Update P1's tree
  // 4. Payload Processing
Status PrivateIntersectionProtocolPartyZeroImpl::ClientPostProcessing(
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
    std::unique_ptr<elgamal::PrivateKey> key_ptr(absl::WrapUnique(this->elgamal_private_key);
    ASSIGN_OR_RETURN(ElGamalDecrypter decrypter, ElGamalDecrypter(this->ec_group, std::move(key_ptr)));
      std::vector<ECPoint> decrypted_element;
      for (size_t i = 0; i < partially_decrypted_element.size(); i++) {
        ASSIGN_OR_RETURN(ECPoint decrypted_ct, decrypter->Decrypt(partially_decrypted_element));
        decrypted_element.push_back(decrypted_ct);
      }
      // Check if decrypted_element = 0
      
    // 3. Update P1's tree
    std::vector<BinaryHash> other_hsh;
    
    for (const std::string& cur_hsh : server_message.hash_set().elements()) {
    	other_hsh.push_back(std::move(cur_hsh));
    }
    /*TODO
    std::vector<elgamal::Ciphertext > encrypted_nodes;
    for (const std::string& cur_node_string : server_message.encrypted_nodes().nodes()) {
    	strstream ss;
    	ss << cur_node_string;
    	CryptoNode<elgamal::Ciphertext> tmp;
    	ss >> tmp;
    	encrypted_nodes.push_back(std::move(tmp));   	
    }
    this->other_crypto_tree.replace_nodes(encrypted_nodes, other_hsh);
    */
      // 4. Payload Processing - TODO
      // TODO - PRINT RESULTS????
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
    auto maybe_client_key_exchange = ClientExchange(server_message.server_key_exchange());
    if (!maybe_server_key_exchange.ok()) {
      return maybe_server_key_exchange.status();
    }
  } else if (server_message.private_intersection_server_message()
          .has_server_round_one()) {
    // Handle the server round one message.
    auto postprocess_status = ClientPostProcessing(server_message.private_intersection_server_message()
                         .server_round_one());
    if (!postprocess_status.ok()) {
      return maybe_client_round_one.status();
    }
  }
    // Mark the protocol as finished here.
    // new "protocol_finished" condition based on the number of days n for updatable
    if (this->current_day >= this->total_days) {
      this->protocol_finished_ = true;
      return OkStatus();
    }
  // If none of the previous cases matched, we received the wrong kind of
  // message.
  return InvalidArgumentError(
      "PrivateIntersectionProtocolClientImpl: Received a server message "
      "of an unknown type.");

}

}  // namespace updatable_private_set_intersection
