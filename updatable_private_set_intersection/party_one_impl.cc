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


#include "absl/memory/memory.h"
#include "updatable_private_set_intersection/utils.h"

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
            //auto ec_group = absl::WrapUnique(new ECGroup(ECGroup::Create(kTestCurveId, ctx).value()));
            //this->ec_group = std::move(ec_group);
            auto ec_group = new ECGroup(ECGroup::Create(kTestCurveId, ctx).value());
            this->ec_group = ec_group; //TODO: delete
            // ElGamal key pairs
            auto elgamal_key_pair = elgamal::GenerateKeyPair(*ec_group).value();
            this->elgamal_public_key = std::move(elgamal_key_pair.first);
            this->elgamal_private_key = std::move(elgamal_key_pair.second);
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
  std::unique_ptr<elgamal::PublicKey> client_public_key = absl::WrapUnique(new elgamal::PublicKey(
    {std::move(client_g), std::move(client_y)}));
  std::vector<std::unique_ptr<elgamal::PublicKey>> key_shares;
  key_shares.reserve(2);
  key_shares.push_back(std::move(client_public_key));
  ASSIGN_OR_RETURN(ECPoint g, this->elgamal_public_key->g.Clone());
  ASSIGN_OR_RETURN(ECPoint y, this->elgamal_public_key->y.Clone());
  key_shares.push_back(std::move(absl::WrapUnique(new elgamal::PublicKey{std::move(g), std::move(y)})));
  ASSIGN_OR_RETURN(auto shared_public_key, elgamal::GeneratePublicKeyFromShares(key_shares));
  this->shared_elgamal_public_key = std::move(shared_public_key);
  // 3. Generate ServerKeyExchange message using P_1's (g, y)
  PrivateIntersectionServerMessage::ServerExchange result;
  ASSIGN_OR_RETURN(*result.mutable_elgamal_g(), this->elgamal_public_key->g.ToBytesCompressed());
  ASSIGN_OR_RETURN(*result.mutable_elgamal_y(), this->elgamal_public_key->y.ToBytesCompressed());
  return result;
}

// Complete server side processing:
StatusOr<PrivateIntersectionServerMessage::ServerRoundOne>
PrivateIntersectionProtocolPartyOneImpl::ServerProcessing(const PrivateIntersectionClientMessage::ClientRoundOne&
                        client_message, std::vector<std::string> server_elements) {
    // A NEW DAY - update
    this->current_day += 1;
    
    std::vector<BinaryHash> other_hsh;
    
    for (const std::string& cur_hsh : client_message.hash_set().elements()) {
    	other_hsh.push_back(std::move(cur_hsh));
    }
    /* TODO
    std::vector<elgamal::Ciphertext > encrypted_nodes;
    for (const std::string& cur_node_string : client_message.encrypted_nodes().nodes()) {
    	std::stringstream ss;
    	ss << cur_node_string;
    	CryptoNode<elgamal::Ciphertext> tmp;
    	ss >> tmp;
    	encrypted_nodes.push_back(std::move(tmp));   	
    }
    this->other_crypto_tree.replace_nodes(encrypted_nodes, other_hsh);
    */
    
    //(x-y) from P0
    
    std::vector<elgamal::Ciphertext> encrypted_element;
    for (const EncryptedElement& element :
      client_message.encrypted_set().elements()) {
      ASSIGN_OR_RETURN(ECPoint u, this->ec_group->CreateECPoint(element.elgamal_u()));
      ASSIGN_OR_RETURN(ECPoint e, this->ec_group->CreateECPoint(element.elgamal_e()));
      encrypted_element.push_back(elgamal::Ciphertext{std::move(u), std::move(e)});
    }
    
    //(x-y) from P1
    int new_elements_cnt = server_elements.size();
    
    for (int i = 0; i < new_elements_cnt; ++i) {
    	std::vector<elgamal::Ciphertext> cur_path = this->other_crypto_tree.getPath(server_elements[i]);
    	int cur_cnt = cur_path.size();
    	BigNum cur_x_num = this->ctx_->CreateBigNum(100); //TODO: -elements[i]
    	ASSIGN_OR_RETURN(ECPoint g, this->shared_elgamal_public_key->g.Clone());
  		ASSIGN_OR_RETURN(ECPoint y, this->shared_elgamal_public_key->y.Clone());
    	ASSIGN_OR_RETURN(elgamal::Ciphertext cur_x, 
    			elgamalEncrypt(this->ec_group, std::move(absl::WrapUnique(new elgamal::PublicKey{std::move(g), std::move(y)})), cur_x_num));
    	for (int j = 0; j < cur_cnt; ++j) {
    		elgamal::Ciphertext cur_y = std::move(cur_path[j]);
    		ASSIGN_OR_RETURN(elgamal::Ciphertext y_minus_x, elgamal::Mul(cur_y, cur_x));
    		encrypted_element.push_back(std::move(y_minus_x));
    	}
    }
    
    
    // 2. Shuffle
    std::random_device rd;
    std::mt19937 gen(rd());
    std::shuffle(encrypted_element.begin(), encrypted_element.end(), gen);
    
    // 3. Mask with a random exponent
    std::vector<elgamal::Ciphertext> masked_encrypted_element;
    for (size_t i = 0; i < encrypted_element.size(); i++) {
      BigNum a = this->ctx_->GenerateRandLessThan(this->ctx_->CreateBigNum(1ull << 63));//this->ec_group_->GeneratePrivateKey();  // generate a random exponent
      ASSIGN_OR_RETURN(elgamal::Ciphertext masked_ct, elgamal::Exp(encrypted_element[i], a));
      masked_encrypted_element.push_back(masked_ct);
    }
    
    // 4. Partial decryption (ElGamal/Paillier)
    std::unique_ptr<elgamal::PrivateKey> key_ptr(absl::WrapUnique(new elgamal::PrivateKey{this->elgamal_private_key->x}));
    ElGamalDecrypter decrypter = ElGamalDecrypter(std::move(key_ptr));
    std::vector<elgamal::Ciphertext> partially_decrypted_element;
    for (size_t i = 0; i < masked_encrypted_element.size(); i++) {
      ASSIGN_OR_RETURN(elgamal::Ciphertext partial_ct, decrypter.PartialDecrypt(masked_encrypted_element[i]));
      partially_decrypted_element.push_back(partial_ct);
    }
    // 6. Update P1's tree
    std::vector<BinaryHash> hsh;
    std::vector<CryptoNode<std::string> > plaintxt_nodes = this->my_crypto_tree.insert(server_elements, hsh);
    
    std::vector<CryptoNode<elgamal::Ciphertext> > encrypted_nodes;
    int node_cnt = plaintxt_nodes.size();
    for (int i = 0; i < node_cnt; ++i) {
    	int cur_node_size = plaintxt_nodes[i].node.size();
    	assert(cur_node_size == plaintxt_nodes[i].node_size);
    	CryptoNode<elgamal::Ciphertext> new_node(cur_node_size);
    	for (int j = 0; j < cur_node_size; ++j) {
    		std::string cur_elem = plaintxt_nodes[i].node[j];
    		BigNum cur_x_num = this->ctx_->CreateBigNum(100);//TODO
    		ASSIGN_OR_RETURN(ECPoint g, this->shared_elgamal_public_key->g.Clone());
  			ASSIGN_OR_RETURN(ECPoint y, this->shared_elgamal_public_key->y.Clone());
    		ASSIGN_OR_RETURN(elgamal::Ciphertext cur_encrypted, 
    			elgamalEncrypt(this->ec_group, std::move(absl::WrapUnique(new elgamal::PublicKey{std::move(g), std::move(y)})), cur_x_num));
    		new_node.addElement(cur_encrypted);
    	}
    	encrypted_nodes.push_back(new_node);
    }
    
    PrivateIntersectionServerMessage::ServerRoundOne result;
   	for (const BinaryHash &cur_hsh : hsh) {
   		result.mutable_hash_set()->add_elements(cur_hsh);
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
    
    // 8. Generate ServerRoundOne back to client
    // Note: maybe need to do the subtraction/comparisions with tree first with input: server_encrypted_element
    
    for (size_t i = 0; i < partially_decrypted_element.size(); i++) {
      EncryptedElement* partial_element = result.mutable_encrypted_set()->add_elements();
      elgamal::Ciphertext partially_decrypted = std::move(partially_decrypted_element[i]);
      // Ciphertext -> Bytes Compressed
      ASSIGN_OR_RETURN(*partial_element->mutable_elgamal_u(), partially_decrypted.u.ToBytesCompressed());
      ASSIGN_OR_RETURN(*partial_element->mutable_elgamal_e(), partially_decrypted.e.ToBytesCompressed());
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
    auto maybe_server_key_exchange = ServerExchange(client_message.start_protocol_request());
    if (!maybe_server_key_exchange.ok()) {
      return maybe_server_key_exchange.status();
    }
    *(server_message.mutable_private_intersection_server_message()
          ->mutable_server_key_exchange()) =
        std::move(maybe_server_key_exchange.value());
  } else if (client_message.has_client_round_one()) {
    // Handle the client round 1 message.
    auto maybe_server_round_one =
        ServerProcessing(client_message.client_round_one()); //TODO
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
