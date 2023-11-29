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

#include "upsi/party_zero_impl.h"

#include <algorithm>
#include <iostream>
#include <iterator>
#include <memory>
#include <ostream>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "upsi/utils.h"

#include "absl/memory/memory.h"

namespace upsi {

PartyZeroImpl::PartyZeroImpl(
    Context* ctx,
    const std::vector<std::string>& elements,
    const std::vector<BigNum>& payloads,
    int32_t modulus_size,
    int32_t statistical_param,
    int total_days
) {
    // Assign context
    this->ctx_ = ctx;
    // Use curve_id and context to create EC_Group for ElGamal
    const int kTestCurveId = NID_X9_62_prime256v1;
    auto ec_group = new ECGroup(ECGroup::Create(kTestCurveId, ctx).value());
    this->ec_group = ec_group; //TODO: delete
                               // ElGamal key pairs
    auto elgamal_key_pair = elgamal::GenerateKeyPair(*ec_group).value();
    this->elgamal_public_key = std::move(elgamal_key_pair.first);
    this->elgamal_private_key = std::move(elgamal_key_pair.second);
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

void PartyZeroImpl::UpdateElements(std::vector<std::string> new_elements) {
    this->new_elements_ = new_elements;
    this->elements_.insert(this->elements_.end(), new_elements.begin(), new_elements.end());
}

void PartyZeroImpl::UpdatePayloads(std::vector<BigNum> new_payloads) {
    this->new_payloads_ = new_payloads;
    this->payloads_.insert(this->payloads_.end(), new_payloads.begin(), new_payloads.end());
}

Status PartyZeroImpl::StartProtocol(MessageSink<ClientMessage>* client_message_sink) {
    ClientMessage client_message;
    PartyZeroMessage::StartProtocolRequest start_protocol_request;
    // Put P_0's ElGamal public key (g, y) into a message and send it to P_1
    ASSIGN_OR_RETURN(*start_protocol_request.mutable_elgamal_g(), this->elgamal_public_key->g.ToBytesCompressed());
    ASSIGN_OR_RETURN(*start_protocol_request.mutable_elgamal_y(), this->elgamal_public_key->y.ToBytesCompressed());
    *(client_message.mutable_private_intersection_client_message()
            ->mutable_start_protocol_request()) =
        std::move(start_protocol_request);
    return client_message_sink->Send(client_message);
}

Status PartyZeroImpl::ClientSendRoundOne(MessageSink<ClientMessage>* client_message_sink) {
    // A NEW DAY - update
    this->current_day += 1;
    ClientMessage client_message;
    auto client_round_one = ClientPreProcessing(this->elements_);
    if (!client_round_one.ok()) {
        return client_round_one.status();
    }
    return client_message_sink->Send(client_message); //???
}


Status PartyZeroImpl::ClientExchange(const PartyOneMessage::ServerExchange&server_message) {
    // 1. Retrieve P_1's (g, y)
    ASSIGN_OR_RETURN(ECPoint server_g, this->ec_group->CreateECPoint(server_message.elgamal_g()));
    ASSIGN_OR_RETURN(ECPoint server_y, this->ec_group->CreateECPoint(server_message.elgamal_y()));
    // 2. Generate Threshold ElGamal public key from shares, save it to P_0's member variable
    auto server_public_key = absl::WrapUnique(new elgamal::PublicKey(
                {std::move(server_g), std::move(server_y)}));
    std::vector<std::unique_ptr<elgamal::PublicKey>> key_shares;
    key_shares.reserve(2);
    key_shares.push_back(std::move(server_public_key));
    ASSIGN_OR_RETURN(ECPoint g, this->elgamal_public_key->g.Clone());
    ASSIGN_OR_RETURN(ECPoint y, this->elgamal_public_key->y.Clone());
    key_shares.push_back(std::move(absl::WrapUnique(new elgamal::PublicKey{std::move(g), std::move(y)})));
    ASSIGN_OR_RETURN(auto shared_public_key, elgamal::GeneratePublicKeyFromShares(key_shares));
    this->shared_elgamal_public_key = std::move(shared_public_key);
    return OkStatus();
}

// Start client side processing (for a new day of UPSI)
StatusOr<PartyZeroMessage::ClientRoundOne> PartyZeroImpl::ClientPreProcessing(
    std::vector<std::string> elements
) {
    // 1. Insert into my own tree
    std::vector<std::string> hsh;
    std::vector<CryptoNode<std::string> > plaintxt_nodes = this->my_crypto_tree.insert(elements, hsh);

    std::vector<CryptoNode<elgamal::Ciphertext> > encrypted_nodes;
    int node_cnt = plaintxt_nodes.size();
    for (int i = 0; i < node_cnt; ++i) {
        int cur_node_size = plaintxt_nodes[i].node.size();
        while(cur_node_size < plaintxt_nodes[i].node_size) {
            plaintxt_nodes[i].node.push_back(GetRandomNumericString(32));
            ++cur_node_size;
        }
        CryptoNode<elgamal::Ciphertext> new_node(cur_node_size);
        for (int j = 0; j < cur_node_size; ++j) {
            std::string cur_elem = plaintxt_nodes[i].node[j];
            BigNum cur_x_num = this->ctx_->CreateBigNum(NumericString2uint(cur_elem));
            ASSIGN_OR_RETURN(ECPoint g, this->shared_elgamal_public_key->g.Clone());
            ASSIGN_OR_RETURN(ECPoint y, this->shared_elgamal_public_key->y.Clone());
            ASSIGN_OR_RETURN(elgamal::Ciphertext cur_encrypted,
                    elgamalEncrypt(this->ec_group, std::move(absl::WrapUnique(new elgamal::PublicKey{std::move(g), std::move(y)})), cur_x_num));
            new_node.addElement(cur_encrypted);
        }
        encrypted_nodes.push_back(std::move(new_node));
    }


    PartyZeroMessage::ClientRoundOne result;

    for (const std::string &cur_hsh : hsh) {
        result.mutable_hash_set()->add_elements(cur_hsh);
    }

    for (int i = 0; i < node_cnt; ++i) {
        std::string *cur_node_string = static_cast<std::string*>(static_cast<void*>(&encrypted_nodes[i]));
        result.mutable_encrypted_nodes()->add_nodes(*cur_node_string);
    }

    // 2. Generate {Path_i}_i
    // 3. ElGamal Encryptor for elements, Threshold Paillier Encryptor for payloads

    int new_elements_cnt = elements.size();

    for (int i = 0; i < new_elements_cnt; ++i) {
        std::vector<elgamal::Ciphertext> cur_path = this->other_crypto_tree.getPath(elements[i]);
        int cur_cnt = cur_path.size();
        BigNum cur_x_num = this->ctx_->CreateBigNum(NumericString2uint(elements[i]));
        ASSIGN_OR_RETURN(ECPoint g, this->shared_elgamal_public_key->g.Clone());
        ASSIGN_OR_RETURN(ECPoint y, this->shared_elgamal_public_key->y.Clone());
        ASSIGN_OR_RETURN(elgamal::Ciphertext cur_x,
                elgamalEncrypt(this->ec_group, std::move(absl::WrapUnique(new elgamal::PublicKey{std::move(g), std::move(y)})), cur_x_num));
        ASSIGN_OR_RETURN(ECPoint u, cur_x.u.Inverse());
        ASSIGN_OR_RETURN(ECPoint e, cur_x.e.Inverse());
        elgamal::Ciphertext cur_minus_x = elgamal::Ciphertext{std::move(u), std::move(e)};
        for (int j = 0; j < cur_cnt; ++j) {
            elgamal::Ciphertext cur_y = std::move(cur_path[j]);
            ASSIGN_OR_RETURN(elgamal::Ciphertext y_minus_x, elgamal::Mul(cur_y, cur_minus_x));

            //rerandomize
            ASSIGN_OR_RETURN(ECPoint g, this->shared_elgamal_public_key->g.Clone());
            ASSIGN_OR_RETURN(ECPoint y, this->shared_elgamal_public_key->y.Clone());
            ElGamalEncrypter encrypter = ElGamalEncrypter(this->ec_group, std::move(absl::WrapUnique(new elgamal::PublicKey{std::move(g), std::move(y)})));
            ASSIGN_OR_RETURN(elgamal::Ciphertext new_y_minus_x, std::move(encrypter.ReRandomize(y_minus_x)));

            //message
            EncryptedElement* cur_element = result.mutable_encrypted_set()->add_elements();
            // Ciphertext -> Bytes Compressed
            ASSIGN_OR_RETURN(*cur_element->mutable_elgamal_u(), new_y_minus_x.u.ToBytesCompressed());
            ASSIGN_OR_RETURN(*cur_element->mutable_elgamal_e(), new_y_minus_x.e.ToBytesCompressed());
        }
    }

    return result;
}

// Complete client side processing (for the same day of UPSI)
// 1. Partial decryption (ElGamal/Paillier)
// 2. Update P0's tree
// 3. Update P1's tree
// 4. Payload Processing
Status PartyZeroImpl::ClientPostProcessing(const PartyOneMessage::ServerRoundOne& server_message) {
    // 1. Reconstruct ElGamal ciphertext
    std::vector<elgamal::Ciphertext> encrypted_element;
    for (const EncryptedElement& element :
            server_message.encrypted_set().elements()) {
        ASSIGN_OR_RETURN(ECPoint u, this->ec_group->CreateECPoint(element.elgamal_u()));
        ASSIGN_OR_RETURN(ECPoint e, this->ec_group->CreateECPoint(element.elgamal_e()));
        encrypted_element.push_back(elgamal::Ciphertext{std::move(u), std::move(e)});
    }

    int ans = 0;
    // 1. Full decryption on a partial decryption (ElGamal/Paillier)
    std::unique_ptr<elgamal::PrivateKey> key_ptr(absl::WrapUnique(new elgamal::PrivateKey{this->elgamal_private_key->x}));
    ElGamalDecrypter decrypter = ElGamalDecrypter(std::move(key_ptr));
    std::vector<elgamal::Ciphertext> decrypted_element;
    for (size_t i = 0; i < encrypted_element.size(); i++) {
        ASSIGN_OR_RETURN(ECPoint plaintxt, decrypter.Decrypt(encrypted_element[i]));
        // Check the plaintext
        if(plaintxt.IsPointAtInfinity()) ++ans;
    }

    std::cout<< ans << std::endl;


    // 3. Update P1's tree
    std::vector<std::string> other_hsh;

    for (const std::string& cur_hsh : server_message.hash_set().elements()) {
        other_hsh.push_back(std::move(cur_hsh));
    }

    std::vector<CryptoNode<elgamal::Ciphertext> > new_nodes;
    for (const std::string& str : server_message.encrypted_nodes().nodes()) {
        std::string *cur_node_string = new std::string(str);
        CryptoNode<elgamal::Ciphertext> *tmp = static_cast<CryptoNode<elgamal::Ciphertext>* >(static_cast<void*>(cur_node_string));
        new_nodes.push_back(std::move(*tmp));
    }
    this->other_crypto_tree.replaceNodes(other_hsh.size(), new_nodes, other_hsh);

    // 4. Payload Processing - TODO
    // TODO - PRINT RESULTS????
    return OkStatus();
}


Status PartyZeroImpl::Handle(
    const ServerMessage& server_message,
    MessageSink<ClientMessage>* client_message_sink
) {
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

    if (server_message.private_intersection_server_message().has_server_key_exchange()) {
        // Handle the server key exchange message.
        auto maybe_client_key_exchange = ClientExchange(
            server_message.private_intersection_server_message().server_key_exchange()
        );
        if (!maybe_client_key_exchange.ok()) {
            return maybe_client_key_exchange;
        }
    } else if (server_message.private_intersection_server_message().has_server_round_one()) {
        // Handle the server round one message.
        auto postprocess_status = ClientPostProcessing(
            server_message.private_intersection_server_message().server_round_one()
        );
        if (!postprocess_status.ok()) {
            return postprocess_status;
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

}  // namespace upsi
