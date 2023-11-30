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


#include "absl/memory/memory.h"

#include "upsi/crypto/ec_point_util.h"
#include "upsi/crypto/elgamal.h"
#include "upsi/util/elgamal_proto_util.h"
#include "upsi/util/proto_util.h"
#include "upsi/utils.h"

namespace upsi {

PartyZeroImpl::PartyZeroImpl(
    Context* ctx,
    const std::string pk_fn,
    const std::string sk_fn,
    const std::vector<PartyZeroDataset>& elements,
    int32_t modulus_size,
    int32_t statistical_param,
    int total_days
) {
    this->ctx_ = ctx;

    this->elements_ = elements;

    this->total_days = total_days;


    // set up keys
    auto group = new ECGroup(ECGroup::Create(CURVE_ID, ctx).value());
    this->group = group; // TODO: delete

    auto pk = ProtoUtils::ReadProtoFromFile<ElGamalPublicKey>(pk_fn);
    if (!pk.ok()) {
        std::runtime_error("[PartyZeroImpl] failure in reading shared public key");
    }

    encrypter = std::make_unique<ElGamalEncrypter>(
        this->group, elgamal_proto_util::DeserializePublicKey(this->group, pk.value()).value()
    );

    auto sk = ProtoUtils::ReadProtoFromFile<ElGamalSecretKey>(sk_fn);
    if (!sk.ok()) {
        std::runtime_error("[PartyZeroImpl] failure in reading secret key");
    }

    decrypter = std::make_unique<ElGamalDecrypter>(
        elgamal_proto_util::DeserializePrivateKey(ctx_, sk.value()).value()
    );

}

Status PartyZeroImpl::ClientSendRoundOne(MessageSink<ClientMessage>* sink) {
    // A NEW DAY - update
    this->current_day += 1;
    ClientMessage client_message;

    auto client_round_one = ClientPreProcessing(this->elements_[current_day].first);
    if (!client_round_one.ok()) {
        return client_round_one.status();
    }
    return sink->Send(client_message); //???
}


// Start client side processing (for a new day of UPSI)
StatusOr<PartyZeroMessage::ClientRoundOne> PartyZeroImpl::ClientPreProcessing(
    std::vector<std::string> elements
) {
    // 1. Insert into my own tree
    if(DEBUG) std::cerr<< "P0: Insert into my own tree\n";
    std::vector<std::string> hsh;
    std::vector<CryptoNode<std::string> > plaintxt_nodes = this->my_crypto_tree.insert(elements, hsh);


    std::vector<CryptoNode<Ciphertext> > encrypted_nodes;
    int node_cnt = plaintxt_nodes.size();
    for (int i = 0; i < node_cnt; ++i) {
        int cur_node_size = plaintxt_nodes[i].node.size();
        while(cur_node_size < plaintxt_nodes[i].node_size) {
            plaintxt_nodes[i].node.push_back(GetRandomNumericString(32));
            ++cur_node_size;
        }
        CryptoNode<Ciphertext> new_node(cur_node_size);
        for (int j = 0; j < cur_node_size; ++j) {
            std::string cur_elem = plaintxt_nodes[i].node[j];
            BigNum cur_x_num = this->ctx_->CreateBigNum(NumericString2uint(cur_elem));
            ASSIGN_OR_RETURN(Ciphertext cur_encrypted, encrypter->Encrypt(cur_x_num));
            new_node.addElement(cur_encrypted);
        }
        encrypted_nodes.push_back(std::move(new_node));
    }


    if(DEBUG) std::cerr<< "P0: tree updates\n";
    PartyZeroMessage::ClientRoundOne result;

    for (const std::string &cur_hsh : hsh) {
        result.mutable_hash_set()->add_elements(cur_hsh);
    }

    for (int i = 0; i < node_cnt; ++i) {
        OneNode* cur_node = result.mutable_encrypted_nodes()->add_nodes();
        *(cur_node->mutable_node_size()) = std::to_string(encrypted_nodes[i].node_size);
        for (int j = 0; j < encrypted_nodes[i].node_size; ++j) {
        	EncryptedElement* cur_element = cur_node->add_node_content();
            ASSIGN_OR_RETURN(*cur_element->mutable_elgamal_u(), (encrypted_nodes[i].node[j]).u.ToBytesCompressed());
            ASSIGN_OR_RETURN(*cur_element->mutable_elgamal_e(), (encrypted_nodes[i].node[j]).e.ToBytesCompressed());
    	}
    }

    // 2. Generate {Path_i}_i
    // 3. ElGamal Encryptor for elements, Threshold Paillier Encryptor for payloads

    if(DEBUG) std::cerr<< "P0: compute (y - x) \n";

    int new_elements_cnt = elements.size();

    for (int i = 0; i < new_elements_cnt; ++i) {
        std::vector<Ciphertext> cur_path = this->other_crypto_tree.getPath(elements[i]);
        int cur_cnt = cur_path.size();
        BigNum cur_x_num = this->ctx_->CreateBigNum(NumericString2uint(elements[i]));

        ASSIGN_OR_RETURN(Ciphertext cur_x, encrypter->Encrypt(cur_x_num));
        ASSIGN_OR_RETURN(Ciphertext cur_minus_x, elgamal::Invert(cur_x));

        for (int j = 0; j < cur_cnt; ++j) {
            Ciphertext cur_y = std::move(cur_path[j]);

            // homomorphically subtract x and rerandomize
            ASSIGN_OR_RETURN(Ciphertext y_minus_x, elgamal::Mul(cur_y, cur_minus_x));
            ASSIGN_OR_RETURN(Ciphertext new_y_minus_x, encrypter->ReRandomize(y_minus_x));

            // add this to the message
            EncryptedElement* cur_element = result.mutable_encrypted_set()->add_elements();
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
    std::vector<Ciphertext> encrypted_element;
    for (const EncryptedElement& element :
            server_message.encrypted_set().elements()) {
        ASSIGN_OR_RETURN(ECPoint u, this->group->CreateECPoint(element.elgamal_u()));
        ASSIGN_OR_RETURN(ECPoint e, this->group->CreateECPoint(element.elgamal_e()));
        encrypted_element.push_back(Ciphertext{std::move(u), std::move(e)});
    }

    int ans = 0;
    // 1. Full decryption on a partial decryption (ElGamal/Paillier)
    std::vector<Ciphertext> decrypted_element;
    for (size_t i = 0; i < encrypted_element.size(); i++) {
        ASSIGN_OR_RETURN(ECPoint plaintxt, decrypter->Decrypt(encrypted_element[i]));
        // Check the plaintext
        if (plaintxt.IsPointAtInfinity()) ++ans;
    }

    std::cout<< ans << std::endl;


    // 3. Update P1's tree
    std::vector<std::string> other_hsh;

    for (const std::string& cur_hsh : server_message.hash_set().elements()) {
        other_hsh.push_back(std::move(cur_hsh));
    }

     std::vector<CryptoNode<elgamal::Ciphertext> > new_nodes;
    for (const OneNode& cur_node : server_message.encrypted_nodes().nodes()) {
        CryptoNode<elgamal::Ciphertext> *cur_new_node = new CryptoNode<elgamal::Ciphertext>(std::stoi(cur_node.node_size()));
        for (const EncryptedElement& element : cur_node.node_content()) {
        ASSIGN_OR_RETURN(ECPoint u, this->group->CreateECPoint(element.elgamal_u()));
        ASSIGN_OR_RETURN(ECPoint e, this->group->CreateECPoint(element.elgamal_e()));
        auto ciphertxt = elgamal::Ciphertext{std::move(u), std::move(e)};
        cur_new_node->addElement(ciphertxt);
    }
        new_nodes.push_back(std::move(*cur_new_node));
    }
    this->other_crypto_tree.replaceNodes(other_hsh.size(), new_nodes, other_hsh);

    // 4. Payload Processing - TODO
    // TODO - PRINT RESULTS????
    return OkStatus();
}


Status PartyZeroImpl::Handle(const ServerMessage& response, MessageSink<ClientMessage>* sink) {
    if (protocol_finished()) {
        return InvalidArgumentError("[PartyZeroImpl] protocol is already complete");
    }

    if (!response.has_party_one_msg()) {
        return InvalidArgumentError("[PartyZeroImpl] incorrect message type");
    }

    if (response.party_one_msg().has_server_round_one()) {
        // Handle the server round one message.
        auto postprocess_status = ClientPostProcessing(
            response.party_one_msg().server_round_one()
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

    return InvalidArgumentError("[PartyZeroImpl] received a party one message of unknown type");
}

}  // namespace upsi
