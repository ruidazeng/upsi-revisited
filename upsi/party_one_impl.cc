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

#include "upsi/party_one_impl.h"

#include "absl/memory/memory.h"

#include "upsi/crypto/ec_point_util.h"
#include "upsi/crypto/elgamal.h"
#include "upsi/util/elgamal_proto_util.h"
#include "upsi/util/proto_util.h"
#include "upsi/utils.h"

namespace upsi {

PartyOneImpl::PartyOneImpl(
    Context* ctx,
    std::string pk_fn,
    std::string sk_fn,
    const std::vector<std::string>& elements,
    int32_t modulus_size,
    int32_t statistical_param,
    int total_days
)  {
    this->ctx_ = ctx;

    this->elements_ = elements;
    this->new_elements_ = elements;

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

void PartyOneImpl::UpdateElements(std::vector<std::string> new_elements) {
    this->new_elements_ = new_elements;
    this->elements_.insert(this->elements_.end(), new_elements.begin(), new_elements.end());
}

// Complete server side processing:
StatusOr<PartyOneMessage::ServerRoundOne> PartyOneImpl::ServerProcessing(
    const PartyZeroMessage::ClientRoundOne& client_message,
    std::vector<std::string> server_elements
) {
    // A NEW DAY - update
    this->current_day += 1;

    //update P0's tree
    std::vector<std::string> other_hsh;

    for (const std::string& cur_hsh : client_message.hash_set().elements()) {
        other_hsh.push_back(std::move(cur_hsh));
    }

    std::vector<CryptoNode<elgamal::Ciphertext> > new_nodes;
    for (const OneNode& cur_node : client_message.encrypted_nodes().nodes()) {
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


    //(x-y) from P0

    std::vector<elgamal::Ciphertext> encrypted_element;
    for (const EncryptedElement& element :
        client_message.encrypted_set().elements()) {
        ASSIGN_OR_RETURN(ECPoint u, this->group->CreateECPoint(element.elgamal_u()));
        ASSIGN_OR_RETURN(ECPoint e, this->group->CreateECPoint(element.elgamal_e()));
        encrypted_element.push_back(elgamal::Ciphertext{std::move(u), std::move(e)});
    }

    //(x-y) from P1
    int new_elements_cnt = server_elements.size();

    for (int i = 0; i < new_elements_cnt; ++i) {
        std::vector<elgamal::Ciphertext> cur_path = this->other_crypto_tree.getPath(server_elements[i]);
        int cur_cnt = cur_path.size();
        BigNum cur_x_num = this->ctx_->CreateBigNum(NumericString2uint(server_elements[i]));

        ASSIGN_OR_RETURN(Ciphertext cur_x, encrypter->Encrypt(cur_x_num));
        ASSIGN_OR_RETURN(Ciphertext cur_minus_x, elgamal::Invert(cur_x));

        for (int j = 0; j < cur_cnt; ++j) {
            elgamal::Ciphertext cur_y = std::move(cur_path[j]);
            ASSIGN_OR_RETURN(elgamal::Ciphertext y_minus_x, elgamal::Mul(cur_y, cur_minus_x));
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
        BigNum a = this->ctx_->GenerateRandLessThan(this->ctx_->CreateBigNum(1ull << 32));//this->group_->GeneratePrivateKey();  // generate a random exponent
        ASSIGN_OR_RETURN(elgamal::Ciphertext masked_ct, elgamal::Exp(encrypted_element[i], a));
        masked_encrypted_element.push_back(std::move(masked_ct));
    }

    // 4. Partial decryption (ElGamal/Paillier)
    std::vector<elgamal::Ciphertext> partially_decrypted_element;
    for (size_t i = 0; i < masked_encrypted_element.size(); i++) {
        ASSIGN_OR_RETURN(elgamal::Ciphertext partial_ct, decrypter->PartialDecrypt(masked_encrypted_element[i]));
        partially_decrypted_element.push_back(std::move(partial_ct));
    }

    // 6. Update P1's tree
    std::vector<std::string> hsh;
    auto plaintxt_nodes = this->my_crypto_tree.insert(server_elements, hsh);

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
            ASSIGN_OR_RETURN(Ciphertext cur_encrypted, encrypter->Encrypt(cur_x_num));
            new_node.addElement(cur_encrypted);
        }
        encrypted_nodes.push_back(std::move(new_node));
    }

    PartyOneMessage::ServerRoundOne result;
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

Status PartyOneImpl::Handle(const ClientMessage& request, MessageSink<ServerMessage>* sink) {
    if (protocol_finished()) {
        return InvalidArgumentError("[PartyOneImpl] protocol is already complete");
    }
    if (!request.has_party_zero_msg()) {
        return InvalidArgumentError("[PartyOneImpl] incorrect message type");
    }
    const PartyZeroMessage& msg = request.party_zero_msg();

    ServerMessage response;

    if (msg.has_client_round_one()) {
        // Handle the client round 1 message.
        std::vector<std::string> server_elements; // TODO
        auto maybe_server_round_one =
            ServerProcessing(msg.client_round_one(), server_elements);
        if (!maybe_server_round_one.ok()) {
            return maybe_server_round_one.status();
        }
        *(response.mutable_party_one_msg()
                ->mutable_server_round_one()) =
            std::move(maybe_server_round_one.value());

        // Mark the protocol as finished here.
        // change protocol_finished condition for updatable
        if (current_day >= total_days) {
            this->protocol_finished_ = true;
        }
    } else {
        return InvalidArgumentError(
            "[PartyOneImpl] received a party zero message of unknown type"
        );
    }

    return sink->Send(response);
}

}  // namespace upsi
