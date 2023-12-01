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
    const std::vector<PartyOneDataset>& elements,
    int32_t modulus_size,
    int32_t statistical_param,
    int total_days
)  {
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

// Complete server side processing:
StatusOr<PartyOneMessage::MessageII> PartyOneImpl::GenerateMessageII(
    const PartyZeroMessage::MessageI& request,
    std::vector<std::string> elements
) {
    PartyOneMessage::MessageII response;
    this->current_day += 1;

    std::clog << "[PartyOneImpl] updating other party's tree" << std::endl;
    std::vector<std::string> other_hsh;

    for (const std::string& cur_hsh : request.hash_set().elements()) {
        other_hsh.push_back(std::move(cur_hsh));
    }

    std::vector<CryptoNode<elgamal::Ciphertext>> new_nodes;
    for (const OneNode& cur_node : request.encrypted_nodes().nodes()) {
        auto* node = new CryptoNode<elgamal::Ciphertext>(DEFAULT_NODE_SIZE);
        for (const EncryptedElement& element : cur_node.elements()) {
            ASSIGN_OR_RETURN(
                auto ciphertext,
                this->encrypter->Deserialize(element)
            );
            node->addElement(ciphertext);
        }
        new_nodes.push_back(std::move(*node));
    }
    this->other_tree.replaceNodes(other_hsh.size(), new_nodes, other_hsh);


    std::clog << "[PartyOneImpl] combining candidates" << std::endl;
    std::vector<elgamal::Ciphertext> candidates;
    for (const EncryptedElement& element : request.encrypted_set().elements()) {
        ASSIGN_OR_RETURN(Ciphertext ciphertext, encrypter->Deserialize(element));
        candidates.push_back(std::move(ciphertext));
    }

    for (size_t i = 0; i < elements.size(); ++i) {
        std::vector<Ciphertext> path = this->other_tree.getPath(elements[i]);
        BigNum asnumber = this->ctx_->CreateBigNum(NumericString2uint(elements[i]));
        ASSIGN_OR_RETURN(Ciphertext x, encrypter->Encrypt(asnumber));
        ASSIGN_OR_RETURN(Ciphertext minus_x, elgamal::Invert(x));

        for (size_t j = 0; j < path.size(); ++j) {
            elgamal::Ciphertext y = std::move(path[j]);
            ASSIGN_OR_RETURN(Ciphertext y_minus_x, elgamal::Mul(y, minus_x));
            candidates.push_back(std::move(y_minus_x));
        }
    }

    std::clog << "[PartyOneImpl] shuffling candidates" << std::endl;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::shuffle(candidates.begin(), candidates.end(), gen);

    std::clog << "[PartyOneImpl] masking candidates with random element" << std::endl;
    for (size_t i = 0; i < candidates.size(); i++) {
        BigNum mask = this->encrypter->CreateRandomMask();
        ASSIGN_OR_RETURN(candidates[i], elgamal::Exp(candidates[i], mask));
    }

    std::clog << "[PartyOneImpl] partially decrypting candidates" << std::endl;
    for (size_t i = 0; i < candidates.size(); i++) {
        ASSIGN_OR_RETURN(candidates[i], decrypter->PartialDecrypt(candidates[i]));
        RETURN_IF_ERROR(
            encrypter->Serialize(candidates[i], response.mutable_encrypted_set()->add_elements())
        );
    }

    std::clog << "[PartyOneImpl] inserting our elements into tree" << std::endl;
    std::vector<std::string> hsh;
    auto plaintext_nodes = this->my_tree.insert(elements, hsh);
    std::vector<CryptoNode<elgamal::Ciphertext>> encrypted_nodes(plaintext_nodes.size());

    for (size_t i = 0; i < plaintext_nodes.size(); ++i) {
        plaintext_nodes[i].pad();

        ASSIGN_OR_RETURN(
            encrypted_nodes[i],
            plaintext_nodes[i].encrypt(this->ctx_, this->encrypter.get())
        );
    }

    std::clog << "[PartyOneImpl] prepare message with tree updates" << std::endl;
    for (const std::string &cur_hsh : hsh) {
        response.mutable_hash_set()->add_elements(cur_hsh);
    }

    for (CryptoNode<Ciphertext>& enode : encrypted_nodes) {
        OneNode* onenode = response.mutable_encrypted_nodes()->add_nodes();
        RETURN_IF_ERROR(enode.serialize(onenode));
    }

    return response;
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

    if (msg.has_message_i()) {
        ASSIGN_OR_RETURN(
            auto message_ii,
            GenerateMessageII(msg.message_i(), elements_[current_day])
        );
        *(response.mutable_party_one_msg()->mutable_message_ii()) = std::move(message_ii);
        if (current_day >= total_days) { this->protocol_finished_ = true; }
    } else {
        return InvalidArgumentError(
            "[PartyOneImpl] received a party zero message of unknown type"
        );
    }

    return sink->Send(response);
}

}  // namespace upsi
