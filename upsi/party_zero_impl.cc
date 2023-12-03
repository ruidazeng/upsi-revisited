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

Status PartyZeroImpl::SendMessageI(MessageSink<ClientMessage>* sink) {
    ClientMessage msg;

    ASSIGN_OR_RETURN(auto message_i, GenerateMessageI(this->elements_[current_day].first));
    this->current_day += 1;

    *(msg.mutable_party_zero_msg()->mutable_message_i()) = message_i;
    return sink->Send(msg);
}


StatusOr<PartyZeroMessage::MessageI> PartyZeroImpl::GenerateMessageI(
    std::vector<std::string> elements
) {
    Timer timer("[Timer] generate MessageI" );
    PartyZeroMessage::MessageI msg;

    std::clog << "[PartyZeroImpl] inserting our into tree" << std::endl;
    Timer insert("[Timer] our tree update");
    std::vector<std::string> hsh;
    std::vector<CryptoNode<std::string>> plaintext_nodes = this->my_tree.insert(elements, hsh);
    std::vector<CryptoNode<Ciphertext>> encrypted_nodes(plaintext_nodes.size());

    for (size_t i = 0; i < plaintext_nodes.size(); ++i) {
        plaintext_nodes[i].pad();

        ASSIGN_OR_RETURN(
            encrypted_nodes[i],
            plaintext_nodes[i].encrypt(this->ctx_, this->encrypter.get())
        );
    }

    std::clog << "[PartyZeroImpl] prepare message with tree updates" << std::endl;

    for (const std::string &cur_hsh : hsh) {
        msg.mutable_hash_set()->add_elements(cur_hsh);
    }

    for (CryptoNode<Ciphertext>& enode : encrypted_nodes) {
        OneNode* onenode = msg.mutable_encrypted_nodes()->add_nodes();
        RETURN_IF_ERROR(enode.serialize(onenode));
    }
    insert.stop();

    std::clog << "[PartyZeroImpl] computing (y - x)" << std::endl;
    Timer compute("[Timer] computing (y - x)");

    for (size_t i = 0; i < elements.size(); ++i) {
        //std::cerr<< "path...\n";
        std::vector<Ciphertext> path = this->other_tree.getPath(elements[i]);
        //std::cerr<< "path got\n";
        BigNum asnumber = this->ctx_->CreateBigNum(NumericString2uint(elements[i]));
        ASSIGN_OR_RETURN(Ciphertext x, encrypter->Encrypt(asnumber));
        ASSIGN_OR_RETURN(Ciphertext minus_x, elgamal::Invert(x));

        for (size_t j = 0; j < path.size(); ++j) {
            Ciphertext y = std::move(path[j]);

            // homomorphically subtract x and rerandomize
            ASSIGN_OR_RETURN(Ciphertext y_minus_x, elgamal::Mul(y, minus_x));
            ASSIGN_OR_RETURN(Ciphertext randomized, encrypter->ReRandomize(y_minus_x));

            // add this to the message
            RETURN_IF_ERROR(
                encrypter->Serialize(randomized, msg.mutable_encrypted_set()->add_elements())
            );
        }
    }

    compute.stop();
    timer.stop();
    return msg;
}

// Complete client side processing (for the same day of UPSI)
// 1. Partial decryption (ElGamal/Paillier)
// 2. Update P0's tree
// 3. Update P1's tree
// 4. Payload Processing
Status PartyZeroImpl::ClientPostProcessing(const PartyOneMessage::MessageII& server_message) {
    Timer timer("[Timer] process MessageII" );

    Timer results("[Timer] get cardinality");
    // 1. Reconstruct ElGamal ciphertext
    std::vector<elgamal::Ciphertext> candidates;
    for (const EncryptedElement& element : server_message.encrypted_set().elements()) {
        ASSIGN_OR_RETURN(Ciphertext ciphertext, encrypter->Deserialize(element));
        candidates.push_back(std::move(ciphertext));
    }

    for (size_t i = 0; i < candidates.size(); i++) {
        ASSIGN_OR_RETURN(ECPoint plaintext, decrypter->Decrypt(candidates[i]));
        if (plaintext.IsPointAtInfinity()) { this->cardinality++; }
    }
    results.stop();
    Timer update("[Timer] their tree update");

    // 3. Update P1's tree
    std::vector<std::string> other_hsh;

    for (const std::string& cur_hsh : server_message.hash_set().elements()) {
        other_hsh.push_back(std::move(cur_hsh));
    }

    std::vector<CryptoNode<elgamal::Ciphertext>> new_nodes;
    for (const OneNode& cur_node : server_message.encrypted_nodes().nodes()) {
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

    update.stop();
    timer.stop();

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

    if (response.party_one_msg().has_message_ii()) {
        // Handle the server round one message.
        auto postprocess_status = ClientPostProcessing(
            response.party_one_msg().message_ii()
        );
        if (!postprocess_status.ok()) {
            return postprocess_status;
        }
    } else {
        return InvalidArgumentError(
            "[PartyZeroImpl] received a party one message of unknown type"
        );
    }

    protocol_finished_ = (this->current_day == this->total_days);

    return OkStatus();
}

}  // namespace upsi
