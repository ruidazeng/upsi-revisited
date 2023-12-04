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

Status PartyZeroImpl::SendMessageI(MessageSink<ClientMessage>* sink) {
    ClientMessage msg;

    std::vector<ElementAndPayload> set;
    for (size_t i = 0; i < this->datasets[current_day].first.size(); i++) {
        set.push_back(std::make_pair(
                this->datasets[current_day].first[i],
                this->datasets[current_day].second[i]
        ));
    }

    ASSIGN_OR_RETURN(auto message_i, GenerateMessageI(set));

    *(msg.mutable_party_zero_msg()->mutable_message_i()) = message_i;
    return sink->Send(msg);
}


StatusOr<PartyZeroMessage::MessageI> PartyZeroImpl::GenerateMessageI(
    std::vector<ElementAndPayload> elements
) {
    Timer timer("[Timer] generate MessageI");
    PartyZeroMessage::MessageI msg;

    std::clog << "[PartyZeroImpl] inserting our into tree" << std::endl;
    Timer insert("[Timer] our tree update");
    std::vector<std::string> hsh;

    std::vector<CryptoNode<ElementAndPayload>> updates = this->my_tree.insert(elements, hsh);

    for (size_t i = 0; i < updates.size(); ++i) {
        updates[i].pad(this->ctx_);

        ASSIGN_OR_RETURN(
            CryptoNode<CiphertextAndPayload> ciphertext,
            EncryptNode(this->ctx_, this->encrypter.get(), this->paillier.get(), updates[i])
        );

        // attach to outgoing message
        RETURN_IF_ERROR(ciphertext.serialize(msg.mutable_tree_updates()->add_nodes()));
    }

    for (const std::string &cur_hsh : hsh) {
        msg.mutable_hash_set()->add_elements(cur_hsh);
    }
    insert.stop();

    std::clog << "[PartyZeroImpl] computing (y - x)" << std::endl;
    Timer compute("[Timer] computing (y - x)");

    for (size_t i = 0; i < elements.size(); ++i) {
        std::vector<Ciphertext> path = this->other_tree.getPath(elements[i].first);
        ASSIGN_OR_RETURN(Ciphertext x, encrypter->Encrypt(elements[i].first));
        ASSIGN_OR_RETURN(Ciphertext minus_x, elgamal::Invert(x));
        ASSIGN_OR_RETURN(BigNum payload, paillier->Encrypt(elements[i].second));

        for (size_t j = 0; j < path.size(); ++j) {
            Ciphertext y = std::move(path[j]);

            // homomorphically subtract x and rerandomize
            ASSIGN_OR_RETURN(Ciphertext y_minus_x, elgamal::Mul(y, minus_x));
            ASSIGN_OR_RETURN(Ciphertext randomized, encrypter->ReRandomize(y_minus_x));

            // add this to the message
            auto candidate = msg.mutable_candidates()->add_elements();
            ASSIGN_OR_RETURN(
                *candidate->mutable_element(),
                elgamal_proto_util::SerializeCiphertext(randomized)
            );
            *candidate->mutable_payload() = payload.ToBytes();
        }
    }

    compute.stop();
    timer.stop();
    return msg;
}

Status PartyZeroImpl::SendMessageIII(
    const PartyOneMessage::MessageII& res,
    MessageSink<ClientMessage>* sink
) {
    Timer timer("[Timer] process MessageII" );

    Timer update("[Timer] their tree update");
    std::vector<std::string> other_hsh;

    for (const std::string& cur_hsh : res.hash_set().elements()) {
        other_hsh.push_back(std::move(cur_hsh));
    }

    std::vector<CryptoNode<Ciphertext>> new_nodes;
    for (const TreeNode& cur_node : res.tree_updates().nodes()) {
        auto* node = new CryptoNode<Ciphertext>(DEFAULT_NODE_SIZE);
        for (const EncryptedElement& element : cur_node.elements()) {
            ASSIGN_OR_RETURN(
                auto ciphertext,
                elgamal_proto_util::DeserializeCiphertext(this->group, element.element())
            );
            node->addElement(ciphertext);
        }
        new_nodes.push_back(std::move(*node));
    }
    this->other_tree.replaceNodes(other_hsh.size(), new_nodes, other_hsh);
    update.stop();

    Timer results("[Timer] generate MessageIII");
    ASSIGN_OR_RETURN(
        std::vector<CiphertextAndPayload> candidates,
        DeserializeCandidates(res.candidates().elements(), this->ctx_, this->group)
    );

    ClientMessage msg;

    ASSIGN_OR_RETURN(
        PartyZeroMessage::MessageIII req,
        GenerateMessageIII(std::move(candidates))
    );
    *(msg.mutable_party_zero_msg()->mutable_message_iii()) = std::move(req);
    results.stop();
    timer.stop();

    return sink->Send(msg);
}


StatusOr<PartyZeroMessage::MessageIII> PartyZeroImpl::GenerateMessageIII(
    std::vector<CiphertextAndPayload> candidates
) {
    PartyZeroMessage::MessageIII req;
    BigNum sum = this->ctx_->Zero();

    for (size_t i = 0; i < candidates.size(); i++) {
        ASSIGN_OR_RETURN(ECPoint plaintext, decrypter->Decrypt(candidates[i].first));
        if (plaintext.IsPointAtInfinity()) { 
            if (sum.IsZero()) {
                sum = candidates[i].second;
            } else {
                sum = paillier->Add(sum, candidates[i].second);
            }
        }
    }

    this->sum_ciphertext = sum;
    req.add_payloads()->assign(sum.ToBytes()); 
    return req;
}

Status PartyZeroImpl::ProcessMessageIV(const PartyOneMessage::MessageIV& msg) {
    for (auto bytes : msg.payloads()) {
        ASSIGN_OR_RETURN(
            BigNum big, 
            this->paillier->Decrypt(this->sum_ciphertext, this->ctx_->CreateBigNum(bytes))
        );
        ASSIGN_OR_RETURN(uint64_t sum, big.ToIntValue());
        this->sum += sum;
    }
    return OkStatus();
}

Status PartyZeroImpl::Handle(const ServerMessage& msg, MessageSink<ClientMessage>* sink) {
    if (protocol_finished()) {
        return InvalidArgumentError("[PartyZeroImpl] protocol is already complete");
    } else if (!msg.has_party_one_msg()) {
        return InvalidArgumentError("[PartyZeroImpl] incorrect message type");
    }

    if (msg.party_one_msg().has_message_ii()) {
        RETURN_IF_ERROR(SendMessageIII(msg.party_one_msg().message_ii(), sink));
    } else if (msg.party_one_msg().has_message_iv()) {
        RETURN_IF_ERROR(ProcessMessageIV(msg.party_one_msg().message_iv()));
        this->current_day += 1;
    } else {
        return InvalidArgumentError(
            "[PartyZeroImpl] received a party one message of unknown type"
        );
    }

    return OkStatus();
}

}  // namespace upsi
