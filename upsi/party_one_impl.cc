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

StatusOr<PartyOneMessage::MessageII> PartyOneImpl::GenerateMessageII(
    const PartyZeroMessage::MessageI& request,
    std::vector<Element> elements
) {
    Timer timer("[Timer] generate MessageII");
    PartyOneMessage::MessageII response;

    Timer update("[Timer] their tree update");
    std::vector<std::string> other_hsh;

    for (const std::string& cur_hsh : request.hash_set().elements()) {
        other_hsh.push_back(std::move(cur_hsh));
    }

    std::vector<CryptoNode<CiphertextAndPayload>> new_nodes;
    for (const TreeNode& cur_node : request.tree_updates().nodes()) {
        auto* node = new CryptoNode<CiphertextAndPayload>(DEFAULT_NODE_SIZE);
        for (const EncryptedElement& element : cur_node.elements()) {
            ASSIGN_OR_RETURN(
                auto ciphertext,
                elgamal_proto_util::DeserializeCiphertext(this->group, element.element())
            );
            auto pair = std::make_pair(
                std::move(ciphertext), 
                this->ctx_->CreateBigNum(element.payload())
            );
            node->addElement(pair);
        }
        new_nodes.push_back(std::move(*node));
    }
    this->other_tree.replaceNodes(other_hsh.size(), new_nodes, other_hsh);
    update.stop();

    Timer cand("[Timer] compute candidates");
    ASSIGN_OR_RETURN(
        std::vector<CiphertextAndPayload> candidates,
        DeserializeCandidates(request.candidates().elements(), this->ctx_, this->group)
    );

    for (size_t i = 0; i < elements.size(); ++i) {
        std::vector<CiphertextAndPayload> path = this->other_tree.getPath(elements[i]);
        ASSIGN_OR_RETURN(Ciphertext x, encrypter->Encrypt(elements[i]));
        ASSIGN_OR_RETURN(Ciphertext minus_x, elgamal::Invert(x));

        for (size_t j = 0; j < path.size(); ++j) {
            Ciphertext y = std::move(path[j].first);
            ASSIGN_OR_RETURN(Ciphertext y_minus_x, elgamal::Mul(y, minus_x));
            candidates.push_back(
                std::make_pair(
                    std::move(y_minus_x), 
                    path[j].second
                )
            );
        }
    }
    cand.stop();

    Timer shuffle("[Timer] shuffle candidates");
    std::random_device rd;
    std::mt19937 gen(rd());
    std::shuffle(candidates.begin(), candidates.end(), gen);
    shuffle.stop();

    Timer masking("[Timer] mask candidates");
    for (size_t i = 0; i < candidates.size(); i++) {
        BigNum mask = this->encrypter->CreateRandomMask();
        ASSIGN_OR_RETURN(
            candidates[i].first, 
            elgamal::Exp(candidates[i].first, mask)
        );
    }
    masking.stop();

    Timer partial("[Timer] part decrypting");
    for (size_t i = 0; i < candidates.size(); i++) {
        auto candidate = response.mutable_candidates()->add_elements();
        ASSIGN_OR_RETURN(candidates[i].first, decrypter->PartialDecrypt(candidates[i].first));
        ASSIGN_OR_RETURN(
            *candidate->mutable_element(),
            elgamal_proto_util::SerializeCiphertext(candidates[i].first)
        );
        // TODO: rerandomize the payload
        *candidate->mutable_payload() = candidates[i].second.ToBytes();
    }
    partial.stop();

    Timer ourupdate("[Timer] our tree update");
    std::vector<std::string> hsh;
    auto updates = this->my_tree.insert(elements, hsh);

    for (size_t i = 0; i < updates.size(); ++i) {
        updates[i].pad(this->ctx_);

        ASSIGN_OR_RETURN(
            CryptoNode<Ciphertext> ciphertext,
            EncryptNode(this->ctx_, this->encrypter.get(), updates[i])
        );

        // attach to outgoing message
        RETURN_IF_ERROR(ciphertext.serialize(response.mutable_tree_updates()->add_nodes()));
    }

    for (const std::string &cur_hsh : hsh) {
        response.mutable_hash_set()->add_elements(cur_hsh);
    }
    ourupdate.stop();

    timer.stop();
    return response;
}

StatusOr<PartyOneMessage::MessageIV> PartyOneImpl::GenerateMessageIV(
    const PartyZeroMessage::MessageIII& msg
) {
    Timer timer("[Timer] generate MessageIV");
    PartyOneMessage::MessageIV res;

    for (auto bytes : msg.payloads()) {
        ASSIGN_OR_RETURN(
            BigNum partial, 
            this->paillier->PartialDecrypt(this->ctx_->CreateBigNum(bytes))
        );
        res.add_payloads()->assign(partial.ToBytes());
    }
    timer.stop();

    return res;
}

Status PartyOneImpl::Handle(const ClientMessage& req, MessageSink<ServerMessage>* sink) {
    if (protocol_finished()) {
        return InvalidArgumentError("[PartyOneImpl] protocol is already complete");
    } else if (!req.has_party_zero_msg()) {
        return InvalidArgumentError("[PartyOneImpl] incorrect message type");
    }
    const PartyZeroMessage& msg = req.party_zero_msg();

    ServerMessage res;

    if (msg.has_message_i()) {
        ASSIGN_OR_RETURN(
            auto message_ii,
            GenerateMessageII(msg.message_i(), datasets[current_day])
        );
        *(res.mutable_party_one_msg()->mutable_message_ii()) = std::move(message_ii);
    } else if (msg.has_message_iii()) {
        ASSIGN_OR_RETURN(
            auto message_iv,
            GenerateMessageIV(msg.message_iii())
        );
        *(res.mutable_party_one_msg()->mutable_message_iv()) = std::move(message_iv);
        std::clog << "[PartyOne] finished day " << this->current_day << std::endl;
        this->current_day += 1;
    } else {
        return InvalidArgumentError(
            "[PartyOneImpl] received a party zero message of unknown type"
        );
    }

    return sink->Send(res);
}

}  // namespace upsi
