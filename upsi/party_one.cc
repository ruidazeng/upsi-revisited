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

#include "upsi/party_one.h"

#include "absl/memory/memory.h"

#include "upsi/crypto/ec_point_util.h"
#include "upsi/crypto/elgamal.h"
#include "upsi/util/elgamal_proto_util.h"
#include "upsi/util/proto_util.h"
#include "upsi/utils.h"

namespace upsi {

////////////////////////////////////////////////////////////////////////////////
// WITH PAYLOAD CLASS METHODS
////////////////////////////////////////////////////////////////////////////////

StatusOr<PartyOneMessage::MessageII> PartyOneWithPayload::GenerateMessageII(
    const PartyZeroMessage::MessageI& request,
    std::vector<Element> elements
) {
    Timer timer("[Timer] generate MessageII");
    PartyOneMessage::MessageII response;

    Timer update("[Timer] their tree update");
    RETURN_IF_ERROR(other_tree.Update(this->ctx_, this->group, &request.updates()));
    update.stop();

    Timer cand("[Timer] compute candidates");
    ASSIGN_OR_RETURN(
        std::vector<CiphertextAndPayload> candidates,
        DeserializeCiphertextAndPayloads(request.candidates().elements(), this->ctx_, this->group)
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
            *candidate->mutable_paillier()->mutable_element(),
            elgamal_proto_util::SerializeCiphertext(candidates[i].first)
        );
        // TODO: rerandomize the payload
        *candidate->mutable_paillier()->mutable_payload() = candidates[i].second.ToBytes();
    }
    partial.stop();

    // update our tree
    RETURN_IF_ERROR(my_tree.Update(
        this->ctx_, this->encrypter.get(), elements, response.mutable_updates()
    ));

    timer.stop();
    return response;
}

////////////////////////////////////////////////////////////////////////////////
// CARDINALITY
////////////////////////////////////////////////////////////////////////////////

StatusOr<PartyOneMessage::MessageII> PartyOnePSI::GenerateMessageII(
    const PartyZeroMessage::MessageI& request,
    std::vector<Element> elements
) {
    Timer timer("[Timer] generate MessageII");
    PartyOneMessage::MessageII response;

    Timer update("[Timer] their tree update");
    RETURN_IF_ERROR(other_tree.Update(this->ctx_, this->group, &request.updates()));
    update.stop();

    Timer cand("[Timer] compute candidates");
    ASSIGN_OR_RETURN(
        auto candidates,
        DeserializeCiphertextAndElGamals(request.candidates().elements(), this->group)
    );

    for (size_t i = 0; i < elements.size(); ++i) {
        std::vector<Ciphertext> path = this->other_tree.getPath(elements[i]);
        ASSIGN_OR_RETURN(Ciphertext x, encrypter->Encrypt(elements[i]));
        ASSIGN_OR_RETURN(Ciphertext minus_x, elgamal::Invert(x));

        for (size_t j = 0; j < path.size(); ++j) {
            Ciphertext y = std::move(path[j]);
            ASSIGN_OR_RETURN(Ciphertext y_minus_x, elgamal::Mul(y, minus_x));
            candidates.push_back(std::make_pair(
                std::move(y_minus_x), std::move(y)
            ));
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
        BigNum alpha = this->encrypter->CreateRandomMask();
        BigNum beta = this->encrypter->CreateRandomMask();
        ASSIGN_OR_RETURN(
            candidates[i].first, 
            elgamal::Exp(candidates[i].first, alpha)
        );
        ASSIGN_OR_RETURN(
            Ciphertext mask,
            elgamal::Exp(candidates[i].first, beta)
        );
        ASSIGN_OR_RETURN(
            candidates[i].second,
            elgamal::Mul(candidates[i].second, mask)
        );
    }
    masking.stop();

    Timer partial("[Timer] part decrypting");
    for (size_t i = 0; i < candidates.size(); i++) {
        auto candidate = response.mutable_candidates()->add_elements();
        ASSIGN_OR_RETURN(candidates[i].first, decrypter->PartialDecrypt(candidates[i].first));
        ASSIGN_OR_RETURN(candidates[i].second, decrypter->PartialDecrypt(candidates[i].second));
        ASSIGN_OR_RETURN(
            *candidate->mutable_elgamal()->mutable_element(),
            elgamal_proto_util::SerializeCiphertext(candidates[i].first)
        );
        ASSIGN_OR_RETURN(
            *candidate->mutable_elgamal()->mutable_payload(),
            elgamal_proto_util::SerializeCiphertext(candidates[i].second)
        );
    }
    partial.stop();

    // update our tree
    RETURN_IF_ERROR(my_tree.Update(
        this->ctx_, this->encrypter.get(), elements, response.mutable_updates()
    ));

    timer.stop();
    return response;
}


////////////////////////////////////////////////////////////////////////////////
// CARDINALITY
////////////////////////////////////////////////////////////////////////////////

StatusOr<PartyOneMessage::MessageII> PartyOneCardinality::GenerateMessageII(
    const PartyZeroMessage::MessageI& request,
    std::vector<Element> elements
) {
    Timer timer("[Timer] generate MessageII");
    PartyOneMessage::MessageII response;

    Timer update("[Timer] their tree update");
    RETURN_IF_ERROR(other_tree.Update(this->ctx_, this->group, &request.updates()));
    update.stop();

    Timer cand("[Timer] compute candidates");
    ASSIGN_OR_RETURN(
        std::vector<Ciphertext> candidates,
        DeserializeCiphertexts(request.candidates().elements(), this->ctx_, this->group)
    );

    for (size_t i = 0; i < elements.size(); ++i) {
        std::vector<Ciphertext> path = this->other_tree.getPath(elements[i]);
        ASSIGN_OR_RETURN(Ciphertext x, encrypter->Encrypt(elements[i]));
        ASSIGN_OR_RETURN(Ciphertext minus_x, elgamal::Invert(x));

        for (size_t j = 0; j < path.size(); ++j) {
            Ciphertext y = std::move(path[j]);
            ASSIGN_OR_RETURN(Ciphertext y_minus_x, elgamal::Mul(y, minus_x));
            candidates.push_back(std::move(y_minus_x));
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
            candidates[i], 
            elgamal::Exp(candidates[i], mask)
        );
    }
    masking.stop();

    Timer partial("[Timer] part decrypting");
    for (size_t i = 0; i < candidates.size(); i++) {
        auto candidate = response.mutable_candidates()->add_elements();
        ASSIGN_OR_RETURN(candidates[i], decrypter->PartialDecrypt(candidates[i]));
        ASSIGN_OR_RETURN(
            *candidate->mutable_no_payload()->mutable_element(),
            elgamal_proto_util::SerializeCiphertext(candidates[i])
        );
    }
    partial.stop();

    // update our tree
    RETURN_IF_ERROR(my_tree.Update(
        this->ctx_, this->encrypter.get(), elements, response.mutable_updates()
    ));

    timer.stop();
    return response;
}


////////////////////////////////////////////////////////////////////////////////
// PROCESS MESSAGE III
////////////////////////////////////////////////////////////////////////////////

StatusOr<PartyOneMessage::MessageIV> PartyOneSum::ProcessMessageIII(
    const PartyZeroMessage::MessageIII& msg
) {
    Timer timer("[Timer] generate MessageIV");
    PartyOneMessage::MessageIV res;

    for (auto payload : msg.payloads()) {
        ASSIGN_OR_RETURN(
            BigNum partial, 
            this->paillier->PartialDecrypt(this->ctx_->CreateBigNum(payload.ciphertext()))
        );
        *res.add_payloads()->mutable_ciphertext() = partial.ToBytes();
    }
    timer.stop();

    return res;
}

StatusOr<PartyOneMessage::MessageIV> PartyOneSecretShare::ProcessMessageIII(
    const PartyZeroMessage::MessageIII& msg
) {
    for (auto i = 0; i < msg.payloads().size(); i += 2) {
        ASSIGN_OR_RETURN(
            BigNum share, this->paillier->Decrypt(
                this->ctx_->CreateBigNum(msg.payloads().at(i).ciphertext()),
                this->ctx_->CreateBigNum(msg.payloads().at(i + 1).ciphertext())
            )
        );
        shares.push_back(share);
    }

    // still have to return something even if it isn't sent
    PartyOneMessage::MessageIV res;
    return res;
}

////////////////////////////////////////////////////////////////////////////////
// HANDLE
////////////////////////////////////////////////////////////////////////////////

Status PartyOneNoPayload::Handle(const ClientMessage& req, MessageSink<ServerMessage>* sink) {
    if (protocol_finished()) {
        return InvalidArgumentError("[PartyOneWithPayload] protocol is already complete");
    } else if (!req.has_party_zero_msg()) {
        return InvalidArgumentError("[PartyOneWithPayload] incorrect message type");
    }
    const PartyZeroMessage& msg = req.party_zero_msg();

    ServerMessage res;

    if (msg.has_message_i()) {
        ASSIGN_OR_RETURN(
            auto message_ii,
            GenerateMessageII(msg.message_i(), datasets[current_day])
        );
        *(res.mutable_party_one_msg()->mutable_message_ii()) = std::move(message_ii);
        this->current_day++;
    } else {
        return InvalidArgumentError(
            "[PartyOneWithPayload] received a party zero message of unknown type"
        );
    }

    return sink->Send(res);
}


Status PartyOneSum::Handle(const ClientMessage& req, MessageSink<ServerMessage>* sink) {
    if (protocol_finished()) {
        return InvalidArgumentError("[PartyOneWithPayload] protocol is already complete");
    } else if (!req.has_party_zero_msg()) {
        return InvalidArgumentError("[PartyOneWithPayload] incorrect message type");
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
            ProcessMessageIII(msg.message_iii())
        );
        *(res.mutable_party_one_msg()->mutable_message_iv()) = std::move(message_iv);
        std::clog << "[PartyOne] finished day " << this->current_day << std::endl;
        this->current_day++;
    } else {
        return InvalidArgumentError(
            "[PartyOneWithPayload] received a party zero message of unknown type"
        );
    }

    return sink->Send(res);
}

Status PartyOneSecretShare::Handle(
    const ClientMessage& req, 
    MessageSink<ServerMessage>* sink
) {
    if (protocol_finished()) {
        return InvalidArgumentError("[PartyOneWithPayload] protocol is already complete");
    } else if (!req.has_party_zero_msg()) {
        return InvalidArgumentError("[PartyOneWithPayload] incorrect message type");
    }
    const PartyZeroMessage& msg = req.party_zero_msg();

    ServerMessage res;

    if (msg.has_message_i()) {
        ASSIGN_OR_RETURN(
            auto message_ii,
            GenerateMessageII(msg.message_i(), datasets[current_day])
        );
        *(res.mutable_party_one_msg()->mutable_message_ii()) = std::move(message_ii);
        return sink->Send(res);
    } else if (msg.has_message_iii()) {
        auto status = ProcessMessageIII(msg.message_iii());
        if (!status.ok()) { return status.status(); }
        std::clog << "[PartyOne] finished day " << this->current_day << std::endl;
        this->current_day++;
        return OkStatus();
    } else {
        return InvalidArgumentError(
            "[PartyOneWithPayload] received a party zero message of unknown type"
        );
    }
}

}  // namespace upsi
