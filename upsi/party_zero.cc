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

#include "upsi/party_zero.h"


#include "absl/memory/memory.h"

#include "upsi/connection.h"
#include "upsi/crypto/ec_point_util.h"
#include "upsi/crypto/elgamal.h"
#include "upsi/util/elgamal_proto_util.h"
#include "upsi/util/proto_util.h"
#include "upsi/utils.h"

namespace upsi {

////////////////////////////////////////////////////////////////////////////////
// WITHOUT PAYLOAD CLASS METHODS
////////////////////////////////////////////////////////////////////////////////

void PartyZeroNoPayload::LoadData(const std::vector<PartyZeroDataset>& datasets) {
    this->datasets.resize(this->total_days);
    for (auto day = 0; day < this->total_days; day++) {
        std::vector<Element> dailyset;
        for (size_t i = 0; i < datasets[day].first.size(); i++) {
            dailyset.push_back(datasets[day].first[i]);
        }
        this->datasets[day] = dailyset;
    }
}

Status PartyZeroNoPayload::Run(Connection* sink) {
    Timer timer("[PartyZero] Daily");
    while (!protocol_finished()) {
        Timer day("[PartyZero] Day " + std::to_string(this->current_day));
        timer.lap();
        RETURN_IF_ERROR(SendMessageI(sink));
        ServerMessage message_ii = sink->last_server_response();
        RETURN_IF_ERROR(Handle(message_ii, sink));
        timer.stop();
        day.stop();
    }
    timer.print();
    return OkStatus();
}

Status PartyZeroNoPayload::SendMessageI(MessageSink<ClientMessage>* sink) {
    ClientMessage msg;

    ASSIGN_OR_RETURN(auto message_i, GenerateMessageI(datasets[current_day]));

    *(msg.mutable_party_zero_msg()->mutable_message_i()) = message_i;
    std::cout << "[PartyZeroNoPartyLoad] Day " + std::to_string(this->current_day) + " (B): " << msg.ByteSizeLong() << std::endl;
    this->total_cost += msg.ByteSizeLong();
    return sink->Send(msg);
}

Status PartyZeroNoPayload::Handle(
    const ServerMessage& msg, 
    MessageSink<ClientMessage>* sink
) {
    if (protocol_finished()) {
        return InvalidArgumentError("[PartyZeroWithPayload] protocol is already complete");
    } else if (!msg.has_party_one_msg()) {
        return InvalidArgumentError("[PartyZeroWithPayload] incorrect message type");
    }

    if (msg.party_one_msg().has_message_ii()) {
        RETURN_IF_ERROR(ProcessMessageII(msg.party_one_msg().message_ii()));
    } else {
        return InvalidArgumentError(
            "[PartyZeroWithPayload] received a party one message of unknown type"
        );
    }

    return OkStatus();
}

////////////////////////////////////////////////////////////////////////////////
// WITH PAYLOAD CLASS METHODS
////////////////////////////////////////////////////////////////////////////////

void PartyZeroWithPayload::LoadData(const std::vector<PartyZeroDataset>& datasets) {
    this->datasets.resize(this->total_days);
    for (auto day = 0; day < this->total_days; day++) {
        std::vector<ElementAndPayload> dailyset;
        for (size_t i = 0; i < datasets[day].first.size(); i++) {
            dailyset.push_back(
                GetPayload(datasets[day].first[i], datasets[day].second[i])
            );
        }
        this->datasets[day] = dailyset;
    }
}

Status PartyZeroWithPayload::SendMessageI(MessageSink<ClientMessage>* sink) {
    ClientMessage msg;

    ASSIGN_OR_RETURN(auto message_i, GenerateMessageI(datasets[current_day]));

    *(msg.mutable_party_zero_msg()->mutable_message_i()) = message_i;
    std::cout << "[PartyZeroWithPartyLoad I] Day " + std::to_string(this->current_day) + " (B): " << msg.ByteSizeLong() << std::endl;
    this->total_cost += msg.ByteSizeLong();
    return sink->Send(msg);
}

StatusOr<PartyZeroMessage::MessageI> PartyZeroWithPayload::GenerateMessageI(
    std::vector<ElementAndPayload> elements
) {
    PartyZeroMessage::MessageI msg;

    // update our tree
    RETURN_IF_ERROR(my_tree.Update(
        this->ctx_, this->encrypter.get(), this->paillier.get(), elements, msg.mutable_updates()
    ));

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
                *candidate->mutable_paillier()->mutable_element(),
                elgamal_proto_util::SerializeCiphertext(randomized)
            );
            *candidate->mutable_paillier()->mutable_payload() = payload.ToBytes();
        }
    }

    return msg;
}

Status PartyZeroWithPayload::SendMessageIII(
    const PartyOneMessage::MessageII& res,
    MessageSink<ClientMessage>* sink
) {

    RETURN_IF_ERROR(other_tree.Update(this->ctx_, this->group, &res.updates()));


    ASSIGN_OR_RETURN(
        std::vector<CiphertextAndPayload> candidates,
        DeserializeCiphertextAndPayloads(res.candidates().elements(), this->ctx_, this->group)
    );

    ClientMessage msg;

    ASSIGN_OR_RETURN(
        PartyZeroMessage::MessageIII req,
        GenerateMessageIII(std::move(candidates))
    );
    *(msg.mutable_party_zero_msg()->mutable_message_iii()) = std::move(req);
    
    std::cout << "[PartyZeroWithPartyLoad III] Day " + std::to_string(this->current_day) + " (B): " << msg.ByteSizeLong() << std::endl;
    this->total_cost += msg.ByteSizeLong();
    return sink->Send(msg);
}

Status PartyZeroWithPayload::Handle(const ServerMessage& msg, MessageSink<ClientMessage>* sink) {
    if (protocol_finished()) {
        return InvalidArgumentError("[PartyZeroWithPayload] protocol is already complete");
    } else if (!msg.has_party_one_msg()) {
        return InvalidArgumentError("[PartyZeroWithPayload] incorrect message type");
    }

    if (msg.party_one_msg().has_message_ii()) {
        RETURN_IF_ERROR(SendMessageIII(msg.party_one_msg().message_ii(), sink));
    } else if (msg.party_one_msg().has_message_iv()) {
        RETURN_IF_ERROR(ProcessMessageIV(msg.party_one_msg().message_iv()));
    } else {
        return InvalidArgumentError(
            "[PartyZeroWithPayload] received a party one message of unknown type"
        );
    }

    return OkStatus();
}


////////////////////////////////////////////////////////////////////////////////
// GENERATE MESSAGE I (NO PAYLOADS)
////////////////////////////////////////////////////////////////////////////////

StatusOr<PartyZeroMessage::MessageI> PartyZeroPSI::GenerateMessageI(
    std::vector<Element> elements
) {
    PartyZeroMessage::MessageI msg;

    // update our tree
    RETURN_IF_ERROR(my_tree.Update(
        this->ctx_, this->encrypter.get(), elements, msg.mutable_updates()
    ));

    for (size_t i = 0; i < elements.size(); ++i) {
        // record g^x so we can check if it is in the intersection later
        ASSIGN_OR_RETURN(ECPoint point, this->encrypter->getPublicKey()->g.Mul(elements[i]));
        ASSIGN_OR_RETURN(auto key, point.ToBytesUnCompressed());
        group_mapping[key] = elements[i].ToDecimalString();

        std::vector<Ciphertext> path = this->other_tree.getPath(elements[i]);

        ASSIGN_OR_RETURN(Ciphertext x, encrypter->Encrypt(point));
        ASSIGN_OR_RETURN(Ciphertext minus_x, elgamal::Invert(x));

        for (size_t j = 0; j < path.size(); ++j) {
            Ciphertext y = std::move(path[j]);

            // homomorphically subtract x and rerandomize
            ASSIGN_OR_RETURN(Ciphertext y_minus_x, elgamal::Mul(y, minus_x));
            ASSIGN_OR_RETURN(Ciphertext randomized, encrypter->ReRandomize(y_minus_x));

            // add (y - x) and x to the message
            auto candidate = msg.mutable_candidates()->add_elements();
            ASSIGN_OR_RETURN(
                *candidate->mutable_elgamal()->mutable_element(),
                elgamal_proto_util::SerializeCiphertext(randomized)
            );
            ASSIGN_OR_RETURN(
                *candidate->mutable_elgamal()->mutable_payload(),
                elgamal_proto_util::SerializeCiphertext(x)
            );
        }
    }

    return msg;
}

StatusOr<PartyZeroMessage::MessageI> PartyZeroCardinality::GenerateMessageI(
    std::vector<Element> elements
) {
    PartyZeroMessage::MessageI msg;

    // update our tree
    RETURN_IF_ERROR(my_tree.Update(
        this->ctx_, this->encrypter.get(), elements, msg.mutable_updates()
    ));

    for (size_t i = 0; i < elements.size(); ++i) {
        std::vector<Ciphertext> path = this->other_tree.getPath(elements[i]);
        ASSIGN_OR_RETURN(Ciphertext x, encrypter->Encrypt(elements[i]));
        ASSIGN_OR_RETURN(Ciphertext minus_x, elgamal::Invert(x));

        for (size_t j = 0; j < path.size(); ++j) {
            Ciphertext y = std::move(path[j]);

            // homomorphically subtract x and rerandomize
            ASSIGN_OR_RETURN(Ciphertext y_minus_x, elgamal::Mul(y, minus_x));
            ASSIGN_OR_RETURN(Ciphertext randomized, encrypter->ReRandomize(y_minus_x));

            // add this to the message
            auto candidate = msg.mutable_candidates()->add_elements();
            ASSIGN_OR_RETURN(
                *candidate->mutable_no_payload()->mutable_element(),
                elgamal_proto_util::SerializeCiphertext(randomized)
            );
        }
    }

    return msg;
}

////////////////////////////////////////////////////////////////////////////////
// PROCESS MESSAGE II (NO PAYLOADS)
////////////////////////////////////////////////////////////////////////////////

Status PartyZeroPSI::ProcessMessageII(const PartyOneMessage::MessageII& res) {

    RETURN_IF_ERROR(other_tree.Update(this->ctx_, this->group, &res.updates()));


    ASSIGN_OR_RETURN(
        auto candidates,
        DeserializeCiphertextAndElGamals(res.candidates().elements(), this->group)
    );

    for (const std::pair<Ciphertext, Ciphertext>& candidate : candidates) {
        ASSIGN_OR_RETURN(ECPoint plaintext, decrypter->Decrypt(candidate.first));
        if (plaintext.IsPointAtInfinity()) { 
            ASSIGN_OR_RETURN(ECPoint point, decrypter->Decrypt(candidate.second));
            ASSIGN_OR_RETURN(auto key, point.ToBytesUnCompressed());
            intersection.push_back(group_mapping[key]);
        }
    }

    // the day is over after the second message
    FinishDay();
    return OkStatus();
}

Status PartyZeroCardinality::ProcessMessageII(const PartyOneMessage::MessageII& res) {

    RETURN_IF_ERROR(other_tree.Update(this->ctx_, this->group, &res.updates()));

    ASSIGN_OR_RETURN(
        std::vector<Ciphertext> candidates,
        DeserializeCiphertexts(res.candidates().elements(), this->ctx_, this->group)
    );

    for (const Ciphertext& candidate : candidates) {
        ASSIGN_OR_RETURN(ECPoint plaintext, decrypter->Decrypt(candidate));
        if (plaintext.IsPointAtInfinity()) { 
            this->cardinality++;
        }
    }

    // the day is over after the second message
    FinishDay();
    return OkStatus();
}

////////////////////////////////////////////////////////////////////////////////
// GET PAYLOAD
////////////////////////////////////////////////////////////////////////////////

ElementAndPayload PartyZeroSum::GetPayload(BigNum element, BigNum value) {
    return std::make_pair(element, value);
}

ElementAndPayload PartyZeroSecretShare::GetPayload(BigNum element, BigNum value) {
    return std::make_pair(element, element);
}

////////////////////////////////////////////////////////////////////////////////
// RUN
////////////////////////////////////////////////////////////////////////////////

Status PartyZeroSum::Run(Connection* sink) {
    Timer timer("[PartyZero] Daily");
    while (!protocol_finished()) {
        Timer day("[PartyZero] Day " + std::to_string(this->current_day));
        timer.lap();
        RETURN_IF_ERROR(SendMessageI(sink));

        ServerMessage message_ii = sink->last_server_response();
        RETURN_IF_ERROR(Handle(message_ii, sink));

        ServerMessage message_iv = sink->last_server_response();
        RETURN_IF_ERROR(Handle(message_iv, sink));
        timer.stop();
        day.stop();
    }
    timer.print();
    return OkStatus();
}

Status PartyZeroSecretShare::Run(Connection* sink) {
    Timer timer("[PartyZero] Daily");
    while (!protocol_finished()) {
        Timer day("[PartyZero] Day " + std::to_string(this->current_day));
        timer.lap();
        RETURN_IF_ERROR(SendMessageI(sink));

        ServerMessage message_ii = sink->last_server_response();

        RETURN_IF_ERROR(Handle(message_ii, sink));
        timer.stop();
        day.stop();
    }
    timer.print();
    return OkStatus();
}

////////////////////////////////////////////////////////////////////////////////
// GENERATE MESSAGE III
////////////////////////////////////////////////////////////////////////////////

StatusOr<PartyZeroMessage::MessageIII> PartyZeroSum::GenerateMessageIII(
    std::vector<CiphertextAndPayload> candidates
) {
    PartyZeroMessage::MessageIII req;
    BigNum ciphertext = this->ctx_->Zero();

    for (size_t i = 0; i < candidates.size(); i++) {
        ASSIGN_OR_RETURN(ECPoint plaintext, decrypter->Decrypt(candidates[i].first));
        if (plaintext.IsPointAtInfinity()) { 
            this->cardinality++;
            if (ciphertext.IsZero()) {
                ciphertext = candidates[i].second;
            } else {
                ciphertext = paillier->Add(ciphertext, candidates[i].second);
            }
        }
    }

    // if the intersection is empty today, send a random value
    if (ciphertext.IsZero()) {
        *req.add_payloads()->mutable_ciphertext() = (
            this->ctx_->GenerateRandLessThan(paillier->n_squared_).ToBytes()
        );
    } else {
        *req.add_payloads()->mutable_ciphertext() = ciphertext.ToBytes(); 
    }
    this->sum_ciphertext = ciphertext;

    return req;
}

StatusOr<PartyZeroMessage::MessageIII> PartyZeroSecretShare::GenerateMessageIII(
    std::vector<CiphertextAndPayload> candidates
) {
    PartyZeroMessage::MessageIII req;

    for (size_t i = 0; i < candidates.size(); i++) {
        ASSIGN_OR_RETURN(ECPoint plaintext, decrypter->Decrypt(candidates[i].first));
        if (plaintext.IsPointAtInfinity()) { 
            BigNum share = this->ctx_->GenerateRandLessThan(this->paillier->n);

            // save -share as our share
            shares.push_back(this->paillier->n - share);

            // element + share is their share
            ASSIGN_OR_RETURN(BigNum encrypted, this->paillier->Encrypt(share));
            encrypted = paillier->Add(candidates[i].second, encrypted);
            ASSIGN_OR_RETURN(BigNum partial, this->paillier->PartialDecrypt(encrypted));
            *req.add_payloads()->mutable_ciphertext() = encrypted.ToBytes(); 
            *req.add_payloads()->mutable_ciphertext() = partial.ToBytes(); 
        }
    }
    // the day is over for us since there are no more incoming messages
    FinishDay();
    return req;
}

////////////////////////////////////////////////////////////////////////////////
// PROCESS MESSAGE IV
////////////////////////////////////////////////////////////////////////////////

Status PartyZeroSum::ProcessMessageIV(const PartyOneMessage::MessageIV& msg) {

    FinishDay();

    // if the intersection was empty today, no need to decrypt
    if (this->sum_ciphertext.IsZero()) {
        return OkStatus();
    }

    for (auto payload : msg.payloads()) {
        ASSIGN_OR_RETURN(
            BigNum big, 
            this->paillier->Decrypt(
                this->sum_ciphertext, 
                this->ctx_->CreateBigNum(payload.ciphertext())
            )
        );
        ASSIGN_OR_RETURN(uint64_t sum, big.ToIntValue());
        this->sum += sum;
    }

    return OkStatus();
}

Status PartyZeroSecretShare::ProcessMessageIV(const PartyOneMessage::MessageIV& msg) {
    // there is no fourth message for secret share
    return OkStatus();
}

////////////////////////////////////////////////////////////////////////////////
// PRINT RESULT
////////////////////////////////////////////////////////////////////////////////

void PartyZeroPSI::PrintResult() {
    std::cout << "[PartyZero] CARDINALITY = " << this->intersection.size() << std::endl;
    if (this->intersection.size() < 250) {
        for (const std::string& element : this->intersection) {
            std::cout << "            " << element << std::endl;
        }
    }
}

void PartyZeroCardinality::PrintResult() {
    std::cout << "[PartyZero] CARDINALITY = " << this->cardinality << std::endl;
}

void PartyZeroSum::PrintResult() {
    std::cout << "[PartyZero] CARDINALITY = " << this->cardinality << std::endl;
    std::cout << "[PartyZero] SUM = " << this->sum << std::endl;
}

void PartyZeroSecretShare::PrintResult() {
    std::cout << "[PartyZero] CARDINALITY = " << this->shares.size() << std::endl;
}

}  // namespace upsi
