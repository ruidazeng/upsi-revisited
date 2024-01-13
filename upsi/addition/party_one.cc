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

#include "upsi/addition/party_one.h"

#include "absl/memory/memory.h"

#include "upsi/crypto/ec_point_util.h"
#include "upsi/crypto/elgamal.h"
#include "upsi/roles.h"
#include "upsi/util/elgamal_proto_util.h"
#include "upsi/util/proto_util.h"
#include "upsi/utils.h"

namespace upsi {
namespace addonly {

////////////////////////////////////////////////////////////////////////////////
// HANDLE
////////////////////////////////////////////////////////////////////////////////

Status PartyOneNoPayload::Handle(const ClientMessage& req, MessageSink<ServerMessage>* sink) {
    if (ProtocolFinished()) {
        return InvalidArgumentError("[PartyOneNoPayload] protocol is already complete");
    } else if (!req.has_party_zero_msg()) {
        return InvalidArgumentError("[PartyOneNoPayload] incorrect message type");
    }
    this->AddComm(req);
    const PartyZeroMessage& msg = req.party_zero_msg();

    ServerMessage res;

    if (msg.has_message_i()) {
        ASSIGN_OR_RETURN(
            auto message_ii,
            GenerateMessageII(msg.message_i(), datasets[current_day])
        );
        *(res.mutable_party_one_msg()->mutable_message_ii()) = std::move(message_ii);
        this->AddComm(res);
        FinishDay();
    } else {
        return InvalidArgumentError(
            "[PartyOneNoPayload] received a party zero message of unknown type"
        );
    }

    return sink->Send(res);
}


Status PartyOneSum::Handle(const ClientMessage& req, MessageSink<ServerMessage>* sink) {
    if (ProtocolFinished()) {
        return InvalidArgumentError("[PartyOneSum] protocol is already complete");
    } else if (!req.has_party_zero_msg()) {
        return InvalidArgumentError("[PartyOneSum] incorrect message type");
    }
    this->AddComm(req);
    const PartyZeroMessage& msg = req.party_zero_msg();

    ServerMessage res;

    if (msg.has_message_i()) {
        ASSIGN_OR_RETURN(
            auto message_ii,
            GenerateMessageII(msg.message_i(), datasets[current_day])
        );
        *(res.mutable_party_one_msg()->mutable_message_ii()) = std::move(message_ii);
        this->AddComm(res);
    } else if (msg.has_message_iii_sum()) {
        ASSIGN_OR_RETURN(
            auto message_iv,
            ProcessMessageIII(msg.message_iii_sum())
        );
        *(res.mutable_party_one_msg()->mutable_message_iv()) = std::move(message_iv);
        this->AddComm(res);
        FinishDay();
    } else {
        return InvalidArgumentError(
            "[PartyOneSum] received a party zero message of unknown type"
        );
    }

    return sink->Send(res);
}

Status PartyOneSecretShare::Handle(
    const ClientMessage& req,
    MessageSink<ServerMessage>* sink
) {
    if (ProtocolFinished()) {
        return InvalidArgumentError("[PartyOneSecretShare] protocol is already complete");
    } else if (!req.has_party_zero_msg()) {
        return InvalidArgumentError("[PartyOneSecretShare] incorrect message type");
    }
    const PartyZeroMessage& msg = req.party_zero_msg();
    this->AddComm(req);

    ServerMessage res;

    if (msg.has_message_i()) {
        ASSIGN_OR_RETURN(
            auto message_ii,
            GenerateMessageII(msg.message_i(), datasets[current_day])
        );
        *(res.mutable_party_one_msg()->mutable_message_ii()) = std::move(message_ii);
        this->AddComm(res);
        return sink->Send(res);
    } else if (msg.has_message_iii_ss()) {
        auto status = ProcessMessageIII(msg.message_iii_ss());
        if (!status.ok()) { return status; }
        FinishDay();
        return OkStatus();
    } else {
        return InvalidArgumentError(
            "[PartyOneSecretShare] received a party zero message of unknown type"
        );
    }
}

////////////////////////////////////////////////////////////////////////////////
// REGULAR PSI
////////////////////////////////////////////////////////////////////////////////

StatusOr<PartyOneMessage::MessageII> PartyOnePSI::GenerateMessageII(
    const PartyZeroMessage::MessageI& request,
    std::vector<Element> elements
) {
    PartyOneMessage::MessageII response;

    RETURN_IF_ERROR(other_tree.Update(this->ctx_, this->group, &request.updates()));

    ASSIGN_OR_RETURN(
        auto candidates,
        DeserializeCiphertexts<CiphertextAndElGamal>(
            request.candidates().elements(), this->ctx_, this->group
        )
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

    std::random_device rd;
    std::mt19937 gen(rd());
    std::shuffle(candidates.begin(), candidates.end(), gen);

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

    // update our tree
    RETURN_IF_ERROR(my_tree.Update(
        this->ctx_, this->encrypter.get(), elements, response.mutable_updates()
    ));

    return response;
}


////////////////////////////////////////////////////////////////////////////////
// CARDINALITY
////////////////////////////////////////////////////////////////////////////////

StatusOr<PartyOneMessage::MessageII> PartyOneCardinality::GenerateMessageII(
    const PartyZeroMessage::MessageI& request,
    std::vector<Element> elements
) {
    PartyOneMessage::MessageII response;

    RETURN_IF_ERROR(other_tree.Update(this->ctx_, this->group, &request.updates()));

    ASSIGN_OR_RETURN(
        std::vector<Ciphertext> candidates,
        DeserializeCiphertexts<Ciphertext>(
            request.candidates().elements(), this->ctx_, this->group
        )
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

    std::random_device rd;
    std::mt19937 gen(rd());
    std::shuffle(candidates.begin(), candidates.end(), gen);

    for (size_t i = 0; i < candidates.size(); i++) {
        BigNum mask = this->encrypter->CreateRandomMask();
        ASSIGN_OR_RETURN(
            candidates[i],
            elgamal::Exp(candidates[i], mask)
        );
    }

    for (size_t i = 0; i < candidates.size(); i++) {
        auto candidate = response.mutable_candidates()->add_elements();
        ASSIGN_OR_RETURN(candidates[i], decrypter->PartialDecrypt(candidates[i]));
        ASSIGN_OR_RETURN(
            *candidate->mutable_no_payload()->mutable_element(),
            elgamal_proto_util::SerializeCiphertext(candidates[i])
        );
    }

    // update our tree
    RETURN_IF_ERROR(my_tree.Update(
        this->ctx_, this->encrypter.get(), elements, response.mutable_updates()
    ));

    return response;
}

////////////////////////////////////////////////////////////////////////////////
// SUM
////////////////////////////////////////////////////////////////////////////////

StatusOr<PartyOneMessage::MessageII> PartyOneSum::GenerateMessageII(
    const PartyZeroMessage::MessageI& request,
    std::vector<Element> elements
) {
    PartyOneMessage::MessageII response;

    RETURN_IF_ERROR(other_tree.Update(this->ctx_, this->group, &request.updates()));

    ASSIGN_OR_RETURN(
        std::vector<CiphertextAndElGamal> candidates,
        DeserializeCiphertexts<CiphertextAndElGamal>(
            request.candidates().elements(), this->ctx_, this->group
        )
    );

    for (size_t i = 0; i < elements.size(); ++i) {
        std::vector<CiphertextAndElGamal> path = this->other_tree.getPath(elements[i]);
        ASSIGN_OR_RETURN(Ciphertext x, encrypter->Encrypt(elements[i]));
        ASSIGN_OR_RETURN(Ciphertext minus_x, elgamal::Invert(x));

        for (size_t j = 0; j < path.size(); ++j) {
            Ciphertext y = std::move(path[j].first);
            ASSIGN_OR_RETURN(Ciphertext y_minus_x, elgamal::Mul(y, minus_x));
            candidates.push_back(
                std::make_pair(
                    std::move(y_minus_x),
                    std::move(path[j].second)
                )
            );
        }
    }

    std::random_device rd;
    std::mt19937 gen(rd());
    std::shuffle(candidates.begin(), candidates.end(), gen);

    for (size_t i = 0; i < candidates.size(); i++) {
        BigNum mask = this->encrypter->CreateRandomMask();
        ASSIGN_OR_RETURN(
            candidates[i].first,
            elgamal::Exp(candidates[i].first, mask)
        );
    }

    for (size_t i = 0; i < candidates.size(); i++) {
        auto candidate = response.mutable_candidates()->add_elements();
        ASSIGN_OR_RETURN(candidates[i].first, decrypter->PartialDecrypt(candidates[i].first));
        ASSIGN_OR_RETURN(
            *candidate->mutable_elgamal()->mutable_element(),
            elgamal_proto_util::SerializeCiphertext(candidates[i].first)
        );
        ASSIGN_OR_RETURN(Ciphertext randomized, encrypter->ReRandomize(candidates[i].second));
        ASSIGN_OR_RETURN(
            *candidate->mutable_elgamal()->mutable_payload(),
            elgamal_proto_util::SerializeCiphertext(randomized)
        );
    }

    // update our tree
    RETURN_IF_ERROR(my_tree.Update(
        this->ctx_, this->encrypter.get(), elements, response.mutable_updates()
    ));

    return response;
}

StatusOr<PartyOneMessage::MessageIV> PartyOneSum::ProcessMessageIII(
    const PartyZeroMessage::MessageIII_SUM& req
) {
    PartyOneMessage::MessageIV res;

    ASSIGN_OR_RETURN(
        Ciphertext sum,
        elgamal_proto_util::DeserializeCiphertext(this->group, req.sum())
    );

    ASSIGN_OR_RETURN(
        Ciphertext partial,
        decrypter->PartialDecrypt(sum)
    );

    ASSIGN_OR_RETURN(
        *res.mutable_sum(),
        elgamal_proto_util::SerializeCiphertext(partial)
    );
    return res;
}


////////////////////////////////////////////////////////////////////////////////
// SECRET SHARE
////////////////////////////////////////////////////////////////////////////////

StatusOr<PartyOneMessage::MessageII> PartyOneSecretShare::GenerateMessageII(
    const PartyZeroMessage::MessageI& request,
    std::vector<Element> elements
) {
    PartyOneMessage::MessageII response;

    RETURN_IF_ERROR(other_tree.Update(this->ctx_, this->group, &request.updates()));

    ASSIGN_OR_RETURN(
        std::vector<CiphertextAndPaillier> candidates,
        DeserializeCiphertexts<CiphertextAndPaillier>(
            request.candidates().elements(), this->ctx_, this->group
        )
    );

    for (size_t i = 0; i < elements.size(); ++i) {
        std::vector<CiphertextAndPaillier> path = this->other_tree.getPath(elements[i]);
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

    std::random_device rd;
    std::mt19937 gen(rd());
    std::shuffle(candidates.begin(), candidates.end(), gen);

    for (size_t i = 0; i < candidates.size(); i++) {
        BigNum mask = this->encrypter->CreateRandomMask();
        ASSIGN_OR_RETURN(
            candidates[i].first,
            elgamal::Exp(candidates[i].first, mask)
        );
    }

    for (size_t i = 0; i < candidates.size(); i++) {
        auto candidate = response.mutable_candidates()->add_elements();
        ASSIGN_OR_RETURN(candidates[i].first, decrypter->PartialDecrypt(candidates[i].first));
        ASSIGN_OR_RETURN(
            *candidate->mutable_paillier()->mutable_element(),
            elgamal_proto_util::SerializeCiphertext(candidates[i].first)
        );
        ASSIGN_OR_RETURN(BigNum randomized, this->paillier->ReRand(candidates[i].second));
        *candidate->mutable_paillier()->mutable_payload() = randomized.ToBytes();
    }

    // update our tree
    RETURN_IF_ERROR(my_tree.Update(
        this->ctx_, this->encrypter.get(), elements, response.mutable_updates()
    ));

    return response;
}

Status PartyOneSecretShare::ProcessMessageIII(
    const PartyZeroMessage::MessageIII_SS& msg
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

    return OkStatus();
}

}  // namespace addonly
}  // namespace upsi
