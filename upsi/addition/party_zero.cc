#include "upsi/addition/party_zero.h"

#include "absl/memory/memory.h"

#include "upsi/network/connection.h"
#include "upsi/crypto/ec_point_util.h"
#include "upsi/crypto/elgamal.h"
#include "upsi/roles.h"
#include "upsi/util/data_util.h"
#include "upsi/util/elgamal_proto_util.h"
#include "upsi/util/proto_util.h"
#include "upsi/utils.h"

namespace upsi {
namespace addonly {

////////////////////////////////////////////////////////////////////////////////
// WITHOUT PAYLOAD CLASS METHODS
////////////////////////////////////////////////////////////////////////////////

void PartyZeroNoPayload::LoadData(const std::vector<Dataset>& datasets) {
    this->datasets.resize(this->total_days);
    for (auto day = 0; day < this->total_days; day++) {
        this->datasets[day] = datasets[day].Elements();
    }
}

Status PartyZeroNoPayload::Run(Connection* sink) {
    Timer timer("[PartyZero] Daily Comp");
    while (!ProtocolFinished()) {
        Timer day("[PartyZero] Day " + std::to_string(this->current_day) + " Comp");
        timer.lap();
        RETURN_IF_ERROR(SendMessageI(sink));
        ServerMessage message_ii = sink->GetResponse();
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
    return sink->Send(msg);
}

Status PartyZeroNoPayload::Handle(
    const ServerMessage& msg,
    MessageSink<ClientMessage>* sink
) {
    if (ProtocolFinished()) {
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

void PartyZeroWithPayload::LoadData(const std::vector<Dataset>& datasets) {
    this->datasets.resize(this->total_days);
    for (auto day = 0; day < this->total_days; day++) {
        std::vector<ElementAndPayload> dailyset = datasets[day].ElementsAndValues();
        for (const ElementAndPayload& element : dailyset) {
            this->datasets[day].push_back(
                GetPayload(element.first, element.second)
            );
        }
    }
}

Status PartyZeroWithPayload::SendMessageI(MessageSink<ClientMessage>* sink) {
    ClientMessage msg;

    ASSIGN_OR_RETURN(auto message_i, GenerateMessageI(datasets[current_day]));

    *(msg.mutable_party_zero_msg()->mutable_message_i()) = message_i;
    return sink->Send(msg);
}

Status PartyZeroWithPayload::Handle(const ServerMessage& msg, MessageSink<ClientMessage>* sink) {
    if (ProtocolFinished()) {
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
// GENERATE MESSAGE I
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

StatusOr<PartyZeroMessage::MessageI> PartyZeroSum::GenerateMessageI(
    std::vector<ElementAndPayload> elements
) {
    PartyZeroMessage::MessageI msg;

    // update our tree
    RETURN_IF_ERROR(my_tree.Update(
        this->ctx_, this->encrypter.get(), elements, msg.mutable_updates()
    ));

    for (size_t i = 0; i < elements.size(); ++i) {
        std::vector<Ciphertext> path = this->other_tree.getPath(elements[i].first);
        ASSIGN_OR_RETURN(Ciphertext x, encrypter->Encrypt(elements[i].first));
        ASSIGN_OR_RETURN(Ciphertext minus_x, elgamal::Invert(x));
        ASSIGN_OR_RETURN(Ciphertext payload, encrypter->Encrypt(elements[i].second));

        for (size_t j = 0; j < path.size(); ++j) {
            Ciphertext y = std::move(path[j]);

            // homomorphically subtract x and rerandomize
            ASSIGN_OR_RETURN(Ciphertext y_minus_x, elgamal::Mul(y, minus_x));
            ASSIGN_OR_RETURN(Ciphertext randomized, encrypter->ReRandomize(y_minus_x));

            // add this to the message
            auto candidate = msg.mutable_candidates()->add_elements();
            ASSIGN_OR_RETURN(
                *candidate->mutable_elgamal()->mutable_element(),
                elgamal_proto_util::SerializeCiphertext(randomized)
            );
            ASSIGN_OR_RETURN(
                *candidate->mutable_elgamal()->mutable_payload(),
                elgamal_proto_util::SerializeCiphertext(payload)
            );
        }
    }

    return msg;
}

StatusOr<PartyZeroMessage::MessageI> PartyZeroSecretShare::GenerateMessageI(
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

////////////////////////////////////////////////////////////////////////////////
// PROCESS MESSAGE II
////////////////////////////////////////////////////////////////////////////////

Status PartyZeroPSI::ProcessMessageII(const PartyOneMessage::MessageII& res) {

    RETURN_IF_ERROR(other_tree.Update(this->ctx_, this->group, &res.updates()));

    ASSIGN_OR_RETURN(
        auto candidates,
        DeserializeCiphertexts<CiphertextAndElGamal>(
            res.candidates().elements(),
            this->ctx_,
            this->group
        )
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
        DeserializeCiphertexts<Ciphertext>(res.candidates().elements(), this->ctx_, this->group)
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

Status PartyZeroSum::SendMessageIII(
    const PartyOneMessage::MessageII& res,
    MessageSink<ClientMessage>* sink
) {
    // update their tree
    RETURN_IF_ERROR(other_tree.Update(this->ctx_, this->group, &res.updates()));

    // deserialize candidates
    ASSIGN_OR_RETURN(
        std::vector<CiphertextAndElGamal> candidates,
        DeserializeCiphertexts<CiphertextAndElGamal>(
            res.candidates().elements(), this->ctx_, this->group
        )
    );

    // compute ciphertext of intersection sum
    ASSIGN_OR_RETURN(Ciphertext sum, encrypter->Encrypt(this->ctx_->Zero()));
    for (size_t i = 0; i < candidates.size(); i++) {
        ASSIGN_OR_RETURN(ECPoint plaintext, decrypter->Decrypt(candidates[i].first));
        if (plaintext.IsPointAtInfinity()) {
            this->cardinality++;
            ASSIGN_OR_RETURN(sum, elgamal::Mul(sum, candidates[i].second));
        }
    }

    // send ciphertext for decryption
    PartyZeroMessage::MessageIII_SUM req;
    ASSIGN_OR_RETURN(
        *req.mutable_sum(),
        elgamal_proto_util::SerializeCiphertext(sum)
    );

    ClientMessage msg;
    *(msg.mutable_party_zero_msg()->mutable_message_iii_sum()) = std::move(req);
    return sink->Send(msg);
}

Status PartyZeroSecretShare::SendMessageIII(
    const PartyOneMessage::MessageII& res,
    MessageSink<ClientMessage>* sink
) {
    // update their tree
    RETURN_IF_ERROR(other_tree.Update(this->ctx_, this->group, &res.updates()));

    // deserialize candidates
    ASSIGN_OR_RETURN(
        std::vector<CiphertextAndPaillier> candidates,
        DeserializeCiphertexts<CiphertextAndPaillier>(
            res.candidates().elements(), this->ctx_, this->group
        )
    );

    // generate our shares and evaluate the ciphertexts for their shares
    PartyZeroMessage::MessageIII_SS req;
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

    ClientMessage msg;
    *(msg.mutable_party_zero_msg()->mutable_message_iii_ss()) = std::move(req);
    return sink->Send(msg);
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
    Timer timer("[PartyZero] Daily Comp");
    while (!ProtocolFinished()) {
        Timer day("[PartyZero] Day " + std::to_string(this->current_day) + " Comp");
        timer.lap();
        RETURN_IF_ERROR(SendMessageI(sink));

        ServerMessage message_ii = sink->GetResponse();
        RETURN_IF_ERROR(Handle(message_ii, sink));

        ServerMessage message_iv = sink->GetResponse();
        RETURN_IF_ERROR(Handle(message_iv, sink));
        timer.stop();
        day.stop();
    }
    timer.print();
    return OkStatus();
}

Status PartyZeroSecretShare::Run(Connection* sink) {
    Timer timer("[PartyZero] Daily Comp");
    while (!ProtocolFinished()) {
        Timer day("[PartyZero] Day " + std::to_string(this->current_day) + " Comp");
        timer.lap();
        RETURN_IF_ERROR(SendMessageI(sink));

        ServerMessage message_ii = sink->GetResponse();

        RETURN_IF_ERROR(Handle(message_ii, sink));
        timer.stop();
        day.stop();
    }
    timer.print();
    return OkStatus();
}

////////////////////////////////////////////////////////////////////////////////
// PROCESS MESSAGE IV
////////////////////////////////////////////////////////////////////////////////

Status PartyZeroSum::ProcessMessageIV(const PartyOneMessage::MessageIV& res) {

    ASSIGN_OR_RETURN(
        Ciphertext ciphertext,
        elgamal_proto_util::DeserializeCiphertext(this->group, res.sum())
    );

    ASSIGN_OR_RETURN(BigNum big, decrypter->DecryptExp(ciphertext));
    ASSIGN_OR_RETURN(uint64_t sum, big.ToIntValue());

    this->sum += sum;

    FinishDay();
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

}  // namespace addonly
}  // namespace upsi
