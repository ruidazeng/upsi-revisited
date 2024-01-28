#include "upsi/original/party_zero.h"

#include "absl/memory/memory.h"

#include "upsi/network/connection.h"
#include "upsi/crypto/ec_point_util.h"
#include "upsi/crypto/elgamal.h"
#include "upsi/roles.h"
#include "upsi/util/data_util.h"
#include "upsi/util/elgamal_proto_util.h"
#include "upsi/util/proto_util.h"
#include "upsi/util/status.inc"
#include "upsi/utils.h"

namespace upsi {
namespace original {

Status PartyZero::Handle(const ClientMessage& msg, MessageSink<ServerMessage>* sink) {
    if (ProtocolFinished()) {
        return InvalidArgumentError("[PartyZero] protocol is already complete");
    } else if (!msg.has_og_msg()) {
        return InvalidArgumentError("[PartyZero] incorrect message type");
    }
    AddComm(msg);

    if (msg.og_msg().has_message_i()) {
        std::clog << "[Debug] message i size = " << msg.og_msg().message_i().ByteSizeLong() << std::endl;
        RETURN_IF_ERROR(SendMessageII(msg.og_msg().message_i(), sink));
    } else if (msg.og_msg().has_message_iii()) {
        std::clog << "[Debug] message iii size = " << msg.og_msg().message_iii().ByteSizeLong() << std::endl;
        RETURN_IF_ERROR(SendMessageIV(msg.og_msg().message_iii(), sink));
    } else if (msg.og_msg().has_message_v()) {
        std::clog << "[Debug] message v size = " << msg.og_msg().message_v().ByteSizeLong() << std::endl;
        RETURN_IF_ERROR(ProcessMessageV(msg.og_msg().message_v()));
        FinishDay();
    } else {
        return InvalidArgumentError("[PartyZero] received a message of unknown type");
    }

    return OkStatus();
}

Status PartyZero::SendMessageII(
    const OriginalMessage::MessageI& req, MessageSink<ServerMessage>* sink
) {
    OriginalMessage::MessageII res;
    std::vector<Element> elements = datasets[current_day];

    RETURN_IF_ERROR(tree.Update(this->ctx_, this->group, &req.updates()));

    for (const auto& ciphertext : req.ciphertexts()) {
        ASSIGN_OR_RETURN(ECPoint hy_to_a, this->group->CreateECPoint(ciphertext));
        ASSIGN_OR_RETURN(ECPoint hy_to_ab, hy_to_a.Mul(this->decrypter->getPrivateKey()->x));
        ASSIGN_OR_RETURN(auto key, hy_to_ab.ToBytesUnCompressed());
        if (group_mapping.count(key) > 0) {
            intersection.push_back(group_mapping[key]);
        }
    }

    // sample a random group element
    BigNum r = this->ctx_->GenerateRandLessThan(this->group->GetOrder());
    ASSIGN_OR_RETURN(
        ECPoint hr, this->group->GetPointByHashingToCurveSha256(r.ToBytes())
    );

    // send under my pk
    ASSIGN_OR_RETURN(Ciphertext alpha, this->my_pk->Encrypt(hr));
    ASSIGN_OR_RETURN(
        *res.mutable_alpha(), elgamal_proto_util::SerializeCiphertext(alpha)
    );

    // homomorphically evaluate under their pk
    ASSIGN_OR_RETURN(alpha, their_pk->Encrypt(hr));

    std::vector<std::vector<Ciphertext>> candidates(elements.size());
    for (size_t i = 0; i < elements.size(); ++i) {
        std::vector<Ciphertext> path = this->tree.getPath(elements[i]);
        ASSIGN_OR_RETURN(Ciphertext x, their_pk->Encrypt(elements[i]));

        for (size_t j = 0; j < path.size(); ++j) {
            // each element in the path y
            Ciphertext y = std::move(path[j]);
            ASSIGN_OR_RETURN(Ciphertext minus_y, elgamal::Invert(y));

            // compute Enc(alpha + beta * (x - y)) under their pk
            BigNum beta = this->my_pk->CreateRandomMask();
            ASSIGN_OR_RETURN(Ciphertext x_minus_y, elgamal::Mul(x, minus_y));
            ASSIGN_OR_RETURN(Ciphertext beta_times_x_minus_y, elgamal::Exp(x_minus_y, beta));
            ASSIGN_OR_RETURN(Ciphertext ct_beta, elgamal::Mul(alpha, beta_times_x_minus_y));
            candidates[i].push_back(std::move(ct_beta));
        }
    }

    for (size_t i = 0; i < candidates.size(); i++) {
        auto encrypted_set = res.add_candidates();
        for (size_t j = 0; j < candidates[i].size(); j++) {
            auto candidate = encrypted_set->add_elements();
            ASSIGN_OR_RETURN(
                *candidate->mutable_no_payload()->mutable_element(),
                elgamal_proto_util::SerializeCiphertext(candidates[i][j])
            );
        }
    }
    ServerMessage msg;
    *(msg.mutable_og_msg()->mutable_message_ii()) = res;
    std::clog << "[Debug] message ii size = " << msg.og_msg().message_ii().ByteSizeLong() << std::endl;
    AddComm(msg);
    return sink->Send(msg);
}

Status PartyZero::SendMessageIV(
    const OriginalMessage::MessageIII& res, MessageSink<ServerMessage>* sink
) {
    OriginalMessage::MessageIV msg;
    this->masks.clear();
    uint32_t n = 0;
    for (int i = 0; i < res.candidates().size(); i++) {
        ASSIGN_OR_RETURN(
            std::vector<Ciphertext> candidates,
            DeserializeCiphertexts<Ciphertext>(
                res.candidates()[i].elements(), this->ctx_, this->group
            )
        );

        n += candidates.size();
        bool in_intersection = false;
        for (const Ciphertext& candidate : candidates) {
            ASSIGN_OR_RETURN(ECPoint decrypted, this->decrypter->Decrypt(candidate));
            if (decrypted.IsPointAtInfinity()) {
                this->intersection.push_back(datasets[current_day][i].ToDecimalString());
                in_intersection = true;
                break;
            }
        }

        if (in_intersection) {
            BigNum r = this->ctx_->GenerateRandLessThan(this->group->GetOrder());
            ASSIGN_OR_RETURN(
                ECPoint hr, this->group->GetPointByHashingToCurveSha256(r.ToBytes())
            );

            ASSIGN_OR_RETURN(auto serialized, hr.ToBytesCompressed());
            msg.add_ciphertexts(serialized);
            this->masks.push_back(ctx_->Zero());
        } else {
            ASSIGN_OR_RETURN(
                ECPoint hx,
                this->group->GetPointByHashingToCurveSha256(datasets[current_day][i].ToBytes())
            );
            ASSIGN_OR_RETURN(ECPoint hx_to_a, hx.Mul(this->decrypter->getPrivateKey()->x));

            BigNum mask = this->my_pk->CreateRandomMask();
            ASSIGN_OR_RETURN(ECPoint hx_to_am, hx_to_a.Mul(mask));

            ASSIGN_OR_RETURN(auto serialized, hx_to_am.ToBytesCompressed());
            msg.add_ciphertexts(serialized);
            this->masks.push_back(mask);
        }
    }
    //std::cout << "[DEBUG] candidates.size() = " << n << std::endl;

    ServerMessage sm;
    *(sm.mutable_og_msg()->mutable_message_iv()) = msg;
    AddComm(sm);
    std::clog << "[Debug] message iv size = " << sm.og_msg().message_iv().ByteSizeLong() << std::endl;
    return sink->Send(sm);
}

Status PartyZero::ProcessMessageV(const OriginalMessage::MessageV& res) {
    for (int i = 0; i < res.ciphertexts().size(); i++) {
        if (this->masks[i].IsZero()) { continue; }
        ASSIGN_OR_RETURN(ECPoint hx_to_abm, this->group->CreateECPoint(res.ciphertexts()[i]));
        ASSIGN_OR_RETURN(BigNum minus_mask, this->masks[i].ModInverse(this->group->GetOrder()));
        ASSIGN_OR_RETURN(ECPoint hx_to_ab, hx_to_abm.Mul(minus_mask));
        ASSIGN_OR_RETURN(auto key, hx_to_ab.ToBytesUnCompressed());
        group_mapping[key] = datasets[current_day][i].ToDecimalString();
    }

    return OkStatus();
}

void PartyZero::PrintComm() {
    unsigned long long total = 0;
    for (size_t day = 0; day < comm_.size(); day++) {
        std::cout << "[PartyZero] Day " << std::to_string(day + 1) << " Comm (B):\t";
        std::cout << comm_[day] << std::endl;
        total += comm_[day];
    }
    std::cout << "[PartyZero] Total Comm (B):\t" << total << std::endl;
}

void PartyZero::PrintResult() {
    std::cout << "[PartyZero] CARDINALITY = " << this->intersection.size() << std::endl;
    if (this->intersection.size() < 10) {
        for (const std::string& element : this->intersection) {
            std::cout << "            " << element << std::endl;
        }
    }
}

}  // namespace original
}  // namespace upsi
