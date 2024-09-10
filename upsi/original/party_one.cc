#include "upsi/original/party_one.h"

#include "absl/memory/memory.h"

#include "upsi/crypto/ec_point_util.h"
#include "upsi/crypto/elgamal.h"
#include "upsi/roles.h"
#include "upsi/util/elgamal_proto_util.h"
#include "upsi/util/proto_util.h"
#include "upsi/utils.h"

namespace upsi {
namespace original {

Status PartyOne::Handle(const ServerMessage& msg, MessageSink<ClientMessage>* sink) {
    return OkStatus();
};

Status PartyOne::Run(Connection* sink) {
    Timer timer("[PartyOne] Daily Comp");
    while (!ProtocolFinished()) {
        Timer day("[PartyOne] Day " + std::to_string(this->current_day) + " Comp");
        timer.lap();
        RETURN_IF_ERROR(SendMessageI(sink));
        ServerMessage message_ii = sink->GetResponse();
        RETURN_IF_ERROR(SendMessageIII(message_ii.og_msg().message_ii(), sink));
        ServerMessage message_iv = sink->GetResponse();
        RETURN_IF_ERROR(SendMessageV(message_iv.og_msg().message_iv(), sink));
        FinishDay();
        timer.stop();
        day.stop();
    }
    timer.print();
    return OkStatus();
}

Status PartyOne::SendMessageI(MessageSink<ClientMessage>* sink) {
    OriginalMessage::MessageI msg;
    std::vector<Element> elements = datasets[current_day];

    // update our tree
    RETURN_IF_ERROR(tree.Update(
        this->ctx_, this->my_pk.get(), elements, msg.mutable_updates()
    ));

    for (size_t i = 0; i < elements.size(); ++i) {
        ASSIGN_OR_RETURN(
            ECPoint hx, this->group->GetPointByHashingToCurveSha256(elements[i].ToBytes())
        );
        ASSIGN_OR_RETURN(ECPoint hx_to_a, hx.Mul(this->decrypter->getPrivateKey()->x));
        ASSIGN_OR_RETURN(auto serialized, hx_to_a.ToBytesCompressed());
        msg.add_ciphertexts(serialized);
    }

    ClientMessage cm;
    *(cm.mutable_og_msg()->mutable_message_i()) = msg;
    return sink->Send(cm);
}

Status PartyOne::SendMessageIII(
    const OriginalMessage::MessageII& res, MessageSink<ClientMessage>* sink
) {
    OriginalMessage::MessageIII msg;

    ASSIGN_OR_RETURN(
        Ciphertext minus_alpha,
        elgamal_proto_util::DeserializeCiphertext(this->group, res.alpha())
    );
    ASSIGN_OR_RETURN(minus_alpha, elgamal::Invert(minus_alpha));

    for (const auto& repeated : res.candidates()) {
        ASSIGN_OR_RETURN(
            std::vector<Ciphertext> incoming,
            DeserializeCiphertexts<Ciphertext>(
                repeated.elements(), this->ctx_, this->group
            )
        );

        std::vector<Ciphertext> outgoing;
        for (const Ciphertext& ciphertexts : incoming) {
            BigNum gamma = this->my_pk->CreateRandomMask();
            ASSIGN_OR_RETURN(ECPoint beta_point, this->decrypter->Decrypt(ciphertexts));
            ASSIGN_OR_RETURN(Ciphertext beta, this->their_pk->Encrypt(beta_point));
            ASSIGN_OR_RETURN(Ciphertext beta_minus_alpha, elgamal::Mul(beta, minus_alpha));
            ASSIGN_OR_RETURN(
                Ciphertext gamma_x_beta_minus_alpha, elgamal::Exp(beta_minus_alpha, gamma)
            );
            outgoing.push_back(std::move(gamma_x_beta_minus_alpha));
        }

        std::random_device rd;
        std::mt19937 gen(rd());
        std::shuffle(outgoing.begin(), outgoing.end(), gen);

        auto encrypted_set = msg.add_candidates();
        for (size_t i = 0; i < outgoing.size(); i++) {
            auto candidate = encrypted_set->add_elements();
            ASSIGN_OR_RETURN(
                *candidate->mutable_no_payload()->mutable_element(),
                elgamal_proto_util::SerializeCiphertext(outgoing[i])
            );
        }
    }

    ClientMessage cm;
    *(cm.mutable_og_msg()->mutable_message_iii()) = msg;
    return sink->Send(cm);
}

Status PartyOne::SendMessageV(
    const OriginalMessage::MessageIV& res, MessageSink<ClientMessage>* sink
) {
    std::vector<ECPoint> ciphertexts;
    OriginalMessage::MessageV msg;
    for (const auto& ciphertext : res.ciphertexts()) {
        ASSIGN_OR_RETURN(ECPoint hy_to_am, this->group->CreateECPoint(ciphertext));
        ASSIGN_OR_RETURN(ECPoint hy_to_abm, hy_to_am.Mul(this->decrypter->getPrivateKey()->x));
        ASSIGN_OR_RETURN(auto serialized, hy_to_abm.ToBytesCompressed());
        msg.add_ciphertexts(serialized);
    }

    ClientMessage cm;
    *(cm.mutable_og_msg()->mutable_message_v()) = msg;
    return sink->Send(cm);
}

}  // namespace original
}  // namespace upsi
