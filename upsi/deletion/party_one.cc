#include "upsi/deletion/party_one.h"

#include "absl/memory/memory.h"

#include "upsi/crypto/ec_point_util.h"
#include "upsi/crypto/elgamal.h"
#include "upsi/util/elgamal_proto_util.h"
#include "upsi/util/proto_util.h"
#include "upsi/utils.h"

namespace upsi {
namespace deletion {

Status PartyOne::Handle(const ClientMessage& req, MessageSink<ServerMessage>* sink) {
    if (ProtocolFinished()) {
        return InvalidArgumentError("[PartyOne] protocol is already complete");
    } else if (!req.has_party_zero_msg()) {
        return InvalidArgumentError("[PartyOne] incorrect message type");
    }
    const PartyZeroMessage& msg = req.party_zero_msg();

    ServerMessage res;

    if (msg.has_message_i()) {
    	std::cerr<<"Handle m1...\n";
        ASSIGN_OR_RETURN(
            auto message_ii,
            GenerateMessageII(msg.message_i(), datasets[current_day])
        );
        *(res.mutable_party_one_msg()->mutable_message_ii()) = std::move(message_ii);
        FinishDay();
        std::cerr<<"done...\n";
    } else {
        return InvalidArgumentError(
            "[PartyOne] received a party zero message of unknown type"
        );
    }

    RETURN_IF_ERROR(sink->Send(res));
    return OkStatus();
}

StatusOr<PartyOneMessage::MessageII> PartyOne::GenerateMessageII(
    const PartyZeroMessage::MessageI& request,
    std::vector<ElementAndPayload> elements
) {

	ResetGarbledCircuit();

    PartyOneMessage::MessageII response;

    RETURN_IF_ERROR(other_tree.Update(this->ctx_, this->group, &request.updates()));

    ASSIGN_OR_RETURN(
        std::vector<BigNum> candidates,
        DeserializeCiphertexts<BigNum>(request.candidates().elements(), this->ctx_, this->group)
    );

    RETURN_IF_ERROR(CombinePathResponder(candidates));

    // update our tree
    RETURN_IF_ERROR(my_tree.Update(
        this->ctx_, this->sk.get(), elements, response.mutable_updates()
    ));

     for (size_t i = 0; i < elements.size(); ++i) {

        std::vector<Element> cur_msg;
        ASSIGN_OR_RETURN(cur_msg, CombinePathInitiator(elements[i]));

        for (size_t j = 0; j < cur_msg.size(); ++j) {
            auto candidate = response.mutable_candidates()->add_elements();
            *candidate->mutable_only_paillier()->mutable_element() = cur_msg[j].ToBytes();
        }
    }

    return response;
}

}  // namespace deletion
}  // namespace upsi
