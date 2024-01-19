#include "upsi/deletion/party_zero.h"

#include "absl/memory/memory.h"

#include "upsi/network/connection.h"
#include "upsi/crypto/ec_point_util.h"
#include "upsi/crypto/elgamal.h"
#include "upsi/util/elgamal_proto_util.h"
#include "upsi/util/proto_util.h"
#include "upsi/utils.h"

namespace upsi {
namespace deletion {

////////////////////////////////////////////////////////////////////////////////
// DELETION METHODS
////////////////////////////////////////////////////////////////////////////////

void PartyZero::LoadData(const std::vector<Dataset>& datasets) {
    this->datasets.resize(this->total_days);
    for (auto day = 0; day < this->total_days; day++) {
        this->datasets[day] = datasets[day].ElementsAndValues();
    }
}

Status PartyZero::Handle(const ServerMessage& msg, MessageSink<ClientMessage>* sink) {
    if (ProtocolFinished()) {
        return InvalidArgumentError("[PartyZero] protocol is already complete");
    } else if (!msg.has_party_one_msg()) {
        return InvalidArgumentError("[PartyZero] incorrect message type");
    }

    if (msg.party_one_msg().has_message_ii()) {
        RETURN_IF_ERROR(ProcessMessageII(msg.party_one_msg().message_ii(), sink));
    } else {
        return InvalidArgumentError(
            "[PartyZero] received a party one message of unknown type"
        );
    }

    return OkStatus();
}

Status PartyZero::Run(Connection* sink) {
    ResetGarbledCircuit();
    RETURN_IF_ERROR(SendMessageI(sink));
    ServerMessage message_ii = sink->GetResponse();
    RETURN_IF_ERROR(Handle(message_ii, sink));
    return OkStatus();
}

void PartyZero::PrintResult(){
	std::cout << "[PartyZero] CA/SUM = " << result << std::endl;
}

void PartyZero::UpdateResult(uint64_t cur_ans) {
	this->result += cur_ans;
}

Status PartyZero::SendMessageI(MessageSink<ClientMessage>* sink) {
    ClientMessage msg;

    ASSIGN_OR_RETURN(auto message_i, GenerateMessageI(datasets[current_day]));

    *(msg.mutable_party_zero_msg()->mutable_message_i()) = message_i;
    
    this->AddComm(msg, this->current_day);
    
    return sink->Send(msg);
}

Status PartyZero::ProcessMessageII(
    const PartyOneMessage::MessageII& res,
    MessageSink<ClientMessage>* sink
) {

    RETURN_IF_ERROR(other_tree.Update(this->ctx_, this->group, &res.updates()));

    ASSIGN_OR_RETURN(
        std::vector<BigNum> candidates,
        DeserializeCiphertexts<BigNum>(res.candidates().elements(), this->ctx_, this->group)
    );

	RETURN_IF_ERROR(CombinePathResponder(candidates));

    FinishDay();

	return OkStatus();
}

StatusOr<PartyZeroMessage::MessageI> PartyZero::GenerateMessageI(
    std::vector<ElementAndPayload> elements
) {
    PartyZeroMessage::MessageI msg;

    // update our tree
    RETURN_IF_ERROR(my_tree.Update(
        this->ctx_, this->sk.get(), elements, msg.mutable_updates()
    ));

    for (size_t i = 0; i < elements.size(); ++i) {

        std::vector<Element> cur_msg;
        ASSIGN_OR_RETURN(cur_msg , CombinePathInitiator(elements[i]));

        for (size_t j = 0; j < cur_msg.size(); ++j) {
            auto candidate = msg.mutable_candidates()->add_elements();
            *candidate->mutable_only_paillier()->mutable_element() = cur_msg[j].ToBytes();
        }
    }

    return msg;
}

}  // namespace deletion
}  // namespace upsi
