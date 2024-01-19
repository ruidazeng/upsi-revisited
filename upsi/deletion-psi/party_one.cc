#include "upsi/deletion-psi/party_one.h"

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
            GenerateMessageII(msg.message_i(), 
            	first_round_finished? datasets[1][current_day] : datasets[0][current_day])
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

Status PartyOne::SecondPhase() {
	ASSIGN_OR_RETURN(std::vector<uint64_t> rs, GarbledCircuit());
	int cnt = rs.size();
	
	BigNum cur_n = pk->n();
	int len = cur_n.ToBytes().length();
	int cnt_block = (len * 2 + 15) >> 4;
	int msg_len = cnt_block << 4;
	
	std::vector<BigNum> msg;
	
	for (int i = 0; i < cnt; ++i) {
		std::string tmp_str(msg_len, 0);
		gc_io_->recv_data(&tmp_str[0], msg_len);
		BigNum encrypted_x = ctx_->CreateBigNum(tmp_str);
		ASSIGN_OR_RETURN(BigNum encrypted_y, pk->Encrypt(ctx_->CreateBigNum(rs[i])));
		BigNum encrypted_rs = pk->Add(encrypted_x, encrypted_y);
		msg.push_back(encrypted_rs);
	}
	
	std::random_device rd;
	std::mt19937 gen(rd());
	std::shuffle(msg.begin(), msg.end(), gen);
	
	for (int i = 0; i < cnt; ++i) {
		std::string tmp_str = msg[i].ToBytes();
		PadBytes(tmp_str, cnt_block << 4);
		gc_io_->send_data(&tmp_str[0], msg_len);
	}
	gc_io_->flush();
	
	return OkStatus();
}

StatusOr<PartyOneMessage::MessageII> PartyOne::GenerateMessageII(
    const PartyZeroMessage::MessageI& request,
    std::vector<ElementAndPayload> elements
) {

    PartyOneMessage::MessageII response;

    RETURN_IF_ERROR(other_tree.Update(this->ctx_, this->group, &request.updates()));

    std::vector<std::vector<BigNum> > candidates;
	for (auto cur_elements: request.candidates_vct().elements()) {
		ASSIGN_OR_RETURN(
		    std::vector<BigNum> cur_vct,
		    DeserializeCiphertexts<BigNum>(cur_elements.elements(), this->ctx_, this->group)
		);
		candidates.push_back(cur_vct);
	}

	RETURN_IF_ERROR(CombinePathResponder(candidates));

    // update our tree
    RETURN_IF_ERROR(my_tree.Update(
        this->ctx_, this->sk.get(), elements, response.mutable_updates()
    ));

    for (size_t i = 0; i < elements.size(); ++i) {
        auto cur_candidates = response.mutable_candidates_vct()->add_elements();

        std::vector<Element> cur_msg;
        ASSIGN_OR_RETURN(cur_msg , CombinePathInitiator(elements[i]));
        
        for (size_t j = 0; j < cur_msg.size(); ++j) {
        	auto candidate = cur_candidates->add_elements();
            *candidate->mutable_only_paillier()->mutable_element() = cur_msg[j].ToBytes();
        }
    }
    
    this->AddComm(response, this->current_day);

    return response;
}

}  // namespace deletion
}  // namespace upsi
