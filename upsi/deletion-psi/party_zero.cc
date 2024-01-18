#include "upsi/deletion-psi/party_zero.h"

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
    this->datasets[0].resize(this->total_days);
    this->datasets[1].resize(this->total_days);
    for (int day = 0; day < this->total_days; day++) {
    	std::vector<std::pair<BigNum, BigNum>> cur_day = datasets[day].ElementsAndValues();
    	int cnt = cur_day.size();
    	for (int i = 0; i < cnt; ++i) {
    		if(cur_day[i].second.IsNonNegative()) this->datasets[1][day].push_back(cur_day[i]); //addition
    		else this->datasets[0][day].push_back(cur_day[i]); //deletion
    	}
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
        std::cerr<<"done...\n";
    } else {
        return InvalidArgumentError(
            "[PartyZero] received a party one message of unknown type"
        );
    }

    return OkStatus();
}

Status PartyZero::Run(Connection* sink) {
    ResetGarbledCircuit();
    
    RETURN_IF_ERROR(SendMessageI(sink, datasets[0][current_day])); //deletion
    ServerMessage message_ii = sink->GetResponse();
    RETURN_IF_ERROR(Handle(message_ii, sink));
    
    RETURN_IF_ERROR(SendMessageI(sink, datasets[1][current_day])); //addition
    ServerMessage message_ii_ = sink->GetResponse();
    RETURN_IF_ERROR(Handle(message_ii_, sink));
    
    FinishDay();
    
    return OkStatus();
}

Status PartyZero::SecondPhase() {
	ASSIGN_OR_RETURN(std::vector<uint64_t> rs, GarbledCircuit());
	int cnt = rs.size();
	
	BigNum cur_n = sk->n();
	int len = cur_n.ToBytes().length();
	int cnt_block = (len * 2 + 15) >> 4;
	int msg_len = cnt_block << 4;
	
	for (int i = 0; i < cnt; ++i) {
		ASSIGN_OR_RETURN(BigNum encrypted_x, sk->Encrypt(ctx_->CreateBigNum(rs[i])));
		std::string tmp_str = encrypted_x.ToBytes();
		PadBytes(tmp_str, cnt_block << 4);
		gc_io_->send_data(&tmp_str[0], msg_len);
	}
	
	uint64_t minus_one = -1; //2^64 - 1
	BigNum mod = ctx_->CreateBigNum(minus_one) + ctx_->One();
	
	std::vector<uint64_t> result_updates;
	
	for (int i = 0; i < cnt; ++i) {
		std::string tmp_str(msg_len, 0);
		gc_io_->recv_data(&tmp_str[0], msg_len);
		BigNum encrypted_x = ctx_->CreateBigNum(tmp_str);
		ASSIGN_OR_RETURN(BigNum decrypted_x, sk->Decrypt(encrypted_x));
		if(decrypted_x >= mod) decrypted_x -= mod;
		ASSIGN_OR_RETURN(uint64_t tmp, decrypted_x.ToIntValue());
		if(tmp > 0) result_updates.push_back(tmp);
	}
	
	int result_size = result_updates.size();
	for (int i = 0; i < result_size; ++i) {
		long long num = result_updates[i];
		//std::cerr<<num << endl;
		if(num < 0) --result;
		else ++result;
		std::set<std::string>::iterator it = intersection.find(std::to_string(-num));
		if(it == intersection.end()) intersection.insert(std::to_string(num));
		else intersection.erase(it);
	}
	
	return OkStatus();
}

void PartyZero::PrintResult(){
	std::cout << "[PartyZero] cardinality = " << result << std::endl;
	if(intersection.size() < 10) {
		std::cout << "[PartyZero] intersection = \n";
		for (auto elem:intersection) {
			std::cout << elem << "\n";
		}
	}
}

Status PartyZero::SendMessageI(MessageSink<ClientMessage>* sink, std::vector<ElementAndPayload> elements) {
    ClientMessage msg;

    ASSIGN_OR_RETURN(auto message_i, GenerateMessageI(elements));

    *(msg.mutable_party_zero_msg()->mutable_message_i()) = message_i;
    return sink->Send(msg);
}

Status PartyZero::ProcessMessageII(
    const PartyOneMessage::MessageII& res,
    MessageSink<ClientMessage>* sink
) {

    RETURN_IF_ERROR(other_tree.Update(this->ctx_, this->group, &res.updates()));
	
	std::vector<std::vector<BigNum> > candidates;
	for (auto cur_elements: res.candidates_vct().elements()) {
		ASSIGN_OR_RETURN(
		    std::vector<BigNum> cur_vct,
		    DeserializeCiphertexts<BigNum>(cur_elements.elements(), this->ctx_, this->group)
		);
		candidates.push_back(cur_vct);
	}

	RETURN_IF_ERROR(CombinePathResponder(candidates));

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
        auto cur_candidates = msg.mutable_candidates_vct()->add_elements();

        std::vector<Element> cur_msg;
        ASSIGN_OR_RETURN(cur_msg , CombinePathInitiator(elements[i]));
        
        for (size_t j = 0; j < cur_msg.size(); ++j) {
        	auto candidate = cur_candidates->add_elements();
            *candidate->mutable_only_paillier()->mutable_element() = cur_msg[j].ToBytes();
        }
    }

    return msg;
}

}  // namespace deletion
}  // namespace upsi
