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
// LOAD DATA
////////////////////////////////////////////////////////////////////////////////

void PartyZeroCASUM::LoadData(const std::vector<PartyZeroDataset>& datasets) {
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

ElementAndPayload PartyZeroSum::GetPayload(BigNum element, BigNum value) {
	long long ele = element.ToIntValue().value();
	if(ele >= 0) return std::make_pair(element, value);
	if(value == this->ctx_->Zero()) return std::make_pair(ctx_->CreateBigNum(-ele), value);
	return std::make_pair(ctx_->CreateBigNum(-ele), ctx_->Zero() - value);
}

ElementAndPayload PartyZeroCardinality::GetPayload(BigNum element, BigNum value) {
	long long ele = element.ToIntValue().value();
	if(ele >= 0) return std::make_pair(element, ctx_->One());
	return std::make_pair(ctx_->CreateBigNum(-ele), ctx_->Zero() - ctx_->One());
}

Status PartyZeroCASUM::Handle(const ServerMessage& msg, MessageSink<ClientMessage>* sink) {
    if (protocol_finished()) {
        return InvalidArgumentError("[PartyZeroCASUM] protocol is already complete");
    } else if (!msg.has_party_one_msg()) {
        return InvalidArgumentError("[PartyZeroCASUM] incorrect message type");
    }

    if (msg.party_one_msg().has_message_ii()) {
        RETURN_IF_ERROR(ProcessMessageII(msg.party_one_msg().message_ii(), sink));
        //std::cerr<<"done...\n";
    } else {
        return InvalidArgumentError(
            "[PartyZeroCASUM] received a party one message of unknown type"
        );
    }

    return OkStatus();
}

////////////////////////////////////////////////////////////////////////////////
// RUN
////////////////////////////////////////////////////////////////////////////////

Status PartyZeroCASUM::Run(Connection* sink) {
    //while (!protocol_finished()) {
        
        //std::cerr << "Day " << this->current_day << std::endl;
        ResetGarbledCircuit();
        //std::cerr<<"SendMessageI...\n";
        RETURN_IF_ERROR(SendMessageI(sink));

        //std::cerr<<"ProcessMessageII...\n";
        ServerMessage message_ii = sink->last_server_response();
        RETURN_IF_ERROR(Handle(message_ii, sink));
    //}
    return OkStatus();
}

void PartyZeroCASUM::PrintResult(){
	std::cout << "[PartyZero] CA/SUM = " << result << std::endl;
}

void PartyZeroCASUM::UpdateResult(uint64_t cur_ans) {
	this->result += cur_ans;
}

////////////////////////////////////////////////////////////////////////////////
// GENERATE MESSAGES
////////////////////////////////////////////////////////////////////////////////


Status PartyZeroCASUM::SendMessageI(MessageSink<ClientMessage>* sink) {
    ClientMessage msg;

    ASSIGN_OR_RETURN(auto message_i, GenerateMessageI(datasets[current_day]));

    *(msg.mutable_party_zero_msg()->mutable_message_i()) = message_i;
    return sink->Send(msg);
}

Status PartyZeroCASUM::ProcessMessageII(
    const PartyOneMessage::MessageII& res,
    MessageSink<ClientMessage>* sink
) {

    RETURN_IF_ERROR(other_tree.Update(this->ctx_, this->group, &res.updates()));

    ASSIGN_OR_RETURN(
        std::vector<Element> candidates,
        DeserializeElement(res.candidates(), this->ctx_, this->group)
    );

	RETURN_IF_ERROR(CombinePathResponder(candidates));
	
    FinishDay();
	
	return OkStatus();
}

StatusOr<PartyZeroMessage::MessageI> PartyZeroCASUM::GenerateMessageI(
    std::vector<ElementAndPayload> elements
) {
    PartyZeroMessage::MessageI msg;

    // update our tree
    RETURN_IF_ERROR(my_tree.Update(
        this->ctx_, this->my_paillier.get(), elements, msg.mutable_updates()
    ));

    for (size_t i = 0; i < elements.size(); ++i) {
        
        std::vector<Element> cur_msg;
        ASSIGN_OR_RETURN(cur_msg , CombinePathInitiator(elements[i]));
		
        for (size_t j = 0; j < cur_msg.size(); ++j) {
            // add this to the message
            msg.mutable_candidates()->add_elements(cur_msg[j].ToBytes());
            //*candidate->mutable_payload() = cur_msg[j].second.ToBytes();
        }
    }

    return msg;
}

}  // namespace upsi
