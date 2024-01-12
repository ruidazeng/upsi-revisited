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

#include "upsi/party_one.h"

#include "absl/memory/memory.h"

#include "upsi/crypto/ec_point_util.h"
#include "upsi/crypto/elgamal.h"
#include "upsi/util/elgamal_proto_util.h"
#include "upsi/util/proto_util.h"
#include "upsi/utils.h"

namespace upsi {

////////////////////////////////////////////////////////////////////////////////
// LOAD DATA
////////////////////////////////////////////////////////////////////////////////

void PartyOneCASUM::LoadData(const std::vector<PartyOneDataset>& datasets) {
    this->datasets.resize(this->total_days);
    for (auto day = 0; day < this->total_days; day++) {
        std::vector<ElementAndPayload> dailyset;
        for (size_t i = 0; i < datasets[day].size(); i++) {
            dailyset.push_back(
                GetPayload(datasets[day][i])
            );
        }
        this->datasets[day] = dailyset;
    }
}

ElementAndPayload PartyOneCASUM::GetPayload(BigNum element) {
	long long ele = element.ToIntValue().value();
	if(ele >= 0) return std::make_pair(element, ctx_->One());
	return std::make_pair(ctx_->CreateBigNum(-ele), ctx_->Zero() - ctx_->One());
}

////////////////////////////////////////////////////////////////////////////////
// HANDLE
////////////////////////////////////////////////////////////////////////////////

Status PartyOneCASUM::Handle(const ClientMessage& req, MessageSink<ServerMessage>* sink) {
    if (protocol_finished()) {
        return InvalidArgumentError("[PartyOneCASUM] protocol is already complete");
    } else if (!req.has_party_zero_msg()) {
        return InvalidArgumentError("[PartyOneCASUM] incorrect message type");
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
        day_finished = true;
        std::cerr<<"done...\n";
    } else {
        return InvalidArgumentError(
            "[PartyOneCASUM] received a party zero message of unknown type"
        );
    }

    RETURN_IF_ERROR(sink->Send(res));
    return OkStatus();
}


////////////////////////////////////////////////////////////////////////////////
// GENARATE MESSAGES
////////////////////////////////////////////////////////////////////////////////

StatusOr<PartyOneMessage::MessageII> PartyOneCASUM::GenerateMessageII(
    const PartyZeroMessage::MessageI& request,
    std::vector<ElementAndPayload> elements
) {

	ResetGarbledCircuit();
	
    PartyOneMessage::MessageII response;

    RETURN_IF_ERROR(other_tree.Update(this->ctx_, this->group, &request.updates()));

    ASSIGN_OR_RETURN(
        std::vector<Element> candidates,
        DeserializeElement(request.candidates(), this->ctx_, this->group)
    );
    
    RETURN_IF_ERROR(CombinePathResponder(candidates));

    // update our tree
    RETURN_IF_ERROR(my_tree.Update(
        this->ctx_, this->my_paillier.get(), elements, response.mutable_updates()
    ));
    
     for (size_t i = 0; i < elements.size(); ++i) {
        
        std::vector<Element> cur_msg;
        ASSIGN_OR_RETURN(cur_msg , CombinePathInitiator(elements[i]));
		
        for (size_t j = 0; j < cur_msg.size(); ++j) {
            // add this to the message
            response.mutable_candidates()->add_elements(cur_msg[j].ToBytes());
            //*candidate->mutable_payload() = cur_msg[j].second.ToBytes();
        }
    }

    return response;
}


}  // namespace upsi
