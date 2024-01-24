#pragma once

#include "src/google/protobuf/message_lite.h"

#include "upsi/addition/party.h"
#include "upsi/crypto/context.h"
#include "upsi/network/message_sink.h"
#include "upsi/roles.h"
#include "upsi/network/upsi.pb.h"
#include "upsi/util/data_util.h"
#include "upsi/util/status.inc"
#include "upsi/utils.h"

namespace upsi {
namespace addonly {

class PartyOne : public Server {
    public:
        PartyOne(PSIParams* params, const std::vector<Dataset>& datasets)
            : Server(params), datasets(params->total_days), comm_(params->total_days)
        {
            for (int day = 0; day < params->total_days; day++) {
                this->datasets[day] = datasets[day].Elements();
            }
        };

        void AddComm(const google::protobuf::Message& msg) {
            comm_[current_day] += msg.ByteSizeLong();
        }

        void PrintComm() {
            unsigned long long total = 0;
            for (size_t day = 0; day < comm_.size(); day++) {
                std::cout << "[PartyOne] Day " << std::to_string(day + 1) << " Comm (B):\t";
                std::cout << comm_[day] << std::endl;
                total += comm_[day];
            }
            std::cout << "[PartyOne] Total Comm (B):\t" << total << std::endl;
        }

    protected:
        // one dataset for each day
        std::vector<std::vector<Element>> datasets;

        // each day's comms cost in bytes
        std::vector<int> comm_;
};

class PartyOneNoPayload : public Party<Element, Ciphertext>, public PartyOne {
    public:
        PartyOneNoPayload(PSIParams* params, const std::vector<Dataset>& datasets) :
            Party<Element, Ciphertext>(params), PartyOne(params, datasets) {}

        virtual ~PartyOneNoPayload() = default;

        /**
         * update their tree, compute candidates, & send tree updates
         */
        virtual StatusOr<PartyOneMessage::MessageII> GenerateMessageII(
            const PartyZeroMessage::MessageI& msg,
            std::vector<Element> elements
        ) = 0;

        /**
         * delegate incoming messages to other methods
         */
        Status Handle(const ClientMessage& request, MessageSink<ServerMessage>* sink) override;
};

class PartyOnePSI : public PartyOneNoPayload {
    public:
        using PartyOneNoPayload::PartyOneNoPayload;

        ~PartyOnePSI() override = default;

        /**
         * update their tree, compute candidates, & send tree updates
         */
        StatusOr<PartyOneMessage::MessageII> GenerateMessageII(
            const PartyZeroMessage::MessageI& msg,
            std::vector<Element> elements
        );
};

class PartyOneCardinality : public PartyOneNoPayload {
    public:
        // use default constructor
        using PartyOneNoPayload::PartyOneNoPayload;

        ~PartyOneCardinality() override = default;

        /**
         * update their tree, compute candidates, & send tree updates
         */
        StatusOr<PartyOneMessage::MessageII> GenerateMessageII(
            const PartyZeroMessage::MessageI& msg,
            std::vector<Element> elements
        );
};

class PartyOneSum : public Party<Element, CiphertextAndElGamal>, public PartyOne {
    public:
        PartyOneSum(PSIParams* params, const std::vector<Dataset>& datasets) :
            Party<Element, CiphertextAndElGamal>(params),
            PartyOne(params, datasets) {}

        ~PartyOneSum() = default;

        /**
         * update their tree, compute candidates, & send tree updates
         */
        StatusOr<PartyOneMessage::MessageII> GenerateMessageII(
            const PartyZeroMessage::MessageI& msg,
            std::vector<Element> elements
        );

        /**
         * receive our secret shares
         */
        StatusOr<PartyOneMessage::MessageIV> ProcessMessageIII(
            const PartyZeroMessage::MessageIII_SUM& msg
        );

        /**
         * delegate incoming messages to other methods
         */
        Status Handle(const ClientMessage& request, MessageSink<ServerMessage>* sink) override;
};

class PartyOneSecretShare : public Party<Element, CiphertextAndPaillier>, public PartyOne {
    public:
        PartyOneSecretShare(PSIParams* params, const std::vector<Dataset>& datasets) :
            Party<Element, CiphertextAndPaillier>(params),
            PartyOne(params, datasets) {}

        ~PartyOneSecretShare() = default;

        /**
         * update their tree, compute candidates, & send tree updates
         */
        StatusOr<PartyOneMessage::MessageII> GenerateMessageII(
            const PartyZeroMessage::MessageI& msg,
            std::vector<Element> elements
        );

        /**
         * receive our secret shares
         */
        Status ProcessMessageIII(const PartyZeroMessage::MessageIII_SS& msg);

        /**
         * delegate incoming messages to other methods
         */
        Status Handle(const ClientMessage& request, MessageSink<ServerMessage>* sink) override;

        // the output secret shares
        std::vector<Element> shares;
};

}  // namespace only
}  // namespace upsi