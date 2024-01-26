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
            Party<Element, CiphertextAndPaillier>(params), PartyOne(params, datasets)
        {
            if (params->start_size > 0) {
                auto status = CreateMockTrees(params->start_size);
                if (!status.ok()) {
                    std::cerr << status << std::endl;
                    std::runtime_error("[PartyZeroSum] failure in creating mock trees");
                }
            }
        }

        ~PartyOneSecretShare() = default;

        Status CreateMockTrees(size_t size) {
            std::cout << "[PartyOneSecretShare] creating mock plaintext tree..." << std::flush;

            // fill plaintext tree with random elements
            std::vector<Element> elements;
            for (size_t i = 0; i < size; i++) {
                elements.push_back(this->ctx_->CreateBigNum(std::stoull(GetRandomSetElement())));
            }

            std::vector<std::string> hashes;
            this->my_tree.insert(elements, hashes);
            std::cout << " done" << std::endl;

            std::cout << "[PartyOneSecretShare] creating mock encrypted tree..." << std::flush;

            // fill encrypted tree with encryptions of zero
            ASSIGN_OR_RETURN(Ciphertext zero_ct, this->encrypter->Encrypt(ctx_->Zero()));
            ASSIGN_OR_RETURN(BigNum zero_bn, this->paillier->Encrypt(ctx_->Zero()));
            this->other_tree.crypto_tree.clear();
            this->other_tree.depth = this->my_tree.depth;
            this->other_tree.actual_size = this->my_tree.actual_size;
            for (const CryptoNode<Element>& pnode : this->my_tree.crypto_tree) {
                CryptoNode<CiphertextAndPaillier> enode(pnode.node_size);
                for (size_t i = 0; i < pnode.node_size; i++) {
                    ASSIGN_OR_RETURN(Ciphertext clone, elgamal::CloneCiphertext(zero_ct));
                    CiphertextAndPaillier pair = std::make_pair(std::move(clone), zero_bn);
                    enode.node.push_back(std::move(pair));
                }
                this->other_tree.crypto_tree.push_back(std::move(enode));
            }
            std::cout << " done" << std::endl;
            return OkStatus();
        }

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
