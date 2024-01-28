#pragma once

#include "src/google/protobuf/message_lite.h"

#include "upsi/original/party.h"
#include "upsi/crypto/context.h"
#include "upsi/network/message_sink.h"
#include "upsi/roles.h"
#include "upsi/network/upsi.pb.h"
#include "upsi/util/data_util.h"
#include "upsi/util/status.inc"
#include "upsi/utils.h"

namespace upsi {
namespace original {

class PartyOne : public Client, public Party {
    public:
        PartyOne(PSIParams* params, const std::vector<Dataset>& datasets)
            : Client(params), Party(params, datasets), tree(params->stash_size, params->node_size) {
            // if specified, load initial trees in from file
            if (params->ImportTrees()) {
                std::cout << "[PartyOne] reading in " << params->my_tree_fn << std::endl;
                auto plaintext = ProtoUtils::ReadProtoFromFile<PlaintextTree>(
                    params->my_tree_fn
                );
                if (!plaintext.ok()) {
                    throw std::runtime_error("[PartyOne] error reading PlaintextTree");
                }
                Status load = this->tree.Deserialize(plaintext.value(), this->ctx_, this->group);
                if (!load.ok()) {
                    std::cerr << load << std::endl;
                    throw std::runtime_error("[PartyOne] error loading my tree");
                }
            }
            
            if (params->start_size > 0) {
                auto status = CreateMockTrees(params->start_size);
                if (!status.ok()) {
                    std::cerr << status << std::endl;
                    std::runtime_error("[PartyZeroSum] failure in creating mock trees");
                }
            }
        }
        
        Status CreateMockTrees(size_t size) {
            std::cout << "[PartyOneSecretShare] creating mock plaintext tree..." << std::flush;

            // fill plaintext tree with random elements
            std::vector<Element> elements;
            for (size_t i = 0; i < size; i++) {
                elements.push_back(this->ctx_->CreateBigNum(std::stoull(GetRandomSetElement())));
            }

            std::vector<std::string> hashes;
            this->tree.insert(elements, hashes);
            std::cout << " done" << std::endl;

            
            return OkStatus();
        }

        Status Run(Connection* sink) override;

        Status Handle(const ServerMessage& msg, MessageSink<ClientMessage>* sink) override;

        Status SendMessageI(MessageSink<ClientMessage>* sink);
        Status SendMessageIII(
            const OriginalMessage::MessageII& res, MessageSink<ClientMessage>* sink
        );
        Status SendMessageV(
            const OriginalMessage::MessageIV& res, MessageSink<ClientMessage>* sink
        );

        void PrintResult() override { };

    protected:
        // our plaintext set
        CryptoTree<Element> tree;
};

}  // namespace original
}  // namespace upsi
