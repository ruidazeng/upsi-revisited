#pragma once

#include "upsi/original/party.h"
#include "upsi/network/connection.h"
#include "upsi/network/message_sink.h"
#include "upsi/roles.h"
#include "upsi/network/upsi.pb.h"
#include "upsi/util/data_util.h"
#include "upsi/util/status.inc"
#include "upsi/utils.h"

namespace upsi {
namespace original {

class PartyZero : public Server, public Party {
    public:
        PartyZero(PSIParams* params, const std::vector<Dataset>& datasets)
            : Server(params), Party(params, datasets), tree(params->stash_size, params->node_size),
              comm_(params->total_days)
        {
            // if specified, load initial trees in from file
            if (params->ImportTrees()) {
                std::cout << "[PartyZero] reading in " << params->my_tree_fn;
                std::cout << " and " << params->oprf_fn << std::endl;
                auto encrypted = ProtoUtils::ReadProtoFromFile<EncryptedTree>(params->my_tree_fn);
                if (!encrypted.ok()) {
                    throw std::runtime_error("[PartyZero] error reading EncryptedTree");
                }

                auto load = this->tree.Deserialize(encrypted.value(), this->ctx_, this->group);
                if (!load.ok()) {
                    std::cerr << load << std::endl;
                    throw std::runtime_error("[PartyZero] error loading tree");
                }

                auto oprf = ProtoUtils::ReadProtoFromFile<OPRF>(params->oprf_fn);
                for (const auto& kv : oprf.value().kv()) {
                    std::string element = kv.element();
                    auto output = this->group->CreateECPoint(kv.output());
                    auto key = output.value().ToBytesUnCompressed();
                    group_mapping[key.value()] = element;
                }
            }
        }

        Status Handle(const ClientMessage& msg, MessageSink<ServerMessage>* sink) override;

        Status SendMessageII(
            const OriginalMessage::MessageI& res, MessageSink<ServerMessage>* sink
        );

        Status SendMessageIV(
            const OriginalMessage::MessageIII& res, MessageSink<ServerMessage>* sink
        );

        Status ProcessMessageV(const OriginalMessage::MessageV& res);

        void AddComm(const google::protobuf::Message& msg) {
            comm_[current_day] += msg.ByteSizeLong();
        }
        void PrintComm();

        void PrintResult() override;

    protected:
        // their encrypted set
        CryptoTree<Ciphertext> tree;

        // maps H(x)^ab to x
        std::map<std::string, std::string> group_mapping;

        // elements in the intersection
        std::vector<std::string> intersection;

        // masks sampled when creating message iv
        std::vector<BigNum> masks;

        // each day's comms cost in bytes
        std::vector<int> comm_;
};

}  // namespace original
}  // namespace upsi
