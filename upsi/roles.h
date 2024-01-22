#pragma once

#include "upsi/crypto/context.h"
#include "upsi/crypto/ec_group.h"
#include "upsi/crypto_tree.h"
#include "upsi/network/connection.h"
#include "upsi/network/message_sink.h"
#include "upsi/params.h"
#include "upsi/network/upsi.pb.h"
#include "upsi/util/proto_util.h"
#include "upsi/util/status.inc"
#include "upsi/utils.h"

namespace upsi {

class ProtocolRole {
    protected:
        int total_days;

        // this is volatile to keep the server from hanging once the protocol is finished
        volatile int current_day = 0;
    public:
        ProtocolRole(PSIParams* params) : total_days(params->total_days) { }

        // call once the day is finished for this party
        virtual void FinishDay() {
            this->current_day++;
        }

        // protocol is finished when we've gone through all days
        virtual bool ProtocolFinished() {
            return (this->current_day >= this->total_days);
        }
};

class Server : public ProtocolRole {
    public:
        using ProtocolRole::ProtocolRole;

        // method called to handle incoming requests
        virtual Status Handle(const ClientMessage& msg, MessageSink<ServerMessage>* sink) = 0;

        // method called at the end of the protocol
        virtual void PrintResult() { }
};

class Client : public ProtocolRole {
    public:
        using ProtocolRole::ProtocolRole;

        // method called to initialize the protocol
        virtual Status Run(Connection* sink) = 0;

        // method called to process responses
        virtual Status Handle(const ServerMessage& msg, MessageSink<ClientMessage>* sink) = 0;

        // method called at the end of the protocol
        virtual void PrintResult() = 0;
};

// handles the tree
template<typename P, typename E>
class HasTree {
    protected:
        // used for various crypto operations
        Context* ctx_;
        ECGroup* group;

    public:
        // our plaintext tree & their encrypted tree
        CryptoTree<P> my_tree;
        CryptoTree<E> other_tree;

        HasTree(PSIParams* params) :
            my_tree(params->stash_size, params->node_size),
            other_tree(params->stash_size, params->node_size)
        {
            this->ctx_ = params->ctx;

            auto group = new ECGroup(ECGroup::Create(CURVE_ID, ctx_).value());
            this->group = group;

            // if specified, load initial trees in from file
            if (params->ImportTrees()) {
                std::cout << "[HasTree] reading in " << params->my_tree_fn;
                std::cout << " and " << params->other_tree_fn << std::endl;
                auto plaintext = ProtoUtils::ReadProtoFromFile<PlaintextTree>(
                    params->my_tree_fn
                );
                if (!plaintext.ok()) {
                    throw std::runtime_error("[HasTree] error reading PlaintextTree");
                }
                Status load = this->my_tree.Deserialize(plaintext.value(), this->ctx_, this->group);
                if (!load.ok()) {
                    std::cerr << load << std::endl;
                    throw std::runtime_error("[HasTree] error loading my tree");
                }

                auto encrypted = ProtoUtils::ReadProtoFromFile<EncryptedTree>(params->other_tree_fn);
                if (!encrypted.ok()) {
                    throw std::runtime_error("[HasTree] error reading EncryptedTree");
                }
                load = this->other_tree.Deserialize(encrypted.value(), this->ctx_, this->group);
                if (!load.ok()) {
                    std::cerr << load << std::endl;
                    throw std::runtime_error("[HasTree] error loading other tree");
                }
            }
        }
};

}  // namespace upsi
