#ifndef PARTY_H_
#define PARTY_H_

#include "upsi/crypto/elgamal.h"
#include "upsi/crypto/threshold_paillier.h"
#include "upsi/crypto_tree.h"
#include "upsi/util/elgamal_proto_util.h"
#include "upsi/util/proto_util.h"
#include "upsi/utils.h"

namespace upsi {

struct PSIParams {

    // pointer to the running context object
    Context* ctx;

    // filename for el gamal (shared) public key
    std::string epk_fn;

    // filename for el gamal secret key
    std::string esk_fn;

    // filename for paillier shared secret key
    std::string psk_fn;

    // number of days to run protocol for
    int total_days;

    // filename for this party's initial plaintext tree
    std::string my_tree_fn;

    // filename for other party's initial encrypted tree
    std::string other_tree_fn;

    PSIParams(
        Context* ctx,
        std::string epk_fn,
        std::string esk_fn,
        std::string psk_fn,
        int total_days,
        std::string my_tree_fn = "",
        std::string other_tree_fn = ""
    ) : ctx(ctx), epk_fn(epk_fn), esk_fn(esk_fn), psk_fn(psk_fn), total_days(total_days),
        my_tree_fn(my_tree_fn), other_tree_fn(other_tree_fn) { }

    // true when we are importing initial trees from file
    bool ImportTrees() {
        return my_tree_fn != "";
    }
};

/**
 * handles basic time tracking
 */
class BaseParty {
    protected:
        int total_days;

        // this is volatile to keep the server from hanging once the protocol is finished
        volatile int current_day = 0;
    public:
        BaseParty(PSIParams* params) : total_days(params->total_days) { }

        // call once the day is finished for this party
        virtual void FinishDay() {
            this->current_day++;
        }

        // protocol is finished when we've gone through all days
        bool protocol_finished() {
            return (this->current_day >= this->total_days);
        }
};


template<typename P, typename E>
class Party {
    protected:
        // used for various crypto operations
        Context* ctx_;
        ECGroup* group;

        // el gamal encryption tools
        std::unique_ptr<ElGamalEncrypter> encrypter;
        std::unique_ptr<ElGamalDecrypter> decrypter;

        // paillier encryption tool
        std::unique_ptr<ThresholdPaillier> paillier;


        // our plaintext tree & their encrypted tree
        CryptoTree<P> my_tree;
        CryptoTree<E> other_tree;

    public:
        Party(PSIParams* params) {
            this->ctx_ = params->ctx;

            // set up el gamal keys
            auto group = new ECGroup(ECGroup::Create(CURVE_ID, ctx_).value());
            this->group = group; // TODO: delete

            auto epk = ProtoUtils::ReadProtoFromFile<ElGamalPublicKey>(params->epk_fn);
            if (!epk.ok()) {
                std::runtime_error("[Party] failure in reading shared public key");
            }

            encrypter = std::make_unique<ElGamalEncrypter>(
                this->group,
                elgamal_proto_util::DeserializePublicKey(this->group, epk.value()).value()
            );

            auto esk = ProtoUtils::ReadProtoFromFile<ElGamalSecretKey>(params->esk_fn);
            if (!esk.ok()) {
                std::runtime_error("[Party] failure in reading secret key");
            }

            decrypter = std::make_unique<ElGamalDecrypter>(
                elgamal_proto_util::DeserializePrivateKey(ctx_, esk.value()).value()
            );

            // set up pailier key
            auto psk = ProtoUtils::ReadProtoFromFile<ThresholdPaillierKey>(params->psk_fn);
            if (!psk.ok()) {
                std::runtime_error("[Party] failure in reading paillier key");
            }

            paillier = std::make_unique<ThresholdPaillier>(ctx_, psk.value());

            // if specified, load initial trees in from file
            if (params->ImportTrees()) {
                std::cout << "[Party] reading in " << params->my_tree_fn;
                std::cout << " and " << params->other_tree_fn << std::endl;
                auto plaintext = ProtoUtils::ReadProtoFromFile<PlaintextTree>(
                    params->my_tree_fn
                );
                if (!plaintext.ok()) {
                    throw std::runtime_error("[Party] error reading PlaintextTree");
                }
                Status load = this->my_tree.Deserialize(plaintext.value(), this->ctx_, this->group);
                if (!load.ok()) {
                    std::cerr << load << std::endl;
                    throw std::runtime_error("[Party] error loading my tree");
                }

                auto encrypted = ProtoUtils::ReadProtoFromFile<EncryptedTree>(params->other_tree_fn);
                if (!encrypted.ok()) {
                    throw std::runtime_error("[Party] error reading EncryptedTree");
                }
                load = this->other_tree.Deserialize(encrypted.value(), this->ctx_, this->group);
                if (!load.ok()) {
                    std::cerr << load << std::endl;
                    throw std::runtime_error("[Party] error loading other tree");
                }
            }
        }
};

} // namespace upsi

#endif  // PARTY_H_
