#ifndef CryptoNode_H
#define CryptoNode_H

#include "upsi/crypto/threshold_paillier.h"
#include "upsi/upsi.pb.h"
#include "upsi/utils.h"

namespace upsi {

/*
   Type T can be a tuple for element and payload
   or be one type for element only when there's no payload
   */
template<typename T>
    class CryptoNode
    {
        public:
            std::vector<T> node;
            size_t node_size;

            CryptoNode(size_t node_size = DEFAULT_NODE_SIZE);

            // Get node size
            //int getNodeSize();

            // Get the node vector
            //std::vector<T> getNode();

            void clear();

            /**
             * create a copy of this node
             */
            CryptoNode<T> copy();

            void copyElementsTo(std::vector<T> &elem);

            // Add an element to the node vector, return true if success, false if it's already full
            bool addElement(T &elem);

            // pad with padding elements to the node_size
            void pad(Context* ctx);

            // serialize the node to be sent over the network
            Status serialize(TreeNode* obj);
    };

StatusOr<CryptoNode<Ciphertext>> EncryptNode(
    Context* ctx, 
    ElGamalEncrypter* encrypter,
    const CryptoNode<Element>& node
);

StatusOr<CryptoNode<CiphertextAndPayload>> EncryptNode(
    Context* ctx, 
    ElGamalEncrypter* elgamal,
    ThresholdPaillier* paillier,
    const CryptoNode<ElementAndPayload>& node
);

} // namespace upsi

#endif
