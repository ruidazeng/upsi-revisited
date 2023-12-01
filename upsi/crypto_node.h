#ifndef CryptoNode_H
#define CryptoNode_H

#include "upsi/match.pb.h"
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
            void pad();

            // create a node with the elements in this node but encrypted
            StatusOr<CryptoNode<elgamal::Ciphertext>> encrypt(
                Context* ctx,
                ElGamalEncrypter* encrypter
            );

            // serialize the node to be sent over the network
            Status serialize(OneNode* obj);
    };

} // namespace upsi

#endif
