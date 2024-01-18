#ifndef CryptoNode_H
#define CryptoNode_H

#include "upsi/crypto/paillier.h"
#include "upsi/crypto/threshold_paillier.h"
#include "upsi/network/upsi.pb.h"
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

        CryptoNode() = delete;
        CryptoNode(size_t node_size);

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
};

Status SerializeNode(CryptoNode<Element>* cnode, PlaintextNode* pnode);
Status SerializeNode(CryptoNode<ElementAndPayload>* cnode, PlaintextNode* pnode);
Status SerializeNode(CryptoNode<Ciphertext>* cnode, TreeNode* tnode);
Status SerializeNode(CryptoNode<CiphertextAndPaillier>* cnode, TreeNode* tnode);
Status SerializeNode(CryptoNode<CiphertextAndElGamal>* cnode, TreeNode* tnode);
Status SerializeNode(CryptoNode<PaillierPair>* cnode, TreeNode* tnode);

template<typename T>
StatusOr<CryptoNode<T>> DeserializeNode(const PlaintextNode& pnode, Context* ctx, ECGroup* group);

template<typename T>
StatusOr<CryptoNode<T>> DeserializeNode(const TreeNode& tnode, Context* ctx, ECGroup* group);

StatusOr<CryptoNode<Ciphertext>> EncryptNode(
    Context* ctx,
    ElGamalEncrypter* encrypter,
    const CryptoNode<Element>& node
);

StatusOr<CryptoNode<CiphertextAndElGamal>> EncryptNode(
    Context* ctx,
    ElGamalEncrypter* encrypter,
    const CryptoNode<ElementAndPayload>& node
);

StatusOr<CryptoNode<CiphertextAndPaillier>> EncryptNode(
    Context* ctx,
    ElGamalEncrypter* elgamal,
    ThresholdPaillier* paillier,
    const CryptoNode<ElementAndPayload>& node
);

StatusOr<CryptoNode<PaillierPair>> EncryptNode(
    Context* ctx,
    PrivatePaillier* paillier,
    const CryptoNode<ElementAndPayload>& node
);

} // namespace upsi

#endif
