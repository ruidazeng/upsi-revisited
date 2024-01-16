#pragma once

#include "upsi/crypto/elgamal.h"
#include "upsi/crypto/ec_group.h"
#include "upsi/crypto/paillier.h"
#include "upsi/crypto/threshold_paillier.h"
#include "upsi/crypto_node.h"
#include "upsi/network/upsi.pb.h"
#include "upsi/utils.h"

namespace upsi {

template<typename T, typename S>
class BaseTree
{
    protected:

        // The node and stash size of the tree
        size_t node_size;
        int stash_size;

        // The max stash of the subtree
        int max_stash = 0;

        /// @brief Helper Methods
        // Add a new layer to the tree, expand the size of the vector
        void addNewLayer();
        int computeIndex(BinaryHash binary_hash);
        void extractPathIndices(int* leaf_ind, int leaf_cnt, std::vector<int> &ind);
        int* generateRandomPaths(int cnt, std::vector<int> &ind, std::vector<BinaryHash> &hsh);

    public:

        // Array list representation
        /*    0 (stash)
        	  1 (root)
           2     3
          4  5  6  7
        */
        std::vector<CryptoNode<T>> crypto_tree;

        // Depth of the tree (empty tree or just root is depth 0)
        int depth = 0;

        // the number of set elements in the tree (= size of set)
        int actual_size = 0;

        BaseTree(int stash_size = DEFAULT_STASH_SIZE, size_t node_size = DEFAULT_NODE_SIZE);
        std::vector<CryptoNode<T>> insert(std::vector<T> &elem, std::vector<BinaryHash> &hsh);
        void replaceNodes(
            int new_elem_cnt,
            std::vector<CryptoNode<T>>& new_nodes,
            std::vector<BinaryHash>& hsh
        );
		std::vector<T> getPath(Element element);

        StatusOr<std::vector<S*>> Serialize();

        Status Deserialize(const std::vector<S>& trees, Context* ctx, ECGroup* group);

        virtual Status Print() = 0;
};

template<typename T>
class CryptoTree { };

template<>
class CryptoTree<Element> : public BaseTree<Element, PlaintextTree>
{
    public:
        using BaseTree<Element, PlaintextTree>::BaseTree;

        Status Update(
            Context* ctx,
            ElGamalEncrypter* elgamal,
            std::vector<Element>& elements,
            TreeUpdates* updates
        );

        Status Print() override;
};

template<>
class CryptoTree<ElementAndPayload> : public BaseTree<ElementAndPayload, PlaintextTree>
{
    public:
        using BaseTree<ElementAndPayload, PlaintextTree>::BaseTree;

        std::vector<CryptoNode<ElementAndPayload>> InsertWithDeletions(
            std::vector<ElementAndPayload> &elem, std::vector<BinaryHash> &hsh
        );

        // use for encrypting the payload with elgamal
        Status Update(
            Context* ctx,
            ElGamalEncrypter* elgamal,
            std::vector<ElementAndPayload>& elements,
            TreeUpdates* updates
        );

        // use for encrypting the payload with paillier
        Status Update(
            Context* ctx,
            ElGamalEncrypter* elgamal,
            ThresholdPaillier* paillier,
            std::vector<ElementAndPayload>& elements,
            TreeUpdates* updates
        );

        // use for encrypting both element and payload with paillier
        Status Update(
            Context* ctx,
            PrivatePaillier* paillier,
            std::vector<ElementAndPayload>& elements,
            TreeUpdates* updates
        );

        Status Print() override;
};

template<>
class CryptoTree<Ciphertext> : public BaseTree<Ciphertext, EncryptedTree>
{
    public:
        using BaseTree<Ciphertext, EncryptedTree>::BaseTree;

        Status Update(
            Context* ctx,
            ECGroup* group,
            const TreeUpdates* updates
        );

        Status Print();
};

template<>
class CryptoTree<CiphertextAndPaillier> : public BaseTree<CiphertextAndPaillier, EncryptedTree>
{
    public:
        using BaseTree<CiphertextAndPaillier, EncryptedTree>::BaseTree;

        Status Update(
            Context* ctx,
            ECGroup* group,
            const TreeUpdates* updates
        );

        Status Print() override;
};

template<>
class CryptoTree<CiphertextAndElGamal> : public BaseTree<CiphertextAndElGamal, EncryptedTree>
{
    public:
        using BaseTree<CiphertextAndElGamal, EncryptedTree>::BaseTree;

        Status Update(
            Context* ctx,
            ECGroup* group,
            const TreeUpdates* updates
        );

        Status Print() override;
};

template<>
class CryptoTree<PaillierPair> : public BaseTree<PaillierPair, EncryptedTree>
{
    public:
        using BaseTree<PaillierPair, EncryptedTree>::BaseTree;

        Status Update(
            Context* ctx,
            ECGroup* group,
            const TreeUpdates* updates
        );

        Status Print() override;
};

}      // namespace upsi
