#ifndef CRYPTOTREE_H_
#define CRYPTOTREE_H_

#include "upsi/crypto/elgamal.h"
#include "upsi/crypto/ec_group.h"
#include "upsi/crypto/threshold_paillier.h"
#include "upsi/crypto_node.h"
#include "upsi/upsi.pb.h"
#include "upsi/utils.h"

namespace upsi {

template<typename T>
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

        virtual Status Print() = 0;
};

template<typename T>
class CryptoTree : public BaseTree<T> { };

template<>
class CryptoTree<Element> : public BaseTree<Element>
{
    public:
        using BaseTree<Element>::BaseTree;

        Status Load(const PlaintextTree& tree, Context* ctx);

        Status Update(
            Context* ctx,
            ElGamalEncrypter* elgamal,
            std::vector<Element>& elements,
            TreeUpdates* updates
        );

        Status Serialize(PlaintextTree* tree);

        Status Print() override;
};

template<>
class CryptoTree<ElementAndPayload> : public BaseTree<ElementAndPayload>
{
    public:
        using BaseTree<ElementAndPayload>::BaseTree;

        Status Load(const PlaintextTree& tree, Context* ctx);

        Status Update(
            Context* ctx,
            ElGamalEncrypter* elgamal,
            ThresholdPaillier* paillier,
            std::vector<ElementAndPayload>& elements,
            TreeUpdates* updates
        );

        Status Serialize(PlaintextTree* tree);

        Status Print() override;
};

template<>
class CryptoTree<Ciphertext> : public BaseTree<Ciphertext>
{
    public:
        using BaseTree<Ciphertext>::BaseTree;

        Status Load(const EncryptedTree& tree, Context* ctx, ECGroup* group);

        Status Update(
            Context* ctx,
            ECGroup* group,
            const TreeUpdates* updates
        );

        Status Serialize(EncryptedTree* tree);

        Status Print();
};

template<>
class CryptoTree<CiphertextAndPayload> : public BaseTree<CiphertextAndPayload>
{
    public:
        using BaseTree<CiphertextAndPayload>::BaseTree;

        Status Load(const EncryptedTree& tree, Context* ctx, ECGroup* group);

        Status Update(
            Context* ctx,
            ECGroup* group,
            const TreeUpdates* updates
        );

        Status Serialize(EncryptedTree* tree);

        Status Print() override;
};

}      // namespace upsi
#endif // CRYPTOTREE_H_

