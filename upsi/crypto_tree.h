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
    private:
        // Depth of the tree (empty tree or just root is depth 0)
        int depth = 0;

        // Size of the tree (including root node)
        // int size = 0;

        // The node and stash size of the tree
        size_t node_size;
        int stash_size;

        // The number of set elements in the tree (= size of set)
        int actual_size = 0;

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

        BaseTree(int stash_size = DEFAULT_NODE_SIZE, size_t node_size = DEFAULT_NODE_SIZE);
        std::vector<CryptoNode<T>> insert(std::vector<T> &elem, std::vector<BinaryHash> &hsh);       
        void replaceNodes(
            int new_elem_cnt, 
            std::vector<CryptoNode<T>>& new_nodes, 
            std::vector<BinaryHash>& hsh
        );
		std::vector<T> getPath(Element element);
};

template<class T>
class CryptoTree : public BaseTree<T> { };

template<>
class CryptoTree<Element> : public BaseTree<Element>
{
    public:
        Status Update(
            Context* ctx,
            ElGamalEncrypter* elgamal,
            std::vector<Element>& elements, 
            TreeUpdates* updates
        );
};

template<>
class CryptoTree<ElementAndPayload> : public BaseTree<ElementAndPayload>
{
    public:
        Status Update(
            Context* ctx,
            ElGamalEncrypter* elgamal,
            ThresholdPaillier* paillier,
            std::vector<ElementAndPayload>& elements, 
            TreeUpdates* updates
        );
};

template<>
class CryptoTree<Ciphertext> : public BaseTree<Ciphertext>
{
    public:
        Status Update(
            Context* ctx,
            ECGroup* group,
            const TreeUpdates* updates
        );
};

template<>
class CryptoTree<CiphertextAndPayload> : public BaseTree<CiphertextAndPayload>
{
    public:
        Status Update(
            Context* ctx,
            ECGroup* group,
            const TreeUpdates* updates
        );
};

}      // namespace upsi
#endif // CRYPTOTREE_H_

