#ifndef CryptoTree_H
#define CryptoTree_H

#include "upsi/utils.h"
#include "upsi/crypto_node.h"

namespace upsi {

// typedef std::tuple<ECPoint, BigNum> EncryptedElement;
// typedef std::tuple<std::string, int> EncryptedElement;

template<typename T>
class CryptoTree
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


    public:

    // Array list representation
        std::vector<CryptoNode<T>> crypto_tree;
        /*    0 (stash)
        	  1 (root)
           2     3
          4  5  6  7
        */
        /// @brief Tree Construction
        //CryptoTree();

        CryptoTree(int stash_size = DEFAULT_NODE_SIZE, size_t node_size = DEFAULT_NODE_SIZE);

        int getDepth();

        // int getSize();

        size_t getNodeSize();

        int getStashSize();

        //std::vector<CryptoNode<T> > getTree();

        /// @brief Helper Methods
        // Add a new layer to the tree, expand the size of the vector
        void addNewLayer();


        int computeIndex(BinaryHash binary_hash);

        void extractPathIndices(int* leaf_ind, int cnt, std::vector<int> &ind);

        int* generateRandomPaths(int cnt, std::vector<int> &ind, std::vector<BinaryHash> &hsh);

        std::vector<CryptoNode<T>> insert(std::vector<T> &elem, std::vector<BinaryHash> &hsh);

        void replaceNodes(int new_elem_cnt, std::vector<CryptoNode<T> > &new_nodes, std::vector<BinaryHash> &hsh);

		std::vector<T> getPath(Element element);
};

}

#endif

