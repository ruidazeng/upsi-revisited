#ifndef CryptoTree_H
#define CryptoTree_H

#include "updatable_private_set_intersection/utils.h"
#include "updatable_private_set_intersection/crypto_node.h"

namespace updatable_private_set_intersection {

// typedef std::tuple<ECPoint, BigNum> EncryptedElement;
// typedef std::tuple<std::string, int> EncryptedElement;

template<typename T>
class CryptoTree
{
    private:
        // Array list representation
        std::vector<CryptoNode<T> > crypto_tree;

        // Current stash node of the tree
        CryptoNode<T> stash;

        // Depth of the tree (empty tree or just root is depth 0)
        int depth = 0;
        
        // Size of the tree (including root node)
        int size = 0;

        // The node and stash size of the tree
        int node_size;
        int stash_size;

        // The max stash of the subtree
        int max_stash = 0;


    public:
        /// @brief Tree Construction
        CryptoTree();

        CryptoTree(int node_size, int stash_size);

        int getDepth();

        int getSize();

        int getNodeSize();

        int getStashSize();

        /// @brief Helper Methods
        // Add a new layer to the tree, expand the size of the vector
        void addNewLayer();

        std::string binaryHash(std::string const &byte_hash);

        std::vector<CryptoNode<T> > findPath(int depth, std::string binary_hash);

        /// @brief Actual methods
        // Generate a completley random path
        std::vector<CryptoNode<T> > getPath();

        // Generate a path based on an element
        std::vector<CryptoNode<T> > getPath(std::string element);

        // Insert a new element
        void insert(std::string element);
        
        // Replace the stash
        void replaceStash(CryptoNode<T> new_stash);

        // Given a leaf node on the tree, replace the root to leaf path with a new path
        // Return true if success, false if failure
        bool replacePath(int leaf, std::vector<CryptoNode<T> > new_path);
};

}

#endif

