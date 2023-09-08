#ifndef CryptoTree_H
#define CryptoTree_H

#include "private_join_and_compute/crypto_node.h"
#include "private_join_and_compute/crypto/context.h"
#include "private_join_and_compute/crypto/ec_commutative_cipher.h"
#include "private_join_and_compute/crypto/paillier.h"

#include <array>
#include <cassert>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <list>
#include <memory>
#include <sstream>
#include <stack>
#include <vector>

typedef std::tuple<ECPoint, BigNum> EncryptedElement;

class CryptoTree
{
    private:
        // Array list representation
        std::vector<CryptoNode> crypto_tree;

        // Current stash node of the tree
        CryptoNode stash;

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

        /// @brief Actual methods
        // Generate a completley random path
        std::vector<CryptoNode> getPath();

        // Generate a path based on an element
        std::vector<CryptoNode> getPath(std::string element);

        // Insert a new element
        void insert(std::string);

        // Given a path on the tree, replace it with a new path
        // Return true if success, false if failure
        bool replacePath(std::vector<CryptoNode> old_path, std::vector<CryptoNode> new_path);
};

#endif

