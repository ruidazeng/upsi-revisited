#ifndef CryptoTree_H
#define CryptoTree_H

#include "crypto_node.h"
#include "util/hash.h"
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


class CryptoTree
{
    private:
        // Array list representation
        std::vector<CryptoNode> crypto_tree;

        // Current stash node of the tree
        std::vector<CryptoNode> stash;

        // Depth of the tree
        int depth = 0;
        
        // Size of the tree (including root node)
        int size = 0;

        // The node size of the tree
        int node_size;

        // The max stash of the subtree
        int max_stash = 0;

        // Helper function: generate zero or one
        std::string randomBinary();

    public:
        CryptoTree();

        CryptoTree(int node_size);

        // Add a new layer to the tree, expand the size of the vector
        void addNewLayer();

        // Generate a number that corresponds to a leaf node
        void generateLeaf();

        // Generate a path based on content using hash, hashing the same content will result in the same path
        int hashPath(std::vector<bytes*> content);

        // Generate a path based on leaf node generated
        void generatePath();

        // Insert a new node
        void insert();

        // Update Tree (sender)
        void senderUpdateTree();

        // Update Tree (receiver)
        void receiverUpdateTree();
};

#endif

