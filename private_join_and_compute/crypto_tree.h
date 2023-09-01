#ifndef CryptoTree_H
#define CryptoTree_H

#include "crypto_node.h"
#include "util/hash.h"
#include <array>
#include <cassert>
#include <cmath>
#include <cstddef>
#include <cstdint>
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
        int depth;
        
        // Size of the tree
        int size;

        // The node size of the tree
        int node_size;

        // The max stash of the subtree
        int max_stash = 0;

    public:
        CryptoTree();

        CryptoTree(int node_size);

        void getNextPath();

        void insert();

        void getPath();

        void clientUpdateTree();

        void serverUpdateTree();
};

#endif

