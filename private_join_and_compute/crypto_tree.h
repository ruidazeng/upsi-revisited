#ifndef CryptoTree_H
#define CryptoTree_H

#include "crypto_node.h"
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

        // Current position root node of the tree
        int root = 0;

        // Current stash node of the tree
        int stash = nullptr;

        // The node size of the tree
        uint8_t node_size;

        // The max stash of the subtree
        int max_stash;

    public:
        CryptoTree();
        CryptoTree(std::string iTextContent, std::string iTagName);

        void appendChild(CryptoTree *child);
        void setParent(CryptoTree *parent);

        void popBackChild();
        void removeChild(int pos);

        bool hasChildren();
        bool hasParent();

        CryptoTree* getParent();
        CryptoTree* getChild(int pos);

        int childrenNumber();
        int grandChildrenNum();

        std::string getTextContent();
        std::string getTagName();
};

#endif

