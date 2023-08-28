#ifndef CryptoTree_H
#define CryptoTree_H

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

class TreeNode
{
    protected:
        std::string textContent;
        std::string tagName;

        TreeNode *parent;

        std::vector<TreeNode *> children;

        int countNodesRec(TreeNode *root, int& count);

    public:
        TreeNode();
        TreeNode(std::string iTextContent, std::string iTagName);

        void appendChild(TreeNode *child);
        void setParent(TreeNode *parent);

        void popBackChild();
        void removeChild(int pos);

        bool hasChildren();
        bool hasParent();

        TreeNode* getParent();
        TreeNode* getChild(int pos);

        int childrenNumber();
        int grandChildrenNum();

        std::string getTextContent();
        std::string getTagName();
};

#endif

