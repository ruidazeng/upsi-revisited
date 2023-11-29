#ifndef CryptoNode_H
#define CryptoNode_H

#include "updatable_private_set_intersection/utils.h"

namespace updatable_private_set_intersection {

/*
Type T can be a tuple for element and payload 
	or be one type for element only when there's no payload
*/
template<typename T>
class CryptoNode
{
    public:
        std::vector<T> node;
        int node_size;

    
        // Default constructor
        // CryptoNode();
        
        
		//CryptoNode(const CryptoNode&) = delete;
		//CryptoNode operator=(const CryptoNode&) = delete;

        // Initialize CryptoNode with node size
        CryptoNode(int node_size = default_node_size);

        // Get node size
        //int getNodeSize();

        // Get the node vector
        //std::vector<T> getNode();
        
        void clear();
        
        void copyElementsTo(const std::vector<T> &elem);

        // Add an element to the node vector, return true if success, false if it's already full
        bool addElement(T &elem);
};

} // namespace updatable_private_set_intersection

#endif
