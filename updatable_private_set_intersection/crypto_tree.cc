#include "updatable_private_set_intersection/utils.h"
#include "updatable_private_set_intersection/crypto_tree.h"
#include "updatable_private_set_intersection/crypto_node.h"


/// @brief Tree Construction

namespace updatable_private_set_intersection {

template<typename T> 
CryptoTree<T>::CryptoTree() {};

template<typename T> 
CryptoTree<T>::CryptoTree(int stash_size, int node_size) {
    this->node_size = node_size;
    this->stash_size = node_size;
    
    // Index for root node is 1, index for stash node is 0
    CryptoNode<T> stash = CryptoNode<T>(stash_size);
    CryptoNode<T> root = CryptoNode<T>(node_size);

    // depth = 0
    this->crypto_tree.push_back(stash);
    this->crypto_tree.push_back(root);
    
}

template<typename T> 
int CryptoTree<T>::getDepth() {
    return this->depth;
}
/*
template<typename T> 
int CryptoTree<T>::getSize() {
    return this->size;
}
*/
template<typename T> 
int CryptoTree<T>::getNodeSize() {
    return this->node_size;
}

template<typename T> 
int CryptoTree<T>::getStashSize() {
    return this->stash_size;
}
/*
template<typename T> 
CryptoNode<T>& CryptoTree<T>::stash() {
    return this->crypto_tree[0];
}
*/

/// @brief Helper methods
template<typename T> 
void CryptoTree<T>::addNewLayer() {
    this->depth += 1;
    int new_size = (1 << (this->depth + 1));
    this->crypto_tree.resize(new_size);
}


/*
template<typename T> 
std::vector<CryptoNode<T> > CryptoTree<T>::findPath(int depth, std::string binary_hash) {
    std::vector<CryptoNode<T> > path;
    
    int node = 0; // root
    path.push_back(this->crypto_tree[node]);

    for (int i=0; i <= depth; ++i) {
        if (binary_hash[i] == '0') {
            node = node * 2 + 1;
        }
        else if (binary_hash[i] == '1') {
            node = node * 2 + 2;
        }
        path.push_back(this->crypto_tree[node]);
    }
    return path;
}

/// @brief Real methods

// Generate a completley random path

template<typename T> 
std::vector<CryptoNode<T> > CryptoTree<T>::getPath() {
    Context ctx;
    std::string random_path = ctx.GenerateRandomBytes(32); // 32 bytes for SHA256 => obtain random_path as a byte string
    std::string random_path_binary = this->binaryHash(random_path);

    // Find path in tree
    auto tree_path = this->findPath(this->depth, random_path_binary);
    return tree_path;
}

// Generate a path based on an element
template<typename T> 
std::vector<CryptoNode<T> > CryptoTree<T>::getPath(std::string element) {
    Context ctx;
    absl::string_view sv_element = element;
    // TODO: PRF?????
    std::string fixed_path = ctx.Sha256String(sv_element);
    std::string fixed_path_binary = this->binaryHash(fixed_path);

    // Find path in tree
    auto tree_path = this->findPath(this->depth, fixed_path_binary);
    return tree_path;
}

// Insert a new element
// TODO: WHEN TO ADD A NEW LEVEL OF TREE???
template<typename T> 
void CryptoTree<T>::insert(std::string element) {
    // find the path based on hash
    auto old_path = this->getPath(element);
    // gather every element in the path + stash
    std::vector<T> pathstash;

    // find the leaf node of the path based on depth

    // construct the new path

    // replace the old path with the new path

    // replace the old stash with the new stash

}
*/

// compute leaf index of a binary hash
template<typename T> 
int CryptoTree<T>::computeIndex(BinaryHash binary_hash) {
	int x = 1;
	for (int i = 0; i <= this->depth; ++i) {
        if (binary_hash[i] == '0') {
            x = (x << 1);
        }
        else if (binary_hash[i] == '1') {
            x = ((x << 1) | 1);
        }
    }
    return x;
}

// Return indices in paths in decreasing order
template<typename T> 
void CryptoTree<T>::extractPathIndices(int* leaf_ind, int leaf_cnt, std::vector<int> &ind) {
	assert(ind.size() == 0);
	
	// add the indicies of leaves
	for (int i = leaf_cnt - 1; i >= 0; --i) 
		ind.push_back(leaf_ind[i]);  
		
	// erase duplicates and sort in decreasing order
	std::sort(ind.begin(), ind.end(), std::greater<int>());
	ind.erase(std::unique(ind.begin(), ind.end()), ind.end());
	
	int node_cnt = ind.size();
	for (int i = 0; i <= node_cnt; ++i) {
		if(ind[i] == 1) break; // is root
		int par = (ind[i] >> 1); // add its parent 
		assert(ind[node_cnt - 1] >= par);
		if(ind[node_cnt - 1] > par) {
			ind.push_back(par);
			++node_cnt;
		}
	}
}

// Generate random paths, return the indices of leaves and nodes(including stash)
template<typename T> 
int* CryptoTree<T>::generateRandomPaths(int cnt, std::vector<int> &ind) { //ind: node indices
	// generate binary hash
	std::vector<BinaryHash> hsh;
	generateRandomHash(cnt, hsh);
	
	// compute leaf indices of the paths
	int *leaf_ind = new int[cnt];
	for (int i = 0; i < cnt; ++i) leaf_ind[i] = computeIndex(hsh[i]);
	
	// extract indices of nodes in these paths
	extractPathIndices(leaf_ind, cnt, ind);
	
	// insert stash
	ind.push_back(0);
	
	return leaf_ind;
	// the sender requires indices of leaves (if update paths on its tree one by one)
	// need to delete leaf_ind outside this function
}

// Insert new set elements (sender)
// Return vector of (plaintext) nodes
// stash: index = 0
template<typename T> 
std::vector<CryptoNode<T> > CryptoTree<T>::insert(std::vector<T> elem) {
	int new_elem_cnt = elem.size();
	
	// add new layer when tree is full
	while(new_elem_cnt + this->actual_size >= (1 << this->depth + 1)) addNewLayer();
	// no need to tell the receiver the new depth of tree?
	
	// get the node indices in random paths
	std::vector<int> ind;
	int *leaf_ind = generateRandomPaths(new_elem_cnt, &ind);
	
	// TODO: rewrite the following code if each time replace one path
	delete [] leaf_ind;
	
	// extract all elements in these nodes and empty the origin node
	int node_cnt = ind.size();
	for (int i = 0; i < node_cnt; ++i) crypto_tree[ind[i]].moveElements(elem);
	
	int elem_cnt = elem.size();
	
	/*
	// sort the elements by their hash (corresponding leaf index)
	std::pair<int, int> *elem_pair = new std::pair<int, int> [elem_cnt];
	for (int i = 0; i < elem_cnt; ++i) {
		int leaf_index = computeIndex( computeBinaryHash<T>(elem[i]) );
		elem_pair[i] = std::pair(leaf_index, i);
	}
	sort(elem_pair.begin(), elem_pair.end());
	
	int *nxt = new int[elem_cnt + 1];
	for (int i = 0; i < elem_cnt; ++i) nxt[i] = i + 1;
	
	// fill nodes
	for (int i = 0; i <= node_cnt; ++i) {
		
	}
	delete [] elem_pair;
	delete [] nxt;
	*/
	
	//TODO: fill the nodes
	
	// update actual_size
	this->actual_size += elem_cnt;
	
	std::vector<CryptoNode<T> > rs;
	for (int i = 0; i < node_cnt; ++i) rs.push_back(crypto_tree[ind[i]]);
	return rs;
}

// Update tree (receiver)
template<typename T> 
void CryptoTree<T>::replaceNodes(int new_elem_cnt, std::vector<CryptoNode<T> > new_nodes) {
	
	int node_cnt = new_nodes.size();
	
	// add new layer when tree is full
	while(new_elem_cnt + this->actual_size >= (1 << this->depth + 1)) addNewLayer();

	std::vector<int> ind;
	int *leaf_ind = generateRandomPaths(new_elem_cnt, &ind);
	delete [] leaf_ind;
	
	assert(node_cnt == ind.size());
	
	// replace nodes (including stash)
	for (int i = 0; i < node_cnt; ++i) crypto_tree[ind[i]] = new_nodes[i];
	
	// update actual_size
	this->actual_size += new_elem_cnt;
}
	

} // namespace updatable_private_set_intersection
