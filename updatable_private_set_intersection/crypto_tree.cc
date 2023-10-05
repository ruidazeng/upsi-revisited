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



// compute leaf index of a binary hash
template<typename T> 
int CryptoTree<T>::computeIndex(BinaryHash binary_hash) {
	int x = 1;
	for (int i = 0; i < this->depth; ++i) {
        if (binary_hash[i] == '0') x = (x << 1);
        else if (binary_hash[i] == '1') x = ((x << 1) | 1);
    }
    return x;
}

// Return indices in paths in decreasing order (including stash)
template<typename T> 
void CryptoTree<T>::extractPathIndices(int* leaf_ind, int leaf_cnt, std::vector<int> &ind, std::vector<int>* par) {
	assert(ind.size() == 0);
	
	// add the indicies of leaves
	for (int i = leaf_cnt - 1; i >= 0; --i) 
		ind.push_back(leaf_ind[i]);
		
	// erase duplicates and sort in decreasing order
	std::sort(ind.begin(), ind.end(), std::greater<int>());
	ind.erase(std::unique(ind.begin(), ind.end()), ind.end());
	
	int node_cnt = ind.size();
	for (int i = 0; i < node_cnt; ++i) {
		if(ind[i] == 0) break; // stash
		int tmp = (ind[i] >> 1); // find its parent 
		if(par != NULL) par->push_back(tmp); // store its parent
		assert(ind[node_cnt - 1] >= tmp);
		if(ind[node_cnt - 1] > tmp) {
			ind.push_back(tmp);
			++node_cnt;
		}
	}
}

// Generate random paths, return the indices of leaves and nodes(including stash)
template<typename T> 
int* CryptoTree<T>::generateRandomPaths(int cnt, std::vector<int> &ind, std::vector<int>* par) { //ind: node indices
	// generate binary hash
	std::vector<BinaryHash> hsh;
	generateRandomHash(cnt, hsh);
	
	// compute leaf indices of the paths
	int *leaf_ind = new int[cnt];
	for (int i = 0; i < cnt; ++i) leaf_ind[i] = computeIndex(hsh[i]);
	
	// extract indices of nodes in these paths (including stash)
	extractPathIndices(leaf_ind, cnt, ind, par);
	
	return leaf_ind;
	// the sender requires indices of leaves if update one path at a time
	// need to delete leaf_ind outside this function
}


// @brief Real methods

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
	// int *leaf_ind = generateRandomPaths(new_elem_cnt, &ind, par); -- for merge-find set
	
	// TODO: rewrite the following if each time replace one path
	delete [] leaf_ind;
	
	// extract all elements in these nodes and empty the origin node
	int node_cnt = ind.size();
	for (int i = 0; i < node_cnt; ++i) crypto_tree[ind[i]].moveElements(elem);
	
	int elem_cnt = elem.size();
	
	int leaf_cnt = 0; while(leaf_cnt < node_cnt && ind[leaf_cnt] >= (1 << (this->depth + 1))) ++leaf_cnt;
	
	// fill the nodes
	/* merge-find set (disjoint-set data structure)
	int *nxt = new int[node_cnt + 1]; // next available node 
	for (int i = 0; i < node_cnt; ++i) nxt[i] = i; // merge-find set setup
	*/
	for (int i = 0; i < elem_cnt; ++i) {
		int x = computeIndex( computeBinaryHash(elem[i]) );
		// O(log(leaf_cnt))
		int p = std::lower_bound(ind.begin(), ind.begin() + leaf_cnt, x, std::greater<int>()) - ind.begin();
		int steps = this->depth;
		/*
			To compute lca of x , y:
			let t be the leftmost 1 of (x xor y), steps = log2(t) + 1
			lca = x / 2t = x >> steps
		*/
		if(p < leaf_cnt && ind[p] == x) steps = 0;
		else {
			if(p < leaf_cnt) 
				steps = std::min(steps, 32 - __builtin_clz(x ^ ind[p])); //__builtin_clz: count leading zeros
			if(p > 0) 
				steps = std::min(steps, 32 - __builtin_clz(x ^ ind[p - 1]));
		}
		int lca = x >> steps;
		
		// O(depth)
		while(crypto_tree[lca].insert(elem[i]) == false) {
			assert(lca > 0);
			lca >>= 1;
		}
		/* use merge-find set: O(log(node_cnt))
		int u = std::lower_bound(ind.begin(), ind.end(), x, std::greater<int>()) - ind.begin(); // find lca in ind
		assert(u < node_cnt && ind[u] == x); 
		while(crypto_tree[ind[u]].insert(elem[i]) == false) {
			assert(ind[u] > 0); // not stash
			nxt[u] = find_set_rep(par[u], nxt); // find next available node
		}
		*/
	}
	
	 // delete [] nxt; -- merge-find set
	
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


// Find path for an element (including stash) and extract all elements on the path
template<typename T> 
std::vector<T> CryptoTree<T>::getPath(std::string element) {
    std::vector<T> encyrpted_elem;
    std::string binary_hash = computeBinaryHash(element);
    
    this->crypto_tree[0].copyElements(encyrpted_elem); // stash
    this->crypto_tree[1].copyElements(encyrpted_elem); // root
    for (int i = 0, x = 1; i < this->depth; ++i) {
        if (binary_hash[i] == '0') x = (x << 1);
        else if (binary_hash[i] == '1') x = ((x << 1) | 1);
    	this->crypto_tree[x].copyElements(encyrpted_elem);
    }
    return encyrpted_elem;
}

} // namespace updatable_private_set_intersection
