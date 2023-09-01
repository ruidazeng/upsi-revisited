# UPSI Project

## Completed

- Completed insert() function.

- Wrote function to generate a random path based on a key.

- Completed basic structure for crypto_tree using array representation (std::vector).

- Added hash.h with a simply sha256 hash function with depedency on openssl/sha.h in the util folder. Modified the BUILD file to contain the dependency.

- Completed most of crypto_node. (Note: still need to add an utility function to process the encryptions of payload/content into/from a vector of bytes)

- Experimented with the files in this repository. Removed unneeded libraries (java/py), the external library is required to build successfully using bazel.

- Initialized new crypto_node and crypto_tree class.

## In Progress

1. Still need to get the OpenSSL library to build using bazel.

2. Implement functionality to update the tree that differ based on sender/receiver. 

3. Need to implement OpenSSL AES encryption for both parties to agree on a shared key.

## TODO's

1. PSI addition only - one-sided cardinality

2. PSI addition only - one-sided sum with cardinality

3. PSI addition only - secret share (with cardinality)

4. PSI addition & deletion - one-sided sum with cardinality

## Questions

1. Cost of loading bytes into elliptical curves.