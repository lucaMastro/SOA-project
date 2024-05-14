#ifndef HASH_HELPER

#define HASH_HELPER

#define HASH_FUNC   "sha256"
#define HASH_SIZE   32

int compute_hash(char *input_string, int input_size, char *output_buffer);


#endif
