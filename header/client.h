#ifndef CLIENT_H
#define CLIENT_H

#include <string>
#include <iostream>
#include <vector>
#include <algorithm>
#include "pirparams.h"

class Client {
public:
    // Constructor with pir_params
    Client(PirParams& pir_params);
    Client(PirParams &pir_params, seal::KeyGenerator* keygen);

    // Public member functions

    std::pair<seal::GaloisKeys, seal::RelinKeys> get_public_keys();
    PIRQuery gen_query(uint64_t index);
    PIRQuery gen_query(vector<uint64_t> indices);
    seal::KeyGenerator* get_keygen();
    vector<uint64_t> get_entry_list();
    std::vector<unsigned char> decode_response(PIRResponseList response);
    RawResponses decode_responses(PIRResponseList response);
    std::vector<std::vector<unsigned char>> single_pir_decode_responses(PIRResponseList response);
    RawResponses decode_responses_chunks(PIRResponseList response);
    vector<RawResponses> decode_merged_responses(PIRResponseList response, size_t cuckoo_size,vector<vector<uint64_t>> entry_slot_lists);

private:
    // Private member variables
    PirParams pir_params_;
    seal::SEALContext* context_;
    seal::KeyGenerator* keygen_;
    seal::SecretKey secret_key_;
    seal::Encryptor* encryptor_;
    seal::Decryptor* decryptor_;
    seal::BatchEncoder* batch_encoder_;
    seal::GaloisKeys gal_keys_;
    seal::RelinKeys relin_keys_;

    size_t plaint_bit_count_;
    size_t polynomial_degree_;
    uint32_t num_columns_per_entry_;
    uint64_t entry_slot_;
    vector<uint64_t> entry_slot_list_;
    size_t gap_;
    size_t row_size_; 
    size_t num_databases_;

    // Private member functions
    std::vector<size_t> compute_indices(uint64_t desired_index);
    std::vector<unsigned char> convert_to_rawdb_entry(std::vector<uint64_t>  input_list);
    PIRQuery merge_pir_queries(vector<PirDB> plain_queries);
    void check_noise_budget(const seal::Ciphertext& response); 
};

#endif // CLIENT_H

