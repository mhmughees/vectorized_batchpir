#ifndef SERVER_H
#define SERVER_H

#include <string>
#include <vector>
#include <iostream>
#include <chrono>
#include "pirparams.h"

using namespace seal;
using namespace utils;

class Server {
public:
    // Constructor and destructor
    Server(PirParams &pir_params);
    Server(PirParams &pir_params, vector<RawDB> sub_buckets);

    // Creating raw database only used when server is initialized independently
    void populate_raw_db();
    void load_raw_dbs();

    bool print_raw_database_status();

    void transform_into_pir_db();
    void convert_merge_pir_dbs();

    void ntt_preprocess_db();

    void set_client_keys(uint32_t client_id, std::pair<seal::GaloisKeys, seal::RelinKeys>);
    void set_client_keys(uint32_t client_id, std::pair<seal::GaloisKeys, seal::RelinKeys> keys, uint64_t id);
    void get_client_keys();

    PIRResponseList generate_response(uint32_t client_id, PIRQuery query);

    bool check_decoded_entry( std::vector<unsigned char> entry, int index);
    bool check_decoded_entries(std::vector<std::vector<unsigned char>> entries, vector<uint64_t> indices);

    PIRResponseList merge_responses_chunks_buckets(vector<PIRResponseList>& responses, uint32_t client_id);
    PIRResponseList merge_responses_buckets_chunks(vector<PIRResponseList>& responses, uint32_t client_id);


private:
    // Private member variables
    PirParams pir_params_;
    seal::SEALContext *context_;
    seal::Evaluator *evaluator_;
    seal::BatchEncoder *batch_encoder_;
    std::map<uint32_t, std::pair<seal::GaloisKeys, seal::RelinKeys>> client_keys_;
    vector<std::pair<seal::GaloisKeys, seal::RelinKeys>> client_keys_2;
    size_t plaint_bit_count_;
    size_t polynomial_degree_;
    vector<size_t> pir_dimensions_;
    size_t row_size_;
    size_t gap_;
    bool is_db_preprocessed_;
    bool is_client_keys_set_;
    PIRQuery query_; 
    size_t num_databases_;

    uint64_t server_id_ = 0;

    
    
    RawDB rawdb_;
    std::vector<RawDB> rawdb_list_;
    PirDB  db_;
    std::vector<PirDB>  db_list_;
    std::vector<seal::Plaintext> encoded_db_;

    
    RawDB populate_return_raw_db();
    void round_dbs();
    void round_db(RawDB& db);

    PirDB convert_to_pir_db(int rawdb_index);
    void merge_pir_dbs();

    std::vector<uint64_t> convert_to_list_of_coeff(std::vector<unsigned char> input_list);
    void rotate_db_cols();
    vector<seal::Ciphertext> rotate_copy_query(uint32_t client_id);
    void encode_db();
    void merge_to_db(PirDB new_db, int rotation_index);

    vector<Ciphertext> process_first_dimension(uint32_t client_id);
    vector<Ciphertext> old_process_first_dimension_delayed_mod(uint32_t client_id);
    vector<Ciphertext> process_first_dimension_delayed_mod(uint32_t client_id);

    vector<Ciphertext> process_second_dimension(uint32_t client_id, vector<Ciphertext> first_intermediate_data);
    PIRResponseList process_last_dimension(uint32_t client_id, vector<Ciphertext> second_intermediate_data, bool is_2d_pir_);


    // Check if rawdb_ has been generated correctly
    bool check_raw_db() const {
        size_t expected_entries = pir_params_.get_rounded_num_entries();
        size_t expected_entry_size = pir_params_.get_entry_size();
        

        bool has_correct_entries = (rawdb_.size() == expected_entries);
        bool has_correct_entry_size = (rawdb_[0].size() == expected_entry_size);

        return (has_correct_entries && has_correct_entry_size);
    }

    void print_db();
    void print_encoded_db();
    void print_rawdb();
    void modulus_switch(PIRResponseList& list);
};

#endif // SERVER_H
