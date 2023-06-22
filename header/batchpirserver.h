#ifndef BATCHPIR_SERVER_H
#define BATCHPIR_SERVER_H

#include "batchpirparams.h"
#include "server.h"
#include "src/utils.h"


class BatchPIRServer {

public:
    
    BatchPIRServer( BatchPirParams& batchpir_params);
    std::unordered_map<std::string, uint64_t> get_hash_map() const;
    void set_client_keys(uint32_t client_id, std::pair<seal::GaloisKeys, seal::RelinKeys> keys);
    void get_client_keys();
    PIRResponseList generate_response(uint32_t client_id, vector<PIRQuery> queries);
    bool check_decoded_entries(vector<std::vector<std::vector<unsigned char>>> entries_list, vector<uint64_t> cuckoo_table);
   

    

private:
    BatchPirParams *batchpir_params_;
    RawDB rawdb_;
    vector<RawDB> buckets_;
    vector<Server> server_list_;
    bool is_simple_hash_;
    bool is_client_keys_set_;
    std::unordered_map<std::string, uint64_t> map_; // map from key to bucket index


    void simeple_hash();
    std::vector<std::vector<uint64_t>>  simeple_hash_with_map();
    void prepare_pir_server();
    void populate_raw_db();
    std::size_t get_max_bucket_size() const;
    std::size_t get_min_bucket_size() const;
    std::size_t get_avg_bucket_size() const;
    void balance_buckets();
    size_t get_first_dimension_size(size_t num_entries);
    PIRResponseList merge_responses(vector<PIRResponseList>& responses, uint32_t client_id);
    void print_stats() const; 


};

#endif // BATCHPIR_SERVER_H
