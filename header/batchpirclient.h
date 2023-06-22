#ifndef BATCHPIRCLIENT_H
#define BATCHPIRCLIENT_H


#include "batchpirparams.h"
#include "client.h"
#include "src/utils.h"

using namespace std;

class BatchPIRClient {
public:
    BatchPIRClient(const BatchPirParams& params);
    void set_map(std::unordered_map<std::string, uint64_t> map);
    vector<PIRQuery> create_queries(vector<uint64_t> batch);
    vector<RawResponses> decode_responses(vector<PIRResponseList> responses);
    vector<RawResponses> decode_responses_chunks(PIRResponseList responses);

    std::pair<seal::GaloisKeys, seal::RelinKeys> get_public_keys();
    bool cuckoo_hash_witout_checks(vector<uint64_t> batch);
    vector<uint64_t> get_cuckoo_table();
    size_t get_serialized_commm_size();
    

private:
    BatchPirParams batchpir_params_;
    size_t max_attempts_;
    vector<uint64_t> cuckoo_table_;
    bool is_cuckoo_generated_;
    bool is_map_set_;
    std::unordered_map<std::string, uint64_t> map_;
    vector<Client> client_list_;
    size_t serialized_comm_size_ = 0;

    void measure_size(vector<Ciphertext> list, size_t seeded = 1);
    bool cuckoo_hash(vector<uint64_t> batch);
    void translate_cuckoo();
    void prepare_pir_clients();
    bool cuckoo_insert(uint64_t key, size_t attempt, std::unordered_map<uint64_t, std::vector<size_t>> key_to_buckets, std::unordered_map<uint64_t, uint64_t>& bucket_to_key);
};

#endif // BATCHPIRCLIENT_H
