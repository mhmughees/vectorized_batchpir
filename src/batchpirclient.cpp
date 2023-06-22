#include "batchpirclient.h"

BatchPIRClient::BatchPIRClient(const BatchPirParams &params)
    : batchpir_params_(params), is_cuckoo_generated_(false), is_map_set_(false)
{
    max_attempts_ = batchpir_params_.get_max_attempts();

    prepare_pir_clients();
}

bool BatchPIRClient::cuckoo_insert(uint64_t key, size_t attempt, std::unordered_map<uint64_t, std::vector<size_t>> key_to_buckets, std::unordered_map<uint64_t, uint64_t> &bucket_to_key)
{
    if (attempt > max_attempts_)
    {
        throw std::invalid_argument("Error: Cuckoo hashing failed");
        return false;
    }

    for (auto v : key_to_buckets[key])
    {
        if (bucket_to_key.find(v) == bucket_to_key.end())
        {
            bucket_to_key[v] = key;
            return true;
        }
    }

    std::vector<size_t> candidate_buckets = key_to_buckets[key];
    int idx = rand() % candidate_buckets.size();
    auto picked_bucket = candidate_buckets[idx];
    auto old = bucket_to_key[picked_bucket];
    bucket_to_key[picked_bucket] = key;

    cuckoo_insert(old, attempt + 1, key_to_buckets, bucket_to_key);
    return true;
}

vector<PIRQuery> BatchPIRClient::create_queries(vector<uint64_t> batch)
{

    if (batch.size() != batchpir_params_.get_batch_size())
        throw std::runtime_error("Error: batch is not selected size");

    cuckoo_hash(batch);
    vector<PIRQuery> queries;

    size_t max_bucket_size = batchpir_params_.get_max_bucket_size();
    size_t entry_size = batchpir_params_.get_entry_size();
    size_t dim_size = batchpir_params_.get_first_dimension_size();
    auto max_slots = batchpir_params_.get_seal_parameters().poly_modulus_degree();
    auto num_buckets = cuckoo_table_.size();
    size_t per_server_capacity = max_slots / dim_size;
    size_t num_servers = ceil(num_buckets / per_server_capacity);

    auto previous_idx = 0;
    for (int i = 0; i < client_list_.size(); i++)
    {
        const size_t offset = std::min(per_server_capacity, num_buckets - previous_idx);
        vector<uint64_t> sub_buckets(cuckoo_table_.begin() + previous_idx, cuckoo_table_.begin() + previous_idx + offset);
        previous_idx += offset;
        auto query = client_list_[i].gen_query(sub_buckets);
        measure_size(query, 2);
        queries.push_back(query);
    }

    return queries;
}



bool BatchPIRClient::cuckoo_hash(vector<uint64_t> batch)
{

    if (!is_map_set_)
    {
        throw std::runtime_error("Error: Map is not set");
    }

    auto total_buckets = ceil(batchpir_params_.get_cuckoo_factor() * batchpir_params_.get_batch_size());
    auto db_entries = batchpir_params_.get_num_entries();
    auto num_candidates = batchpir_params_.get_num_hash_funcs();
    auto attempts = batchpir_params_.get_max_attempts();

    if (batch.size() != batchpir_params_.get_batch_size())
    {
        cout << batch.size() << " " << batchpir_params_.get_batch_size() << " " << endl;
        throw std::invalid_argument("Error: Batch size is wrong");
    }

    cuckoo_table_.resize(std::ceil(batchpir_params_.get_batch_size() * batchpir_params_.get_cuckoo_factor()), batchpir_params_.get_default_value());

    std::unordered_map<uint64_t, std::vector<size_t>> key_to_buckets;
    for (auto v : batch)
    {
        auto candidates = utils::get_candidate_buckets(v, num_candidates, total_buckets);
        key_to_buckets[v] = candidates;
    }
    std::unordered_map<uint64_t, uint64_t> bucket_to_key;

    // seed the random number generator with current time
    srand(time(nullptr));
    for (auto const &[key, value] : key_to_buckets)
    {
        cuckoo_insert(key, 0, key_to_buckets, bucket_to_key);
    }

    for (auto const &[key, value] : bucket_to_key)
    {
        cuckoo_table_[key] = value;
    }

    bucket_to_key.clear();
    key_to_buckets.clear();

    is_cuckoo_generated_ = true;

    translate_cuckoo();
    return true;
}

bool BatchPIRClient::cuckoo_hash_witout_checks(vector<uint64_t> batch)
{

    auto total_buckets = ceil(batchpir_params_.get_cuckoo_factor() * batchpir_params_.get_batch_size());
    auto db_entries = batchpir_params_.get_num_entries();
    auto num_candidates = batchpir_params_.get_num_hash_funcs();
    auto attempts = batchpir_params_.get_max_attempts();

    if (batch.size() != batchpir_params_.get_batch_size())
    {
        cout << batch.size() << " " << batchpir_params_.get_batch_size() << " " << endl;
        throw std::invalid_argument("Error: Batch size is wrong");
    }

    cuckoo_table_.resize(std::ceil(batchpir_params_.get_batch_size() * batchpir_params_.get_cuckoo_factor()), batchpir_params_.get_default_value());

    std::unordered_map<uint64_t, std::vector<size_t>> key_to_buckets;
    for (auto v : batch)
    {
        auto candidates = utils::get_candidate_buckets(v, num_candidates, total_buckets);
        key_to_buckets[v] = candidates;
    }
    std::unordered_map<uint64_t, uint64_t> bucket_to_key;

    // seed the random number generator with current time
    srand(time(nullptr));
    for (auto const &[key, value] : key_to_buckets)
    {
        cuckoo_insert(key, 0, key_to_buckets, bucket_to_key);
    }

    for (auto const &[key, value] : bucket_to_key)
    {
        cuckoo_table_[key] = value;
    }

    bucket_to_key.clear();
    key_to_buckets.clear();

    is_cuckoo_generated_ = true;

    // translate_cuckoo();
    return true;
}

void BatchPIRClient::measure_size(vector<Ciphertext> list, size_t seeded){


    for (int i=0; i < list.size(); i++){
    serialized_comm_size_ += ceil(list[i].save_size()/seeded);
    }
}

size_t BatchPIRClient::get_serialized_commm_size(){
    return ceil(serialized_comm_size_/1024);
}


void BatchPIRClient::set_map(std::unordered_map<std::string, uint64_t> map)
{
    map_ = map;
    is_map_set_ = true;
}


vector<uint64_t> BatchPIRClient::get_cuckoo_table()
{
    return cuckoo_table_;
}

void BatchPIRClient::translate_cuckoo()
{
    if (!is_map_set_ || !is_cuckoo_generated_)
    {
        throw std::runtime_error("Error: Cannot translate the data because either the map has not been set or the cuckoo hash table has not been generated.");
    }

    auto num_buckets = cuckoo_table_.size();
    for (int i = 0; i < num_buckets; i++)
    {
        // check if bucket is empty
        if (cuckoo_table_[i] != batchpir_params_.get_default_value())
        {
            // convert from db index to bucket index
            cuckoo_table_[i] = map_[to_string(cuckoo_table_[i]) + to_string(i)];
        }
    }
}

void BatchPIRClient::prepare_pir_clients()
{

    size_t max_bucket_size = batchpir_params_.get_max_bucket_size();
    size_t entry_size = batchpir_params_.get_entry_size();

    size_t dim_size = batchpir_params_.get_first_dimension_size();
    auto max_slots = batchpir_params_.get_seal_parameters().poly_modulus_degree();
    auto num_buckets = ceil(batchpir_params_.get_batch_size() * batchpir_params_.get_cuckoo_factor());
    size_t per_client_capacity = max_slots / dim_size;
    size_t num_client = ceil(num_buckets / per_client_capacity);
    auto remaining_buckets = num_buckets;
    auto previous_idx = 0;
    seal::KeyGenerator *keygen;

    for (int i = 0; i < num_client; i++)
    {
        const size_t num_dbs = std::min(per_client_capacity, static_cast<size_t>(num_buckets - previous_idx));
        previous_idx += num_dbs;
        PirParams params(max_bucket_size, entry_size, num_dbs, batchpir_params_.get_seal_parameters(), dim_size);
        if (i == 0)
        {
            Client client(params);
            client_list_.push_back(client);
            keygen = client.get_keygen();
        }
        else
        {
            Client client(params, keygen);
            client_list_.push_back(client);
        }
    }
}

vector<RawDB> BatchPIRClient::decode_responses(vector<PIRResponseList> responses)
{
    vector<std::vector<std::vector<unsigned char>>> entries_list;
    for (int i = 0; i < responses.size(); i++)
    {
        std::vector<std::vector<unsigned char>> entries = client_list_[i].decode_responses(responses[i]);
        entries_list.push_back(entries);
    }
    return entries_list;
}

vector<RawDB> BatchPIRClient::decode_responses_chunks(PIRResponseList responses)
{
    vector<std::vector<std::vector<unsigned char>>> entries_list;
    const size_t num_slots_per_entry = batchpir_params_.get_num_slots_per_entry();
    const size_t num_slots_per_entry_rounded = utils::next_power_of_two(num_slots_per_entry);
    const size_t max_empty_slots = batchpir_params_.get_first_dimension_size();
    const size_t row_size = batchpir_params_.get_seal_parameters().poly_modulus_degree() / 2;
    const size_t gap = row_size / max_empty_slots;

    measure_size(responses, 1);

    auto current_fill = gap * num_slots_per_entry_rounded;
    size_t num_buckets_merged = (row_size / current_fill);

    if (ceil(num_slots_per_entry * 1.0 / max_empty_slots) > 1 || num_buckets_merged <= 1 || client_list_.size() == 1)
    {

        size_t num_chunk_ctx = ceil((num_slots_per_entry * 1.0) / max_empty_slots);

        for (int i = 0; i < client_list_.size(); i++)
        {
            auto start_idx = (i * num_chunk_ctx);
            PIRResponseList subvector(responses.begin() + start_idx, responses.begin() + start_idx + num_chunk_ctx);
            std::vector<std::vector<unsigned char>> entries = client_list_[i].decode_responses(subvector);
            entries_list.push_back(entries);
        }
    }
    else
    {
        vector<vector<uint64_t>> entry_slot_lists;
        for (int i = 0; i < client_list_.size(); i++)
        {
            entry_slot_lists.push_back(client_list_[i].get_entry_list());
        }

        entries_list = client_list_[0].decode_merged_responses(responses, cuckoo_table_.size(), entry_slot_lists);
    }
    return entries_list;
}

std::pair<seal::GaloisKeys, seal::RelinKeys> BatchPIRClient::get_public_keys()
{
    std::pair<seal::GaloisKeys, seal::RelinKeys> keys;
    keys = client_list_[0].get_public_keys();
    return keys;
}