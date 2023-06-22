#ifndef BATCH_PIR_PARAMS_H
#define BATCH_PIR_PARAMS_H

#include <cstddef>
#include <iomanip> 
#include <cstdlib>
#include "database_constants.h"
#include "../src/utils.h"
using namespace seal;

class BatchPirParams {
public:
    BatchPirParams(int batch_size ,size_t num_entries, size_t entry_size, EncryptionParameters seal_params);

    int get_num_hash_funcs();
    int get_batch_size();
    double get_cuckoo_factor();
    size_t get_num_entries();
    size_t get_entry_size();
    size_t get_max_attempts(); 
    size_t get_max_bucket_size();
    size_t get_first_dimension_size();
    uint64_t get_default_value();
    uint32_t get_num_slots_per_entry();
    seal::EncryptionParameters get_seal_parameters() const;
    void set_max_bucket_size(size_t max_bucket_size);

    void print_params() const;

private:
    int num_hash_funcs_ = 0;
    int batch_size_= 0;
    double cuckoo_factor_= 0;
    size_t num_entries_= 0;
    size_t entry_size_= 0;
    size_t max_attempts_= 0;
    size_t max_bucket_size_= 0;
    size_t dim_size_= 0;
    uint64_t default_value_ = DatabaseConstants::DefaultVal;
    seal::EncryptionParameters seal_params_;

    void set_first_dimension_size(size_t max_bucket_size);
};

#endif // BATCH_PIR_PARAMS_H
