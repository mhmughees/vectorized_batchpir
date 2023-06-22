#ifndef PIRPARAMS_H
#define PIRPARAMS_H

#include <cstddef>
#include <cstdlib>
#include <vector>
#include <cmath>
#include "src/utils.h"
#include "seal/seal.h"


using namespace std;

class PirParams {
public:
    PirParams(size_t num_entries, size_t entry_size, size_t db_count, seal::EncryptionParameters seal_params, size_t first_two_dimensions);

    size_t get_num_entries() const;
    size_t get_rounded_num_entries() const;
    size_t get_entry_size() const;
    uint32_t get_num_slots_per_entry() const;
    uint32_t get_db_rows() const;
    vector<size_t>  get_dimensions() const;
    size_t  get_max_db_count() const;
    size_t  get_db_count() const;
    seal::EncryptionParameters get_seal_parameters() const;
    uint64_t get_default_value() const;
    void print_values();
    

private:
    size_t num_entries_;
    size_t num_rounded_entries_;
    size_t entry_size_;
    size_t row_size_;
    size_t max_db_count_ = 0;
    size_t db_count_ = 0;
    size_t num_db_;
    uint32_t num_columns_per_entry_;
    uint32_t db_ptx_;
    vector<size_t> dimensions_;
    seal::EncryptionParameters seal_params_;
    uint64_t default_value_ = DatabaseConstants::DefaultVal;


    void calculate_dimensions(size_t num_entries, size_t first_two_dimensions);
    void calculate_dimensions(size_t num_entries);
    void calculate_rounded_db_size();
    void calculate_num_slots_per_entry(size_t entry_size);
    void calculate_db_ptx();
    void calculate_max_num_db();

};

#endif // PIRPARAMS_H
