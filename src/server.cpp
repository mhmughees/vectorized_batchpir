#include "server.h"

// Constructor
Server::Server(PirParams &pir_params) : pir_params_(pir_params)
{
    context_ = new seal::SEALContext(pir_params.get_seal_parameters());
    evaluator_ = new seal::Evaluator(*context_);
    batch_encoder_ = new seal::BatchEncoder(*context_);
    plaint_bit_count_ = pir_params_.get_seal_parameters().plain_modulus().bit_count();
    polynomial_degree_ = pir_params_.get_seal_parameters().poly_modulus_degree();
    pir_dimensions_ = pir_params_.get_dimensions();
    row_size_ = polynomial_degree_ / 2;
    gap_ = row_size_ / pir_dimensions_[0];
    num_databases_ = pir_params_.get_db_count();
    is_db_preprocessed_ = false;
    is_client_keys_set_ = false;
}

Server::Server(PirParams &pir_params, vector<RawDB> sub_buckets) : pir_params_(pir_params)
{
    context_ = new seal::SEALContext(pir_params.get_seal_parameters());
    evaluator_ = new seal::Evaluator(*context_);
    batch_encoder_ = new seal::BatchEncoder(*context_);
    plaint_bit_count_ = pir_params_.get_seal_parameters().plain_modulus().bit_count();
    polynomial_degree_ = pir_params_.get_seal_parameters().poly_modulus_degree();
    pir_dimensions_ = pir_params_.get_dimensions();
    row_size_ = polynomial_degree_ / 2;
    gap_ = row_size_ / pir_dimensions_[0];
    num_databases_ = pir_params_.get_db_count();
    is_db_preprocessed_ = false;
    is_client_keys_set_ = false;
    rawdb_list_ = sub_buckets;
    round_dbs();
    convert_merge_pir_dbs();
    ntt_preprocess_db();
}

void Server::set_client_keys(uint32_t client_id, std::pair<seal::GaloisKeys, seal::RelinKeys> keys)
{
    client_keys_[client_id] = keys;
    is_client_keys_set_ = true;
}

void Server::get_client_keys()
{

    // cout << "server_id_: " << server_id_ << endl;
}

// Implementation of populateRawDB() function
void Server::populate_raw_db()
{
    auto db_entries = pir_params_.get_num_entries();
    auto rounded_db_entries = pir_params_.get_rounded_num_entries();
    auto entry_size = pir_params_.get_entry_size();

    // Clear any existing data
    rawdb_.clear();

    // Resize the rawdb_ vector to the correct size
    rawdb_.resize(rounded_db_entries);

    // Define a function to generate a random entry
    auto generate_random_entry = [entry_size]() -> std::vector<unsigned char>
    {
        std::vector<unsigned char> entry(entry_size);
        std::generate(entry.begin(), entry.end(), []()
                      {
                          return rand() % 0xFF;
                          // return 1;
                      });
        return entry;
    };

    // Define a function to generate a zero-filled entry
    auto generate_one_entry = [entry_size]() -> std::vector<unsigned char>
    {
        return std::vector<unsigned char>(entry_size, 1);
    };

    // Populate the rawdb_ vector with entries
    for (size_t i = 0; i < rounded_db_entries; ++i)
    {
        if (i < db_entries)
        {
            rawdb_[i] = generate_random_entry();
        }
        else
        {
            rawdb_[i] = generate_one_entry();
        }
    }
}

///   data functions to be used with bathcpir server
void Server::round_dbs()
{
    for (int i = 0; i < rawdb_list_.size(); i++)
    {
        round_db(rawdb_list_[i]);
    }
}

void Server::round_db(RawDB &db)
{
    auto db_entries = pir_params_.get_num_entries();
    auto rounded_db_entries = pir_params_.get_rounded_num_entries();
    auto entry_size = pir_params_.get_entry_size();

    // Define a function to generate a zero-filled entry
    auto generate_one_entry = [entry_size]() -> std::vector<unsigned char>
    {
        return std::vector<unsigned char>(entry_size, 1);
    };

    for (int i = 0; i < (rounded_db_entries - db_entries); i++)
    {
        db.push_back(generate_one_entry());
    }
}

///   data functions to be used with pir server
void Server::load_raw_dbs()
{
    rawdb_list_.clear();
    rawdb_list_.resize(num_databases_);

    for (int i = 0; i < rawdb_list_.size(); i++)
    {
        rawdb_list_[i] = populate_return_raw_db();
    }
}

RawDB Server::populate_return_raw_db()
{
    auto db_entries = pir_params_.get_num_entries();
    auto rounded_db_entries = pir_params_.get_rounded_num_entries();
    auto entry_size = pir_params_.get_entry_size();

    // Resize the rawdb vector to the correct size
    RawDB rawdb(rounded_db_entries);

    // Define a function to generate a random entry
    auto generate_random_entry = [entry_size]() -> std::vector<unsigned char>
    {
        std::vector<unsigned char> entry(entry_size);
        std::generate(entry.begin(), entry.end(), []()
                      { return rand() % 0xFF; });
        return entry;
    };

    // Define a function to generate a zero-filled entry
    auto generate_one_entry = [entry_size]() -> std::vector<unsigned char>
    {
        return std::vector<unsigned char>(entry_size, 1);
    };

    // Populate the rawdb vector with entries
    for (size_t i = 0; i < rounded_db_entries; ++i)
    {
        if (i < db_entries)
        {
            rawdb[i] = generate_random_entry();
        }
        else
        {
            rawdb[i] = generate_one_entry();
        }
    }

    return rawdb;
}

void Server::merge_pir_dbs()
{
    const auto total_db_plaintexts = pir_params_.get_db_rows();

    db_.resize(total_db_plaintexts);
    for (auto &row : db_)
    {
        row.assign(polynomial_degree_, 0ULL);
    }

    for (int j = 0; j < total_db_plaintexts; j++)
    {
        for (int i = 0; i < db_list_.size(); i++)
        {
            if (i > gap_)
            {
                utils::rotate_vector_col(db_list_[i][j]);
            }
            auto rotated = utils::rotate_vector_row(db_list_[i][j], i);

            for (int k = 0; k < db_[j].size(); k++)
            {
                db_[j][k] = db_[j][k] + rotated[k];
            }
        }
    }
}

void Server::merge_to_db(PirDB new_db, int rotation_index)
{
    const auto total_db_plaintexts = pir_params_.get_db_rows();

    auto rotate_amount = rotation_index;

    if (rotate_amount == 0)
    {
        db_.resize(total_db_plaintexts);
        for (auto &row : db_)
        {
            row.assign(polynomial_degree_, 0ULL);
        }
    }

    if (rotate_amount >= gap_)
    {
        rotate_amount = rotate_amount - gap_;
    }

    for (int j = 0; j < total_db_plaintexts; j++)
    {

        if (rotation_index >= gap_)
        {
            utils::rotate_vector_col(new_db[j]);
        }
        auto rotated = utils::rotate_vector_row(new_db[j], rotate_amount);

        for (int k = 0; k < db_[j].size(); k++)
        {
            db_[j][k] = db_[j][k] + rotated[k];
        }
    }
}

void Server::convert_merge_pir_dbs()
{
    db_list_.clear();
    db_list_.resize(num_databases_);

    // Inform the user that the conversion and merging process has started
    std::cout << "BatchPIRServer: Converting and merging databases. This may take some time..." << std::endl;

    // Convert and merge each raw database into uint_64 PIR elements
    for (int i = 0; i < num_databases_; i++)
    {
        auto db = convert_to_pir_db(i);
        merge_to_db(db, i);
        std::cout << "BatchPIRServer: Processed database " << i + 1 << " of " << num_databases_ << "\r" << std::flush;
    }

    cout << endl;
    // Rotate for the rotated query trick
    rotate_db_cols();

    // Encode the database into Plaintexts
    encode_db();

    // Inform the user that the conversion and merging process has completed
    std::cout << "BatchPIRServer: Database converted to PIR DB and merged successfully!" << std::endl;
}

PirDB Server::convert_to_pir_db(int rawdb_index)
{
    // Get necessary parameters
    const auto total_db_plaintexts = pir_params_.get_db_rows();
    const auto total_rawdb_entries = pir_params_.get_rounded_num_entries();
    const auto num_columns_per_entry = pir_params_.get_num_slots_per_entry();
    const auto plaintexts_per_chunk = std::ceil(total_rawdb_entries / pir_dimensions_[0]);

    // Initialize database

    PirDB db(total_db_plaintexts);
    for (auto &row : db)
    {
        row.assign(polynomial_degree_, 0ULL);
    }
    // cout  <<  "total_rawdb_entries: " << total_rawdb_entries << endl;

    // Populate database
    for (int i = 0; i < total_rawdb_entries; ++i)
    {
        // cout  <<  "total_rawdb_entries: " << i << endl;
        auto coeffs = convert_to_list_of_coeff(rawdb_list_[rawdb_index][i]);

        int plaintext_idx = i / pir_dimensions_[0];
        const int slot = (i * gap_) % row_size_;

        for (int j = 0; j < num_columns_per_entry; j++)
        {

            if (plaintext_idx >= total_db_plaintexts || slot >= row_size_)
            {
                // Handle out-of-bounds access
                std::cerr << "Error: Out-of-bounds access at ciphertext_idx = " << plaintext_idx
                          << ", slot = " << slot << std::endl;
            }
            db[plaintext_idx][slot] = coeffs[j];
            plaintext_idx += plaintexts_per_chunk;
        }
    }

    return db;
}

void Server::transform_into_pir_db()
{
    // Get necessary parameters
    const auto total_db_plaintexts = pir_params_.get_db_rows();
    const auto total_rawdb_entries = pir_params_.get_rounded_num_entries();
    const auto num_columns_per_entry = pir_params_.get_num_slots_per_entry();
    const auto plaintexts_per_chunk = std::ceil(total_rawdb_entries / pir_dimensions_[0]);

    // Initialize database
    db_.resize(total_db_plaintexts);
    for (auto &row : db_)
    {
        row.assign(polynomial_degree_, 0ULL);
    }

    // Populate database
    for (int i = 0; i < total_rawdb_entries; ++i)
    {
        auto coeffs = convert_to_list_of_coeff(rawdb_[i]);

        int plaintext_idx = i / pir_dimensions_[0];
        const int slot = (i * gap_) % row_size_;

        for (int j = 0; j < num_columns_per_entry; j++)
        {

            if (plaintext_idx >= total_db_plaintexts || slot >= row_size_)
            {
                // Handle out-of-bounds access
                std::cerr << "Error: Out-of-bounds access at ciphertext_idx = " << plaintext_idx
                          << ", slot = " << slot << std::endl;
                return;
            }
            db_[plaintext_idx][slot] = coeffs[j];
            plaintext_idx += plaintexts_per_chunk;
        }
    }

    rotate_db_cols();
    encode_db();

    // Check if db_ is populated
    if (encoded_db_.size() == total_db_plaintexts)
    {
        std::cout << "BatchPIRServer: Database is transformed to PIR DB!" << std::endl;
    }
}

// strategy which always merge chunks first

PIRResponseList Server::merge_responses_chunks_buckets(vector<PIRResponseList> &responses, uint32_t client_id)
{
    const size_t num_slots_per_entry = pir_params_.get_num_slots_per_entry();
    const size_t num_slots_per_entry_rounded = utils::next_power_of_two(num_slots_per_entry);

    const size_t max_empty_slots = pir_params_.get_dimensions()[0];
    auto num_chunk_ctx = ceil(num_slots_per_entry * 1.0 / max_empty_slots);

    PIRResponseList chunk_response;

    for (int i = 0; i < responses.size(); i++)
    {
        auto remaining_slots_entry = num_slots_per_entry;

        
        // number of ciphertexts needed to  pack chunks
        for (int j = 0; j < num_chunk_ctx; j++)
        {
            auto chunk_idx = j * max_empty_slots;

            // loop through chunks that can fit in a single ctxt
            uint32_t loop = std::min(max_empty_slots, remaining_slots_entry);
            Ciphertext chunk_ct_acc = responses[i][chunk_idx];
            for (size_t k = 1; k < loop; k++)
            {
                evaluator_->rotate_rows_inplace(responses[i][chunk_idx + k], -1 * (k * gap_), client_keys_[client_id].first);
                evaluator_->add_inplace(chunk_ct_acc, responses[i][chunk_idx + k]);
            }
            remaining_slots_entry -= loop;
            chunk_response.push_back(chunk_ct_acc);
        }
    }

    
    auto current_fill = gap_ * num_slots_per_entry;
    size_t num_buckets_merged = (row_size_ / current_fill);


    // for now if chunks are in multiple ciphertexts then return
    // if remaining
    if (ceil(num_slots_per_entry * 1.0 / max_empty_slots) > 1 || num_buckets_merged <= 1 || chunk_response.size() == 1 )
    {
        modulus_switch(chunk_response);
        return chunk_response;
    }

    current_fill = gap_ * num_slots_per_entry_rounded;
    auto merged_ctx_needed = ceil((chunk_response.size() * current_fill * 1.0) / row_size_);

    PIRResponseList chunk_bucket_responses;
    for (int i = 0; i < merged_ctx_needed; i++)
    {
        Ciphertext ct_acc;
        for (int j = 0; j < num_buckets_merged; j++)
        {
            Ciphertext copy_ct_acc = chunk_response[i * num_buckets_merged + j];
            Ciphertext tmp_ct = copy_ct_acc;
            // copy logic: copy_ct_acc will hold coppied result
            for (size_t k = 1; k < row_size_ / current_fill; k *= 2)
            {
                evaluator_->rotate_rows_inplace(tmp_ct, -1 * k * current_fill, client_keys_[client_id].first);
                evaluator_->add_inplace(copy_ct_acc, tmp_ct);
                tmp_ct = copy_ct_acc;
            }

            // selection logic: select consecutive gap_  entries from each bucket
            std::vector<uint64_t> selection_vector(polynomial_degree_, 0ULL);
            std::fill_n(selection_vector.begin() + (j * current_fill), current_fill, 1ULL);
            std::fill_n(selection_vector.begin() + row_size_ + (j * current_fill), current_fill, 1ULL);

            Plaintext selection_pt;
            batch_encoder_->encode(selection_vector, selection_pt);
            evaluator_->multiply_plain_inplace(copy_ct_acc, selection_pt);
            if (j == 0)
            {
                ct_acc = copy_ct_acc;
            }
            else
            {
                evaluator_->add_inplace(ct_acc, copy_ct_acc);
            }
        }
        chunk_bucket_responses.push_back(ct_acc);
    }

    
    modulus_switch(chunk_bucket_responses);
    return chunk_bucket_responses;
}

void Server::modulus_switch(PIRResponseList& list){
    for( int i = 0; i < list.size(); i++){
        evaluator_->mod_switch_to_next_inplace(list[i]);
        //evaluator_->mod_switch_to_next_inplace(list[i]);
    
    }
}

PIRResponseList Server::merge_responses_buckets_chunks(vector<PIRResponseList> &responses, uint32_t client_id)
{

    auto current_fill = responses.size() * gap_;
    if (current_fill > row_size_)
    {
        throw std::runtime_error("Error: Not supported batch size");
    }
    PIRResponseList bucket_response;
    PIRResponseList bucket_chunk_response;
    // go over the chunks
    for (int j = 0; j < responses[0].size(); j++)
    {
        Ciphertext bucket_ct_acc;

        // go over the buckets
        for (int i = 0; i < responses.size(); i++)
        {
            Ciphertext ct_acc = responses[i][j];
            Ciphertext ct = ct_acc;

            // copy logic: ct_acc will hold coppied result
            for (size_t k = 1; k < row_size_ / gap_; k *= 2)
            {
                evaluator_->rotate_rows_inplace(ct, -1 * k * gap_, client_keys_[client_id].first);
                evaluator_->add_inplace(ct_acc, ct);
                ct = ct_acc;
            }

            // selection logic: select consecutive gap_  entries from each bucket
            std::vector<uint64_t> selection_vector(polynomial_degree_, 0ULL);
            std::fill_n(selection_vector.begin() + (i * gap_), gap_, 1ULL);
            std::fill_n(selection_vector.begin() + row_size_ + (i * gap_), gap_, 1ULL);

            cout << endl;
            Plaintext pt;
            batch_encoder_->encode(selection_vector, pt);
            evaluator_->multiply_plain(ct_acc, pt, ct);

            // if first bucket nothing to accumlate
            if (i == 0)
            {
                bucket_ct_acc = ct;
            }
            else
            {
                evaluator_->add_inplace(bucket_ct_acc, ct);
            }
        }
        bucket_response.push_back(bucket_ct_acc);
    }

    // check if ciphertexts dont have space then return
    if (current_fill == row_size_)
    {
        return bucket_response;
    }

    auto capacity = row_size_ / current_fill;
    const auto slots_per_entry = pir_params_.get_num_slots_per_entry();
    auto ciphertext_needed = ceil(slots_per_entry * 1.0 / capacity);

    for (int i = 0; i < ciphertext_needed; i++)
    {
        Ciphertext chunk_ct_acc = bucket_response[i * capacity];
        for (int j = 1; j < capacity; j++)
        {
            evaluator_->rotate_rows_inplace(bucket_response[j + (i * capacity)], -1 * i * gap_, client_keys_[client_id].first);
            evaluator_->add_inplace(chunk_ct_acc, bucket_response[j]);
        }
        bucket_chunk_response.push_back(chunk_ct_acc);
    }

    return bucket_chunk_response;
}

void Server::rotate_db_cols()
{
    const auto total_db_plaintexts = pir_params_.get_db_rows();

    for (int idx = 0; idx < total_db_plaintexts; idx += pir_dimensions_[1])
    {
        for (int i = 0; i < pir_dimensions_[1]; i++)
        {
            db_[idx + i] = utils::rotate_vector_row(db_[idx + i], i * gap_);
        }
    }
}

void Server::print_db()
{
    int idx = 0;
    for (const auto &row : db_)
    {
        std::cout << idx << " ";
        for (const auto &entry : row)
        {
            if (1)
            {
                std::cout << entry << " ";
            }
        }
        idx++;
        std::cout << std::endl;
        std::cout << std::endl;
    }
}

void Server::print_rawdb()
{
    std::cout << "BatchPIRServer: Size of raw db " << rawdb_.size() << std::endl;
    int idx = 0;
    for (const auto &row : rawdb_)
    {
        std::cout << idx << " [";
        for (auto it = row.begin(); it != row.end(); it++)
        {
            std::cout << static_cast<int>(*it) << " ";
        }
        std::cout << " ]";
        idx++;
        std::cout << std::endl;
        std::cout << std::endl;
    }
}

void Server::print_encoded_db()
{
    for (const auto &row : encoded_db_)
    {
        std::vector<uint64_t> decoded_plain;
        batch_encoder_->decode(row, decoded_plain);

        for (const auto &entry : decoded_plain)
        {
            if (entry != 0)
            {
                std::cout << entry << " ";
            }
        }
        std::cout << std::endl;
        std::cout << std::endl;
    }
}

void Server::encode_db()
{
    // Check for null batch encoder
    if (batch_encoder_ == nullptr)
    {
        std::cerr << "Error: batch encoder is not initialized" << std::endl;
        return;
    }

    // Check for empty database
    if (db_.empty())
    {
        std::cerr << "Error: database is empty" << std::endl;
        return;
    }

    // Resize encoded database to match size of database
    encoded_db_.resize(db_.size());

    // Encode each element of the database
    for (int i = 0; i < db_.size(); i++)
    {
        try
        {
            batch_encoder_->encode(db_[i], encoded_db_[i]);
        }
        catch (const std::exception &e)
        {
            std::cerr << "Error encoding data: " << e.what() << std::endl;
            return;
        }
    }
}

void Server::ntt_preprocess_db()
{
    if (encoded_db_.size() == 0)
    {
        std::cout << "BatchPIRServer: Database not set! preprocess failed!" << std::endl;
        exit(1);
    }
    if (is_db_preprocessed_)
        return;
    auto pid = context_->first_parms_id();
    for (int i = 0; i < encoded_db_.size(); i++)
    {
        evaluator_->transform_to_ntt_inplace(encoded_db_[i], pid);
    }
    is_db_preprocessed_ = true;

    std::cout << "BatchPIRServer: Database is NTT processed!" << std::endl;
}

std::vector<uint64_t> Server::convert_to_list_of_coeff(std::vector<unsigned char> input_list)
{
    auto size_of_input = input_list.size();
    const int size_of_coeff = plaint_bit_count_ - 1;
    const int remain = (size_of_input * 8) % size_of_coeff;
    const int cols = pir_params_.get_num_slots_per_entry();
    std::vector<uint64_t> output_list(cols);
    std::string bit_str;

    for (int i = 0; i < size_of_input; i++)
    {
        bit_str += std::bitset<8>(input_list[i]).to_string();
    }

    if (remain != 0)
    {
        for (int i = 0; i < (size_of_coeff - remain); i++)
            bit_str += "1";
    }

    for (int i = 0; i < cols; i++)
    {
        uint64_t value = 0;
        for (char bit : bit_str.substr(i * size_of_coeff, size_of_coeff)) {
            value <<= 1;
            value |= (bit == '1') ? 1 : 0;
        }

        output_list[i] = value;
    }
    return output_list;
}

bool Server::print_raw_database_status()
{
    if (check_raw_db())
    {
        std::cout << "BatchPIRServer: Raw database generated successfully." << std::endl;
        return true;
    }
    else
    {
        std::cout << "BatchPIRServer: Error generating raw database." << std::endl;
        return false;
    }
}

vector<seal::Ciphertext> Server::rotate_copy_query(uint32_t client_id)
{
    vector<seal::Ciphertext> rotated_query;

    for (int i = 0; i < pir_dimensions_[0]; i++)
    {
        Ciphertext ct;
        evaluator_->rotate_rows(query_[0], -1 * i * gap_, client_keys_[client_id].first, ct);
        evaluator_->transform_to_ntt_inplace(ct);
        rotated_query.push_back(ct);
    }

    return rotated_query;
}

vector<Ciphertext> Server::process_first_dimension(uint32_t client_id)
{

    auto rotated_query = rotate_copy_query(client_id);
    vector<Ciphertext> first_intermediate_data;

    Ciphertext ct_acc;
    Ciphertext ct;
    for (int idx = 0; idx < encoded_db_.size(); idx += pir_dimensions_[1])
    {
        evaluator_->multiply_plain(rotated_query[0], encoded_db_[idx], ct_acc);

        for (int i = 1; i < pir_dimensions_[1]; i++)
        {

            evaluator_->multiply_plain(rotated_query[i], encoded_db_[idx + i], ct);
            evaluator_->add_inplace(ct_acc, ct);
        }

        evaluator_->transform_from_ntt_inplace(ct_acc);
        first_intermediate_data.push_back(ct_acc);
    }

    return first_intermediate_data;
}

vector<Ciphertext> Server::process_first_dimension_delayed_mod(uint32_t client_id)
{
    auto rotated_query = rotate_copy_query(client_id);
    vector<Ciphertext> first_intermediate_data;

    auto context_data_ptr = context_->get_context_data(rotated_query[0].parms_id());
    auto &context_data = *context_data_ptr;
    auto &parms = context_data.parms();
    auto &coeff_modulus = parms.coeff_modulus();
    size_t coeff_count = parms.poly_modulus_degree();
    size_t coeff_mod_count = coeff_modulus.size();
    size_t encrypted_ntt_size = rotated_query[0].size();
    std::vector<std::vector<uint128_t>> buffer(encrypted_ntt_size, std::vector<uint128_t>(coeff_count * coeff_mod_count, 0));

    Ciphertext ct_acc;

    for (int col_id = 0; col_id < encoded_db_.size(); col_id += pir_dimensions_[1])
    {

        std::vector<std::vector<uint128_t>> buffer(encrypted_ntt_size, std::vector<uint128_t>(coeff_count * coeff_mod_count, 1));
        for (int i = 0; i < pir_dimensions_[1]; i++)
        {
            for (size_t poly_id = 0; poly_id < encrypted_ntt_size; poly_id++)
            {
                utils::multiply_poly_acum(rotated_query[i].data(poly_id), encoded_db_[col_id + i].data(), coeff_count * coeff_mod_count, buffer[poly_id].data());
            }
        }

        ct_acc = rotated_query[0];
        for (size_t poly_id = 0; poly_id < encrypted_ntt_size; poly_id++)
        {
            auto ct_ptr = ct_acc.data(poly_id);
            auto pt_ptr = buffer[poly_id];
            for (int mod_id = 0; mod_id < coeff_mod_count; mod_id++)
            {
                auto mod_idx = (mod_id * coeff_count);

                for (int coeff_id = 0; coeff_id < coeff_count; coeff_id++)
                {
                    pt_ptr[coeff_id + mod_idx] = pt_ptr[coeff_id + mod_idx] % static_cast<__uint128_t>(coeff_modulus[mod_id].value());
                    ct_ptr[coeff_id + mod_idx] = static_cast<uint64_t>(pt_ptr[coeff_id + mod_idx]);
                }
            }
        }

        evaluator_->transform_from_ntt_inplace(ct_acc);
        //evaluator_->mod_switch_to_next_inplace(ct_acc);
        first_intermediate_data.push_back(ct_acc);
    }
    return first_intermediate_data;
}

vector<Ciphertext> Server::old_process_first_dimension_delayed_mod(uint32_t client_id)
{

    auto rotated_query = rotate_copy_query(client_id);
    vector<Ciphertext> first_intermediate_data;

    auto context_data_ptr = context_->get_context_data(rotated_query[0].parms_id());
    auto &context_data = *context_data_ptr;
    auto &parms = context_data.parms();
    auto &coeff_modulus = parms.coeff_modulus();
    size_t coeff_count = parms.poly_modulus_degree();
    size_t coeff_mod_count = coeff_modulus.size();
    
    size_t encrypted_ntt_size = rotated_query[0].size();

    for (int col_id = 0; col_id < encoded_db_.size(); col_id += pir_dimensions_[1])
    {
        Ciphertext ct_acc = rotated_query[0];
        for (size_t poly_id = 0; poly_id < encrypted_ntt_size; poly_id++)
        {
            // looping through each coefficient
            for (int coeff_id = 0; coeff_id < coeff_count; coeff_id++)
            {
                for (int mod_id = 0; mod_id < coeff_mod_count; mod_id++)
                {
                    __uint128_t product_acum = 1;

                    for (int i = 0; i < pir_dimensions_[1]; i++)
                    {
                        // utils::multiply_acum(&rotated_query[i].data(poly_id)[coeff_id + (mod_id * coeff_count)], &encoded_db_[col_id + i].data()[coeff_id + (mod_id * coeff_count)], &product_acum);
                    }

                    product_acum = product_acum % static_cast<__uint128_t>(coeff_modulus[mod_id].value());
                    ct_acc.data(poly_id)[coeff_id + (mod_id * coeff_count)] = static_cast<uint64_t>(product_acum);
                }
            }
        }
        // evaluator_->transform_from_ntt_inplace(ct_acc);
        first_intermediate_data.push_back(ct_acc);
    }

    return first_intermediate_data;
}

vector<Ciphertext> Server::process_second_dimension(uint32_t client_id, vector<Ciphertext> first_intermediate_data)
{

    vector<Ciphertext> second_intermediate_data;

    Ciphertext ct_acc;
    Ciphertext ct1, ct2;
    
    for (int idx = 0; idx < first_intermediate_data.size(); idx += pir_dimensions_[2])
    {

        evaluator_->multiply(query_[1], first_intermediate_data[idx], ct_acc);
        evaluator_->mod_switch_to_next_inplace(ct_acc);
        evaluator_->relinearize_inplace(ct_acc, client_keys_[client_id].second);

        for (int i = 1; i < pir_dimensions_[2]; i += 1)
        {

            evaluator_->multiply(query_[1], first_intermediate_data[idx + i], ct1);
            evaluator_->mod_switch_to_next_inplace(ct1);
            evaluator_->relinearize_inplace(ct1, client_keys_[client_id].second);
            evaluator_->rotate_rows_inplace(ct1, -1 * i * gap_, client_keys_[client_id].first);
            evaluator_->add_inplace(ct_acc, ct1);
        }

        
        second_intermediate_data.push_back(ct_acc);
    }

    if (second_intermediate_data.size() != pir_params_.get_num_slots_per_entry())
    {
        // Throw an exception
        throw runtime_error("Error: Size of second_intermediate_data is not equal to pir_params_.get_num_slots_per_entry()");
    }

    return second_intermediate_data;
}

PIRResponseList Server::process_last_dimension(uint32_t client_id, vector<Ciphertext> second_intermediate_data, bool is_2d_pir_)
{
    PIRResponseList ct_acc;
    if(!is_2d_pir_){
        evaluator_->mod_switch_to_next_inplace(query_.back());
    }
    for (int idx = 0; idx < second_intermediate_data.size(); idx++)
    {
        Ciphertext ct;
        evaluator_->multiply(query_.back(), second_intermediate_data[idx], ct);

        evaluator_->relinearize_inplace(ct, client_keys_[client_id].second);

        ct_acc.push_back(ct);
    }
    return ct_acc;
}

// PIRResponseList Server::generate_response(uint32_t client_id, PIRQuery query){
//     query_ = query;
//     vector<Ciphertext> first_intermediate_data = process_first_dimension(client_id);
//     vector<Ciphertext> second_intermediate_data = process_second_dimension(client_id, first_intermediate_data);
//     PIRResponseList response = process_third_dimension(client_id, second_intermediate_data);
//     return response;
// };

PIRResponseList Server::generate_response(uint32_t client_id, PIRQuery query)
{

    if (!is_db_preprocessed_)
        throw runtime_error("Error: Database not preprocessed");

    query_ = query;

    // Time process_first_dimension function
    // auto start = chrono::high_resolution_clock::now();
    // vector<Ciphertext> first_intermediate_data = process_first_dimension(client_id);
    vector<Ciphertext> first_intermediate_data = process_first_dimension_delayed_mod(client_id);
    // auto end = chrono::high_resolution_clock::now();
    // auto duration = chrono::duration_cast<chrono::milliseconds>(end - start);
    // cout << "Server: process_first_dimension time: " << duration.count() << " milliseconds" << endl;

    // Time process_second_dimension function
    // start = chrono::high_resolution_clock::now();
    vector<Ciphertext> second_intermediate_data;
    if(pir_dimensions_.size() == 3){
        second_intermediate_data = process_second_dimension(client_id, first_intermediate_data);
    }else{
        second_intermediate_data = first_intermediate_data;
    }
    // end = chrono::high_resolution_clock::now();
    // duration = chrono::duration_cast<chrono::milliseconds>(end - start);
    // cout << "Server: process_second_dimension time: " << duration.count() << " milliseconds" << endl;

    // Time process_third_dimension function
    // start = chrono::high_resolution_clock::now();
    PIRResponseList response = process_last_dimension(client_id, second_intermediate_data, pir_dimensions_.size() == 2);
    // end = chrono::high_resolution_clock::now();
    // duration = chrono::duration_cast<chrono::milliseconds>(end - start);
    // cout << "Server: process_third_dimension time: " << duration.count() << " milliseconds" << endl;

    return response;
}

bool Server::check_decoded_entry(std::vector<unsigned char> entry, int index)
{
    if (entry.size() != rawdb_list_[1][index].size())
    {
        std::cout << "BatchPIRServer: Vectors have different sizes!" << std::endl;
        return false;
    }

    bool result = std::equal(entry.begin(), entry.end(), rawdb_list_[1][index].begin());

    if (!result)
    {
        std::cout << "BatchPIRServer: Vectors are not equal:" << std::endl;
        std::cout << "entry:      ";
        for (auto it = entry.begin(); it != entry.end(); it++)
        {
            std::cout << static_cast<int>(*it) << " ";
        }
        std::cout << std::endl;
        std::cout << std::endl;

        std::cout << "rawdb_list_[1][ " << index << "]: ";
        for (auto it = rawdb_list_[1][index].begin(); it != rawdb_list_[1][index].end(); it++)
        {
            std::cout << static_cast<int>(*it) << " ";
        }
        std::cout << std::endl;
        std::cout << std::endl;
    }

    return result;
}

bool Server::check_decoded_entries(std::vector<std::vector<unsigned char>> entries, vector<uint64_t> indices)
{
    for (int i = 0; i < num_databases_; i++)
    {

        // dont check anything if its a default inddex, only used for cuckoo hashing
        if (indices[i] != pir_params_.get_default_value())
        {
            if (entries[i].size() != rawdb_list_[i][indices[i]].size())
            {
                throw std::runtime_error("Error: Vectors have different sizes!");
            }

            bool result = std::equal(entries[i].begin(), entries[i].end(), rawdb_list_[i][indices[i]].begin());
            if (!result)
            {
                throw std::runtime_error("Error: Entries do not match!");
            }
        }
    }
    cout << endl;
    return true;
}
