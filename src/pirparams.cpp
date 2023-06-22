#include "pirparams.h"
using namespace seal;

PirParams::PirParams(size_t num_entries, size_t entry_size, size_t db_count, seal::EncryptionParameters seal_params, size_t first_two_dimensions = 0) : num_entries_(num_entries),
                                                                                                                entry_size_(entry_size),
                                                                                                                db_count_(db_count)
{

    seal_params_ = seal_params;

    // calculate dimensions

    if (first_two_dimensions == 0)
    {
        calculate_dimensions(num_entries);
    }
    else
    {
        calculate_dimensions(num_entries, first_two_dimensions);
    }

    // calculate number of columns per entry
    calculate_num_slots_per_entry(entry_size);

    // round the number of entries should be called after dimensions are calculated
    calculate_rounded_db_size();

    // calculate number of rows in the database
    calculate_db_ptx();

    calculate_max_num_db();

    if (db_count > get_max_db_count())
    {
        throw std::invalid_argument("Number of databases can not exceed max database count.");
    }

    // print_values();
}

size_t PirParams::get_num_entries() const
{
    return num_entries_;
}

size_t PirParams::get_rounded_num_entries() const
{
    return num_rounded_entries_;
}

size_t PirParams::get_entry_size() const
{
    return entry_size_;
}

uint32_t PirParams::get_num_slots_per_entry() const
{
    return num_columns_per_entry_;
}

uint32_t PirParams::get_db_rows() const
{
    return db_ptx_;
}

vector<size_t> PirParams::get_dimensions() const
{
    return dimensions_;
}

seal::EncryptionParameters PirParams::get_seal_parameters() const
{
    return seal_params_;
}

size_t PirParams::get_max_db_count() const
{
    return max_db_count_;
}

size_t PirParams::get_db_count() const
{
    return db_count_;
}

uint64_t PirParams::get_default_value() const
{
    return default_value_;
}

void PirParams::calculate_num_slots_per_entry(size_t entry_size)
{
    num_columns_per_entry_ = ceil((8 * entry_size * 1.0) / (seal_params_.plain_modulus().bit_count() - 1));
}

void PirParams::calculate_db_ptx()
{
    db_ptx_ = std::ceil(num_rounded_entries_ / (dimensions_[0] * 1.0)) * num_columns_per_entry_;
}

void PirParams::calculate_rounded_db_size()
{
    num_rounded_entries_ = 1;

    for (int i = 0; i < dimensions_.size(); i++)
    {
        num_rounded_entries_ *= dimensions_[i];
    }
}

void PirParams::calculate_max_num_db()
{

    if (dimensions_.size() == 0)
    {
        throw std::invalid_argument("Dimension are not set yet");
    }

    max_db_count_ = seal_params_.poly_modulus_degree() / dimensions_[0];
}

void PirParams::calculate_dimensions(size_t num_entries)
{
    size_t cube_root = std::ceil(std::cbrt(num_entries));

    size_t first_two_dimensions = utils::next_power_of_two(cube_root);

    if (first_two_dimensions > seal_params_.poly_modulus_degree() / 2)
    {
        throw std::invalid_argument("First two dimensions exceed polynomial degree");
    }

    size_t third_dimension = ceil(num_entries / pow(first_two_dimensions, 2));

    dimensions_.push_back(first_two_dimensions);
    dimensions_.push_back(first_two_dimensions);
    dimensions_.push_back(third_dimension);
}

void PirParams::calculate_dimensions(size_t num_entries, size_t first_two_dimensions)
{
    if (first_two_dimensions > seal_params_.poly_modulus_degree() / 2)
    {
        throw std::invalid_argument("First two dimensions exceed row size");
    }

    if (first_two_dimensions > seal_params_.poly_modulus_degree() / 2)
    {
        throw std::invalid_argument("First two dimensions exceed row size");
    }

    if ((first_two_dimensions & (first_two_dimensions - 1)) != 0)
    {
        throw std::invalid_argument("First two dimensions is not a power of 2");
    }

    size_t third_dimension = ceil(num_entries / pow(first_two_dimensions, 2));

    if(third_dimension > 1){
        dimensions_.push_back(first_two_dimensions);
        dimensions_.push_back(first_two_dimensions);
        dimensions_.push_back(third_dimension);
        }
    else{
        dimensions_.push_back(first_two_dimensions);
        dimensions_.push_back(ceil(num_entries*1.0 / first_two_dimensions));
        }
    
    
}

void PirParams::print_values()
{
std::cout << "+---------------------------------------------------+" << std::endl;
std::cout << "|                 PIR PARAMETERS                    |" << std::endl;
std::cout << "+---------------------------------------------------+" << std::endl;
std::cout << "|  num_entries_                  = " << num_entries_ << std::endl;
std::cout << "|  num_rounded_entries_          = " << num_rounded_entries_ << std::endl;
std::cout << "|  entry_size_                   = " << entry_size_ << std::endl;
std::cout << "|  num_columns_per_entry_        = " << num_columns_per_entry_ << std::endl;
std::cout << "|  db_ptx_                       = " << db_ptx_ << std::endl;
std::cout << "|  dimensions_                   = [ ";
for (const auto& dim : dimensions_)
{
    std::cout << dim << " ";
}
std::cout << "]" << std::endl;
std::cout << "+---------------------------------------------------+" << std::endl;

}
