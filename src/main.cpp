#include <iostream>
#include <cstdlib>
#include <cassert>
#include <chrono>
#include <functional>
#include "server.h"
#include "pirparams.h"
#include "client.h"
#include "batchpirparams.h"
#include "batchpirserver.h"
#include "batchpirclient.h"

using namespace std;
using namespace chrono;

void print_usage()
{
    std::cout << "Usage: vectorized_batch_pir -n <db_entries> -s <entry_size>\n";
}

bool validate_arguments(int argc, char *argv[], size_t &db_entries, size_t &entry_size)
{
    if (argc == 2 && string(argv[1]) == "-h")
    {
        print_usage();
        return false;
    }
    if (argc != 5 || string(argv[1]) != "-n" || string(argv[3]) != "-s")
    {
        std::cerr << "Error: Invalid arguments.\n";
        print_usage();
        return false;
    }
    db_entries = stoull(argv[2]);
    entry_size = stoull(argv[4]);
    return true;
}

int vectorized_pir_main(int argc, char *argv[])
{
    size_t db_entries = 0;
    size_t entry_size = 0;
    const int client_id = 0;

    // Validate the command line arguments
    if (!validate_arguments(argc, argv, db_entries, entry_size))
    {
        // Return an error code if the arguments are invalid
        return 1;
    }

    uint64_t num_databases = 128;
    uint64_t first_dim = 64;

    auto encryption_params = utils::create_encryption_parameters();

    // Create a PirParams object with the specified number of entries and entry size and size of first dimension
    PirParams params(db_entries, entry_size, num_databases, encryption_params, first_dim);
    params.print_values();

    // Create a Server object with the PirParams object
    Server server(params);

    // Create a Client object with the PirParams object
    Client client(params);

    // Populate the raw database in the Server object. Change this function to load database from other source
    server.load_raw_dbs();

    // Convert the raw database to the PIR database
    server.convert_merge_pir_dbs();


    // Convert the raw database to the PIR database
    server.ntt_preprocess_db();



    server.set_client_keys(client_id, client.get_public_keys());

    vector<uint64_t> entry_indices;
    for (int i = 0; i < num_databases; i++)
    {
        // entry_indices.push_back(rand() % db_entries);
        entry_indices.push_back(0);
    }


    auto query = client.gen_query(entry_indices);

    auto start_time = std::chrono::high_resolution_clock::now();
    PIRResponseList response = server.generate_response(client_id, query);
    auto end_time = std::chrono::high_resolution_clock::now();
    auto elapsed_time = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);

    // Print the elapsed time in milliseconds
    std::cout << "generate_response time: " << elapsed_time.count() << " ms" << std::endl;

    auto entries = client.single_pir_decode_responses(response);

    server.check_decoded_entries(entries, entry_indices);

    cout << "Main: decoded entries matched" << endl;
    return 0;
}

int hashing_test_main(int argc, char *argv[])
{

    if (argc != 4)
    {
        std::cerr << "Usage: " << argv[0] << " batch_size num_entries entry_size" << std::endl;
        return 1;
    }

    int batch_size = std::stoi(argv[1]);
    size_t num_entries = std::stoull(argv[2]);
    size_t entry_size = std::stoull(argv[3]);

    auto encryption_params = utils::create_encryption_parameters();

    BatchPirParams params(batch_size, num_entries, entry_size, encryption_params);
    BatchPIRClient client(params);

    vector<uint64_t> myvec(batch_size);

    int trials = std::pow(2, 30);
    for (int j = 0; j < trials; j++)
    {
        cout << "Trial " << j << "/" << trials << ": ";
        for (int i = 0; i < batch_size; i++)
        {
            myvec[i] = rand() % num_entries;
        }

        if (client.cuckoo_hash_witout_checks(myvec))
        {
            cout << "success" << endl;
        }
        else
        {
            cout << "failure" << endl;
            throw std::invalid_argument("Attempt failed");
        }
    }
    return 0;
}

int batchpir_main(int argc, char* argv[])
{
    const int client_id = 0;
    //  batch size, number of entries, size of entry
    std::vector<std::array<size_t, 3>> input_choices;
    input_choices.push_back({32, 1048576, 32});
    input_choices.push_back({64, 1048576, 32});
    input_choices.push_back({256, 1048576, 32});
    

    std::vector<std::chrono::milliseconds> init_times;
    std::vector<std::chrono::milliseconds> query_gen_times;
    std::vector<std::chrono::milliseconds> resp_gen_times;
    std::vector<size_t> communication_list;

 for (size_t iteration = 0; iteration < input_choices.size(); ++iteration)
{
    std::cout << "***************************************************" << std::endl;
    std::cout << "             Starting example " << (iteration + 1) << "               " << std::endl;
    std::cout << "***************************************************" << std::endl;

    const auto& choice = input_choices[iteration];

    string selection = std::to_string(choice[0]) + "," + std::to_string(choice[1]) + "," + std::to_string(choice[2]);

    auto encryption_params = utils::create_encryption_parameters(selection);
    BatchPirParams params(choice[0], choice[1], choice[2], encryption_params);
    params.print_params();

    auto start = chrono::high_resolution_clock::now();
    BatchPIRServer batch_server(params);
    auto end = chrono::high_resolution_clock::now();
    auto duration_init = chrono::duration_cast<chrono::milliseconds>(end - start);
    init_times.push_back(duration_init);

    BatchPIRClient batch_client(params);

    auto map = batch_server.get_hash_map();
    batch_client.set_map(map);

    batch_server.set_client_keys(client_id, batch_client.get_public_keys());

    vector<uint64_t> entry_indices;
    for (int i = 0; i < choice[0]; i++)
    {
        entry_indices.push_back(rand() % choice[2]);
    }

    cout << "Main: Starting query generation for example " << (iteration + 1) << "..." << endl;
    start = chrono::high_resolution_clock::now();
    auto queries = batch_client.create_queries(entry_indices);
    end = chrono::high_resolution_clock::now();
    auto duration_querygen = chrono::duration_cast<chrono::milliseconds>(end - start);
    query_gen_times.push_back(duration_querygen);
    cout << "Main: Query generation complete for example " << (iteration + 1) << "." << endl;

    cout << "Main: Starting response generation for example " << (iteration + 1) << "..." << endl;
    start = chrono::high_resolution_clock::now();
    PIRResponseList responses = batch_server.generate_response(client_id, queries);
    end = chrono::high_resolution_clock::now();
    auto duration_respgen = chrono::duration_cast<chrono::milliseconds>(end - start);
    resp_gen_times.push_back(duration_respgen);
    cout << "Main: Response generation complete for example " << (iteration + 1) << "." << endl;

    cout << "Main: Checking decoded entries for example " << (iteration + 1) << "..." << endl;
    auto decode_responses = batch_client.decode_responses_chunks(responses);

    communication_list.push_back(batch_client.get_serialized_commm_size());

    auto cuckoo_table = batch_client.get_cuckoo_table();

    if (batch_server.check_decoded_entries(decode_responses, cuckoo_table))
    {
        cout << "Main: All the entries matched for example " << (iteration + 1) << "!!" << endl;
    }

    cout << endl;
}


    cout << "***********************" << endl;
    cout << "     Timings Report    " << endl;
    cout << "***********************" << endl;
    for (size_t i = 0; i < input_choices.size(); ++i)
    {
        cout << "Input Parameters: ";
        cout << "Batch Size: " << input_choices[i][0] << ", ";
        cout << "Number of Entries: " << input_choices[i][1] << ", ";
        cout << "Entry Size: " << input_choices[i][2] << endl;

        cout << "Initialization time: " << init_times[i].count() << " milliseconds" << endl;
        cout << "Query generation time: " << query_gen_times[i].count() << " milliseconds" << endl;
        cout << "Response generation time: " << resp_gen_times[i].count() << " milliseconds" << endl;
        cout << "Total communication: " << communication_list[i] << " KB" << endl;
        cout << endl;
    }

    return 0;
}



int main(int argc, char *argv[])
{
    //vectorized_pir_main(argc, argv);
    batchpir_main(argc, argv);
    return 0;
}
