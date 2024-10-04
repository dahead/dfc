#include <iostream>
#include <vector>
#include <string>
#include <dirent.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <fstream>
#include <cstring>
#include <unistd.h>

#define PATH_MAX 4096

struct FileItem {
    std::string filename;
    std::string path;
    long size;
};

struct ScanResult {
    std::string original_file;
    std::string duplicate_file;
};

std::vector<FileItem> files;
std::vector<ScanResult> results;

void get_files(const std::string &basedirectory, int recursive, const std::string &filter);
void compare_files(int depth);
void show_scan_results();
void show_help();
void save_file_list();
void load_file_list();
void load_scan_results();
std::string get_file_list_path();
std::string get_scan_results_path();
bool compare_byte_by_byte(const std::string &file1, const std::string &file2);
void get_file_hash_md5(const std::string &filename, std::string &output);
void get_file_hash_sha512(const std::string &filename, std::string &output);

std::string get_file_list_path() {
    const char *path = getenv("DF_INDEX");
    return path ? path : "/tmp/df-index.txt";
}

std::string get_scan_results_path() {
    const char *path = getenv("DF_RESULTS");
    return path ? path : "/tmp/df-results.txt";
}

void load_file_list() {
    std::cout << "Getting file list path...\n";
    std::ifstream file(get_file_list_path(), std::ios::binary);
    
    std::cout << "Opening file...\n";
    if (file.is_open()) {
        FileItem item;
        while (file.read(reinterpret_cast<char*>(&item), sizeof(FileItem))) {
            files.push_back(item);
        }
    }
}

void save_file_list() {
    std::ofstream file(get_file_list_path(), std::ios::binary);
    if (file.is_open()) {
        for (const auto &item : files) {
            file.write(reinterpret_cast<const char*>(&item), sizeof(FileItem));
        }
    }
}

void load_scan_results() {
    std::ifstream file(get_scan_results_path(), std::ios::binary);
    if (file.is_open()) {
        ScanResult result;
        while (file.read(reinterpret_cast<char*>(&result), sizeof(ScanResult))) {
            results.push_back(result);
        }
    }
}

void save_scan_results() {
    std::ofstream file(get_scan_results_path(), std::ios::binary);
    if (file.is_open()) {
        for (const auto &result : results) {
            file.write(reinterpret_cast<const char*>(&result), sizeof(ScanResult));
        }
    }
}

void get_files(const std::string &basedirectory, int recursive, const std::string &filter) {
    DIR *dir;
    struct dirent *entry;
    struct stat file_stat;

    if (!(dir = opendir(basedirectory.c_str()))) {
        perror("Unable to open directory");
        return;
    }

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        std::string fullpath = basedirectory + "/" + entry->d_name;

        if (stat(fullpath.c_str(), &file_stat) == 0 && S_ISDIR(file_stat.st_mode)) {
            if (recursive) {
                get_files(fullpath, recursive, filter);
            }
        } else {
            if (filter.empty() || fullpath.find(filter) != std::string::npos) {
                FileItem item;
                item.filename = entry->d_name;
                item.path = fullpath;
                item.size = file_stat.st_size;
                files.push_back(item);
            }
        }
    }

    save_file_list();
    closedir(dir);
}

void compare_files(int depth) {
    int result_count = 0;

    // Forward iteration for the first file
    for (std::size_t i = 0; i < files.size(); ++i) {
        const FileItem& item_i = files[i];  // Save file i

        // Reverse iteration for the second file
        for (std::size_t f = files.size() - 1; f > i; --f) {
            const FileItem& item_f = files[f];  // Save file f

            // Skip if it's the same file based on filename
            if (item_i.filename == item_f.filename) {
                continue;
            }

            // Check if file sizes are equal
            if (item_i.size == item_f.size) {
                // Initialize hash buffers
                std::string hash1(128, '\0');
                std::string hash2(128, '\0');

                // Get file hashes
                const char* hash_type = getenv("DF_HASH");
                if (hash_type == nullptr) {
                    hash_type = "SHA512";
                }

                if (strcmp(hash_type, "SHA512") == 0) {
                    get_file_hash_sha512(item_i.path.c_str(), hash1);
                    get_file_hash_sha512(item_f.path.c_str(), hash2);
                } else {
                    get_file_hash_md5(item_i.path.c_str(), hash1);
                    get_file_hash_md5(item_f.path.c_str(), hash2);
                }

                // Check if hashes are equal
                if (hash1 == hash2) {
                    // Compare byte-by-byte
                    if (compare_byte_by_byte(item_i.path.c_str(), item_f.path.c_str())) {
                        // Store duplicate in scan results
                        ScanResult result;
                        result.original_file = item_i.path;
                        result.duplicate_file = item_f.path;
                        results.push_back(result);
                        ++result_count;
                    }
                }
            }
        }
    }
}

bool compare_byte_by_byte(const std::string &file1, const std::string &file2) {
    std::ifstream f1(file1, std::ios::binary);
    std::ifstream f2(file2, std::ios::binary);

    if (!f1.is_open() || !f2.is_open()) {
        perror("Unable to open files for byte comparison");
        return false;
    }

    char buffer1[1024], buffer2[1024];

    while (!f1.eof() && !f2.eof()) {
        f1.read(buffer1, sizeof(buffer1));
        f2.read(buffer2, sizeof(buffer2));

        if (f1.gcount() != f2.gcount() || memcmp(buffer1, buffer2, f1.gcount()) != 0) {
            return false;
        }
    }

    return f1.eof() && f2.eof();
}

void get_file_hash_md5(const std::string &filename, std::string &output) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_md5();
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;

    std::ifstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        perror("Unable to open file");
        return;
    }

    EVP_DigestInit_ex(mdctx, md, nullptr);
    char buffer[1024];
    while (file.read(buffer, sizeof(buffer))) {
        EVP_DigestUpdate(mdctx, buffer, file.gcount());
    }

    EVP_DigestFinal_ex(mdctx, hash, &hash_len);
    EVP_MD_CTX_free(mdctx);

    output.clear();
    for (unsigned int i = 0; i < hash_len; i++) {
        char hex[3];
        snprintf(hex, sizeof(hex), "%02x", hash[i]);
        output += hex;
    }
}

void get_file_hash_sha512(const std::string &filename, std::string &output) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_sha512();
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;

    std::ifstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        perror("Unable to open file");
        return;
    }

    EVP_DigestInit_ex(mdctx, md, nullptr);
    char buffer[1024];
    while (file.read(buffer, sizeof(buffer))) {
        EVP_DigestUpdate(mdctx, buffer, file.gcount());
    }

    EVP_DigestFinal_ex(mdctx, hash, &hash_len);
    EVP_MD_CTX_free(mdctx);

    output.clear();
    for (unsigned int i = 0; i < hash_len; i++) {
        char hex[3];
        snprintf(hex, sizeof(hex), "%02x", hash[i]);
        output += hex;
    }
}

void show_scan_results() {
    if (!results.empty()) {
        std::cout << "Found " << results.size() << " duplicates:\n";
        for (const auto &result : results) {
            std::cout << "Original: " << result.original_file << ", Duplicate: " << result.duplicate_file << '\n';
        }
    } else {
        std::cout << "No duplicates found.\n";
    }
}

void show_help() {
    std::cout << "dupefiles 2024 (c) by dahead, version 0.2\n"
              << "Usage:\n"
              << "  scan                : Scan existing index for duplicates\n"
              << "  scan /path/to/scan  : Create a new temp index for /path/ and scan\n"
              << "  add /path/to/add    : Adds a path to the index\n"
              << "  show                : Shows the scan results of the last scan\n"
              << "  print               : Print scan results info\n"
              << "  help                : Display this help message\n"
              << "Options:\n"
              << "  -d <depth>          : Set depth of comparison (default: 1)\n"
              << "  -h                  : Show help\n";
}

int main(int argc, char *argv[]) {
    int depth = 1;
    std::string path;

    std::cout << "Loading file list...\n";
    load_file_list();
    std::cout << "File list loaded.\n";

    std::cout << "Loading scan results...\n";
    load_scan_results();
    std::cout << "Scan results loaded.\n";

    std::cout << "Parsing args...\n";

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "scan") == 0) {
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                path = argv[++i];
            }
        } else if (strcmp(argv[i], "add") == 0) {
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                path = argv[++i];
                get_files(path, 1, "");
            }
        } else if (strcmp(argv[i], "show") == 0) {
            show_scan_results();
            return 0;
        } else if (strcmp(argv[i], "-d") == 0) {
            if (i + 1 < argc) {
                depth = std::stoi(argv[++i]);
            }
        } else if (strcmp(argv[i], "help") == 0 || strcmp(argv[i], "-h") == 0) {
            show_help();
            return 0;
        }
    }

    if (!path.empty()) {
        get_files(path, 1, "");
    }

    if (files.empty()) {
        std::cout << "No files to scan. Use 'add' to add files.\n";
        return 0;
    }

    compare_files(depth);
    save_scan_results();
    show_scan_results();

    return 0;
}


