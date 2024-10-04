#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <unistd.h>

#define PATH_MAX 4096
#define MAX_FILES 1000 // INT_MAX Maximum number of files to index

// Struct to hold file item information
typedef struct {
    char filename[PATH_MAX];
    char path[PATH_MAX];
    // size_t size;
    long size;
} fileitem;

// Struct to hold duplicate scan results
typedef struct {
    char original_file[PATH_MAX];
    char duplicate_file[PATH_MAX];
} scanresult;

// Global variables
fileitem files[MAX_FILES];
scanresult results[MAX_FILES];
int file_count = 0;
int result_count = 0;

// Function declarations
void get_files(const char *basedirectory, int recursive, const char *filter);
void compare_files(int depth);
void show_scan_results();
void show_help();
void save_file_list();
void load_file_list();
void load_scan_results();
char *get_file_list_path();
int compare_byte_by_byte(const char *file1, const char *file2);
void get_file_hash_md5(const char *filename, char *output);
void get_file_hash_sha512(const char *filename, char *output);

// returns the file list/index path (opt: from ENV)
char *get_file_list_path() {
    char *path = getenv("DF_INDEX");
    return path ? path : "/tmp/df-index.txt"; // Use environment variable or default to index.txt
}

char *get_scan_results_path() {
    char *path = getenv("DF_RESULTS");
    return path ? path : "/tmp/df-results.txt";
}

// load file list
void load_file_list() {
    char *path = get_file_list_path();
    FILE *file = fopen(path, "rb");
    if (file) {
        file_count = fread(files, sizeof(fileitem), MAX_FILES, file);
        fclose(file);
    }
}

// save file list
void save_file_list() {
    char *path = get_file_list_path();
    FILE *file = fopen(path, "wb");
    if (file) {
        fwrite(files, sizeof(fileitem), file_count, file);
        fclose(file);
    } 
}

void save_scan_results() {
    char *path = get_scan_results_path();
    FILE *file = fopen(path, "wb");
    if (file) {
        fwrite(files, sizeof(fileitem), file_count, file);
        fclose(file);
    } 
}

void load_scan_results() {
    char *path = get_scan_results_path();
    FILE *file = fopen(path, "r");
    if (file) {
        result_count = fread(results, sizeof(scanresult), MAX_FILES, file);
        fclose(file);
    }
}

// Function to get files from a directory
void get_files(const char *basedirectory, int recursive, const char *filter) {
    DIR *dir;
    struct dirent *entry;
    struct stat file_stat;

    if (!(dir = opendir(basedirectory))) {
        perror("Unable to open directory");
        return;
    }

    while ((entry = readdir(dir)) != NULL) {
        // Ignore "." and ".." entries
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        char fullpath[PATH_MAX];
        snprintf(fullpath, sizeof(fullpath), "%s/%s", basedirectory, entry->d_name);

        // Check if it's a directory
        if (stat(fullpath, &file_stat) == 0 && S_ISDIR(file_stat.st_mode)) {
            if (recursive) {
                get_files(fullpath, recursive, filter); // Recurse into subdirectory
            }
        } else {
            // Check if file matches the filter (if provided)
            if (!filter || strstr(entry->d_name, filter) != NULL) {
                // Ensure no duplicates in index
                //int is_duplicate = 0;
                //for (int i = 0; i < file_count; i++) {
                //    if (strcmp(files[i].filename, entry->d_name) == 0) {
                //        is_duplicate = 1;
                //        break;
                //    }
                
                //if (!is_duplicate) {
                    // Store file information
                    strcpy(files[file_count].filename, entry->d_name);
                    strcpy(files[file_count].path, fullpath);
                    files[file_count].size = file_stat.st_size;
                    file_count++;

                    // printf("Adding file to index: %s\n", fullpath);
                //}
            }
        }
    }

    save_file_list();

    closedir(dir);
}

// Function to compare files and find duplicates
void compare_files(int depth) {
    result_count = 0; // Initialize result count

    for (int i = 0; i < file_count; i++) {
        for (int j = i + 1; j < file_count; j++) {
            // 1. Compare file size
            if (files[i].size == files[j].size) {
                // 2. If depth >= 1: Calculate hashes for both files and compare
                if (depth >= 1) {
                    char hash1[128];  // Buffer for hash
                    char hash2[128];

                    // Read environment variable for hash type
                    const char *hash_type = getenv("DF_HASH");
                    if (hash_type == NULL) {
                        hash_type = "MD5";  // Default to MD5 if not set
                    }

                    // Hash comparison logic (not shown for brevity)
                }

                // 3. If depth >= 2: Compare byte-by-byte (not shown for brevity)

                // Store the duplicate in the results array
                strcpy(results[result_count].original_file, files[i].path);
                strcpy(results[result_count].duplicate_file, files[j].path);
                result_count++; // Increment result count
            }
        }
    }

    // todo: save_compare_results();
}

// Function to compare files byte by byte
int compare_byte_by_byte(const char *file1, const char *file2) {
    FILE *f1 = fopen(file1, "rb");
    FILE *f2 = fopen(file2, "rb");
    if (!f1 || !f2) {
        perror("Unable to open files for byte comparison");
        return 0;
    }

    unsigned char buffer1[1024], buffer2[1024];
    size_t bytes1, bytes2;

    while (1) {
        bytes1 = fread(buffer1, 1, sizeof(buffer1), f1);
        bytes2 = fread(buffer2, 1, sizeof(buffer2), f2);

        if (bytes1 != bytes2 || memcmp(buffer1, buffer2, bytes1) != 0) {
            fclose(f1);
            fclose(f2);
            return 0; // Files are not equal
        }

        if (bytes1 < sizeof(buffer1)) {
            break; // End of file
        }
    }

    fclose(f1);
    fclose(f2);
    return 1; // Files are equal
}

// Function to calculate the MD5 hash of a file
void get_file_hash_md5(const char *filename, char *output) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_md5();
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;

    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Unable to open file");
        return;
    }

    EVP_DigestInit_ex(mdctx, md, NULL);
    unsigned char buffer[1024];
    size_t bytes;

    while ((bytes = fread(buffer, 1, sizeof(buffer), file)) != 0) {
        EVP_DigestUpdate(mdctx, buffer, bytes);
    }

    EVP_DigestFinal_ex(mdctx, hash, &hash_len);
    EVP_MD_CTX_free(mdctx);
    fclose(file);

    // Convert hash to hex string
    for (unsigned int i = 0; i < hash_len; i++) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
    output[hash_len * 2] = '\0'; // Null-terminate the string
}

// Function to calculate the SHA512 hash of a file
void get_file_hash_sha512(const char *filename, char *output) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_sha512();
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;

    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Unable to open file");
        return;
    }

    EVP_DigestInit_ex(mdctx, md, NULL);
    unsigned char buffer[1024];
    size_t bytes;

    while ((bytes = fread(buffer, 1, sizeof(buffer), file)) != 0) {
        EVP_DigestUpdate(mdctx, buffer, bytes);
    }

    EVP_DigestFinal_ex(mdctx, hash, &hash_len);
    EVP_MD_CTX_free(mdctx);
    fclose(file);

    // Convert hash to hex string
    for (unsigned int i = 0; i < hash_len; i++) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
    output[hash_len * 2] = '\0'; // Null-terminate the string
}

// Function to display scan results
void show_scan_results() {
    if (result_count > 0) {
        printf("Found %d duplicates:\n", result_count);
        for (int i = 0; i < result_count; i++) {
            printf("Original: %s, Duplicate: %s\n", results[i].original_file, results[i].duplicate_file);
        }
    } else {
        printf("No duplicates found.\n");
    }
}

// Function to display the help menu
void show_help() {
    printf("dupefiles 2024 (c) by dahead, version 0.2\n");
    printf("Usage:\n");
    printf("  scan                : Scan existing index for duplicates\n");
    printf("  scan /path/to/scan  : Create a new temp index for /path/ and scan\n");
    printf("  add /path/to/add    : Adds a path to the index\n");
    printf("  show                : Shows the scan results of the last scan\n");
    printf("  print               : Print scan results info\n");
    printf("  help                : Display this help message\n");
    printf("Options:\n");
    printf("  -d <depth>          : Set depth of comparison (default: 1)\n");
    printf("  -h                  : Show help\n");
}

// Main function
int main(int argc, char *argv[]) {
    int depth = 1; // Default depth
    char *path = NULL;

    load_file_list(); // Load the file list at program start
    load_scan_results(); // Load scan results at program start

    // Process command-line arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "scan") == 0) {
            if (i + 1 < argc) {
                path = argv[i + 1]; // Get path for scanning
                i++; // Skip the next argument
            }
            
            // compare_files(2);
        } else if (strcmp(argv[i], "-d") == 0) {
            if (i + 1 < argc) {
                depth = atoi(argv[i + 1]); // Set depth from argument
                i++; // Skip the next argument
            }
        } else if (strcmp(argv[i], "add") == 0) {
            if (i + 1 < argc) {
                path = argv[i + 1]; // Get file to add
                i++; // Skip the next argument
                // Add single file logic here (not implemented)
            }
        } else if (strcmp(argv[i], "show") == 0) {
            show_scan_results(); // Show scan results
            return 0;
        } else if (strcmp(argv[i], "help") == 0 || strcmp(argv[i], "-h") == 0) {
            show_help(); // Show help
            return 0;
        }
    }

    // Load files if a path is provided
    if (path) {
        get_files(path, 1, NULL); // Get files from the specified directory
        compare_files(depth); // Compare files for duplicates
    } else {
        fprintf(stderr, "No path provided. Use 'help' for usage.\n");
    }

    return 0;
}
