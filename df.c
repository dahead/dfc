#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>

#define HASH_SIZE SHA512_DIGEST_LENGTH
#define MAX_PATH 4096
#define MAX_FILES 102400

typedef struct FileItem {
    char filename[MAX_PATH];
    char path[MAX_PATH];
    unsigned char hash[HASH_SIZE];
    off_t size;
} FileItem;

int debug = 0;

void get_files(const char *directory, const char *extension, int reverse, FileItem **files, int *file_count);
void find_duplicates(FileItem *files, int compare_bytes, int file_count);

void calculate_hash(const char *filename, unsigned char *output) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_sha512();
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    FILE *file = fopen(filename, "rb");
    unsigned char buffer[1024];
    size_t bytes;

    EVP_DigestInit_ex(mdctx, md, NULL);
    while ((bytes = fread(buffer, 1, sizeof(buffer), file)) != 0) {
        EVP_DigestUpdate(mdctx, buffer, bytes);
    }
    EVP_DigestFinal_ex(mdctx, hash, &hash_len);
    EVP_MD_CTX_free(mdctx);
    fclose(file);

    for (unsigned int i = 0; i < hash_len; i++) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
    output[hash_len * 2] = '\0';
}

int compare_files(const char *file1, const char *file2) {
    int fd1 = open(file1, O_RDONLY);
    int fd2 = open(file2, O_RDONLY);
    if (fd1 == -1 || fd2 == -1) {
        perror("Error opening files for comparison");
        exit(1);
    }

    unsigned char buf1[4096], buf2[4096];
    ssize_t n1, n2;
    int result = 1;

    while ((n1 = read(fd1, buf1, sizeof(buf1))) > 0 && (n2 = read(fd2, buf2, sizeof(buf2))) > 0) {
        if (n1 != n2 || memcmp(buf1, buf2, n1) != 0) {
            result = 0;
            break;
        }
    }

    close(fd1);
    close(fd2);
    return result;
}

void get_files(const char *directory, const char *extension, int reverse, FileItem **files, int *file_count) {
    DIR *dir;
    struct dirent *entry;

    if ((dir = opendir(directory)) == NULL) {
        perror("opendir");
        return;
    }

    if (debug) { printf("Getting files from: %s\n", dir); }

    while ((entry = readdir(dir)) != NULL) {
        // Skip the current and parent directory entries
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        // Construct full path for the file
        char full_path[PATH_MAX];
        snprintf(full_path, sizeof(full_path), "%s/%s", directory, entry->d_name);

        // Check if it's a regular file
        if (entry->d_type == DT_REG) { 
            // Check for extension if specified
            if (extension == NULL || (strrchr(entry->d_name, '.') != NULL && strcmp(strrchr(entry->d_name, '.'), extension) == 0)) {

                // Get file size
		struct stat file_stat;
		long filesize = -1;
                if (stat(full_path, &file_stat) == 0) {
                    filesize = file_stat.st_size;
		}

		// Add to the file list
                FileItem item;
                snprintf(item.filename, sizeof(item.filename), "%s", entry->d_name);
                snprintf(item.path, sizeof(item.path), "%s/%s", directory, entry->d_name);
                item.size = filesize;

		if (debug) { printf("Found file: %s\n", item.filename); }

		// Calculate the hash of the file
                // calculate_hash(full_path, item.hash);
                
		// printf("Adding to index %d...\n", *file_count);
                (*files)[*file_count] = item;  // Add item to files array
                (*file_count)++;
                // printf("Added.\n");
            }
        } else if (entry->d_type == DT_DIR && reverse) { // If it's a directory and reverse is enabled
            get_files(full_path, extension, reverse, files, file_count); // Recursively get files
        }
    }

    closedir(dir);
}


void find_duplicates(FileItem *files, int compare_bytes, int file_count) {
    for (int i = 0; i < file_count; ++i) {
        for (int j = i + 1; j < file_count; ++j) {
            // Verhindert den Vergleich von Datei A mit Datei A
            if (strcmp(files[i].filename, files[j].filename) == 0) continue;

            // Vergleiche die Größe der Dateien
            if (files[i].size != files[j].size) continue;

            if (debug) { printf("Calculating hash for file size duplicates [%lld bytes]:\n- %s\n- %s\n", (long long) files[i].size, files[i].path, files[j].path); }
	    
	    // calc hash
            calculate_hash(files[i].path, files[i].hash);
            calculate_hash(files[j].path, files[j].hash);

            if (debug) { printf("Hash:\n- %s\n- %s\n", files[i].hash, files[j].hash); }

            // Vergleiche die Hash-Werte der Dateien
            if (memcmp(files[i].hash, files[j].hash, HASH_SIZE) == 0) {
                
               if (!compare_bytes) {
                  printf("Found Hash Dupe:\n	%s\n	%s\n", files[i].path, files[j].path);
                  continue;
               }

	       // Führe einen Byte-für-Byte-Vergleich durch
               if (compare_files(files[i].path, files[j].path)) {
                  printf("Found Binary Dupe:\n	%s\n	%s\n", files[i].path, files[j].path);
               }
            }
        }
    }
}

int main(int argc, char *argv[]) {
    printf("dupefiles 0.2 (c) 2024 by dahead\n");

    if (argc < 2) {
        fprintf(stderr, "Usage: %s /path/to/scan [--recursive] [--compare_bytes] [--filter <extension>]\n", argv[0]);
        exit(1);
    }

    int file_count = 0;
    const char *dir_path = argv[1];
    int recursive = 0;
    int compare_bytes = 0;
    const char *filter = NULL;

    for (int i = 2; i < argc; ++i) {
        if (strcmp(argv[i], "--recursive") == 0) {
            recursive = 1;
        } else if (strcmp(argv[i], "--filter") == 0 && i + 1 < argc) {
            filter = argv[++i];  // Get the extension filter
	} else if (strcmp(argv[i], "--compare_bytes") == 0) {
            compare_bytes = 1; // Enable byte comparison
        } else if (strcmp(argv[i], "--debug") == 0) {
	    debug = 1;
	    printf("Debug on\n");
	}
    }

    // Allocate memory for files
    FileItem *files = malloc(sizeof(FileItem) * MAX_FILES);
    if (files == NULL) {
        perror("Failed to allocate memory for files");
        exit(1);
    }

    if (debug) { printf("Scanning directory %s\n", dir_path); }
    // printf("Scanning dir %s\n", dir_path);

    // Call get_files with the specified arguments
    get_files(dir_path, filter, recursive, &files, &file_count);

    // Optional: output file list for debugging
    // if (debug) {
    //    for (int i = 0; i < file_count; i++) {
    //       printf("- %d: %s (%s)\n", i + 1, files[i].path, files[i].filename);
    //    }
    //}

    // Call find_duplicates to find and print duplicate files
    find_duplicates(files, compare_bytes, file_count);

    // close
    free(files); // Free dynamically allocated memory
    return 0;
}
