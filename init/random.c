// gcc -o random random.c -lssl -lcrypto

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>

#define KEY_SIZE 16
#define IV_SIZE 12
#define AAD_SIZE 16
#define TAG_SIZE 16


void saveToFile(const char *filename, const unsigned char *data, size_t len) {
    FILE *fp = fopen(filename, "wb");
    if (fp == NULL) {
        perror("Error opening file");
        exit(EXIT_FAILURE);
    }
    fwrite(data, sizeof(unsigned char), len, fp);
    fclose(fp);
}


int main(){
    unsigned char gcm_key[KEY_SIZE];
    unsigned char gcm_iv[IV_SIZE];
    unsigned char gcm_aad[AAD_SIZE];

    // Generate AES gcm_key and IV
    if (RAND_bytes(gcm_key, sizeof(gcm_key)) != 1 || RAND_bytes(gcm_iv, sizeof(gcm_iv)) != 1 || RAND_bytes(gcm_aad, sizeof(gcm_aad)) != 1) {
        fprintf(stderr, "Error generating random bytes\n");
        exit(EXIT_FAILURE);
    }

    // Save key and IV to files
    saveToFile("./gcm_key.txt", gcm_key, sizeof(gcm_key));
    saveToFile("./gcm_iv.txt", gcm_iv, sizeof(gcm_iv));
    saveToFile("./gcm_aad.txt", gcm_aad, sizeof(gcm_aad));
    printf("key : ");
    for(int i=0;i<KEY_SIZE;i++){
        printf("%x",gcm_key[i]);
    }printf("\n");
    printf("iv : ");
    for(int i=0;i<IV_SIZE;i++){
        printf("%x",gcm_iv[i]);
    }printf("\n");
    printf("aad : ");
    for(int i=0;i<AAD_SIZE;i++){
        printf("%x",gcm_aad[i]);
    }printf("\n");

    return 0;
}
