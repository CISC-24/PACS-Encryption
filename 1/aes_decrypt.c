/*
 * Copyright 2012-2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Simple AES GCM authenticated encryption with additional data (AEAD)
 * demonstration program.
 */

#include "benchmark.h"
#include "benchmark.c"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#define KEY_SIZE 32
#define IV_SIZE 12
#define AAD_SIZE 16
#define TAG_SIZE 16
#define MAX_PATH_LEN 1024

static inline uint64_t cpucycles(void) {
    uint64_t hi, lo;
    __asm__ __volatile__ ("CPUID\n\trdtsc\n\t" : "=a" (lo), "=d"(hi));
    return ((uint64_t)lo) | (((uint64_t)hi) << 32);
}

int main() {
    //uint64_t start = 0, end = 0, ret = 0;

	unsigned int calibration, tMin = 0xFFFFFFFF, start, end, ret = 0, entire_size = 0;
	calibration = calibrate();
    
    unsigned char gcm_key[KEY_SIZE];
    unsigned char gcm_iv[IV_SIZE];
    unsigned char gcm_aad[AAD_SIZE];
    unsigned char gcm_tag[TAG_SIZE];
    long pt_size;
    int len = 0;

    FILE *key_file = fopen("/home/misc/paper/gcm_key.txt", "rb");
    if (key_file == NULL) {
        perror("Error opening key file");
        return EXIT_FAILURE;
    }
    fread(gcm_key, 1, KEY_SIZE, key_file);
    fclose(key_file);

    FILE *iv_file = fopen("/home/misc/paper/gcm_iv.txt", "rb");
    if (iv_file == NULL) {
        perror("Error opening IV file");
        return EXIT_FAILURE;
    }
    fread(gcm_iv, 1, IV_SIZE, iv_file);
    fclose(iv_file);
    
    FILE *aad_file = fopen("/home/misc/paper/gcm_aad.txt", "rb");
    if (aad_file == NULL) {
        perror("Error opening AAD file");
        return EXIT_FAILURE;
    }
    fread(gcm_aad, 1, AAD_SIZE, aad_file);
    fclose(aad_file);

    const char *encrypted_path = "/home/misc/paper/img_crypto";
    const char *decrypted_path = "/home/misc/paper/img_decrypto";

    DIR *dir = opendir(encrypted_path);
    if (dir == NULL) {
        perror("Error opening directory");
        return EXIT_FAILURE;
    }

    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        if (strcmp(strrchr(ent->d_name, '.'), ".enc") == 0) {
            int ret1 = 0;
            char enc_img_path[MAX_PATH_LEN];
            snprintf(enc_img_path, sizeof(enc_img_path), "%s/%s", encrypted_path, ent->d_name);

            FILE *enc_img_file = fopen(enc_img_path, "rb");
            if (enc_img_file == NULL) {
                perror("Error opening image file");
                continue;
            }
            
            fseek(enc_img_file, 0, SEEK_END);
            long img_size = ftell(enc_img_file);
            fseek(enc_img_file, 0, SEEK_SET);

            unsigned char *enc_img_data = (unsigned char *)malloc(img_size);
            if (enc_img_data == NULL) {
                perror("Error allocating memory");
                fclose(enc_img_file);
                continue;
            }
            if (fread(enc_img_data, 1, img_size, enc_img_file) != img_size) {
                perror("Error reading image data");
                free(enc_img_data);
                fclose(enc_img_file);
                continue;
            }
            fclose(enc_img_file);

            unsigned char *decrypted_data = (unsigned char *)malloc(img_size);
            if (decrypted_data == NULL) {
                perror("Error allocating memory");
                free(enc_img_data);
                continue;
            }
            memcpy(gcm_tag, enc_img_data + img_size - TAG_SIZE, TAG_SIZE);

			tMin = 0xFFFFFFFF;
			start = HiResTime();
            //start = cpucycles();
            /*복호화 시작*/
            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            if (ctx == NULL) {
                ERR_print_errors_fp(stderr);
                free(enc_img_data);
                free(decrypted_data);
                closedir(dir);
                return EXIT_FAILURE;
            }

            if (!EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, gcm_key, gcm_iv)) {
                ERR_print_errors_fp(stderr);
                free(enc_img_data);
                free(decrypted_data);
                EVP_CIPHER_CTX_free(ctx);
                closedir(dir);
                return EXIT_FAILURE;
            }

            if (!EVP_DecryptUpdate(ctx, NULL, &len, gcm_aad, AAD_SIZE)) {
                ERR_print_errors_fp(stderr);
                free(enc_img_data);
                free(decrypted_data);
                EVP_CIPHER_CTX_free(ctx);
                closedir(dir);
                return EXIT_FAILURE;
            }

            if (!EVP_DecryptUpdate(ctx, decrypted_data, &len, enc_img_data, img_size - TAG_SIZE)) {
                ERR_print_errors_fp(stderr);
                free(enc_img_data);
                free(decrypted_data);
                EVP_CIPHER_CTX_free(ctx);
                closedir(dir);
                return EXIT_FAILURE;
            }

            pt_size = len;

            if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, TAG_SIZE, gcm_tag)) {
                ERR_print_errors_fp(stderr);
                free(enc_img_data);
                free(decrypted_data);
                EVP_CIPHER_CTX_free(ctx);
                closedir(dir);
                return EXIT_FAILURE;
            }

            ret1 = EVP_DecryptFinal_ex(ctx, decrypted_data + len, &len);
            if(ret1 > 0)
                pt_size +=len;
            else{
                ERR_print_errors_fp(stderr);
                free(enc_img_data);
                free(decrypted_data);
                EVP_CIPHER_CTX_free(ctx);
                closedir(dir);
                return EXIT_FAILURE;
            }

            EVP_CIPHER_CTX_free(ctx);
            // end = cpucycles();
            // ret += end-start;
            /*복호화 끝*/
            end = HiResTime();
            if (tMin > end - start - calibration)       /* keep only the minimum time */
			tMin = end - start - calibration;
            
            char dec_img_path[MAX_PATH_LEN];
            snprintf(dec_img_path, sizeof(dec_img_path), "%s/%s.dcm", decrypted_path, strtok(ent->d_name, "."));

            FILE *fp = fopen(dec_img_path, "wb");
            if (fp == NULL) {
                perror("Error opening file");
                return EXIT_FAILURE;
            }
            fwrite(decrypted_data, 1, pt_size, fp);

            printf("[%d] %7.2f cycles/byte %ld\n", KEY_SIZE, get_cpb(tMin, img_size - TAG_SIZE), img_size - TAG_SIZE);
            ret += get_cpb(tMin, img_size);
            entire_size +=img_size-TAG_SIZE;
            fclose(fp);
            free(enc_img_data);
            free(decrypted_data);
        }
    }
    closedir(dir);

	printf("[%d] %7.2f cycles/byte\n", KEY_SIZE, get_cpb(tMin, entire_size));
	printf("finish. %d\n", tMin);
	printf("finish. %d\n", ret);

    return 0;
}