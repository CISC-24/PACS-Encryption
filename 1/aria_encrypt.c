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

static uint64_t cpucycles(void) {
    uint64_t hi, lo;
    __asm__ __volatile__ ("CPUID\n\trdtsc\n\t" : "=a" (lo), "=d"(hi));
    return ((uint64_t)lo) | (((uint64_t)hi) << 32);
}

int main() {
    //uint64_t start = 0, end = 0, ret = 0;
    int counter = 1;
	unsigned int calibration, tMin = 0xFFFFFFFF, start, end, entire_size = 0;
    float ret = 0;
	calibration = calibrate();

    unsigned char gcm_key[KEY_SIZE];
    unsigned char gcm_iv[IV_SIZE];
    unsigned char gcm_aad[AAD_SIZE];
    unsigned char gcm_tag[TAG_SIZE];
    long ct_size;
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

    const char *sample_path = "/home/misc/paper/sample";
    const char *encrypted_path = "/home/misc/paper/img_crypto";

    DIR *dir = opendir(sample_path);
    if (dir == NULL) {
        perror("Error opening directory");
        return EXIT_FAILURE;
    }

    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        if (strcmp(strrchr(ent->d_name, '.'), ".dcm") == 0) {
            char img_path[MAX_PATH_LEN];
            snprintf(img_path, sizeof(img_path), "%s/%s", sample_path, ent->d_name);

            FILE *img_file = fopen(img_path, "rb");
            if (img_file == NULL) {
                perror("Error opening image file");
                continue;
            }

            fseek(img_file, 0, SEEK_END);
            long img_size = ftell(img_file);
            fseek(img_file, 0, SEEK_SET);
            
            unsigned char *img_data = (unsigned char *)malloc(img_size);
            if (img_data == NULL) {
                perror("Error allocating memory");
                fclose(img_file);
                continue;
            }
            if (fread(img_data, 1, img_size, img_file) != img_size) {
                perror("Error reading image data");
                free(img_data);
                fclose(img_file);
                continue;
            }
            fclose(img_file);

            unsigned char *encrypted_data = (unsigned char *)malloc(img_size + TAG_SIZE);
            if (encrypted_data == NULL) {
                perror("Error allocating memory");
                free(img_data);
                continue;
            }

			tMin = 0xFFFFFFFF;
			start = HiResTime();
            //start = cpucycles();
            /*암호화 시작*/
            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            if (ctx == NULL) {
                ERR_print_errors_fp(stderr);
                free(img_data);
                free(encrypted_data);
                closedir(dir);
                return EXIT_FAILURE;
            }

            if (!EVP_EncryptInit_ex(ctx, EVP_aria_128_gcm(), NULL, gcm_key, gcm_iv)) {
                ERR_print_errors_fp(stderr);
                free(img_data);
                free(encrypted_data);
                EVP_CIPHER_CTX_free(ctx);
                closedir(dir);
                return EXIT_FAILURE;
            }

            if (!EVP_EncryptUpdate(ctx, NULL, &len, gcm_aad, AAD_SIZE)) {
                ERR_print_errors_fp(stderr);
                free(img_data);
                free(encrypted_data);
                EVP_CIPHER_CTX_free(ctx);
                closedir(dir);
                return EXIT_FAILURE;
            }


            if (!EVP_EncryptUpdate(ctx, encrypted_data, &len, img_data, img_size)) {
                ERR_print_errors_fp(stderr);
                free(img_data);
                free(encrypted_data);
                EVP_CIPHER_CTX_free(ctx);
                closedir(dir);
                return EXIT_FAILURE;
            }

            ct_size = len;

            if (!EVP_EncryptFinal_ex(ctx, encrypted_data + len, &len)) {
                ERR_print_errors_fp(stderr);
                free(img_data);
                free(encrypted_data);
                EVP_CIPHER_CTX_free(ctx);
                closedir(dir);
                return EXIT_FAILURE;
            }

            ct_size += len;

            if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, TAG_SIZE, gcm_tag)) {
                ERR_print_errors_fp(stderr);
                free(img_data);
                free(encrypted_data);
                EVP_CIPHER_CTX_free(ctx);
                closedir(dir);
                return EXIT_FAILURE;
            }

            EVP_CIPHER_CTX_free(ctx);
            // end = cpucycles();
            // ret += end-start;
            /*암호화 끝*/
            end = HiResTime();
            if (tMin > end - start - calibration)       /* keep only the minimum time */
			tMin = end - start - calibration;

            char encrypted_img_path[MAX_PATH_LEN];
            snprintf(encrypted_img_path, sizeof(encrypted_img_path), "%s/%s.enc", encrypted_path, strtok(ent->d_name, "."));

            FILE *fp = fopen(encrypted_img_path, "wb");
            if (fp == NULL) {
                perror("Error opening file");
                return EXIT_FAILURE;
            }
            fwrite(encrypted_data, 1, ct_size, fp);
            fwrite(gcm_tag, 1, TAG_SIZE, fp);

            if(counter <=0){
                printf("[%d] %7.2f cycles/byte %ld\n", KEY_SIZE, get_cpb(tMin, img_size), img_size);
                ret += get_cpb(tMin, img_size);
                entire_size +=img_size;

            }
            counter--;
            fclose(fp);
            free(img_data);
            free(encrypted_data);
        }
    }
    closedir(dir);

	printf("[%d] %7.2f cycles/byte\n", KEY_SIZE, get_cpb(tMin, entire_size));
	printf("finish. %d\n", tMin);
	printf("finish. %.2f\n", ret/(-counter+1));
    printf("%d\n",-counter+1);
    return 0;
}