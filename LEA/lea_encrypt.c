#include "src/lea.h"
#include "src/lea_locl.h"

#include "benchmark.h"
#include "lea_benchmark.h"
#include "lea_vs.h"

#include <openssl/modes.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <time.h>

#define KEY_SIZE 16
#define IV_SIZE 12
#define AAD_SIZE 16
#define TAG_SIZE 16
#define MAX_PATH_LEN 1024

static struct timespec start, end;
static uint64_t wal_time_tick;

static inline void INIT_WALL_TIME(void)
{
	wal_time_tick = 0;
}

static inline void START_WALL_TIME(void)
{
	clock_gettime(CLOCK_REALTIME, &start);
}

static inline void END_WALL_TIME(void)
{
	long seconds;
	long nanoseconds;

	clock_gettime(CLOCK_REALTIME, &end);

	seconds = end.tv_sec - start.tv_sec;
	nanoseconds = end.tv_nsec - start.tv_nsec;

	wal_time_tick += ((uint64_t)seconds *(uint64_t)(1e+9) + (uint64_t)nanoseconds);
}

int main(void)
{
	int counter = 0;
	unsigned int calibration, tMin = 0xFFFFFFFF, start, end, entire_size = 0;
	float ret = 0;
	calibration = calibrate();
	INIT_WALL_TIME();

	unsigned char gcm_key[KEY_SIZE];
	unsigned char gcm_iv[IV_SIZE];
	unsigned char gcm_aad[AAD_SIZE];
	unsigned char gcm_tag[TAG_SIZE];

	FILE *key_file = fopen("../init/gcm_key.txt", "rb");
	if (key_file == NULL) {
		perror("Error opening key file");
		exit(EXIT_FAILURE);
	}
	fread(gcm_key, 1, KEY_SIZE, key_file);
	fclose(key_file);

	FILE *iv_file = fopen("../init/gcm_iv.txt", "rb");
	if (iv_file == NULL) {
		perror("Error opening IV file");
		exit(EXIT_FAILURE);
	}
	fread(gcm_iv, 1, IV_SIZE, iv_file);
	fclose(iv_file);

	FILE *aad_file = fopen("../init/gcm_aad.txt", "rb");
	if (aad_file == NULL) {
		perror("Error opening AAD file");
		exit(EXIT_FAILURE);
	}
	fread(gcm_aad, 1, AAD_SIZE, aad_file);
	fclose(aad_file);

	const char *sample_path = "../dataset/sample";
	const char *encrypted_path = "../dataset/encrypted_file";

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

			START_WALL_TIME();

			// Encrypt data
			LEA_GCM_CTX gcm_ctx;
			lea_gcm_init(&gcm_ctx, gcm_key, KEY_SIZE);
			lea_gcm_set_ctr(&gcm_ctx, gcm_iv, IV_SIZE);
			lea_gcm_set_aad(&gcm_ctx, gcm_aad, AAD_SIZE);
			lea_gcm_enc(&gcm_ctx, encrypted_data, img_data, img_size);
			lea_gcm_final(&gcm_ctx, gcm_tag, TAG_SIZE);

			END_WALL_TIME();

			end = HiResTime();
			if (tMin > end - start - calibration)
				tMin = end - start - calibration;

			char encrypted_img_path[MAX_PATH_LEN];
            snprintf(encrypted_img_path, sizeof(encrypted_img_path), "%s/%s.enc", encrypted_path, strtok(ent->d_name, "."));

			FILE *fp = fopen(encrypted_img_path, "wb");
			if (fp == NULL) {
				perror("Error opening file");
				return EXIT_FAILURE;
			}
			fwrite(encrypted_data, sizeof(unsigned char), img_size, fp);
			fwrite(gcm_tag, sizeof(unsigned char), TAG_SIZE, fp);

			ret += get_cpb(tMin, img_size);
			entire_size += img_size;

			counter++;
			fclose(fp);
			free(img_data);
			free(encrypted_data);
		}
	}
	closedir(dir);

	double data_size = entire_size * 8;
	double walltime = wal_time_tick / 1e9;
	double Throughput =  data_size / walltime / 1e9;

	printf("========== LEA-128-GCM Encryption ==========\n");
	printf("[*] clocks/byte: %10.6f\n", ret/427);
	printf("[*] walltime:    %10.6lf\n", walltime);
	printf("[*] Throughput:  %10.6lf\n", Throughput);
	return 0;
}
