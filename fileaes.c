// clang fileaes.c aes256.c -o fileaes

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "aes256.h"

int encrypt(const char *file, const unsigned int **key) {
    FILE *fp = fopen(file, "r");
    if (!fp) {
        return 1;
    }
    
    unsigned char *data = NULL;
    int block_count = 1;
    char buffer[16];
    int bytes = 0;
    
    data = malloc(sizeof(unsigned) * 16);
    
    while ((bytes = fread(buffer, sizeof(char), 16, fp)) > 0) {
        block_count++;
        data = realloc(data, sizeof(unsigned char) * block_count * 16);
        
        if (bytes != 16) {
            memset(&buffer[bytes], 0x00, 16 - bytes);
            memcpy(&data[(block_count - 1) * 16], (unsigned char *)buffer, 16);
            break;
        }
        
        memcpy(&data[(block_count - 1) * 16], (unsigned char *)buffer, 16);
    }
    
    unsigned char head[8] = { 97, 110, 121, 97, 101, 115, 0, 0 };
    head[6] = bytes / 10;
    head[7] = bytes % 10;
    
    memcpy(data, head, 8);
    
    for (int i = 0; i < block_count; i++) {
        cipher256(&data[i * 16], &data[i * 16], key);
    }
    
    fclose(fp);
    fp = fopen(file, "w");
    if (!fp) {
        free(data);
        return 1;
    }
    
    if (fwrite((char *)data, sizeof(char), block_count * 16, fp) != block_count * 16) {
        free(data);
        fclose(fp);
        return 3;
    }
    
    fclose(fp);
    free(data);
    
    return 0;
}

int decrypt(const char *file, const unsigned int **key) {
    FILE *fp = fopen(file, "r");
    if (!fp) {
        return 1;
    }
    
    unsigned char *data = NULL;
    int block_count = 0;
    char buffer[16];
    int bytes = 0;
    
    fread(buffer, sizeof(char), 16, fp);
    data = malloc(sizeof(unsigned char) * 16);
    memcpy(data, (unsigned char *)buffer, 16);
    inv_cipher256(data, data, key);
    
    unsigned char head[6] = { 97, 110, 121, 97, 101, 115 };
    for (int i = 0; i < 6; i++)
        if (data[i] != head[i])
            return 2;
    
    bytes = 10 * data[6];
    bytes += data[7];
    
    while (fread(buffer, sizeof(char), 16, fp) > 0) {
        block_count++;
        data = realloc(data, sizeof(unsigned char) * block_count * 16);
        memcpy(&data[(block_count - 1) * 16], (unsigned char *)buffer, 16);
    }
    
    for (int i = 0; i < block_count; i++) {
        inv_cipher256(&data[i * 16], &data[i * 16], key);
    }
    
    fclose(fp);
    fp = fopen(file, "w");
    if (!fp) {
        free(data);
        return 1;
    }
    
    if (fwrite((char *)data, sizeof(char), block_count * 16 - (16 - bytes), fp) != block_count * 16 - (16 - bytes)) {
        free(data);
        fclose(fp);
        return 3;
    }
    
    fclose(fp);
    free(data);
    
    return 0;
}

int key(const unsigned char *key, unsigned int **w) {
    unsigned char tmp[32];
    if (strlen(key) == 32) {
        for (int i = 0; i < 32; i++) {
            tmp[i] = (unsigned char)key[i];
        }
    } else if (strlen(key) == 64) {
        for (int i = 0; i < 32; i++) {
            char hex[] = { '0', 'x', 0, 0, 0 };
            hex[2] = key[2 * i];
            hex[3] = key[2 * i + 1];
            tmp[i] = (unsigned char)strtol(hex, NULL, 16);
        }
    } else {
        return 4;
    }
    
    key_expansion256(tmp, w);
    
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        printf("%s [-e/-d] <file> <key (32 bytes)>\n", argv[0]);
        return 0;
    }
    
    unsigned int w[60];
    if (key(argv[3], &w)) {
        printf("Key error! Invalid key.\n");
        return 0;
    }
    
    int error = 0;
    
    if (strcmp(argv[1], "-e") == 0) {
        error = encrypt(argv[2], &w);
    } else if (strcmp(argv[1], "-d") == 0) {
        error = decrypt(argv[2], &w);
    } else {
        printf("operation not defined\n");
    }
    
    switch (error) {
        case 1:
            printf("File error! No changes made.\n");
            break;
            
        case 2:
            printf("Encryption error! Cannot decrypt.\n");
            break;
            
        case 3:
            printf("Write error!\n");
            break;
            
        default:
            break;
    }
    
    return 0;
}
