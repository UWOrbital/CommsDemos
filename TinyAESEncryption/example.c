// To build, gcc example.c aes.c -o example

#include "aes.h"
#include <stdio.h>
#include <string.h>

int main() {
    char msg[] = "Hello world, this is an encrypted message.......";
    printf("PLAINTEXT: %s\n", msg);
    char key[] = "1234567812345678";
    char iv[] = "abcdefghabcdefgh";
    
    printf("\n\nEncrypting...\n");

    // Initialize context
    struct AES_ctx encCtx;
    AES_init_ctx_iv(&encCtx, key, iv);
    
    // Encrypt
    AES_CTR_xcrypt_buffer(&encCtx, msg, strlen(msg));
    printf("CIPHERTEXT: %s\n", msg);

    printf("\n\nDecrypting...\n");

    // Initialize context
    struct AES_ctx decCtx;
    AES_init_ctx_iv(&decCtx, key, iv);

    // Decrypt
    AES_CTR_xcrypt_buffer(&decCtx, msg, 48);
    printf("PLAINTEXT: %s\n", msg);

    return 0;
}
