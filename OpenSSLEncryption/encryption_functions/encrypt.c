#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>


void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
        handleErrors();
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
        handleErrors();
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors();
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

void print_data(const char *title, const void* data, int len) { 
  printf("%s : ",title); 
  const unsigned char * p = (const unsigned char*)data; 
  for (int i = 0; i<len; ++i) 
    printf("%02X ", *p++); 
  printf("\n"); 
} 

void set_words(unsigned char *ciphertext, const char *hex, int len) { 
  // Convert hex string to character byte array
  for (int i = 0; i < len/2; ++i) {
    char c = hex[i*2];
    if (c >= '0' && c <= '9')
      c -= '0';
    else if (c >= 'a' && c <= 'f')
      c -= 'a' - 10;
    else if (c >= 'A' && c <= 'F')
      c -= 'A' - 10;
    else
      c = 0;
    ciphertext[i] = c << 4;
    c = hex[i*2+1];
    if (c >= '0' && c <= '9')
      c -= '0';
    else if (c >= 'a' && c <= 'f')
      c -= 'a' - 10;
    else if (c >= 'A' && c <= 'F')
      c -= 'A' - 10;
    else
      c = 0;
    ciphertext[i] |= c;
  }
} 

void decrypt_new_message(const char *encrypted_message, int len, unsigned char *key,
  unsigned char *iv, unsigned char *plaintext){
  unsigned char ciphertext[128];
  memset(ciphertext,'\0',128);
  set_words(ciphertext, encrypted_message, len);
  int length = decrypt(ciphertext, len / 2, key, iv, plaintext);
  plaintext[length] = '\0';
}

// int main (void)
// {
//     /* A 128 bit key */
//     unsigned char *KEY = (unsigned char *)"My 16 Bit key ad";
//     /* A 128 bit IV */
//     unsigned char *IV = (unsigned char *)"0000000000000000";
//     char *hex = "285090d1ede18f63a8702037e0ace67c";
//     int len = strlen(hex);
//     decrypt_new_message(hex,len,KEY,IV);
//     return 0;
// }