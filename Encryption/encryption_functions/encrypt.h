#ifndef ENCRYPT_H   /* Include guard */
#define ENCRYPT_H

void decrypt_new_message(const char *encrypted_message, int len, unsigned char *key,
  unsigned char *iv, unsigned char *plaintext);

#endif // ENCRYPT_H