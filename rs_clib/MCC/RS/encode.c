#include "../libcorrect/include/correct.h"
#include <stdio.h>
#include <string.h>


int main() {
    // Create RS encryption
    correct_reed_solomon* rs = correct_reed_solomon_create(correct_rs_primitive_polynomial_ccsds, 1, 1, 32);
    
    // message to encrypt

    uint8_t msg[223] = ".";

    FILE *ptr;
    ptr = fopen("to_encode.bin","rb");  // r for read, b for binary
    fread(msg,sizeof(msg),1,ptr);

    size_t msg_len = strlen((char *) msg);

    printf("Initial Message: %s \n", msg);

    uint8_t encoded[255] = ".";

   size_t p = strlen((char *) msg);
    //printf("Length of encoded message: %lu \n", p);

    ssize_t n = correct_reed_solomon_encode(rs, msg, msg_len, encoded);

     encoded[3] = 'a';
     encoded[6] = 'p';
     printf("Corrupted Message: %s \n", encoded);


    FILE *write_ptr;
    write_ptr = fopen("../../send_receive.bin","wb");  // w for write, b for binary
    fwrite(encoded,sizeof(encoded),1,write_ptr); // 

    printf("Encoded: %s \n", encoded);
    
    return 0;
}