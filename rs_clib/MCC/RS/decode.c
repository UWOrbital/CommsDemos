#include "../libcorrect/include/correct.h"
#include <stdio.h>
#include <string.h>


int main() {
    // Create RS encryption
    correct_reed_solomon* rs = correct_reed_solomon_create(correct_rs_primitive_polynomial_ccsds, 1, 1, 32);
    
    uint8_t encoded[255] = ".";

    FILE *ptr;

    ptr = fopen("../../send_receive.bin","rb");  // r for read, b for binary

    fread(encoded,sizeof(encoded),1,ptr); // read 10 bytes to our buffer
    // pointer that will eventually hold the printed message

    printf("Encoded: %s \n", encoded);

    uint8_t recovered[255] = ".";
    ssize_t b = correct_reed_solomon_decode(rs, encoded, 255, recovered);
 
    // correct_reed_solomon_decode returns -1 if there are too many corruptions for the message to be decoded
    if (b == -1) {
        printf("Was not able to retrieve message");
    }
    else {
        printf("Recovered message: %s \n", recovered);// 
        
        //for (int i = msg_len; i < 255 - msg_len; i++){
            //recovered[i] = '\0';
        //}
        FILE *decoded;
        decoded = fopen("decoded.bin","wb");  // w for write, b for binary
        fwrite(recovered,sizeof(recovered),1,decoded); 
    }
    return 0;
}