#include <correct.h>
#include <stdio.h>
#include <string.h>


// Not a very robust test, can make it better if required

// Note the output comes out weird because of unicode stuff I think

// gcc -o rstest.exe rstest.c -L/usr/local/lib -I/usr/local/include -lcorrect 
// to run with libcorrect installed
int main() {
    // Create RS encryption
    correct_reed_solomon* rs = correct_reed_solomon_create(correct_rs_primitive_polynomial_ccsds, 1, 1, 32);
    
    // message to encrypt
    const uint8_t msg[223] = "Hello, I am Richard";
    size_t msg_len = strlen(msg);

    printf("Initial Message: %s \n", msg);

    // pointer that will eventually hold the printed message
    uint8_t encoded[255] = ".";

    ssize_t n = correct_reed_solomon_encode(rs, msg, msg_len, encoded);

    printf("Encoded: %s \n", encoded);
    printf("Length of encoded message: %lu \n", n); // The message should be padded automatically to have length 255 (?)

    // simple corruption of two characters in the message
    encoded[1] = 'F';
    encoded[2] = 'a';

    printf("Changed message: %s \n", encoded);

    // pointer that will eventually hold the recovered message
    uint8_t recovered[255] = ".";

    ssize_t b = correct_reed_solomon_decode(rs, encoded, n, recovered);
    
    // correct_reed_solomon_decode returns -1 if there are too many corruptions for the message to be decoded
    if (b == -1) {
        printf("Was not able to retrieve message");
    }
    else {
        printf("Recovered message: %s \n", recovered);
    }
    return 0;
}