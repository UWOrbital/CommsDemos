#include <stdio.h>
#include <stdint.h>
#include <string.h>

// does this look right? i am not sure what other errors there would be
enum ErrorCode { 
    SUCCESS = 0,
    FILE_NOT_FOUND
};

enum ErrorCode send_telemetry(char filename[]);
void rs_encode(char buffer[]); 

int main() {
    send_telemetry("test.txt");
    return 0;
}


// TODO: add other errors to be caught
enum ErrorCode send_telemetry(char filename[]) { 

    const int rs_size = 223;

    FILE *fp = fopen(filename, "r"); 
    
    if (!fp) {
        return FILE_NOT_FOUND;
    }

    uint8_t buffer[rs_size];
    
    size_t r = fread(buffer, 1, rs_size, fp);

    while (r == rs_size) {
        rs_encode(buffer);
        r = fread(buffer, 1, rs_size, fp); 
        printf("%s\n", buffer);

    }

    if (r != 0) {
        memset(buffer + r, ' ', rs_size - r); // use 222 instead of rs_size? not sure why https://stackoverflow.com/a/33689388 
                                              // https://stackoverflow.com/questions/33689274/how-to-fill-a-char-array-in-c/33689388#33689388
        rs_encode(buffer);
    } 

    // free buffer? https://stackoverflow.com/questions/39690836/understanding-free-buffer-before-return-statement

    return SUCCESS;
}

// used for testing only
void rs_encode(char buffer[]) { 
    printf("read: %s\n", buffer);
}