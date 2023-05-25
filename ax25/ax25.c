#include <stdint.h>

#define AX25_TOTAL_FLAG_BYTES 2
#define AX25_SRC_ADDR_BYTES 7
#define AX25_DEST_ADDR_BYTES 7
#define AX25_ADDRESS_BYTES (AX25_SRC_ADDR_BYTES + AX25_DEST_ADDR_BYTES)
#define AX25_CONTROL_BYTES 2
#define AX25_PID_BYTES 1
#define AX25_FCS_BYTES 2
#define AX25_INFO_BYTES 255
#define AX25_MINIMUM_PKT_LEN (AX25_TOTAL_FLAG_BYTES + \
                      AX25_ADDRESS_BYTES +  \
                      AX25_CONTROL_BYTES +  \
                      AX25_PID_BYTES +  \
                      AX25_FCS_BYTES +  \
                      AX25_INFO_BYTES)
#define AX25_MAXIMUM_PKT_LEN AX25_MINIMUM_PKT_LEN*6/5 + 1

#define AX25_FLAG 0x7EU
#define AX25_PID 0xF0U

typedef struct {
    uint8_t flagStart;
    uint8_t flagEnd;
    uint8_t destination[AX25_DEST_ADDR_BYTES];
    uint8_t source[AX25_SRC_ADDR_BYTES];
    uint8_t control;
    uint8_t pid;
    uint8_t data[AX25_INFO_BYTES];
    uint16_t fcs;
} ax25_packet_t;

typedef struct {
    uint8_t data[AX25_MAXIMUM_PKT_LEN];
    uint16_t length;
} packed_ax25_packet_t;

typedef struct {
    uint8_t data[RS_ENCODED_SIZE];
} packed_rs_packet_t;

static uint8_t pktCount = 1;

/**
 * @brief strips away the ax.25 headers from a received packet
 * 
 * @param ax25Data the received ax.25 frame
 * @param rsData 255 byte array to store the reed solomon encoded data without ax.25 headers
 *
 * @return obc_error_code_t - whether or not the ax.25 headers were successfully stripped
*/
void ax25Recv(packed_ax25_packet_t *ax25Data, packed_rs_packet_t *rsData);

void ax25Recv(packed_ax25_packet_t *ax25Data, packed_rs_packet_t *rsData){
    if(ax25Data == NULL){
        return; /* error code on obc*/
    }
    if(rsData == NULL){
        return; /* error code on obc*/
    }
    if(ax25Data.length > AX25_MAXIMUM_PKT_LEN)){
        return; /* error code on obc*/
    }
    // check to make sure that the data starts and ends with a valid flag
    if((ax25Data.data[0] != AX25_FLAG) || (ax25Data.data[ax25Data.length - 1] != AX25_FLAG)){
        return; /* error code on obc */
    }
    // perform bit unstuffing

}


void ax25_unstuff(const packed_ax25_packet_t* packet, packed_ax25_packet_t unstuffed_packet) {
    uint8_t bit_count = 0;
    uint8_t stuffing_flag = 0;
    uint16_t unstuffed_length = 0;
    uint16_t i;

    for (i = 0; i < packet->length; i++) {
        uint8_t current_byte = packet->data[i];
        uint8_t j;

        for (j = 0; j < 8; j++) {
            uint8_t bit = (current_byte >> (7 - j)) & 0x01;

            if (stuffing_flag) {
                bit_count++;
                if (bit_count == 5) {
                    bit_count = 0;
                    stuffing_flag = 0;
                    continue;  // Skip adding the stuffed bit
                }
            }
            else if (bit == 1) {
                bit_count++;
                if (bit_count == 5) {
                    bit_count = 0;
                    stuffing_flag = 1;
                    continue;  // Skip adding the stuffed bit
                }
            }

            unstuffed_packet.data[unstuffed_length / 8] |= bit << (7 - (unstuffed_length % 8));
            unstuffed_length++;
        }
    }

    unstuffed_packet.length = unstuffed_length / 8;
    if (unstuffed_length % 8 != 0)
        unstuffed_packet.length++;
}