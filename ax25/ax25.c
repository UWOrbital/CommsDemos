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
#define AX25_SUPERVISORY_FRAME_LENGTH (AX25_TOTAL_FLAG_BYTES + \
                      AX25_ADDRESS_BYTES +  \
                      AX25_CONTROL_BYTES +  \
                      AX25_PID_BYTES +  \
                      AX25_FCS_BYTES)

#define AX25_FLAG 0x7EU
#define AX25_PID 0xF0U

/* Mock CubeSat callsign */
#define AX25_CUBESAT_CALLSIGN_BYTE_1 0xFFU
#define AX25_CUBESAT_CALLSIGN_BYTE_2 0xFFU
#define AX25_CUBESAT_CALLSIGN_BYTE_3 0xFFU
#define AX25_CUBESAT_CALLSIGN_BYTE_4 0xFFU
#define AX25_CUBESAT_CALLSIGN_BYTE_5 0xFFU
#define AX25_CUBESAT_CALLSIGN_BYTE_6 0xFFU
#define AX25_CUBESAT_CALLSIGN_BYTE_7 0xFFU
static uint8_t cubesatCallsign[AX25_DEST_ADDR_BYTES]= {AX25_CUBESAT_CALLSIGN_BYTE_1, \
                                                       AX25_CUBESAT_CALLSIGN_BYTE_2, \
                                                       AX25_CUBESAT_CALLSIGN_BYTE_3, \
                                                       AX25_CUBESAT_CALLSIGN_BYTE_4, \
                                                       AX25_CUBESAT_CALLSIGN_BYTE_5, \
                                                       AX25_CUBESAT_CALLSIGN_BYTE_6, \
                                                       AX25_CUBESAT_CALLSIGN_BYTE_7};

#define AX25_S_FRAME_RR_CONTROL 0x01U
#define AX25_S_FRAME_RNR_CONTROL 0x05U
#define AX25_S_FRAME_REJ_CONTROL 0x09U
#define AX25_S_FRAME_SREJ_CONTROL 0x0DU

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
    uint8_t data[AX25_MINIMUM_PKT_LEN];
    uint16_t length;
} unstuffed_ax25_packet_t

typedef struct {
    uint8_t data[RS_ENCODED_SIZE];
} packed_rs_packet_t;

static uint8_t pktSentNum = 1;
static uint8_t pktReceiveNum = 1;
static void ax25Unstuff(const packed_ax25_packet_t* packet, unstuffed_ax25_packet_t *unstuffedPacket);
static void sFrameRecv(unstuffed_ax25_packet_t *unstuffedPacket, packed_rs_packet_t *rsData);
static void iFrameRecv(unstuffed_ax25_packet_t *unstuffedPacket, packed_rs_packet_t *rsData);

typedef void (*s_frame_func_t)(uint8_t*);

static const s_frame_func_t sFrameResponseFns[] = {
    [AX25_S_FRAME_RR_CONTROL] = ax25HandleReceiveReady,
    [AX25_S_FRAME_RNR_CONTROL] = ax25HandleReceiveNotReady,
    [AX25_S_FRAME_REJ_CONTROL] = ax25HandleRejected,
    [AX25_S_FRAME_SREJ_CONTROL] = ax25HandleSelectiveReject
};

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
    unstuffed_ax25_packet_t unstuffedPacket;
    ax25Unstuff(&ax25Data, &unstuffedPacket);

    bool supervisoryFrameFlag = false

    if(unstuffedPacket->length == AX25_SUPERVISORY_FRAME_LENGTH){
        supervisoryFrameFlag = true;
    }
    else if (unstuffedPacket->length != AX25_MINIMUM_PKT_LEN){
        printf("Not a valid ax25 packet!");
        return; /* error code */
    }
    supervisoryFrameFlag ? (sFrameRecv(&unstuffedPacket, rsData)) : (iFrameRecv(&unstuffedPacket, rsData));
}


static void ax25Unstuff(const packed_ax25_packet_t* packet, unstuffed_ax25_packet_t* unstuffedPacket) {
    uint8_t bitCount = 0;
    uint8_t stuffingFlag = 0;
    uint16_t unstuffedLength = 0;

    // loop from second byte to second last byte since first and last are the flags
    for (uint16_t stuffedPacketIndex = 1; stuffedPacketIndex < packet->length - 1; ++stuffedPacketIndex) {
        uint8_t current_byte = packet->data[stuffedPacketIndex];

        for (uint8_t offset = 0; offset < 8; ++offset) {
            uint8_t bit = (current_byte >> (7 - offset)) & 0x01;

            if (stuffingFlag) {
                bitCount = 0;
                stuffingFlag = 0;
                continue;  // Skip adding the stuffed bit
            }
            if (bit == 1) {
                bitCount++;
                if (bitCount == 5) {
                    bitCount = 0;
                    stuffingFlag = 1;
                }
            }
            else {
                bitCount = 0;
            }
            unstuffedPacket.data[unstuffedLength / 8] |= bit << (7 - (unstuffedLength % 8));
            unstuffedLength++;
        }
    }
    unstuffedPacket->length = unstuffedLength;
}

static void iFrameRecv(unstuffed_ax25_packet_t *unstuffedPacket, packed_rs_packet_t *rsData){
    for(uint8_t i = 0; i < AX25_DEST_ADDR_BYTES; ++i){
        if(unstuffedPacket[i + AX25_TOTAL_FLAG_BYTES/2] != cubesatCallsign[i]){
            printf("invalid destination address");
            return; /* error code on OBC */
        }
    }
    // first control byte will be the yte after the flag and the address bytes
    // next control byte will be immediately after the previous one
    // See AX.25 standard
    uint8_t controlBytes[AX25_CONTROL_BYTES] = {unstuffedPacket->data[AX25_ADDRESS_BYTES + 1], \
                                                unstuffedPacket->data[AX25_ADDRESS_BYTES + 2]}
    if(controlBytes[0] & 0x01){
        printf("invalid control field");
        return; /* error code on OBC */
    }
    if((controlBytes[0] >> 1) != pktReceiveNum){
        // TODO: implement retransmission requests
    }
    if(cotrolBytes[1] & 0x01){
        // TODO: implement retransmissions
    }
    if((controlBytes[1] >> 1) != pktSendNum){
        // TODO: implement retransmissions
    }
    
    if(unstuffedPacket[AX25_CONTROL_BYTES + AX25_ADDRESS_BYTES + 1] != AX25_PID){
        printf("wrong PID");
        return; /* error code on OBC */
    }
    memcpy(rsData->data, unstuffedPacket + AX25_PID_BYTES + AX25_CONTROL_BYTES + AX25_ADDRESS_BYTES + 1, AX25_INFO_BYTES);

    // Check FCS
}

static void sFrameRecv(unstuffed_ax25_packet_t *unstuffedPacket, packed_rs_packet_t *rsData){
    for(uint8_t i = 0; i < AX25_DEST_ADDR_BYTES; ++i){
        if(unstuffedPacket[i + AX25_TOTAL_FLAG_BYTES/2] != cubesatCallsign[i]){
            printf("invalid destination address");
            return; /* error code on OBC */
        }
    }
    uint8_t controlBytes[AX25_CONTROL_BYTES] = {unstuffedPacket->data[AX25_ADDRESS_BYTES + 1], \
                                                unstuffedPacket->data[AX25_ADDRESS_BYTES + 2]}
    sFrameResponseFns[controlBytes[0]](controlBytes);
}