#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
// for testing purposes only
#include <string.h>

#define AX25_START_FLAG_BYTES 1
#define AX25_END_FLAG_BYTES 1
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

#define RS_ENCODED_SIZE AX25_INFO_BYTES
#define AX25_FLAG 0xFEU
#define AX25_PID 0xF0U

/* Mock CubeSat callsign */
#define AX25_CUBESAT_CALLSIGN_BYTE_1 0xFFU
#define AX25_CUBESAT_CALLSIGN_BYTE_2 0xFFU
#define AX25_CUBESAT_CALLSIGN_BYTE_3 0xFFU
#define AX25_CUBESAT_CALLSIGN_BYTE_4 0xFFU
#define AX25_CUBESAT_CALLSIGN_BYTE_5 0xFFU
#define AX25_CUBESAT_CALLSIGN_BYTE_6 0xFFU
#define AX25_CUBESAT_CALLSIGN_BYTE_7 0xFFU
static const uint8_t cubesatCallsign[AX25_DEST_ADDR_BYTES]= {AX25_CUBESAT_CALLSIGN_BYTE_1, \
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
} unstuffed_ax25_packet_t;

typedef struct {
    uint8_t data[RS_ENCODED_SIZE];
} packed_rs_packet_t;

typedef void (*s_frame_func_t)(uint8_t*);


/**
 * @brief strips away the ax.25 headers from a received packet
 * 
 * @param ax25Data the received ax.25 frame
 * @param rsData 255 byte array to store the reed solomon encoded data without ax.25 headers
 *
 * @return obc_error_code_t - whether or not the ax.25 headers were successfully stripped
*/
void ax25Recv(packed_ax25_packet_t *ax25Data, packed_rs_packet_t *rsData);

static uint8_t pktSentNum = 1;
static uint8_t pktReceiveNum = 1;
static void ax25Unstuff(const packed_ax25_packet_t* packet, unstuffed_ax25_packet_t *unstuffedPacket);
static void sFrameRecv(unstuffed_ax25_packet_t *unstuffedPacket, packed_rs_packet_t *rsData);
static void iFrameRecv(unstuffed_ax25_packet_t *unstuffedPacket, packed_rs_packet_t *rsData);
static void fcsCalculate(const uint8_t* data, uint16_t *calculatedFcs);
static bool fcsCheck(const uint8_t* data, uint16_t fcs);
void bit_stuffing(uint8_t *RAW_DATA, packed_ax25_packet_t *STUFFED_DATA);

void ax25HandleReceiveReady(uint8_t *controlBytes);
void ax25HandleReceiveNotReady(uint8_t *controlBytes);
void ax25HandleRejected(uint8_t *controlBytes);
void ax25HandleSelectiveReject(uint8_t *controlBytes);
unsigned int reverseBits(unsigned int num);
int main(void);

static const s_frame_func_t sFrameResponseFns[] = {
    [AX25_S_FRAME_RR_CONTROL] = ax25HandleReceiveReady,
    [AX25_S_FRAME_RNR_CONTROL] = ax25HandleReceiveNotReady,
    [AX25_S_FRAME_REJ_CONTROL] = ax25HandleRejected,
    [AX25_S_FRAME_SREJ_CONTROL] = ax25HandleSelectiveReject
};

void ax25Recv(packed_ax25_packet_t *ax25Data, packed_rs_packet_t *rsData){
    if(ax25Data == NULL){
        printf("invalid param");
        return; /* error code on obc*/
    }
    if(rsData == NULL){
        printf("invalid param");
        return; /* error code on obc*/
    }
    if(ax25Data->length > AX25_MAXIMUM_PKT_LEN){
        printf("packet is too large");
        return; /* error code on obc*/
    }
    // check to make sure that the data starts and ends with a valid flag
    if((ax25Data->data[0] != AX25_FLAG) || (ax25Data->data[ax25Data->length - 1] != AX25_FLAG)){
        printf("incorrect flags");
        return; /* error code on obc */
    }
    // perform bit unstuffing
    unstuffed_ax25_packet_t unstuffedPacket;
    ax25Unstuff(ax25Data, &unstuffedPacket);
    for(uint16_t i; i < RS_ENCODED_SIZE; ++i){
        printf("%x ", unstuffedPacket.data[i]);
    }

    bool supervisoryFrameFlag = false;

    if(unstuffedPacket.length == AX25_SUPERVISORY_FRAME_LENGTH){
        supervisoryFrameFlag = true;
    }
    else if (unstuffedPacket.length != AX25_MINIMUM_PKT_LEN){
        printf("Did not unstuff properly\n");
        return; /* error code */
    }
    // Check FCS
    if(!fcsCheck(unstuffedPacket.data, unstuffedPacket.data[AX25_INFO_BYTES + \
                                                          AX25_PID_BYTES + \
                                                          AX25_CONTROL_BYTES + \
                                                          AX25_ADDRESS_BYTES + \
                                                          AX25_START_FLAG_BYTES]))
    {
        printf("Invalid FCS");
        return; /* error code on OBC */
    }
    supervisoryFrameFlag ? (sFrameRecv(&unstuffedPacket, rsData)) : (iFrameRecv(&unstuffedPacket, rsData));
}


static void ax25Unstuff(const packed_ax25_packet_t* packet, unstuffed_ax25_packet_t* unstuffedPacket) {
    uint8_t bitCount = 0;
    uint8_t stuffingFlag = 0;
    uint16_t unstuffedLength = AX25_START_FLAG_BYTES*8;
    unstuffedPacket->data[0] = AX25_FLAG;

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
            unstuffedPacket->data[unstuffedLength / 8] |= bit << (7 - (unstuffedLength % 8));
            unstuffedLength++;
        }
    }
    unstuffedPacket->data[AX25_MINIMUM_PKT_LEN - 1] = AX25_FLAG;
    unstuffedLength += AX25_END_FLAG_BYTES*8;
    unstuffedPacket->length = unstuffedLength;
    printf("length is %u\n", unstuffedPacket->length);
}

static void iFrameRecv(unstuffed_ax25_packet_t *unstuffedPacket, packed_rs_packet_t *rsData){
    if(memcmp(unstuffedPacket->data + AX25_START_FLAG_BYTES, cubesatCallsign, AX25_DEST_ADDR_BYTES) != 0){
        printf("invalid destination address");
        return; /* error code on OBC */
    }
    // first control byte will be the yte after the flag and the address bytes
    // next control byte will be immediately after the previous one
    // See AX.25 standard
    uint8_t controlBytes[AX25_CONTROL_BYTES] = {unstuffedPacket->data[AX25_ADDRESS_BYTES + AX25_START_FLAG_BYTES], \
                                                unstuffedPacket->data[AX25_ADDRESS_BYTES + AX25_START_FLAG_BYTES + 1]};
    // LSB should be 0 for a valid I frame
    if(controlBytes[0] & 0x01){
        printf("invalid control field");
        return; /* error code on OBC */
    }
    if((controlBytes[0] >> 1) != pktReceiveNum){
        // TODO: implement retransmission requests
    }
    if(controlBytes[1] & 0x01){
        // TODO: implement retransmissions
    }
    if((controlBytes[1] >> 1) != pktSentNum){
        // TODO: implement retransmissions
    }
    
    if(unstuffedPacket->data[AX25_CONTROL_BYTES + AX25_ADDRESS_BYTES + 1] != AX25_PID){
        printf("wrong PID");
        return; /* error code on OBC */
    }
    memcpy(rsData->data, unstuffedPacket + AX25_PID_BYTES + AX25_CONTROL_BYTES + AX25_ADDRESS_BYTES + AX25_START_FLAG_BYTES, AX25_INFO_BYTES);
    pktReceiveNum++;
}

static void sFrameRecv(unstuffed_ax25_packet_t *unstuffedPacket, packed_rs_packet_t *rsData){
    if(memcmp(unstuffedPacket->data + AX25_START_FLAG_BYTES, cubesatCallsign, AX25_DEST_ADDR_BYTES) != 0){
        printf("invalid destination address");
        return; /* error code on OBC */
    }
    uint8_t controlBytes[AX25_CONTROL_BYTES] = {unstuffedPacket->data[AX25_ADDRESS_BYTES + 1], \
                                                unstuffedPacket->data[AX25_ADDRESS_BYTES + 2]};
    sFrameResponseFns[controlBytes[0]](controlBytes);
}

/* get rid of this in release version since we need fcsCalculate for ax25Send anyways and that can be used with a comparision after */
static bool fcsCheck(const uint8_t* data, uint16_t fcs) {
    // reverse bit order of fcs to account for the fact that it was transmitted in the reverse order as the other bytes
    uint16_t reverse_num = 0;
    for (uint8_t i = 0; i < sizeof(fcs)*8; i++) {
        if ((fcs & (1 << i)))
            reverse_num |= 1 << ((sizeof(fcs)*8 - 1) - i);
    }
    fcs = reverse_num;
    uint16_t calculatedFcs = 0xFFFF;  // Initial calculatedFcs value

    for (uint16_t i = 0; i < (AX25_MINIMUM_PKT_LEN - AX25_FCS_BYTES - AX25_END_FLAG_BYTES); ++i) {
        calculatedFcs ^= (uint16_t)data[i] << 8;

        for (uint8_t j = 0; j < 8; ++j) {
            if (calculatedFcs & 0x8000) {
                calculatedFcs = (calculatedFcs << 1) ^ 0x8408;  // Polynomial X^16 + X^12 + X^5 + 1
            } else {
                calculatedFcs <<= 1;
            }
        }
    }

    calculatedFcs ^= 0xFFFF;  // XOR with 0xFFFF at the end

    if(fcs != calculatedFcs){
        return false;
    }

    return true;
}

static void fcsCalculate(const uint8_t* data, uint16_t *calculatedFcs) {
    *calculatedFcs = 0xFFFF;  // Initial calculatedFcs value

    for (uint16_t i = 0; i < (AX25_MINIMUM_PKT_LEN - AX25_FCS_BYTES - AX25_END_FLAG_BYTES); ++i) {
        *calculatedFcs ^= (uint16_t)data[i] << 8;

        for (uint8_t j = 0; j < 8; ++j) {
            if (*calculatedFcs & 0x8000) {
                *calculatedFcs = (*calculatedFcs << 1) ^ 0x8408;  // Polynomial X^16 + X^12 + X^5 + 1
            } else {
                *calculatedFcs <<= 1;
            }
        }
    }

    *calculatedFcs ^= 0xFFFF;  // XOR with 0xFFFF at the end
    // reverse order so that FCS can be transmitted with most significant bit first as per AX25 standard
    uint16_t reverse_num = 0;
    for (uint8_t i = 0; i < sizeof(*calculatedFcs)*8; i++) {
        if ((*calculatedFcs & (1 << i)))
            reverse_num |= 1 << ((sizeof(*calculatedFcs)*8 - 1) - i);
    }
    *calculatedFcs = reverse_num;
}


void ax25HandleReceiveReady(uint8_t *controlBytes){
    // TODO: implement retransmissions
}
void ax25HandleReceiveNotReady(uint8_t *controlBytes){
    // TODO: implement retransmissions
}
void ax25HandleRejected(uint8_t *controlBytes){
    // TODO: implement retransmissions
}
void ax25HandleSelectiveReject(uint8_t *controlBytes){
    // TODO: implement retransmissions
}

int main(){
    // // hardcode a mock ax25 packet received for testing
    // packed_ax25_packet_t ax25Packet = {
    //     .data = {0},
    //     .length = AX25_MINIMUM_PKT_LEN
    // };
    // ax25Packet.data[0] = AX25_FLAG;
    // ax25Packet.data[AX25_MINIMUM_PKT_LEN - 1] = AX25_FLAG;
    // memcpy(ax25Packet.data + AX25_START_FLAG_BYTES, cubesatCallsign, AX25_DEST_ADDR_BYTES);
    // ax25Packet.data[AX25_START_FLAG_BYTES + AX25_ADDRESS_BYTES] = 0x03;
    // ax25Packet.data[AX25_START_FLAG_BYTES + AX25_ADDRESS_BYTES + 1] = 0x03;
    // ax25Packet.data[AX25_START_FLAG_BYTES + AX25_ADDRESS_BYTES + AX25_CONTROL_BYTES] = AX25_PID;
    // // char str[] = "please tell me this works man";
    // // strcpy(ax25Packet.data + AX25_START_FLAG_BYTES + AX25_ADDRESS_BYTES + AX25_CONTROL_BYTES + AX25_PID_BYTES, str);
    // uint16_t fcs;
    // fcsCalculate(ax25Packet.data, &fcs);
    // ax25Packet.data[AX25_START_FLAG_BYTES + AX25_ADDRESS_BYTES + AX25_CONTROL_BYTES + AX25_PID_BYTES + AX25_INFO_BYTES] = (uint8_t)(fcs >> 8);
    // ax25Packet.data[AX25_START_FLAG_BYTES + AX25_ADDRESS_BYTES + AX25_CONTROL_BYTES + AX25_PID_BYTES + AX25_INFO_BYTES + 1] = (uint8_t)(fcs & 0xFF);
    // hardcode a mock ax25 packet received for testing
    packed_ax25_packet_t testPacket = { .data = {0}, .length = AX25_MINIMUM_PKT_LEN};
    unstuffed_ax25_packet_t testUnstuffed;
    ax25Unstuff(&testPacket, &testUnstuffed);
    packed_ax25_packet_t stuffedPacket = {.data = {0}};
    uint8_t ax25Packet[AX25_MINIMUM_PKT_LEN] = {0};
    ax25Packet[0] = AX25_FLAG;
    ax25Packet[AX25_MINIMUM_PKT_LEN - 1] = AX25_FLAG;
    memcpy(ax25Packet + AX25_START_FLAG_BYTES, cubesatCallsign, AX25_DEST_ADDR_BYTES);
    ax25Packet[AX25_START_FLAG_BYTES + AX25_ADDRESS_BYTES] = 0x03;
    ax25Packet[AX25_START_FLAG_BYTES + AX25_ADDRESS_BYTES + 1] = 0x03;
    ax25Packet[AX25_START_FLAG_BYTES + AX25_ADDRESS_BYTES + AX25_CONTROL_BYTES] = AX25_PID;
    // char str[] = "please tell me this works man";
    // strcpy(ax25Packet.data + AX25_START_FLAG_BYTES + AX25_ADDRESS_BYTES + AX25_CONTROL_BYTES + AX25_PID_BYTES, str);
    uint16_t fcs;
    fcsCalculate(ax25Packet, &fcs);
    ax25Packet[AX25_START_FLAG_BYTES + AX25_ADDRESS_BYTES + AX25_CONTROL_BYTES + AX25_PID_BYTES + AX25_INFO_BYTES] = (uint8_t)(fcs >> 8);
    ax25Packet[AX25_START_FLAG_BYTES + AX25_ADDRESS_BYTES + AX25_CONTROL_BYTES + AX25_PID_BYTES + AX25_INFO_BYTES + 1] = (uint8_t)(fcs & 0xFF);
    bit_stuffing(ax25Packet, &stuffedPacket);
    stuffedPacket.data[0] = AX25_FLAG;
    stuffedPacket.data[stuffedPacket.length - 1] = AX25_FLAG;
    for(uint16_t i; i < stuffedPacket.length; ++i){
        printf("%x ", stuffedPacket.data[i]);
    }
    packed_rs_packet_t rsData;
    ax25Recv(&stuffedPacket, &rsData);
    for(uint16_t i; i < AX25_INFO_BYTES; ++i){
        printf("%x ", rsData.data[i]);
    }
}
/*/* bit stuffing function for ax25 NOT MEANT FOR RECV */
/* added for testing purposes */
// void bit_stuffing(uint8_t *unstuffedData, packed_ax25_packet_t *stuffedPacket) {
//     uint8_t bitCount = 0;
//     uint8_t stuffingFlag = 0;
//     uint16_t stuffedLength = AX25_START_FLAG_BYTES*8;
//     stuffedPacket->data[0] = AX25_FLAG;

//     // loop from second byte to second last byte since first and last are the flags
//     for (uint16_t unstuffedPacketIndex = 1; unstuffedPacketIndex < RS_ENCODED_SIZE - 1; ++unstuffedPacketIndex) {
//         uint8_t current_byte = unstuffedData->data[unstuffedPacketIndex];

//         for (uint8_t offset = 0; offset < 8; ++offset) {
//             uint8_t bit = (current_byte >> (7 - offset)) & 0x01;

//             if (stuffingFlag) {
//                 bitCount = 0;
//                 stuffingFlag = 0;
//                 continue;  // Skip adding the stuffed bit
//             }
//             if (bit == 1) {
//                 bitCount++;
//                 if (bitCount == 5) {
//                     bitCount = 0;
//                     stuffingFlag = 1;
//                 }
//             }
//             else {
//                 bitCount = 0;
//             }
//             unstuffedPacket->data[stuffedLength / 8] |= bit << (7 - (stuffedLength % 8));
//             stuffedLength++;
//         }
//     }
//     unstuffedPacket->data[AX25_MINIMUM_PKT_LEN - 1] = AX25_FLAG;
//     stuffedLength += AX25_END_FLAG_BYTES*8;
//     unstuffedPacket->length = stuffedLength;
//     printf("length is %u\n", unstuffedPacket->length);
// }

/* bit stuffing function for ax25 NOT MEANT FOR RECV */
/* added for testing purposes */
void bit_stuffing(uint8_t *RAW_DATA, packed_ax25_packet_t *STUFFED_DATA) {
    memset(STUFFED_DATA->data, 0, AX25_MAXIMUM_PKT_LEN);
    size_t RAW_OFFSET = 0, STUFFED_OFFSET = 8, bit_count = 0, one_count = 0;
    uint8_t current_bit;

// Cycle through raw data to find 1s
    for (RAW_OFFSET = 8; RAW_OFFSET < (274) * 8; ++RAW_OFFSET) {
        current_bit = (RAW_DATA[RAW_OFFSET / 8] >> (7 - (RAW_OFFSET % 8))) & 1;
        STUFFED_DATA->data[STUFFED_OFFSET / 8] |= (current_bit << (7 - (STUFFED_OFFSET % 8)));
        STUFFED_OFFSET++;

        if (current_bit == 1) {
            one_count++;
            if (one_count == 5) {
                one_count = 0;
                STUFFED_DATA->data[STUFFED_OFFSET / 8] |= (0 << (7 - (STUFFED_OFFSET % 8)));
                STUFFED_OFFSET++;
            }
        } else {
            one_count = 0;
        }
    }
// Set ending flag
    memset(STUFFED_DATA->data + (STUFFED_OFFSET/8) + 1, AX25_FLAG, 1);
    STUFFED_DATA->length = (STUFFED_OFFSET/8) + 2;
    printf("bitstuffing: length is %u\n", STUFFED_DATA->length);
}