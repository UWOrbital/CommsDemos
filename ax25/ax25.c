#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
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

#define AX25_S_FRAME_RR_CONTROL 0x01U
#define AX25_S_FRAME_RNR_CONTROL 0x05U
#define AX25_S_FRAME_REJ_CONTROL 0x09U
#define AX25_S_FRAME_SREJ_CONTROL 0x0DU

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

typedef struct {
    uint8_t data[AX25_DEST_ADDR_BYTES];
    uint8_t length;
} ax25_addr_t;

typedef void (*s_frame_func_t)(uint8_t*);

static uint8_t pktSentNum = 1;
static uint8_t pktReceiveNum = 1;
static const ax25_addr_t cubesatCallsign = { .data = {AX25_CUBESAT_CALLSIGN_BYTE_1, \
                                                      AX25_CUBESAT_CALLSIGN_BYTE_2, \
                                                      AX25_CUBESAT_CALLSIGN_BYTE_3, \
                                                      AX25_CUBESAT_CALLSIGN_BYTE_4, \
                                                      AX25_CUBESAT_CALLSIGN_BYTE_5, \
                                                      AX25_CUBESAT_CALLSIGN_BYTE_6, \
                                                      AX25_CUBESAT_CALLSIGN_BYTE_7}, \
                                                      .length = AX25_DEST_ADDR_BYTES};

/**
 * @brief strips away the ax.25 headers from a received packet
 * 
 * @param ax25Data the received ax.25 frame
 * @param rsData 255 byte array to store the reed solomon encoded data without ax.25 headers
 *
 * @return obc_error_code_t - whether or not the ax.25 headers were successfully stripped
*/
void ax25Recv(packed_ax25_packet_t *ax25Data, packed_rs_packet_t *rsData);

/**
 * @brief adds ax.25 headers onto telemetry being downlinked and stores the length of the packet in az25Data->length
 * 
 * @param rsData reed solomon data that needs ax.25 headers added onto it
 * @param ax25Data array to store the ax.25 frame
 * @param destAddress address of the destination for the ax25 packet
 * 
 * @return obc_error_code_t - whether or not the ax.25 headers were successfully added
*/
void ax25Send(packed_rs_packet_t *rsData, packed_ax25_packet_t *ax25Data, ax25_addr_t* destAddress);

/* MEANT FOR GROUND STATION NOT CUBESAT */
/* USED FOR TESTING PURPOSES AND FOR GROUND STATION EVENTUALLY */
void ax25SendGroundStation(packed_rs_packet_t *rsData, packed_ax25_packet_t *ax25Data, ax25_addr_t* srcAddress);

/**
 * @brief performs bit unstuffing on a receive ax.25 packet
 * 
 * @param packet - pointer to a received stuffed ax.25 packet
 * @param unstuffedPacket - pointer to a unstuffed_ax25_packet_t struct to hold the unstuffed ax.25 packet
*/
static void ax25Unstuff(const packed_ax25_packet_t* packet, unstuffed_ax25_packet_t *unstuffedPacket);

/**
 * @brief strips away the ax.25 headers for an s Frame
 * 
 * @param unstuffedPacket unstuffed ax.25 packet
 * @param rsData 255 byte array to store the reed solomon encoded data without ax.25 headers
*/
static void sFrameRecv(unstuffed_ax25_packet_t *unstuffedPacket, packed_rs_packet_t *rsData);

/**
 * @brief strips away the ax.25 headers for an i Frame
 * 
 * @param unstuffedPacket unstuffed ax.25 packet
 * @param rsData 255 byte array to store the reed solomon encoded data without ax.25 headers
*/
static void iFrameRecv(unstuffed_ax25_packet_t *unstuffedPacket, packed_rs_packet_t *rsData);

/**
 * @brief calculates the FCS for an ax.25 packet
 * 
 * @param data uint8_t array that holds the ax25 packet data
 * @param calculatedFcs pointer to a un16_t to hold the calculated FCS
*/
static void fcsCalculate(const uint8_t* data, uint16_t *calculatedFcs);

/**
 * @brief checks if a received fcs is correct
 * 
 * @param data the received ax.25 packet data
 * @param fcs the FCS of the received packet to be checked if it is valid or not
 * 
 * @return bool - returns true if the fcs was valid and false if not
*/
static bool fcsCheck(const uint8_t* data, uint16_t fcs);

/**
 * @brief performs bit unstuffing on a receive ax.25 packet
 * 
 * @param packet - pointer to a received stuffed ax.25 packet
 * @param unstuffedPacket - pointer to a unstuffed_ax25_packet_t struct to hold the unstuffed ax.25 packet
*/
void bit_stuffing(uint8_t *RAW_DATA, packed_ax25_packet_t *STUFFED_DATA);

/**
 * @brief callback function for when a Receive Ready S frame is received
 * 
 * @param controlBytes array of bytes that holds the control bytes of the received S Frame
*/
void ax25HandleReceiveReady(uint8_t *controlBytes);

/**
 * @brief callback function for when a Receive Not Ready S frame is received
 * 
 * @param controlBytes array of bytes that holds the control bytes of the received S Frame
*/
void ax25HandleReceiveNotReady(uint8_t *controlBytes);

/**
 * @brief callback function for when a Rejected S frame is received
 * 
 * @param controlBytes array of bytes that holds the control bytes of the received S Frame
*/
void ax25HandleRejected(uint8_t *controlBytes);

/**
 * @brief callback function for when a Selective Reject S frame is received
 * 
 * @param controlBytes array of bytes that holds the control bytes of the received S Frame
*/
void ax25HandleSelectiveReject(uint8_t *controlBytes);

static const s_frame_func_t sFrameResponseFns[] = {
    [AX25_S_FRAME_RR_CONTROL] = ax25HandleReceiveReady,
    [AX25_S_FRAME_RNR_CONTROL] = ax25HandleReceiveNotReady,
    [AX25_S_FRAME_REJ_CONTROL] = ax25HandleRejected,
    [AX25_S_FRAME_SREJ_CONTROL] = ax25HandleSelectiveReject
};

void ax25Recv(packed_ax25_packet_t *ax25Data, packed_rs_packet_t *rsData){
    if(ax25Data == NULL){
        printf("invalid param\n");
        return; /* error code on obc*/
    }
    if(rsData == NULL){
        printf("invalid param\n");
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
    bool supervisoryFrameFlag = false;
    // perform bit unstuffing
    unstuffed_ax25_packet_t unstuffedPacket;
    ax25Unstuff(ax25Data, &unstuffedPacket);
    if(unstuffedPacket.length == AX25_SUPERVISORY_FRAME_LENGTH){
        supervisoryFrameFlag = true;
    }
    else if (unstuffedPacket.length != AX25_MINIMUM_PKT_LEN){
        printf("Did not unstuff properly\n");
        return; /* error code */
    }

    // Check FCS
    uint16_t fcs = unstuffedPacket.data[AX25_INFO_BYTES + \
                                                          AX25_PID_BYTES + \
                                                          AX25_CONTROL_BYTES + \
                                                          AX25_ADDRESS_BYTES + \
                                                          AX25_START_FLAG_BYTES] << 8;
    fcs |= unstuffedPacket.data[AX25_INFO_BYTES + \
                                AX25_PID_BYTES + \
                                AX25_CONTROL_BYTES + \
                                AX25_ADDRESS_BYTES + \
                                AX25_START_FLAG_BYTES + 1];
    if(!fcsCheck(unstuffedPacket.data, fcs))
    {
        printf("Invalid FCS\n");
        return; /* error code on OBC */
    }
    supervisoryFrameFlag ? (sFrameRecv(&unstuffedPacket, rsData)) : (iFrameRecv(&unstuffedPacket, rsData));
}

static void ax25Unstuff(const packed_ax25_packet_t* packet, unstuffed_ax25_packet_t* unstuffedPacket) {
    uint8_t bitCount = 0;
    uint8_t stuffingFlag = 0;
    uint16_t unstuffedLength = 0; // count as bytes
    uint16_t unstuffedBitLength = 0; // count as bits

    // Clear the unstuffed data
    memset(unstuffedPacket->data, 0, sizeof(unstuffedPacket->data));

    // Set the first flag
    unstuffedPacket->data[0] = AX25_FLAG;
    unstuffedBitLength += 8;

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
            if(unstuffedBitLength >= (AX25_MINIMUM_PKT_LEN-1)*8){
                break;
            }
            unstuffedPacket->data[unstuffedBitLength / 8] |= bit << (7 - (unstuffedBitLength % 8));
            unstuffedBitLength++;
        }
    }
    // Add last flag
    unstuffedPacket->data[AX25_MINIMUM_PKT_LEN - 1] = AX25_FLAG;
    unstuffedBitLength += 8;

    // convert bits to bytes, rounding up
    unstuffedPacket->length = (unstuffedBitLength + 7)/8;
}

static void iFrameRecv(unstuffed_ax25_packet_t *unstuffedPacket, packed_rs_packet_t *rsData){
    if(memcmp(unstuffedPacket->data + AX25_START_FLAG_BYTES, cubesatCallsign.data, AX25_DEST_ADDR_BYTES) != 0){
        printf("invalid destination address");
        return; /* error code on OBC */
    }
    // first control byte will be the the after the flag and the address bytes
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
    memcpy(rsData->data, unstuffedPacket->data + AX25_PID_BYTES + AX25_CONTROL_BYTES + AX25_ADDRESS_BYTES + AX25_START_FLAG_BYTES, AX25_INFO_BYTES);
    pktReceiveNum++;
}

static void sFrameRecv(unstuffed_ax25_packet_t *unstuffedPacket, packed_rs_packet_t *rsData){
    if(memcmp(unstuffedPacket->data + AX25_START_FLAG_BYTES, cubesatCallsign.data, AX25_DEST_ADDR_BYTES) != 0){
        printf("invalid destination address");
        return; /* error code on OBC */
    }
    uint8_t controlBytes[AX25_CONTROL_BYTES] = {unstuffedPacket->data[AX25_ADDRESS_BYTES + 1], \
                                                unstuffedPacket->data[AX25_ADDRESS_BYTES + 2]};
    sFrameResponseFns[controlBytes[0]](controlBytes);
}

/* TODO: get rid of this and just use fcs calculate and comparision after */
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
    packed_rs_packet_t rsSendData;
    packed_ax25_packet_t stuffedPacket;
    char str[] = "Lorem ipsum dolor sit amet, consectetuer adipiscing elit. Aenean commodo ligula eget dolor. Aenean massa. Cum sociis natoque penatibus et magnis dis parturient montes, nascetur ridiculus mus. Donec quam felis, ultricies nec, pellentesque eu, pretium quis,";
    strcpy(rsSendData.data, str);
    ax25_addr_t src = {.data = {0}, .length = AX25_SRC_ADDR_BYTES};
    ax25SendGroundStation(&rsSendData, &stuffedPacket, &src);
    packed_rs_packet_t rsData;
    ax25Recv(&stuffedPacket, &rsData);
    printf("%s\n", rsData.data);
}

/* bit stuffing function for ax25 NOT MEANT FOR RECV */
/* added for testing purposes */
void bit_stuffing(uint8_t *RAW_DATA, packed_ax25_packet_t *STUFFED_DATA) {
    memset(STUFFED_DATA->data, 0, AX25_MAXIMUM_PKT_LEN);
    size_t RAW_OFFSET = 0, STUFFED_OFFSET = 8, bit_count = 0, one_count = 0;
    uint8_t current_bit;

// Cycle through raw data to find 1s
    for (RAW_OFFSET = 8; RAW_OFFSET < (275) * 8; ++RAW_OFFSET) {
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
    STUFFED_DATA->length = ((STUFFED_OFFSET+7)/8) + 1;
}

/**
 * @brief adds ax.25 headers onto telemetry being downlinked and stores the length of the packet in az25Data->length
 * 
 * @param rsData reed solomon data that needs ax.25 headers added onto it
 * @param ax25Data array to store the ax.25 frame
 * @param destAddress address of the destination for the ax25 packet
 * 
 * @return obc_error_code_t - whether or not the ax.25 headers were successfully added
*/
void ax25Send(packed_rs_packet_t *rsData, packed_ax25_packet_t *ax25Data, ax25_addr_t* destAddress) {
    if (rsData == NULL) {
        return; /* error code on OBC */
    }

    if (ax25Data == NULL) {
        return; /* error code on OBC */
    }

    if (destAddress == NULL) {
        return; /* error code on OBC */
    }
    if (destAddress->length < AX25_DEST_ADDR_BYTES){
        return; /* error code on OBC */
    }

    memset(ax25Data->data, 0, AX25_MAXIMUM_PKT_LEN);

    uint8_t ax25PacketUnstuffed[AX25_MINIMUM_PKT_LEN] = {0};

    ax25PacketUnstuffed[0] = AX25_FLAG;
    //ax25PacketUnstuffed[AX25_MINIMUM_PKT_LEN - 1] = AX25_FLAG;
    memcpy(ax25PacketUnstuffed + AX25_START_FLAG_BYTES, destAddress->data, AX25_DEST_ADDR_BYTES);
    memcpy(ax25PacketUnstuffed + AX25_START_FLAG_BYTES + AX25_DEST_ADDR_BYTES, cubesatCallsign.data, AX25_SRC_ADDR_BYTES);
    ax25PacketUnstuffed[AX25_START_FLAG_BYTES + AX25_ADDRESS_BYTES] = (pktReceiveNum << 1);
    ax25PacketUnstuffed[AX25_START_FLAG_BYTES + AX25_ADDRESS_BYTES + 1] = (pktSentNum << 1);
    ax25PacketUnstuffed[AX25_START_FLAG_BYTES + AX25_ADDRESS_BYTES + AX25_CONTROL_BYTES] = AX25_PID;
    memcpy(ax25PacketUnstuffed + AX25_START_FLAG_BYTES + AX25_ADDRESS_BYTES + AX25_CONTROL_BYTES + AX25_PID_BYTES, rsData->data, RS_ENCODED_SIZE);
    uint16_t fcs;
    fcsCalculate(ax25PacketUnstuffed, &fcs);
    ax25PacketUnstuffed[AX25_START_FLAG_BYTES + AX25_ADDRESS_BYTES + AX25_CONTROL_BYTES + AX25_PID_BYTES + AX25_INFO_BYTES] = (uint8_t)(fcs >> 8);
    ax25PacketUnstuffed[AX25_START_FLAG_BYTES + AX25_ADDRESS_BYTES + AX25_CONTROL_BYTES + AX25_PID_BYTES + AX25_INFO_BYTES + 1] = (uint8_t)(fcs & 0xFF);
    bit_stuffing(ax25PacketUnstuffed, ax25Data);
    ax25Data->data[ax25Data->length - 1] = AX25_FLAG;
    ax25Data->data[0] = AX25_FLAG;
    ++pktSentNum;
}

void ax25SendGroundStation(packed_rs_packet_t *rsData, packed_ax25_packet_t *ax25Data, ax25_addr_t* srcAddress) {
    if (rsData == NULL) {
        return; /* error code on OBC */
    }

    if (ax25Data == NULL) {
        return; /* error code on OBC */
    }

    if (srcAddress == NULL) {
        return; /* error code on OBC */
    }
    if (srcAddress->length < AX25_DEST_ADDR_BYTES){
        return; /* error code on OBC */
    }

    memset(ax25Data->data, 0, AX25_MAXIMUM_PKT_LEN);

    uint8_t ax25PacketUnstuffed[AX25_MINIMUM_PKT_LEN] = {0};

    ax25PacketUnstuffed[0] = AX25_FLAG;
    memcpy(ax25PacketUnstuffed + AX25_START_FLAG_BYTES, cubesatCallsign.data, AX25_SRC_ADDR_BYTES);
    memcpy(ax25PacketUnstuffed + AX25_START_FLAG_BYTES + AX25_DEST_ADDR_BYTES, srcAddress->data, AX25_DEST_ADDR_BYTES);
    ax25PacketUnstuffed[AX25_START_FLAG_BYTES + AX25_ADDRESS_BYTES] = (pktReceiveNum << 1);
    ax25PacketUnstuffed[AX25_START_FLAG_BYTES + AX25_ADDRESS_BYTES + 1] = (pktSentNum << 1);
    ax25PacketUnstuffed[AX25_START_FLAG_BYTES + AX25_ADDRESS_BYTES + AX25_CONTROL_BYTES] = AX25_PID;
    memcpy(ax25PacketUnstuffed + AX25_START_FLAG_BYTES + AX25_ADDRESS_BYTES + AX25_CONTROL_BYTES + AX25_PID_BYTES, rsData->data, RS_ENCODED_SIZE);
    uint16_t fcs;
    fcsCalculate(ax25PacketUnstuffed, &fcs);
    ax25PacketUnstuffed[AX25_START_FLAG_BYTES + AX25_ADDRESS_BYTES + AX25_CONTROL_BYTES + AX25_PID_BYTES + AX25_INFO_BYTES] = (uint8_t)(fcs >> 8);
    ax25PacketUnstuffed[AX25_START_FLAG_BYTES + AX25_ADDRESS_BYTES + AX25_CONTROL_BYTES + AX25_PID_BYTES + AX25_INFO_BYTES + 1] = (uint8_t)(fcs & 0xFF);
    bit_stuffing(ax25PacketUnstuffed, ax25Data);
    ax25Data->data[ax25Data->length - 1] = AX25_FLAG;
    ax25Data->data[0] = AX25_FLAG;
    ++pktSentNum;
}