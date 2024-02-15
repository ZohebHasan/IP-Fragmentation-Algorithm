#include "hw1.h"
// #include <stdio.h>
// #include <stdlib.h>

//Global Variable Declarations 
unsigned int sourceAddress; 
unsigned int destinationAddress; 
unsigned int sourcePort;
unsigned int destinationPort; 
unsigned int fragmentOffset; 
unsigned int packetLength; 
unsigned int maxHopCount;
unsigned int checkSum;
unsigned int compressionScheme;
unsigned int trafficClass;

//Function Prototypes
void decomposePayload(unsigned char packet[], int* payload, int payloadLength);
int getPayloadLength(unsigned char packet[]);
void decomposeHeader(unsigned char packet[]);
unsigned int getPacketLength(unsigned char packet[]);
void print_packet_sf(unsigned char packet[]);
unsigned int compute_checksum_sf(unsigned char packet[]);
unsigned int getAbsoluteUsingTwosComp(int num);

int getPayloadLength(unsigned char packet[]){
    int pktLen = (int) getPacketLength(packet); 
    int val = pktLen - 16;
    // bleh = ((int) ((val) / 4)) + (val % 4 != 0)
    return val / 4; 
}   

unsigned int getPacketLength(unsigned char packet[]){
    unsigned int temp = 0;

    for(int i = 9; i < 12; i++){
        if(i == 9){
            temp |= (unsigned int) (packet[i] & 0x03); 
        }
        else if( i == 11){
            temp |= (unsigned int) packet[i]; 
            temp >>= 4;         
        }
        else {
            temp |= (unsigned int) packet[i]; 
            temp <<= 8;        
        }      
    }
    packetLength = temp; 
    temp = 0; 

    return packetLength;
}

void decomposeHeader(unsigned char packet[]){ 
    getPacketLength(packet);
    unsigned int temp = 0; 
    int length = 16;
    
    for(int i = 0; i < length; i++){  //what if the length is corrupted? gotta check pfft.
        if( i < 4) { 
            temp |= (unsigned int) packet[i];            
            if( i == 3){
                temp >>= 4;
                sourceAddress = temp; 
                temp = 0;           
            }
            else{
                temp <<= 8;
            }     
        }
        else if( i < 7 ){  
            if(i == 3){
               temp |= (unsigned int) (packet[i] & 0x0f);   
            }
            else{
                temp |= (unsigned int) packet[i];
            }
            if( i < 6){
                temp <<= 8;
            }
            else{
                destinationAddress = temp;
                temp = 0; 
            }           
        }
        else if(i == 7){
            temp = packet[i];
            temp >>= 4;
            sourcePort = temp;
            temp = 0;
            temp |= (unsigned int) (packet[i] & 0x0f);  
            destinationPort = temp;
            temp = 0;
        } 
        else if(i < 10){ //needs recheck with different data 
            temp |= (unsigned int) packet[i];
            if( i == 9){
                temp >>= 2;
                fragmentOffset = temp; 
                temp = 0;
            }
            else{
                temp <<= 8;   
            }
        }
        else if(i < 11){
            continue;
        }
        else if( i < 13){
            if( i == 11){
                temp |= (unsigned int) (packet[i] & 0x0f);
                temp <<= 8;
            }
            else{
                temp |= (unsigned int) (packet[i] & 0x80);
                temp >>= 7; 
                maxHopCount = temp;
                temp = 0;
                temp |= (unsigned int) (packet[i] & 0x7f);
                temp <<= 8;          
            }
        }
        else if( i < 15){
            temp |= (unsigned int) packet[i];                   
            if( i == 14){     
                checkSum = temp;                
                temp = 0;
            }
            else{
                temp <<= 8;  
            }
        }
        else if( i == 15){
            temp |= (unsigned int) (packet[i] & 0xC0);
            temp >>= 6; 
            compressionScheme = temp;
            temp = 0;
            temp |= (unsigned int) ( packet[i] & 0x3F);
            trafficClass = temp;
            temp = 0;     
        }
    }
 }

void decomposePayload(unsigned char packet[], int* payload, int payloadLength){
    unsigned int temp = 0; 
    int pktLen = (int) getPacketLength(packet);
    int payLoadLength = getPayloadLength(packet);
  
   
    if(payLoadLength != 0){
        int payloadIndex = 0, bitCount = 0;
        for(int i = 16; i < pktLen; i++){ //tentative algorithm. POTENTIAL VULNERABILITIES (Not checking checksum or looking for corrupted data)  
            temp |= packet[i];
            
            bitCount+=8; 
            if(bitCount == 32){
                payload[payloadIndex] = (int) temp; 
                temp = 0;
                payloadIndex++;
                bitCount = 0;
            }
            else {
                temp <<= 8;
            }
        }
    }
}

void print_packet_sf(unsigned char packet[]){

    int pktLen = (int) getPacketLength(packet);
    int payLoadLength = getPayloadLength(packet);
    int payload[payLoadLength]; 
    decomposeHeader(packet);
    decomposePayload (packet, payload, payLoadLength);

    printf("Source Address: %u\n", sourceAddress);
    printf("Destination Address: %u\n", destinationAddress); 
    printf("Source Port: %u\n", sourcePort); 
    printf("Destination Port: %u\n", destinationPort); 
    printf("Fragment Offset: %u\n", fragmentOffset); 
    printf("Packet Length: %u\n", packetLength); 
    printf("Maximum Hop Count: %u\n", maxHopCount); 
    printf("Checksum: %u\n", checkSum); 
    printf("Compression Scheme: %u\n", compressionScheme); 
    printf("Traffic Class: %u\n", trafficClass);   

    printf("Payload: "); 
    for(int i = 0; i < payLoadLength; i++){
        if( i == payLoadLength - 1){
            printf("%d", payload[i]);
        }
        else{
            printf("%d ", payload[i]);
        }    
    }
    printf("\n"); 
   
}

unsigned int getAbsoluteUsingTwosComp(int num){//This function is as useful as OcaML in our programming life.
    unsigned int stdout = (unsigned int) num;
    unsigned int temp = 0; 
    temp = stdout & 0x1;
    stdout =~ stdout; 
    stdout |=  temp;

    return stdout; 
}

unsigned int compute_checksum_sf(unsigned char packet[]){
    int pktLen = (int) getPacketLength(packet);
    int payLoadLength = getPayloadLength(packet);
    int payload[payLoadLength]; 
    decomposeHeader(packet);
    decomposePayload (packet, payload, payLoadLength);
    unsigned int sum = 0; 

    sum = sourceAddress + destinationAddress + sourcePort + destinationPort + 
          fragmentOffset + packetLength + maxHopCount + compressionScheme +
          trafficClass;
    for (int i = 0 ; i < payLoadLength ; i++){
        if(payload[i] < 0){
            sum += abs(payload[i]);
        }
        else{
            sum += (unsigned int) payload[i];
        }     
    }
    return sum % 8388607 ;
}

unsigned int reconstruct_array_sf(unsigned char *packets[], unsigned int packets_len, int *array, unsigned int array_len) {

    unsigned int payloadCount = 0;
    int pktLen, payLoadLength;
    unsigned int j;
    int k;


    for(unsigned int i = 0; i < packets_len; i++){
        pktLen = (int) getPacketLength(packets[i]);
        payLoadLength = getPayloadLength(packets[i]);
        int payload[payLoadLength]; 
        decomposeHeader(packets[i]);
        decomposePayload (packets[i], payload, payLoadLength);
        if(compute_checksum_sf(packets[i]) == checkSum){
            j = (fragmentOffset / 4);
            k = 0;
            while(j < array_len && k < payLoadLength){
                array[j] = payload[k];
                j++;
                k++;   
                payloadCount++;   
            }
        }
        else{
            continue;
        }
    }
    return payloadCount;
}

unsigned int packetize_array_sf(int *array, unsigned int array_len, unsigned char *packets[], unsigned int packets_len,
                          unsigned int max_payload, unsigned int src_addr, unsigned int dest_addr,
                          unsigned int src_port, unsigned int dest_port, unsigned int maximum_hop_count,
                          unsigned int compression_scheme, unsigned int traffic_class){

unsigned int packetNum = 0; 
// packets[packets_len];
int minIntNum = (max_payload / 4); 
int remainingIntegers = array_len;
int pktlen = 0; 
int shift, payloadShift;
int loaded = 0;
int byteCount = 0;
unsigned int chckSum = 0;
unsigned int fragOffset = 0;
unsigned int index = 0;


for(int i = 0; i < packets_len ; i++){
    chckSum = 0;
    pktlen = 0;
    if( remainingIntegers < minIntNum){
        pktlen = (16 + (remainingIntegers * 4));
        packets[i] = malloc(pktlen);
    }
    else{
        pktlen = (16 + (minIntNum * 4));
        packets[i] = malloc(pktlen);
        remainingIntegers -= minIntNum;
        loaded = 1;
    }


    for(int x = 0; x < pktlen ; x++){
        packets[i][x] = (unsigned char) 0;
    }


    byteCount = 0; 
    payloadShift = 24;
    for(int k = 16; k < pktlen; k++){ 
        packets[i][k] |= (array[index] >> payloadShift);
        byteCount++; 
        if(byteCount == 4){
            payloadShift = 24;        
            if(array[index] < 0){
                chckSum += abs((int)array[index]);
                // chckSum += getAbsoluteUsingTwosComp((int)array[index]);
            }
            else{
                chckSum += array[index];
            }
            index++;
            byteCount = 0;
        }
        else{
            payloadShift-= 8;
        }
    }


    shift = 20;
    for(int j = 0; j < pktlen; j++){
        if(j < 4){
            if( j == 3){
                packets[i][j] |= ((src_addr) << 4);
                shift = 24; 
                packets[i][j] |= ((dest_addr) >> shift);
                shift -= 8;
            }
            else{
                packets[i][j] |= ((src_addr) >> shift);  
                shift -= 8;
            }      
        }   
        else if(j < 8){
            if( j == 7){
                packets[i][j] |= dest_port;
                packets[i][j] |= ((src_port) << 4); 
            }
            else{
                packets[i][j] |= ((dest_addr) >> shift);
                shift -= 8;
            }
        }    
        else if(j == 8){
            if(loaded){
                fragOffset = ((index - minIntNum) * 4);
            }
            else{
                fragOffset = ((index - remainingIntegers) * 4);
            }
            packets[i][j] |= (fragOffset >> 8 );
        }
        else if(j == 9){
            packets[i][j] |= (fragOffset << 2); 
            packets[i][j] |= ((pktlen) >> 12);    
        }
        else if(j == 10){
            packets[i][j] |= ((pktlen) >> 4);  
        }
        else if(j == 11){
            packets[i][j] |= ((pktlen) << 4);
            packets[i][j] |= ((maximum_hop_count) >> 1);
        }
        else if(j == 12){
            chckSum += (src_addr + dest_addr + src_port + dest_port + (unsigned int) fragOffset + (unsigned int) pktlen + 
            maximum_hop_count + compression_scheme + traffic_class);   
            chckSum %= (unsigned int) 8388607;
            shift = 16;
            packets[i][j] |= ((maximum_hop_count) << 7);
            packets[i][j] |= (chckSum >> shift); 
            shift -= 8;
        }
        else if( j < 15){         
            packets[i][j] |= chckSum >> shift; 
            shift -= 8;
        }
        else if( j == 15){
            shift = 0; 
            packets[i][j] |= traffic_class;
            packets[i][j] |= ((compression_scheme) << 6);  
        }       
    }
    packetNum++; 
}
    return packetNum; 
}


// int main() {

//     //Testing Of Print Packet, PacketLength, PayloadLength, Packetize and checksum ---> Functional
//     // TESTCASE 1: PASSED

//     int array[] = {17, 89, 42, 631, 52, 77, 89, 100, 125, -6, 823, 
// 	800, 1024, 1025, 9, 1888, 0, -17, 19, 9999999, -888888, 
// 	723, 1000, 1111, -99, -95, 55, };
//     unsigned int array_len = 22;
//     unsigned char* packets[4];
//     unsigned int packets_len = 4;
//     unsigned int max_payload = 20;
//     unsigned int src_addr = 93737;
//     unsigned int dest_addr = 10973;
//     unsigned int src_port = 11;
//     unsigned int dest_port = 6;
//     unsigned int maximum_hop_count = 25;
//     unsigned int compression_scheme = 3;
//     unsigned int traffic_class = 14;
//     printf("Num of packets return value: %u\n", packetize_array_sf(array, array_len, packets, packets_len, max_payload, src_addr, dest_addr, src_port, dest_port, maximum_hop_count, compression_scheme, traffic_class));
//     // printf("Starting from here: \n");
//     // for(int i = 0; i < packets_len; i++){
//     //     printf("\n");
//     //     print_packet_sf(packets[i]);
//     //     printf("Checksum of each packet: %u\n", compute_checksum_sf(packets[i])); 
//     // }

//     // Testing Of Packetize Array ---> Not Functional
//     // TESTCASE 2: Undefined
    

//     // unsigned char *packets[] = {
//     //         "\x00\x1e\x0f\x32\x0e\xf4\x86\xcd\x00\x80\x02\x07\x10\xd6\x41\x0f\x00\x00\x00\x12\x00\x00\x00\x13\x00\x00\x00\x14\x00\x00\x00\x15",
//     //         "\x00\x1e\x0f\x32\x0e\xf4\x86\xcd\x00\x40\x02\x07\x10\xd6\x21\x0f\x00\x00\x00\x0e\x00\x00\x00\x0f\x00\x00\x00\x10\x00\x00\x00\x11",
//     //         "\x00\x1e\x0f\x32\x0e\xf4\x86\xcd\x00\x00\x02\x07\x10\xd6\x01\x0f\x00\x00\x00\x0a\x00\x00\x00\x0b\x00\x00\x00\x0c\x00\x00\x00\x0d",};
            
//     // int reconstructed_array[] = {675349907, 997962218, 2021193812, 340631633, 909996593, 1092143830, 790789736, 1741697497, 82837431, 1075282486, 2109128536, 962800887, };
//     // int expected_array[] = {10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, };
//     // int size = sizeof(reconstructed_array) / sizeof(reconstructed_array[0]);
//     // // unsigned int expected_num_elements = 12;
//     // unsigned int numPayloads = reconstruct_array_sf((unsigned char **)packets, sizeof(packets)/sizeof(packets[0]), 
//     //     reconstructed_array, sizeof(reconstructed_array) / sizeof(reconstructed_array[0]));
    
//     for(int j = 0; j < array_len; j++){
//         array[j] = 0;
//     }

//     unsigned int numPayloads = reconstruct_array_sf(packets, packets_len, array, array_len);
    
//     // for(int i = 0; i < 3; i++){
//     //     printf("\n");
//     //     print_packet_sf(packets[i]);
//     // }

//     // printf("Num of Payloads: %u\n: ",numPayloads );
//         for(int i = 0; i < array_len; i++ ){
//             printf("Array[%d] is: %d\n ", i, array[i]);
//         }

//     return 0;
// }