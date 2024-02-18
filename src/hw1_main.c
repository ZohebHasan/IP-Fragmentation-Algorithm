// #include "hw1.h"
#include <stdio.h>
#include <stdlib.h>



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
                // printf("Fragment Offset after decomposing: %u\n" , fragmentOffset);
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
// int minIntNum = max_payload <= array_len ? (max_payload / 4) : (array_len / 4) ; 
int maxIntNum =  (max_payload / 4); 
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
    if( remainingIntegers < maxIntNum){
        pktlen = (16 + (remainingIntegers * 4));
    }
    else{
        pktlen = (16 + (maxIntNum * 4));
        remainingIntegers -= maxIntNum;
        loaded = 1;
    }
    packets[i] = malloc(pktlen);
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
    for(int j = 0; j < 16; j++){ //should not be until packetLen , instead, need to change it until 16
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
                fragOffset = ((index - maxIntNum) * 4);
            }
            else{
                fragOffset = ((index - remainingIntegers) * 4);
            }
            packets[i][j] |= (fragOffset >> 6);
        }
        else if(j == 9){
            packets[i][j] |= (fragOffset << 2); 
            packets[i][j] |= ((pktlen) >> 12);  
            // printf("Fragment Offset is: %u\n", fragOffset);  
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

        // if( i == 3){
        //     printf("%x ",packets[i][j]);
        // }       
    }
    packetNum++; 
}
    return packetNum; 
}

int main (){

    // unsigned char expected[]={0x00, 0x02, 0xb6, 0x70, 0x00, 0x56, 0xce, 0xde, 
    //                           0x01, 0x20, 0x02, 0x88, 0xfc, 0x65, 0x0b, 0x6c, 
    //                           0xff, 0xf2, 0x1a, 0x14, 
    //                           0xff, 0xe8, 0x6f, 0xb8, 
    //                           0x00, 0x00, 0x14, 0x5b, 
    //                           0xff, 0xcc, 0x0c, 0xa8, 
    //                           0xff, 0xfb, 0x76, 0x27, 
    //                           0x00, 0x1d, 0xda, 0x4d};
    // printf("\n");
    // print_packet_sf(expected);
    // unsigned char gotten[] ={ 0x0, 0x2, 0xb6, 0x70, 0x0, 0x56, 0xce, 0xde,
    //                           0x0, 0x20, 0x2, 0x88, 0xfc, 0x65, 0xb, 0x6c,
    //                           0xff, 0xf2, 0x1a, 0x14, 
    //                           0xff, 0xe8, 0x6f, 0xb8, 
    //                           0x00, 0x00, 0x14, 0x5b, 
    //                           0xff, 0xcc, 0x0c, 0xa8, 
    //                           0xff, 0xfb, 0x76, 0x27, 
    //                           0x00, 0x1d, 0xda, 0x4d };

    // print_packet_sf(gotten);



    //TEST- 1
    int array[] = {-710617, 1930886, -3307223, -363085, 2747793, -761665, 4885386, 4760492, 1516649, 4641421, 
                    202362, -4509973, -1631310, -2479941, -102237, 2513926, 180540, -4616574, -910828, -1544264,
                    5211, -3404632, -297433, 1956429, 1465782, -3978470, 3722862, -1334877, 174067, 3703135, -3486071, 
                    -3020198, 634022, 723058, 4133069, 898167, 4961393, 4018456, 3175011, 1478042, -3823771, -1622627, 
                    4484421, -455081, 3413784, 1898537, -424802, -1405676, 4798315, 3664370, };
    unsigned char* actual_packets[9] = {0};
    unsigned int num_expected_packets = 9;
    unsigned int max_payload = 24;
    unsigned int src_addr = 11111;
    unsigned int dest_addr = 22222;
    unsigned int src_port = 13;
    unsigned int dest_port = 14;
    unsigned int maximum_hop_count = 17;
    unsigned int compression_scheme = 1;
    unsigned int traffic_class = 44;


    printf("Total Packets: %d\n", packetize_array_sf(array, sizeof(array) / sizeof(array[0]), actual_packets,
			sizeof(actual_packets) / sizeof(actual_packets[0]), max_payload, src_addr, dest_addr, src_port, dest_port, 
			maximum_hop_count, compression_scheme, traffic_class));
    

    
    printf("\n");
    for (int i = 0; i < num_expected_packets; i++){
        printf("\n");
        print_packet_sf(actual_packets[i]);
    }
   
    // //Decomposing the values:
    // printf("\nPacketized:\n");
    // print_packet_sf(actual_packets[3]);

    // printf("\nExpected: \n");
    // print_packet_sf(expectedPacket2); 

    // printf("\n\n");

    // //Printing hex values:
    // printf("Expected Hex\n");
    // for(int i = 0; i < (sizeof(expectedPacket2) / sizeof(expectedPacket2[0])) ; i++){
    //     printf("%x", expectedPacket2[i]);
    // }
    // printf("\n");
    // printf("Packetized Hex\n");
    // for(int i = 0; i < getPacketLength(actual_packets[3]) ; i++){
    //     printf("%x", actual_packets[3][i]);
    // }
    // printf("\n");


    
    // for (unsigned int i = 0; i < num_expected_packets; i++)
    //     free(actual_packets[i]);
    return 0;
}





