#include "bit2bool.h"
#include "noiseprobe.h"

//convert bit mask to bool array
port_INLINE void convert(uint16_t bit, bool* boolArray){
  for(int8_t j=0; j<16; j++){
    //boolArray[j]=(bit&(1<<j))!=0;
    boolArray[j] = ((bit & maskBits[j]) != 0);
  }
}

port_INLINE void convert3(uint16_t bitA, uint16_t bitB, bool* boolArray){
  for(int8_t j=0; j<16; j++){
    //boolArray[j]= (bitA&bitB&(1<<j))!=0;
    boolArray[j] = ((bitA & bitB & maskBits[j]) != 0);
  }
}
