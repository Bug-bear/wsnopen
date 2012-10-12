#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include "kalman.h"
#include "variance.h"
#include "openwsn.h"
#include "noiseprobe.h"

/*** Globals ***/
//intial Q for 16 channels
float Q[] = {      25.6,
                   17.46,
                   11.49,
                   15.58,
                   26.36,
                   27.74,
                   24.41,
                   33.96,
                   40.14,
                   29.1,
                   12.45,
                   11.59,
                   12.9,
                   10.35,
                   37.54,
                   22.45}; 

// The observation noise is constant for all channels, derived from cc2420 datasheet
const uint8_t R = 1;
    
    //initial values for the kalman filter
    float x_est_last = 0;
    //float P_last = 1;
    float P_last[] ={1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1};
    float K;  //Kalman gain
    
    float P;  //estimate covariance
    float P_temp;
    float x_temp_est;
    float x_est;  //updated estimation (final product)
    float z_measured; //the 'noisy' value we measured
  
//float kalman(float raw, float last, uint8_t index){
int16_t kalman(int16_t raw, int16_t last, uint8_t index){
    
    //measure
    z_measured = (float)raw/SCALAR;
    
    //update record of channel variance
    updateVar(z_measured, index); 
    
    //initialize with a measurement
    x_est_last = (float)last/SCALAR;
    
    //do a prediction
    x_temp_est = x_est_last;
    //P_temp = P_last + Q;
    //x_temp_est = x_est_last[index];
    P_temp = P_last[index] + Q[index];
    K = P_temp * (1.0/(P_temp + R));
    
    //correction
    x_est = x_temp_est + K * (z_measured - x_temp_est); 
    P = (1- K) * P_temp;
        
    //update our last's
    //P_last = P;
    //x_est_last = x_est;
    P_last[index] = P;
    
    return (int16_t)(x_est*SCALAR);
}


void adjustQ(uint8_t channel){
  Q[channel] = Q[channel]*getVarRatio(channel);
}

// to be called in noiseprobe.c
void adjustQall(){
  for(uint8_t i=0; i<16; i++)
    Q[i] = Q[i]*getVarRatio(i);
}