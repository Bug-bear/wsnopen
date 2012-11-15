#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include "adaptivekalman.h"
#include "variance.h"
#include "openwsn.h"
#include "noiseprobe.h"

// Globals
typedef struct {
   float Q[16];
   float R;
   float P_last[16];
   float K;
} adaptiveKalman_vars_t;

adaptiveKalman_vars_t adaptiveKalman_vars;

void adaptiveKalman_init() {
   uint8_t     i;

   // reset local variables
   memset(&adaptiveKalman_vars,0,sizeof(adaptiveKalman_vars_t));

    //the noise in the system    
    adaptiveKalman_vars.Q[0] = 25.6;
    adaptiveKalman_vars.Q[1] = 17.46;
    adaptiveKalman_vars.Q[2] = 11.49;
    adaptiveKalman_vars.Q[3] = 15.58;
    adaptiveKalman_vars.Q[4] = 26.36;
    adaptiveKalman_vars.Q[5] = 27.74;
    adaptiveKalman_vars.Q[6] = 24.41;
    adaptiveKalman_vars.Q[7] = 33.96;
    adaptiveKalman_vars.Q[8] = 40.14;
    adaptiveKalman_vars.Q[9] = 29.1;
    adaptiveKalman_vars.Q[10] = 12.45;
    adaptiveKalman_vars.Q[11] = 11.59;
    adaptiveKalman_vars.Q[12] = 12.9;
    adaptiveKalman_vars.Q[13] = 10.35;
    adaptiveKalman_vars.Q[14] = 37.54;
    adaptiveKalman_vars.Q[15] = 22.45; 
    adaptiveKalman_vars.R = 1; //covariance of the observation noise
    
    memset(&adaptiveKalman_vars.P_last, 1,sizeof(adaptiveKalman_vars.P_last));
    //adaptiveKalman_vars.P_last[] ={1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1};
}


  
//float kalman(float raw, float last, uint8_t index){
int16_t adaptiveKalman(int16_t raw, int16_t last, uint8_t index){
    
    //measure
    int16_t z_measured = raw;
    
    //update record of channel variance
    updateVar((float)raw/SCALAR, index); 
    
    //initialize with a measurement
    int16_t x_est_last = last;
    
    //do a prediction
    int16_t x_temp_est = x_est_last;
    //P_temp = P_last + Q;
    //x_temp_est = x_est_last[index];
    float P_temp = adaptiveKalman_vars.P_last[index] + adaptiveKalman_vars.Q[index];
    adaptiveKalman_vars.K = P_temp * (1.0/(P_temp + adaptiveKalman_vars.R));
    
    //correction
    float x_est = x_temp_est + adaptiveKalman_vars.K * (z_measured - x_temp_est); 
    float P = (1- adaptiveKalman_vars.K) * P_temp;
        
    //update our last's
    //P_last = P;
    //x_est_last = x_est;
    adaptiveKalman_vars.P_last[index] = P;
    
    return (int16_t)(x_est);
}


void adjustQ(uint8_t channel){
  adaptiveKalman_vars.Q[channel] = adaptiveKalman_vars.Q[channel]*getVarRatio(channel);
}

// to be called in noiseprobe.c
void adjustQall(){
  for(uint8_t i=0; i<16; i++)
    adaptiveKalman_vars.Q[i] = adaptiveKalman_vars.Q[i]*getVarRatio(i);
}