#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include "kalman.h"
#include "openwsn.h"
#include "noiseprobe.h"

// Globals
typedef struct {
   float Q[16];
   float R;
   float P_last[16];
   float K;
} kalman_vars_t;

kalman_vars_t kalman_vars;

void kalman_init() {
   // reset local variables
   memset(&kalman_vars,0,sizeof(kalman_vars_t));

    //the noise in the system    
    kalman_vars.Q[0] = 25.6;
    kalman_vars.Q[1] = 17.46;
    kalman_vars.Q[2] = 11.49;
    kalman_vars.Q[3] = 15.58;
    kalman_vars.Q[4] = 26.36;
    kalman_vars.Q[5] = 27.74;
    kalman_vars.Q[6] = 24.41;
    kalman_vars.Q[7] = 33.96;
    kalman_vars.Q[8] = 40.14;
    kalman_vars.Q[9] = 29.1;
    kalman_vars.Q[10] = 12.45;
    kalman_vars.Q[11] = 11.59;
    kalman_vars.Q[12] = 12.9;
    kalman_vars.Q[13] = 10.35;
    kalman_vars.Q[14] = 37.54;
    kalman_vars.Q[15] = 22.45; 
    kalman_vars.R = 1; //covariance of the observation noise
    
    memset(&kalman_vars.P_last, 1,sizeof(kalman_vars.P_last));
    //kalman_vars.P_last[] ={1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1};
}
  
int16_t kalman(int16_t raw, int16_t last, uint8_t index){    
    //measure
    int16_t z_measured = raw;
    
    //initialize with a measurement
    int16_t x_est_last = last;
    
    //do a prediction
    int16_t x_temp_est = x_est_last;
    //P_temp = P_last + Q;
    //x_temp_est = x_est_last[index];
    float P_temp = kalman_vars.P_last[index] + kalman_vars.Q[index];
    kalman_vars.K = P_temp * (1.0/(P_temp + kalman_vars.R));
    
    //correction
    float x_est = x_temp_est + kalman_vars.K * (z_measured - x_temp_est); 
    float P = (1- kalman_vars.K) * P_temp;
        
    //update our last's
    //P_last = P;
    //x_est_last = x_est;
    kalman_vars.P_last[index] = P;
    
    return (int16_t)(x_est);
}