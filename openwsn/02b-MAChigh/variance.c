#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include "openwsn.h"
#include "variance.h"
#include "noiseprobe.h"

/*** Globals ***/
typedef struct {
   int16_t var[16];
   int16_t last_var[16];
   float mean[16];
   uint8_t num[16];
} vary_vars_t;

vary_vars_t vary_vars;

void vary_init() {
  memset(&vary_vars, 0, sizeof(vary_vars_t));
  memset(&vary_vars.var, -1, sizeof(vary_vars.var));
  memset(&vary_vars.last_var, -1, sizeof(vary_vars.last_var));
}

/*
int16_t var[] = {-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1};
int16_t last_var[] = {-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1};
float mean[] ={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
//float M2[] ={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
float M2;
uint8_t num[] ={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}; //number of readings taken
*/

void updateVar(float rssi, uint8_t channel){ //online algorithm
  float fvar = ((float)vary_vars.var[channel])/SCALAR;
  vary_vars.num[channel]++;
  float delta = rssi-vary_vars.mean[channel];
  vary_vars.mean[channel] = vary_vars.mean[channel] + delta/vary_vars.num[channel];
  //M2[channel] = M2[channel] + delta*(rssi-mean[channel]);
  //var[channel]=M2[channel]/num[channel];
  float M2 = fvar*(vary_vars.num[channel]-1) + delta*(rssi-vary_vars.mean[channel]); //causing problem,why?
  vary_vars.var[channel] = (uint16_t)(M2*SCALAR/vary_vars.num[channel]);
}

float getVarRatio(uint8_t channel){
  if(vary_vars.last_var[channel] == -1){
      vary_vars.last_var[channel] = vary_vars.var[channel];
      return 1;
  }
  float ret = (float)vary_vars.var[channel]/vary_vars.last_var[channel];
  //for next phase
  vary_vars.last_var[channel] = vary_vars.var[channel];
  vary_vars.var[channel] = 0; 
  vary_vars.num[channel] = 0;
  return ret;
}