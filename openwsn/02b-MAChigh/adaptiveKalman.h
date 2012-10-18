#ifndef __ADPATIVEKALMAN_H
#define __ADPATIVEKALMAN_H

#include "openwsn.h"

void adaptiveKalman_init();

/* float version 
float kalman(float raw, float last, uint8_t index);
void getQ(float, uint8_t);
void getR(float, uint8_t); */

/* int version */
int16_t adaptiveKalman(int16_t raw, int16_t last, uint8_t index);
void getQ(float, uint8_t);
void getR(float, uint8_t);

void adjustQ(uint8_t);
void adjustQall();
#endif