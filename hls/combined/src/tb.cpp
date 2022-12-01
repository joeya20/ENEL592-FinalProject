#include <stdio.h>
#include "ap_int.h"
void compute(unsigned short int n, unsigned short int m, ap_int<1> mode, ap_int<32> *ret);
int main(){
	ap_int<32> out;
	for (int i =1 ; i < 6; i++)
	{
		compute(3*i, i, (ap_int<1>)(i%2), &out);
		printf("%d: %u\n", i, out);
	}
}
