#include <stdio.h>
#include "ap_int.h"
void compute(unsigned short int n,  ap_int<1> mode, ap_int<32> *ret);
void fact(unsigned short int n,  ap_int<32> *ret);
int main(){
	ap_int<32> out;
	for (int i =1 ; i < 6; i++)
	{
		fact(2*i, &out);
		printf("%d: %u\n", i, out);
	}
}
