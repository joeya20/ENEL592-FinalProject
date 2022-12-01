#include <stdio.h>
#include "ap_int.h"
void fib(unsigned short int n,  ap_int<32> *ret);
int main(){
	ap_int<32> out;
	for (int i =1 ; i < 6; i++)
	{
		fib(2*i, &out);
		printf("%d: %u\n", i, out);
	}
}
