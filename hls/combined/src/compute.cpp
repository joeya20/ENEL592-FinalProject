#include "ap_int.h"
#include <stdio.h>
void fib(unsigned short int n, ap_int<32> * ret){
  int a = 0, b = 1, c, i;

  fib_label0:for (i = 2; i <= n; i++)
  {
         c = a + b;
         a = b;
         b = c;
  }

  *ret = b;

}

void fact(unsigned short int n, ap_int<32> * ret){
	int i;
	if (n == 0) *ret = 1;
	else *ret = n;
	fact_label1:for(i = 2; i < n; i++){
		*ret = *ret*i;
	}

}

void compute(unsigned short int n, unsigned short int m, ap_int<1> mode, ap_int<32> *ret){
    if (mode) fib(n, ret);
    else fact(n, ret);
}