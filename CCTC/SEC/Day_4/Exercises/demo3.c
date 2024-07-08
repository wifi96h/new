#include <stdio.h>

int math(num1){
	int sumOf;
	int num2 = 66;
	int num11 = atoi(num1);
	sumOf = num11+num2;
	return sumOf;
}

int main(void){
	char num1[5];
	printf("Enter number: ");
	fgets(num1,5,stdin);
	strtok(num1, "\n");
	printf("%d\n",math(num1));
	return 0;
}