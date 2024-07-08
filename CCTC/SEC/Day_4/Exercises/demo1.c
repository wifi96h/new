#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int firstKey(key1)
{
    int key2 = atoi(key1);
	int p2 = 29;
    if ((key2-123)==0)
    {
        return 13555;
    }
    return 12;     
}

int main(void) 
{
    char key1[20];
    printf("Enter Key: ");
    fgets(key1,20,stdin);
    strtok(key1, "\n");
    if (firstKey(key1)==13555)
    {
        printf("Success!!.\n");
	    Sleep(5000);
		return 0;
    }
    else
    {
        printf("Failed!!.\n", key1);
	    Sleep(5000);
		return 0;
    }
}

	
