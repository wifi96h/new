#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int firstKey(key1)
{
    if (strcmp(key1,"key")==0)
    {
        return 65664;
    }
    return 12;     
}

int main(void) 
{
    char key1[20];
    printf("Enter Key: ");
    fgets(key1,20,stdin);
    strtok(key1, "\n");
    if (firstKey(key1)==65664)
    {
        printf("Success.\n");
	    Sleep(5000);
		return 0;
    }
    else
    {
        printf("%s is not the key.\n", key1);
	    Sleep(5000);
		return 0;
    }
}

	
