#ifndef UTILS_C
#define UTILS_C
#include "utils.h"


void sha_fun(char target_string[], char* sha_result)
{

   SHA1Context sha;
   int i;
   unsigned int g;
   SHA1Reset(&sha);
   SHA1Input(&sha, (const unsigned char *) target_string,
             strlen(target_string));

   if (!SHA1Result(&sha))
   {
     fprintf(stderr, "ERROR-- could not compute message digest\n");
   }else{
      printf("\t");
      for (i = 0; i < 5; i++)
      {
         g = sha.Message_Digest[i];

      }

       sprintf(sha_result,
                "%08X%08X%08X%08X%08X", sha.Message_Digest[0], sha.Message_Digest[1], sha.Message_Digest[2], sha.Message_Digest[3], sha.Message_Digest[4]);

    }

}

//Hex string to in
int htoi(char a)
{
   int i;
   if (a >= 'A' && a <= 'F')
   {
      i = a - 'A' + 10;
   }else{
      i = a - '0';
   }

    return i;

}

void xor_operation(char a, char b, char* xor_result)
{

   int i;
   int j;
   int z;
   char result[10];

   i = htoi(a);
   j = htoi(b);
   z = i ^ j;
   sprintf(result, "%X", z);
   strcat(xor_result, result);

}

/*void xor_operation(char *a, char *b, char *xor_result)
{
    
    printf("\n a = %s\n", a);
    printf("\n b = %s\n", b);
    int len_a = strlen(a);
    int len_b = strlen(b);
    
    printf("\n len_a = %d\n", len_a);
    printf("\n len_b = %d\n", len_b);
    int i, j;
    char tmp[100];
    if (len_a >= len_b)
    {
        memcpy(tmp, a, sizeof(a));
        for (i = len_a - 1, j = len_b - 1; j >= 0; --i, --j)
        {
           tmp[i] = (char)((int)a[i] ^ (int)b[j]);
        }

        printf("\n len_xor_result = %d\n", strlen(xor_result));
        strcat(xor_result, tmp);
        printf("\n len_xor_result = %d\n", strlen(xor_result));
        printf("\n xor_result = %s\n", xor_result);
        printf("\n len_tmp = %d\n", strlen(tmp));
        printf("\n tmp = %s\n", tmp);
    }
    else
    {
        memcpy(tmp, b, sizeof(b));
        for (i = len_a - 1, j = len_b - 1; i >= 0; --i, --j)
        {
            tmp[j] = (char)((int)a[i] ^ (int)b[j]);
        }
        printf("\n len_xor_result = %d\n", strlen(xor_result));
        strcat(xor_result, tmp);
        printf("\n len_xor_result = %d\n", strlen(xor_result));
        printf("\n xor_result = %s\n", xor_result);
        printf("\n len_tmp = %d\n", sizeof(tmp));
        printf("\n tmp = %s\n", tmp);
    }
}*/

#endif // UTILS_C
