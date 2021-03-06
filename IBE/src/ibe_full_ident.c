/*
 Boneh-Franklin Identity-Based Encryption from the Weil Pairing
 
 Flow Chart:
 (1)Setup:Take secruity parameter K(QBITS,RBITS),return the system parameter and master
 key of the PKG.The system parameters include a description of a finite message space M,
 and a dscription of a finite ciphertext space C. The system parameters will be publicly
 known,while the master-key will be known only to the PKG.
 (2)Extract:The receiver extracts the corresponding private key from the PKG.
 (3)Encrypt:The sender will generate a ciphertext based on the receiver ID.
 (4)Decrypt:The receiver will use his private key to get the message digest.
 
 Detail:
 1.H1 function---Element build-in function(element_from_hash)
 2.H2 function---SHA1 function generate 160 bit long number
 3.H3 function---Concatenate the sigma and message digest, and
 then put it into build-in function element_random. The random number will between 0 and q.
 4.H4 function---Input a 160 bit long number and run SHA1 function to generate another 160 bit long number.
 5.As use SHA1 function as H2 function, thus the n is automatically set as 160.
 */


#include "ibe_full_ident.h"

#define SIZE 1000
#define RBITS 160
#define QBITS 512
#define ELE_BASE 10 

void get_private_key(char* ID, pairing_t pairing,element_t s,element_t Sid)
{
  element_t PublicKey,PrivateKey;
  element_init_G1(PublicKey, pairing);
  element_from_hash(PublicKey, ID, strlen(ID));   //Compute user public key
  /*element_mul_zn(Sid, PublicKey, s);
  element_printf("Private key Sid = %B\n", Sid);*/

  FILE *fp;
  char tmp[SIZE];
  fp = fopen("ibe_parameters/Sid.txt", "r");
  fgets(tmp, SIZE, fp);
  element_set_str(Sid, tmp, ELE_BASE); 
  fclose(fp);
  element_printf("Private key Sid = %B\n", Sid);
}

void get_public_key(char* ID, pairing_t pairing,element_t Qid)
{
  element_from_hash(Qid, ID, strlen(ID));
  element_printf("\nPublic key Qid = %B\n", Qid);
}


void rand_n(char* sigma)
{
  int i;
  int unit;
  char tempr[10];
  memset(sigma, 0, sizeof(char)*SIZE);//Clear the memory of sigma
  
  for (i = 0; i < 40; i++)
  {
  unit = rand() % 16;
  sprintf(tempr, "%X", unit);
  strcat(sigma, tempr);
  
  }
  
}

void encryption(char* shamessage,char* ID, element_t P,element_t Ppub,element_t U,char* V,char* W, pairing_t pairing)
{
  int i;
  char sgid[SIZE];   //Sender gid string representation
  char shagid[SIZE]; //Sender H2 function result
  char sigma[SIZE]; //Sender generate the sigma
  char msigma[2*SIZE]; //Sender concatenate the sigma and message digest
  char ssigma[SIZE]; //It is the result of H4(sigma)
  element_t r;
  element_t Qid;
  element_t gid;
  element_init_G1(Qid, pairing);
  element_init_GT(gid, pairing);
  element_init_Zr(r, pairing);
  rand_n(sigma); //Sender generate a sigma
  strcpy(msigma, sigma);
  strcat(msigma, shamessage);
  element_from_hash(r, msigma, strlen(msigma));
  element_mul_zn(U, P, r);
  element_printf("\nr = %B", r);
  element_printf("\nU = %B", U);
  get_public_key(ID, pairing, Qid);
  element_pairing(gid, Qid, Ppub);
  element_pow_zn(gid, gid, r);
  element_printf("\ngid = %B\n", gid);
  element_snprint(sgid, SIZE, gid);
  sha_fun(sgid, shagid); //H2(gid^r)
  sha_fun(sigma, ssigma); //H4(SIGMA)
  
  //Do the XOR operation to the sigma and shagid digest
  for (i = 0; i < 40; i++)
  {
  xor_operation(sigma[i], shagid[i], V);
  }
  //Do the XOR operation to the ssigma and message digest
  for (i = 0; i < 40; i++)
  {
  xor_operation(shamessage[i], ssigma[i], W);
  }
  
  printf("\nV=%s", V);
  printf("\nW=%s\n", W);
}

void decryption(element_t Sid,pairing_t pairing,element_t P,element_t U,char* V,char* W,element_t U_receiver,char* shamessage_receiver)
{
  
  int i;
  element_t rgid;
  element_t r_receiver;
  char sgid_receiver[SIZE]; //Receiver calculated gid string representation
  char shagid_receiver[SIZE]; //Receiver H2 function result
  char sigma_receiver[SIZE]; //Receiver compute the sigma
  char ssigma_receiver[SIZE]; //It is the result of H4(sigma_receiver)
  char msigma_receiver[2*SIZE]; //Receiver concatenate the sigma and message digest
  memset(sigma_receiver, 0, sizeof(char)*SIZE);//Clear the memory of sigma_receiver
  memset(shamessage_receiver, 0, sizeof(char)*SIZE);//Clear the memory of shamessage_receiver
  
  element_init_Zr(r_receiver,pairing);
  element_init_GT(rgid, pairing);
  element_pairing(rgid, Sid, U);
  element_printf("\nrgid = %B\n", rgid);
  element_snprint(sgid_receiver, SIZE, rgid);
  sha_fun(sgid_receiver, shagid_receiver); //Generate H2(e(dID,U));
  
  //XOR V and H2(e(dID,U))=sigma_receiver
  for (i = 0; i < 40; i++)
  {
  xor_operation(V[i], shagid_receiver[i], sigma_receiver);
  }
  
  sha_fun(sigma_receiver, ssigma_receiver);
  
  //XOR W andH4(sigma)
  for (i = 0; i < 40; i++)
  {
  xor_operation(W[i], ssigma_receiver[i], shamessage_receiver);
  }
  
  strcpy(msigma_receiver, sigma_receiver);
  strcat(msigma_receiver, shamessage_receiver);
  element_from_hash(r_receiver, msigma_receiver, strlen(msigma_receiver));
  element_mul_zn(U_receiver, P, r_receiver);
  
  
  
}

void setup_sys(int rbits,int qbits,element_t P,element_t Ppub,pairing_t pairing,element_t s )
{
  
  pbc_param_t par;   //Parameter to generate the pairing
  /*pbc_param_init_a_gen(par, rbits, qbits); //Initial the parameter for the pairing
  pairing_init_pbc_param(pairing, par);   //Initial the pairing
  
  FILE *pbc_param_file = fopen("ibe_parameters/pbc_param.txt", "w");
  pbc_param_out_str(pbc_param_file, par);
  fclose(pbc_param_file);*/

  char params[SIZE] = {'\0'};
  FILE *pbc_param_file = fopen("ibe_parameters/pbc_param.txt", "r");
  fread(params, 1, SIZE, pbc_param_file);
  fclose(pbc_param_file);
  pbc_param_init_set_str(par, params);
  pairing_init_pbc_param(pairing, par); //Initial the pairing

  
  //In our case, the pairing must be symmetric
  if (!pairing_is_symmetric(pairing))
  pbc_die("pairing must be symmetric");
  
  element_init_G1(P, pairing);
  element_init_G1(Ppub, pairing);
  element_init_Zr(s, pairing);
  /*element_random(P);
  element_random(s);
  element_mul_zn(Ppub, P, s);*/

  FILE *fp;
  char tmp[SIZE] = {'\0'};
  fp = fopen("ibe_parameters/P.txt", "r");  
  fgets(tmp, SIZE, fp);
  /*printf("\n^^%s\n", tmp);*/
  int cnt = element_set_str(P, tmp, ELE_BASE);
  /*element_printf("\n$$%B\n", P);*/
  fclose(fp);
  /*printf("\ncnt = %d\n", cnt);*/

  fp = fopen("ibe_parameters/Ppub.txt", "r");
  fgets(tmp, SIZE, fp);
  element_set_str(Ppub, tmp, ELE_BASE);
  fclose(fp);

  fp = fopen("ibe_parameters/s.txt", "r");
  fgets(tmp, SIZE, fp);
  element_set_str(s, tmp, ELE_BASE);
  fclose(fp);
}



int main(int argc, char **argv)
{
  int i;
  char qbits[5];
  char rbits[5];
  char ID[SIZE];
  char message[SIZE];//User message
  char shamessage[SIZE]; //The input message digest(sha1 result)
  
  char V[SIZE];
  char W[SIZE];
  memset(V, 0, sizeof(char)*SIZE);//Clear the memory of V
  memset(W, 0, sizeof(char)*SIZE);//Clear the memory of W
  char shamessage_receiver[SIZE]; //Receiver compute the message
  
  pairing_t pairing;   //The pair of bilinear map
  
  element_t P, Ppub, s, U, U_receiver, Qid, Sid;
  mpz_t messagehash;
  mpz_init(messagehash);
  
  
  
  printf("\n############SETUP############\n");
  /*printf("Please enter rbits:");
  scanf("%[0-9]", rbits);
  getchar();
  printf("\nPlease enter qbits:");
  scanf("%[0-9]", qbits);
  getchar();
  
  setup_sys(atoi(rbits), atoi(qbits), P, Ppub, pairing, s);*/
  setup_sys(RBITS, QBITS, P, Ppub, pairing, s);
  printf("System parameters have been set!\n");
  element_printf("P = %B\n", P);
  element_printf("Ppub = %B\n", Ppub);
    
  /*FILE *fp;
  fp = fopen("ibe_parameters/P.txt", "w");
  element_out_str(fp, ELE_BASE, P);
  fclose(fp);

  fp = fopen("ibe_parameters/Ppub.txt", "w");
  element_out_str(fp, ELE_BASE, Ppub);
  fclose(fp);

  fp = fopen("ibe_parameters/s.txt", "w");
  element_out_str(fp, ELE_BASE, s);
  fclose(fp);*/

  printf("###########EXTRACT###########\n");
  element_init_G1(Qid, pairing);
  element_init_G1(Sid, pairing);
  printf("Plase enter your ID:");
  scanf("%[ a-zA-Z0-9+*-!.,&*@{}$#]",ID);
  printf("\nID=%s\n",ID);
  getchar();
  get_private_key(ID,pairing,s,Sid);
  get_public_key(ID,pairing,Qid);
  
  /*fp = fopen("ibe_parameters/Sid.txt", "w");
  element_out_str(fp, ELE_BASE, Sid);
  fclose(fp);*/
 
  
  printf("##########ENCRPTION##########\n");
  printf("Plase enter the message to encrypt:");
  scanf("%[] a-zA-Z0-9+*-!.,&*@{}$#~`%^()[_=<>?/|\\:;\"']",message);//
  getchar();
  printf("\nThe original message=%s",message);//
  //Get the hash of the message
  sha_fun(message, shamessage);
  
  element_init_G1(U, pairing);
  encryption(shamessage,ID,P,Ppub,U,V,W,pairing);
  
  printf("Send (U,V,W) to the receiver!");
  
  printf("\n##########DECRYPTION##########");
  element_init_G1(U_receiver, pairing);
  decryption(Sid,pairing,P,U,V,W,U_receiver,shamessage_receiver);
  if (element_cmp(U, U_receiver) == 0)
  {
  element_printf("\nU=%B", U);
  element_printf("\nU_receiver=%B", U_receiver);
  printf("\nYeah!The message is decrpted!");
  printf("\nThe Message Disgest=%s\n", shamessage_receiver);
  }
  
  else
  {
  element_printf("\nU=%B", U);
  element_printf("\nU_receiver=%B", U_receiver);
  printf("\nOops!The ciphertext can not be accepted!\n");
  }
  
  element_clear(P);
  element_clear(Ppub);
  element_clear(Qid);
  element_clear(Sid);
  element_clear(U);
  element_clear(s);
  pairing_clear(pairing);
  
  return 0;
}


