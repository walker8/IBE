/**
 Boneh-Franklin Identity-Based Encryption from the Weil Pairing

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
 3.As I use SHA1 function as H2 function, thus the n is automatically set as 160.
 4.Use type A parameter to generate pairing.
 */



#include"ibe_basic_ident.h"


#define SIZE  100
#define RBITS 160
#define QBITS 512



void get_private_key(char* ID, pairing_t pairing, element_t s, element_t Sid)
{
    element_t PublicKey, PrivateKey;
    element_init_G1(PublicKey, pairing);
    element_from_hash(PublicKey, ID, strlen(ID));   //Compute user public key
    element_mul_zn(Sid, PublicKey, s);   //Compute user private key
    element_printf("Private key Sid1 = %B\n", Sid);
}

void get_public_key(char* ID, pairing_t pairing, element_t Qid)
{
  element_from_hash(Qid, ID, strlen(ID));   //Compute user public key*/
  element_printf("\nPublic key Qid1 = %B\n", Qid);
}

void encryption(char* shamessage, char* ID, element_t P, element_t P_pub,
                element_t U, char* V, pairing_t pairing)
{
  int i;
  char sgid[SIZE];   //Sender gid string representation
  char shagid[SIZE]; //Sender H2 function result
    
  element_t r;
  element_t Qid;
  element_t gid;
  element_init_G1(Qid, pairing);
  element_init_GT(gid, pairing);
  element_init_Zr(r, pairing);
  element_random(r);
  element_mul_zn(U, P, r);

  element_printf("U = %B", U);

  get_public_key(ID, pairing, Qid);
  element_pairing(gid, Qid, P_pub);
  element_pow_zn(gid, gid, r);
  element_snprint(sgid, SIZE, gid);
  sha_fun(sgid, shagid);
 
  element_printf("\ngid = %B\n", gid);
    
  //Do the XOR operation to the shamessage and shagid
  for (i = 0; i < 40; i++) {
    xor_operation(shamessage[i], shagid[i], V);
  }
  /*xor_operation(shamessage, shagid, V);*/
  /*printf("\n len_V = %d\n", strlen(V));  */
  printf("\nV=%s\n", V);
}

void decryption(element_t Sid, pairing_t pairing, element_t U, char* V,
                char* xor_result_receiver)
{
    
  int i;
  element_t rgid;
  char sgid_receiver[SIZE]; //Receiver calculated gid string representation
  char shagid_receiver[SIZE]; //Receiver H2 function result
  element_init_GT(rgid, pairing);
  element_pairing(rgid, Sid, U);
  element_snprint(sgid_receiver, SIZE, rgid);
  sha_fun(sgid_receiver, shagid_receiver);  //Generate H2(e(dID,U));
    
  element_printf("\nrgid = %B\n", rgid);
 
  //XOR V and the hash result above
  /*printf("\n b = %s\n", shagid_receiver);*/
  for (i = 0; i < 40; i++) {
    xor_operation(V[i], shagid_receiver[i], xor_result_receiver);
  }
  /*xor_operation(V, shagid_receiver, xor_result_receiver);*/
}

void setup_sys(int rbits,int qbits,element_t P,element_t Ppub,pairing_t pairing,element_t s )
{
    
  pbc_param_t par;   //Parameter to generate the pairing
  pbc_param_init_a_gen(par, rbits, qbits); //Initial the parameter for the pairing
  pairing_init_pbc_param(pairing, par);   //Initial the pairing
    
  //In our case, the pairing must be symmetric
  if (!pairing_is_symmetric(pairing))
    pbc_die("pairing must be symmetric");
    
  element_init_G1(P, pairing);
  element_init_G1(Ppub, pairing);
  element_init_Zr(s, pairing);
  element_random(P);
  element_random(s);
  element_mul_zn(Ppub, P, s);
    
}

int main()
{
    
  char qbits[5];
  char rbits[5];
  char ID[SIZE];   //User ID
  char message[SIZE];   //User message
  char shamessage[SIZE]; //The input message digest(sha1 result)
    
  char xor_result[SIZE]; //Sender XOR result---V
  char xor_result_receiver[SIZE];  //Receiver XOR result
  memset(xor_result, 0, sizeof(char)*SIZE);
  memset(xor_result_receiver, 0, sizeof(char)*SIZE);
    
    
  pairing_t pairing;   //The pair of bilinear map
    
  element_t P, Ppub, s, U, Qid, Sid;
  mpz_t messagehash;
  mpz_init(messagehash);
    
  printf("\n############SETUP############\n");
    /*printf("Please enter rbits:");
  scanf("%[0-9]", rbits);
    getchar();
  printf("\nPlease enter qbits:");
  scanf("%[0-9]", qbits);
    getchar();*/
    
  /*setup_sys(atoi(rbits), atoi(qbits), P, Ppub, pairing, s);*/
  setup_sys(RBITS, QBITS, P, Ppub, pairing, s);
  printf("System parameters have been set!\n");
  element_printf("P = %B\n", P);
  element_printf("Ppub = %B\n", Ppub);
    
    
    printf("###########EXTRACT###########\n");
    element_init_G1(Qid, pairing);
  element_init_G1(Sid, pairing);
  printf("Plase enter your ID:");
  scanf("%[ a-zA-Z0-9+*-!.,&*@{}$#]", ID);
  printf("\nID=%s\n", ID);
    getchar();
    get_private_key(ID, pairing, s, Sid);
  get_public_key(ID, pairing, Qid);
  /*element_printf("\n**Sid** = %B\n", Sid);
  element_printf("\n**Qid** = %B\n", Qid);*/
  printf("##########ENCRPTION##########\n");
    printf("\nPlase enter the message to encrypt:");
  scanf("%[] a-zA-Z0-9+*-!.,&*@{}$#~`%^()[_=<>?/|\\:;\"']", message);
  /*scanf("%[] a-zA-Z0-9+*-!.,&*@{}$#~`%^()[_=<>?/|\\:;\"']", shamessage);*/
  getchar();
  printf("The original message=%s", message);
  /*printf("The original message=%s", shamessage);*/
    
    sha_fun(message, shamessage);   //Get the message digest
  printf("\nThe message hash=%s\n", shamessage);
    
    element_init_G1(U, pairing);
  encryption(shamessage, ID, P, Ppub, U, xor_result, pairing);
  printf("Send <U,V> to the receiver!\n");
    
  printf("##########DECRYPTION##########");
  decryption(Sid, pairing, U, xor_result, xor_result_receiver);
  printf("\nThe recovery message digest is %s\n", xor_result_receiver);
  printf("The original message digest is %s\n", shamessage);
    
  if (strcmp(xor_result_receiver, shamessage) == 0) {
        
    printf("Yeah!The message has been decrpted!\n");
  }
    
  else {
    printf("Oops!The message can not be decrpted!\n");
  }
    
  //Free space
  element_clear(P);
  element_clear(Ppub);
  element_clear(Qid);
  element_clear(Sid);
  element_clear(U);
  element_clear(s);
  pairing_clear(pairing);
    
  return 0;
}
