
#ifndef _BF_4_2_H_
#define _BF_4_2_H_

#include <pbc.h>
#include <gmp.h>
#include <stdio.h>
#include <string.h>
//#include "sha1.h"
#include <stdlib.h>
#include "utils.h"

void get_private_key(element_t Sid);
void get_public_key(char* ID, element_t Qid);
void rand_n(char* sigma);
void encryption(char* shamessage, char* ID, element_t P, element_t Ppub, element_t U, char* V, char* W, pairing_t pairing);
void decryption(element_t Sid, pairing_t pairing, element_t P, element_t U, char* V, char* W, element_t U_receiver, char* shamessage_receiver);
void setup_sys(element_t P, element_t Ppub, pairing_t pairing, element_t s);
char* encrypt_mail_msg(char *mail_msg, char *ID);

#endif
