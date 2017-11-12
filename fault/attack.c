// AES fault attack implimentation based on "Differential Fault Analysis
// of the Advanced Encryption Standard using a Single Fault" by Michael
// Tunstall, Debdeep Mukhopadhyay and Subidh Ali

#include "attack.h"

#define BUFFER_SIZE ( 80 )

pid_t pid = 0;
int target_raw[ 2 ];
int attack_raw[ 2 ];

FILE* target_out = NULL;
FILE* target_in = NULL;

// look up tables for FF multiplication
uint8_t table_2[] = {0x00,0x02,0x04,0x06,0x08,0x0a,0x0c,0x0e,0x10,0x12,0x14,0x16,0x18,0x1a,0x1c,0x1e,
0x20,0x22,0x24,0x26,0x28,0x2a,0x2c,0x2e,0x30,0x32,0x34,0x36,0x38,0x3a,0x3c,0x3e,
0x40,0x42,0x44,0x46,0x48,0x4a,0x4c,0x4e,0x50,0x52,0x54,0x56,0x58,0x5a,0x5c,0x5e,
0x60,0x62,0x64,0x66,0x68,0x6a,0x6c,0x6e,0x70,0x72,0x74,0x76,0x78,0x7a,0x7c,0x7e,
0x80,0x82,0x84,0x86,0x88,0x8a,0x8c,0x8e,0x90,0x92,0x94,0x96,0x98,0x9a,0x9c,0x9e,
0xa0,0xa2,0xa4,0xa6,0xa8,0xaa,0xac,0xae,0xb0,0xb2,0xb4,0xb6,0xb8,0xba,0xbc,0xbe,
0xc0,0xc2,0xc4,0xc6,0xc8,0xca,0xcc,0xce,0xd0,0xd2,0xd4,0xd6,0xd8,0xda,0xdc,0xde,
0xe0,0xe2,0xe4,0xe6,0xe8,0xea,0xec,0xee,0xf0,0xf2,0xf4,0xf6,0xf8,0xfa,0xfc,0xfe,
0x1b,0x19,0x1f,0x1d,0x13,0x11,0x17,0x15,0x0b,0x09,0x0f,0x0d,0x03,0x01,0x07,0x05,
0x3b,0x39,0x3f,0x3d,0x33,0x31,0x37,0x35,0x2b,0x29,0x2f,0x2d,0x23,0x21,0x27,0x25,
0x5b,0x59,0x5f,0x5d,0x53,0x51,0x57,0x55,0x4b,0x49,0x4f,0x4d,0x43,0x41,0x47,0x45,
0x7b,0x79,0x7f,0x7d,0x73,0x71,0x77,0x75,0x6b,0x69,0x6f,0x6d,0x63,0x61,0x67,0x65,
0x9b,0x99,0x9f,0x9d,0x93,0x91,0x97,0x95,0x8b,0x89,0x8f,0x8d,0x83,0x81,0x87,0x85,
0xbb,0xb9,0xbf,0xbd,0xb3,0xb1,0xb7,0xb5,0xab,0xa9,0xaf,0xad,0xa3,0xa1,0xa7,0xa5,
0xdb,0xd9,0xdf,0xdd,0xd3,0xd1,0xd7,0xd5,0xcb,0xc9,0xcf,0xcd,0xc3,0xc1,0xc7,0xc5,
0xfb,0xf9,0xff,0xfd,0xf3,0xf1,0xf7,0xf5,0xeb,0xe9,0xef,0xed,0xe3,0xe1,0xe7,0xe5};

uint8_t table_3[] = {0x00,0x03,0x06,0x05,0x0c,0x0f,0x0a,0x09,0x18,0x1b,0x1e,0x1d,0x14,0x17,0x12,0x11,
0x30,0x33,0x36,0x35,0x3c,0x3f,0x3a,0x39,0x28,0x2b,0x2e,0x2d,0x24,0x27,0x22,0x21,
0x60,0x63,0x66,0x65,0x6c,0x6f,0x6a,0x69,0x78,0x7b,0x7e,0x7d,0x74,0x77,0x72,0x71,
0x50,0x53,0x56,0x55,0x5c,0x5f,0x5a,0x59,0x48,0x4b,0x4e,0x4d,0x44,0x47,0x42,0x41,
0xc0,0xc3,0xc6,0xc5,0xcc,0xcf,0xca,0xc9,0xd8,0xdb,0xde,0xdd,0xd4,0xd7,0xd2,0xd1,
0xf0,0xf3,0xf6,0xf5,0xfc,0xff,0xfa,0xf9,0xe8,0xeb,0xee,0xed,0xe4,0xe7,0xe2,0xe1,
0xa0,0xa3,0xa6,0xa5,0xac,0xaf,0xaa,0xa9,0xb8,0xbb,0xbe,0xbd,0xb4,0xb7,0xb2,0xb1,
0x90,0x93,0x96,0x95,0x9c,0x9f,0x9a,0x99,0x88,0x8b,0x8e,0x8d,0x84,0x87,0x82,0x81,
0x9b,0x98,0x9d,0x9e,0x97,0x94,0x91,0x92,0x83,0x80,0x85,0x86,0x8f,0x8c,0x89,0x8a,
0xab,0xa8,0xad,0xae,0xa7,0xa4,0xa1,0xa2,0xb3,0xb0,0xb5,0xb6,0xbf,0xbc,0xb9,0xba,
0xfb,0xf8,0xfd,0xfe,0xf7,0xf4,0xf1,0xf2,0xe3,0xe0,0xe5,0xe6,0xef,0xec,0xe9,0xea,
0xcb,0xc8,0xcd,0xce,0xc7,0xc4,0xc1,0xc2,0xd3,0xd0,0xd5,0xd6,0xdf,0xdc,0xd9,0xda,
0x5b,0x58,0x5d,0x5e,0x57,0x54,0x51,0x52,0x43,0x40,0x45,0x46,0x4f,0x4c,0x49,0x4a,
0x6b,0x68,0x6d,0x6e,0x67,0x64,0x61,0x62,0x73,0x70,0x75,0x76,0x7f,0x7c,0x79,0x7a,
0x3b,0x38,0x3d,0x3e,0x37,0x34,0x31,0x32,0x23,0x20,0x25,0x26,0x2f,0x2c,0x29,0x2a,
0x0b,0x08,0x0d,0x0e,0x07,0x04,0x01,0x02,0x13,0x10,0x15,0x16,0x1f,0x1c,0x19,0x1a};

// sbox and inverse sbox lookup tables
uint8_t subByte[] = {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};

uint8_t invSubByte[] = {0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d};

// rcon lookup table
unsigned char rcon[] = {0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};

// data structures for storing the solution hypothesis'
// for 4 different deltas (stored in deltas->d[x]) each complete solution
// is stored in a linked list of solutions where the arrays a,b,c,d contain
// the possible solutions satisfying one value of delta for each of the 4
// equations comprising each delta value respectively
typedef struct solution{
	uint8_t a[4]; int count_a;
	uint8_t b[4]; int count_b;
	uint8_t c[4]; int count_c;
	uint8_t d[4]; int count_d;
	struct solution* next;
} solution;

typedef struct deltas{
	solution* d[4];
} deltas;

solution* newSolution(){
	solution* new_solution = (solution*)malloc(sizeof(solution));
	new_solution->count_a = 0;
	new_solution->count_b = 0;
	new_solution->count_c = 0;
	new_solution->count_d = 0;
	new_solution->next = NULL;
	return new_solution;
}

deltas* newDeltas(){
	deltas* new_deltas = (deltas*)malloc(sizeof(deltas));
	for(int i = 0; i < 4; i++){
		new_deltas->d[i] = NULL;
	}
	return new_deltas;
}

void destroyDeltas(deltas* set){
	for(int i = 0; i < 4; i++){
		solution* cursor = set->d[i];
		while(cursor != NULL){
			solution* temp = cursor->next;
			free(cursor);
			cursor = temp;
		}
	}
	free(set);
}

void printDeltas(deltas* deltaSet){
	printf("deltas\n");
	for(int i = 0; i < 4; i++){
		solution* cursor = deltaSet->d[i];
		printf("|  +--d[%d]\n",i);
		while(cursor != NULL){
			printf("|  |  +--[");
			for(int j = 0; j < cursor->count_a; j++){
				printf("%02x",cursor->a[j]);
				if(j != cursor->count_a-1){
					printf(",");
				}
			}
			printf("][");
			for(int j = 0; j < cursor->count_b; j++){
				printf("%02x",cursor->b[j]);
				if(j != cursor->count_b-1){
					printf(",");
				}
			}
			printf("][");
			for(int j = 0; j < cursor->count_c; j++){
				printf("%02x",cursor->c[j]);
				if(j != cursor->count_c-1){
					printf(",");
				}
			}
			printf("][");
			for(int j = 0; j < cursor->count_d; j++){
				printf("%02x",cursor->d[j]);
				if(j != cursor->count_d-1){
					printf(",");
				}
			}
			printf("]\n");
			cursor = cursor->next;
		}
	}
}

deltas* addSolution(deltas* deltaSet, int delta, solution* new_solution){
	solution* cursor;
	if(delta > 3){
		printf("error: delta out of bounds\n");
	} else if(deltaSet->d[delta] == NULL){
		deltaSet->d[delta] = new_solution;
	} else {
		cursor = deltaSet->d[delta];
		while(cursor->next != NULL){
			cursor = cursor->next;
		}
		cursor->next = new_solution;
	}
	return deltaSet;
}

deltas* intersection(deltas* set1, deltas* set2){
	solution *set1cursor,*set2cursor;
	deltas* intersect = newDeltas();
	solution *scratch = newSolution();

	for(int d = 0; d < 4; d++){
		set1cursor = set1->d[d];
		while(set1cursor != NULL){
			set2cursor = set2->d[d];
			while(set2cursor != NULL){
				int full = 0;
				for(int i = 0; i < set1cursor->count_a; i++){
					for(int j = 0; j < set2cursor->count_a; j++){
						if(set1cursor->a[i] == set2cursor->a[j]){
							scratch->a[scratch->count_a] = set1cursor->a[i];
							scratch->count_a = scratch->count_a + 1;
							if(full == 0){
								full = 1;
							}
						}
					}
				}
				for(int i = 0; i < set1cursor->count_b; i++){
					for(int j = 0; j < set2cursor->count_b; j++){
						if(set1cursor->b[i] == set2cursor->b[j]){
							scratch->b[scratch->count_b] = set1cursor->b[i];
							scratch->count_b = scratch->count_b + 1;
							if(full == 1){
								full = 2;
							}
						}
					}
				}
				for(int i = 0; i < set1cursor->count_c; i++){
					for(int j = 0; j < set2cursor->count_c; j++){
						if(set1cursor->c[i] == set2cursor->c[j]){
							scratch->c[scratch->count_c] = set1cursor->c[i];
							scratch->count_c = scratch->count_c + 1;
							if(full == 2){
								full = 3;
							}
						}
					}
				}
				for(int i = 0; i < set1cursor->count_d; i++){
					for(int j = 0; j < set2cursor->count_d; j++){
						if(set1cursor->d[i] == set2cursor->d[j]){
							scratch->d[scratch->count_d] = set1cursor->d[i];
							scratch->count_d = scratch->count_d + 1;
							if(full == 3){
								full = 4;
							}
						}
					}
				}
				if(full == 4){
					intersect = addSolution(intersect,d,scratch);
					scratch = newSolution();
				} else {
					scratch->count_a = 0;
					scratch->count_b = 0;
					scratch->count_c = 0;
					scratch->count_d = 0;
				}
				set2cursor = set2cursor->next;
			}
			set1cursor = set1cursor->next;
		}
	}
	return intersect;
}

int validSolution(deltas* deltas){
	for(int i = 0; i < 4; i++){
		if(deltas->d[i] == NULL){
			return 0;
		} else if(deltas->d[i]->next != NULL){
			return 0;
		} else if(deltas->d[i]->count_a != 1
				||deltas->d[i]->count_b != 1
				||deltas->d[i]->count_c != 1
				||deltas->d[i]->count_d != 1){
			return 0;
		}
	}
	return 1;
}

// interact with target with message m,
// fault specification (r,f,p,i,j), if r is -1 interaction has no fault
// ciphertext c
void interact(mpz_t m, int r, int f, int p, int i, int j, mpz_t c){
	char* t = NULL;
	char s[33];
	for(int x = 0; x < 32; x++){
		s[x] = '0';
	}
	s[32] = '\0';
	t = mpz_get_str(t,-16,m);

	for(int x = 0; x < (int)strlen(t); x++){
		s[x + 32 - strlen(t)] = t[x];
	}

	if(r == -1){
		fprintf(target_in, "\n");
	} else {
		fprintf(target_in, "%d,", r);
		fprintf(target_in, "%d,", f);
		fprintf(target_in, "%d,", p);
		fprintf(target_in, "%d,", i);
		fprintf(target_in, "%d\n", j);
	}
	fprintf(target_in, "%s\n", s); fflush( target_in );
	if ( 1 != fscanf( target_out, "%s", s) ){
		abort();
	}

	mpz_set_str(c,s,16);
}

uint32_t subWord(uint32_t input){
	uint32_t output;
	unsigned char c0,c1,c2,c3;

	c0 = input >> 24;
	c1 = 255 & (input >> 16);
	c2 = 255 & (input >> 8);
	c3 = 255 & input;

	c0 = subByte[c0];
	c1 = subByte[c1];
	c2 = subByte[c2];
	c3 = subByte[c3];

	output = (c0 << 24) + (c1 << 16) + (c2 << 8) + c3;
	
	return output;
}

uint32_t rotWord(uint32_t input){
	uint32_t output;
	unsigned char c0,c1,c2,c3;
	unsigned char d0,d1,d2,d3;

	c0 = input >> 24;
	c1 = 255 & (input >> 16);
	c2 = 255 & (input >> 8);
	c3 = 255 & input;

	d0 = c1;
	d1 = c2;
	d2 = c3;
	d3 = c0;

	output = (d0 << 24) + (d1 << 16) + (d2 << 8) + d3;
	
	return output;
}

void invRoundKey(mpz_t output, mpz_t input){
	uint32_t prev;
	uint32_t words[44];
	mpz_t mask,temp;
	mpz_init(mask);
	mpz_init(temp);

	mpz_set_ui(mask,1);
	mpz_mul_2exp(mask,mask,32);
	mpz_sub_ui(mask,mask,1);
	mpz_and(temp,input,mask);
	words[43] = mpz_get_ui(temp);

	mpz_mul_2exp(mask,mask,32);
	mpz_and(temp,input,mask);
	mpz_div_2exp(temp,temp,32);
	words[42] = mpz_get_ui(temp);

	mpz_mul_2exp(mask,mask,32);
	mpz_and(temp,input,mask);
	mpz_div_2exp(temp,temp,64);
	words[41] = mpz_get_ui(temp);

	mpz_mul_2exp(mask,mask,32);
	mpz_and(temp,input,mask);
	mpz_div_2exp(temp,temp,96);
	words[40] = mpz_get_ui(temp);

	for(int i = 39; i >= 0; i--){
		prev = words[i+3];
		if(i % 4 == 0){
			prev = rotWord(prev);
			prev = subWord(prev);
			prev = prev ^ (rcon[(i/4) + 1] << 24);
		}
		words[i] = words[i+4] ^ prev;
	}

	mpz_set_ui(temp,0);
	mpz_add_ui(temp,temp,words[0]);
	mpz_mul_2exp(temp,temp,32);
	mpz_add_ui(temp,temp,words[1]);
	mpz_mul_2exp(temp,temp,32);
	mpz_add_ui(temp,temp,words[2]);
	mpz_mul_2exp(temp,temp,32);
	mpz_add_ui(temp,temp,words[3]);

	mpz_set(output,temp);

	mpz_clear(mask);
	mpz_clear(temp);
}

deltas* buildDeltas(mpz_t x, mpz_t x_fault){
	mpz_t temp,mask;
	mpz_init(temp);
	mpz_init(mask);
	uint8_t xBytes[16];
	uint8_t x_faultBytes[16];
	deltas* deltaSet = newDeltas();
	mpz_set_ui(mask,255);
	mpz_mul_2exp(mask,mask,120);
	int shift = 120;
	uint8_t value;

	for(int i = 0; i < 16; i++){
		mpz_and(temp,mask,x);
		mpz_div_2exp(temp,temp,shift);
		xBytes[i] = (uint8_t)mpz_get_ui(temp);

		mpz_and(temp,mask,x_fault);
		mpz_div_2exp(temp,temp,shift);
		x_faultBytes[i] = (uint8_t)mpz_get_ui(temp);

		mpz_div_2exp(mask,mask,8);
		shift = shift - 8;
	}

	solution* scratch = newSolution();

	for(int i = 0; i < 256; i++){
		for(int k1 = 0; k1 < 256; k1++){
			value = invSubByte[xBytes[0] ^ k1] ^ invSubByte[x_faultBytes[0] ^ k1];
			if(value == table_2[i]){
				scratch->a[scratch->count_a] = k1;
				scratch->count_a = scratch->count_a + 1;
			}
		}
		for(int k14 = 0; k14 < 256; k14++){
			value = invSubByte[xBytes[13] ^ k14] ^ invSubByte[x_faultBytes[13] ^ k14];
			if(value == i){
				scratch->b[scratch->count_b] = k14;
				scratch->count_b = scratch->count_b + 1;
			}
		}
		for(int k11 = 0; k11 < 256; k11++){
			value = invSubByte[xBytes[10] ^ k11] ^ invSubByte[x_faultBytes[10] ^ k11];
			if(value == i){
				scratch->c[scratch->count_c] = k11;
				scratch->count_c = scratch->count_c + 1;
			}
		}
		for(int k8 = 0; k8 < 256; k8++){
			value = invSubByte[xBytes[7] ^ k8] ^ invSubByte[x_faultBytes[7] ^ k8];
			if(value == table_3[i]){
				scratch->d[scratch->count_d] = k8;
				scratch->count_d = scratch->count_d + 1;
			}
		}

		if(scratch->count_a != 0 &&
			scratch->count_b != 0 &&
			scratch->count_c != 0 &&
			scratch->count_d != 0){
			deltaSet = addSolution(deltaSet,0,scratch);
			scratch = newSolution();
		} else {
			scratch->count_a = 0;
			scratch->count_b = 0;
			scratch->count_c = 0;
			scratch->count_d = 0;
		}
	}
	for(int i = 0; i < 256; i++){
		for(int k5 = 0; k5 < 256; k5++){
			value = invSubByte[xBytes[4] ^ k5] ^ invSubByte[x_faultBytes[4] ^ k5];
			if(value == i){
				scratch->a[scratch->count_a] = k5;
				scratch->count_a = scratch->count_a + 1;
			}
		}
		for(int k2 = 0; k2 < 256; k2++){
			value = invSubByte[xBytes[1] ^ k2] ^ invSubByte[x_faultBytes[1] ^ k2];
			if(value == i){
				scratch->b[scratch->count_b] = k2;
				scratch->count_b = scratch->count_b + 1;
			}
		}
		for(int k15 = 0; k15 < 256; k15++){
			value = invSubByte[xBytes[14] ^ k15] ^ invSubByte[x_faultBytes[14] ^ k15];
			if(value == table_3[i]){
				scratch->c[scratch->count_c] = k15;
				scratch->count_c = scratch->count_c + 1;
			}
		}
		for(int k12 = 0; k12 < 256; k12++){
			value = invSubByte[xBytes[11] ^ k12] ^ invSubByte[x_faultBytes[11] ^ k12];
			if(value == table_2[i]){
				scratch->d[scratch->count_d] = k12;
				scratch->count_d = scratch->count_d + 1;
			}
		}

		if(scratch->count_a != 0 &&
			scratch->count_b != 0 &&
			scratch->count_c != 0 &&
			scratch->count_d != 0){
			deltaSet = addSolution(deltaSet,1,scratch);
			scratch = newSolution();
		} else {
			scratch->count_a = 0;
			scratch->count_b = 0;
			scratch->count_c = 0;
			scratch->count_d = 0;
		}
	}
	for(int i = 0; i < 256; i++){
		for(int k9 = 0; k9 < 256; k9++){
			value = invSubByte[xBytes[8] ^ k9] ^ invSubByte[x_faultBytes[8] ^ k9];
			if(value == i){
				scratch->a[scratch->count_a] = k9;
				scratch->count_a = scratch->count_a + 1;
			}
		}
		for(int k6 = 0; k6 < 256; k6++){
			value = invSubByte[xBytes[5] ^ k6] ^ invSubByte[x_faultBytes[5] ^ k6];
			if(value == table_3[i]){
				scratch->b[scratch->count_b] = k6;
				scratch->count_b = scratch->count_b + 1;
			}
		}
		for(int k3 = 0; k3 < 256; k3++){
			value = invSubByte[xBytes[2] ^ k3] ^ invSubByte[x_faultBytes[2] ^ k3];
			if(value == table_2[i]){
				scratch->c[scratch->count_c] = k3;
				scratch->count_c = scratch->count_c + 1;
			}
		}
		for(int k16 = 0; k16 < 256; k16++){
			value = invSubByte[xBytes[15] ^ k16] ^ invSubByte[x_faultBytes[15] ^ k16];
			if(value == i){
				scratch->d[scratch->count_d] = k16;
				scratch->count_d = scratch->count_d + 1;
			}
		}

		if(scratch->count_a != 0 &&
			scratch->count_b != 0 &&
			scratch->count_c != 0 &&
			scratch->count_d != 0){
			deltaSet = addSolution(deltaSet,2,scratch);
			scratch = newSolution();
		} else {
			scratch->count_a = 0;
			scratch->count_b = 0;
			scratch->count_c = 0;
			scratch->count_d = 0;
		}
	}
	for(int i = 0; i < 256; i++){
		for(int k13 = 0; k13 < 256; k13++){
			value = invSubByte[xBytes[12] ^ k13] ^ invSubByte[x_faultBytes[12] ^ k13];
			if(value == table_3[i]){
				scratch->a[scratch->count_a] = k13;
				scratch->count_a = scratch->count_a + 1;
			}
		}
		for(int k10 = 0; k10 < 256; k10++){
			value = invSubByte[xBytes[9] ^ k10] ^ invSubByte[x_faultBytes[9] ^ k10];
			if(value == table_2[i]){
				scratch->b[scratch->count_b] = k10;
				scratch->count_b = scratch->count_b + 1;
			}
		}
		for(int k7 = 0; k7 < 256; k7++){
			value = invSubByte[xBytes[6] ^ k7] ^ invSubByte[x_faultBytes[6] ^ k7];
			if(value == i){
				scratch->c[scratch->count_c] = k7;
				scratch->count_c = scratch->count_c + 1;
			}
		}
		for(int k4 = 0; k4 < 256; k4++){
			value = invSubByte[xBytes[3] ^ k4] ^ invSubByte[x_faultBytes[3] ^ k4];
			if(value == i){
				scratch->d[scratch->count_d] = k4;
				scratch->count_d = scratch->count_d + 1;
			}
		}

		if(scratch->count_a != 0 &&
			scratch->count_b != 0 &&
			scratch->count_c != 0 &&
			scratch->count_d != 0){
			deltaSet = addSolution(deltaSet,3,scratch);
			scratch = newSolution();
		} else {
			scratch->count_a = 0;
			scratch->count_b = 0;
			scratch->count_c = 0;
			scratch->count_d = 0;
		}
	}
	
	free(scratch);
	mpz_clear(temp);
	mpz_clear(mask);

	return deltaSet;
}

void assembleKey(mpz_t output, deltas* solution){
	mpz_set_ui(output,0);
	mpz_add_ui(output,output,solution->d[0]->a[0]);
	mpz_mul_2exp(output,output,8);
	mpz_add_ui(output,output,solution->d[1]->b[0]);
	mpz_mul_2exp(output,output,8);
	mpz_add_ui(output,output,solution->d[2]->c[0]);
	mpz_mul_2exp(output,output,8);
	mpz_add_ui(output,output,solution->d[3]->d[0]);
	mpz_mul_2exp(output,output,8);
	mpz_add_ui(output,output,solution->d[1]->a[0]);
	mpz_mul_2exp(output,output,8);
	mpz_add_ui(output,output,solution->d[2]->b[0]);
	mpz_mul_2exp(output,output,8);
	mpz_add_ui(output,output,solution->d[3]->c[0]);
	mpz_mul_2exp(output,output,8);
	mpz_add_ui(output,output,solution->d[0]->d[0]);
	mpz_mul_2exp(output,output,8);
	mpz_add_ui(output,output,solution->d[2]->a[0]);
	mpz_mul_2exp(output,output,8);
	mpz_add_ui(output,output,solution->d[3]->b[0]);
	mpz_mul_2exp(output,output,8);
	mpz_add_ui(output,output,solution->d[0]->c[0]);
	mpz_mul_2exp(output,output,8);
	mpz_add_ui(output,output,solution->d[1]->d[0]);
	mpz_mul_2exp(output,output,8);
	mpz_add_ui(output,output,solution->d[3]->a[0]);
	mpz_mul_2exp(output,output,8);
	mpz_add_ui(output,output,solution->d[0]->b[0]);
	mpz_mul_2exp(output,output,8);
	mpz_add_ui(output,output,solution->d[1]->c[0]);
	mpz_mul_2exp(output,output,8);
	mpz_add_ui(output,output,solution->d[2]->d[0]);
}

void attack(){
	int interactions = 0;
	uint64_t seed;
	mpz_t a,c,c_fault,maxSize;
	mpz_init(a);
	mpz_init(c);
	mpz_init(c_fault);
	mpz_init(maxSize);

	mpz_set_ui(maxSize,2);
	mpz_pow_ui(maxSize,maxSize,128);

	int randomData = open("/dev/urandom", O_RDONLY);
	int success = -1;
	while(success < 0){
		success = read(randomData, &seed, (sizeof(seed)));
	}
	gmp_randstate_t r_state;
	gmp_randinit_default(r_state);
	gmp_randseed_ui(r_state,seed);

	int correct = 0;
	while(correct != 1){
		// randomly generates plaintext a
		mpz_urandomm(a,r_state,maxSize);
		gmp_printf("a = %ZX\n",a);
		interact(a,-1,0,0,0,0,c);
		// collects ciphertext c, and faulty ciphertext c_fault
		// if c_fault is the same as c it reattempts
		gmp_printf("c = %ZX\n",c);
		interact(a,8,1,0,0,0,c_fault);
		gmp_printf("c_fault = %ZX\n",c_fault);
		while(mpz_cmp(c,c_fault) == 0){
			interact(a,8,1,0,0,0,c_fault);
		}

		// creates hypothesis based on c and c_fault
		deltas* set1 = buildDeltas(c,c_fault);
		printDeltas(set1);

		// collects a second c_fault
		interact(a,8,1,0,0,0,c_fault);
		while(mpz_cmp(c,c_fault) == 0){
			interact(a,8,1,0,0,0,c_fault);
		}
		// creates hypothsis based on new c_fault
		deltas* set2 = buildDeltas(c,c_fault);
		printDeltas(set2);
		// takes intersection of two hypothesis'
		deltas* intersect = intersection(set1,set2);
		printDeltas(intersect);
		destroyDeltas(set1);
		destroyDeltas(set2);
		
		// if intersection only contains one solution loop terminates
		correct = validSolution(intersect);
		// assembles mpz_t key from delta*
		assembleKey(a,intersect);
		interactions += 3;
	}

	gmp_printf("10th round key = %ZX\n",a);
	// inverses round key
	invRoundKey(a,a);
	gmp_printf("AES cipher key = %ZX\n",a);
	printf("number of interactions: %d\n",interactions);

	mpz_clear(a);
	mpz_clear(c);
	mpz_clear(c_fault);
	mpz_clear(maxSize);
}

void cleanup(){
	fclose( target_in  );
	fclose( target_out );

	close( target_raw[ 0 ] );
	close( target_raw[ 1 ] );
	close( attack_raw[ 0 ] );
	close( attack_raw[ 1 ] );

	if( pid > 0 ) {
		kill( pid, SIGKILL );
	}

	exit( 1 );
}

int main( int argc, char* argv[]) {
	if( pipe( target_raw ) == -1){
		abort();
	}
	if( pipe( attack_raw ) == -1){
		abort();
	}
	
	pid = fork();

	if( pid > 0 ){
		if( ( target_out = fdopen( attack_raw[ 0 ], "r") ) == NULL ){
			abort();
		}
		if( ( target_in  = fdopen( target_raw[ 1 ], "w") ) == NULL ){
			abort();
		}

		attack();

	} else if (pid == 0){
		close( STDOUT_FILENO );
		if( dup2( attack_raw[ 1 ], STDOUT_FILENO ) == -1 ){
			abort();
		}
		close( STDIN_FILENO );
		if( dup2( target_raw[ 0 ], STDIN_FILENO ) == -1 ){
			abort();
		}

		execl( argv[ 1 ], argv[ 0 ], NULL );
	} else if ( pid < 0 ){
		abort();
	}

	cleanup( SIGINT );
	
	return 0;
}
