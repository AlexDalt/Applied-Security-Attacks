#include "attack.h"

#define BUFFER_SIZE ( 80 )
#define SAMPLE_SIZE 20
#define TRACE_SIZE 2500

pid_t pid = 0;
int target_raw[ 2 ];
int attack_raw[ 2 ];

FILE* target_out = NULL;
FILE* target_in = NULL;

// subByte lookup table
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

// interact with oracle with i block adress, j 1-block XTS-AES tweak and
// return the tracePointer, traceLength, and plaintext m
void interact(int i, mpz_t j, uint8_t** tracePointer, int* traceLength, mpz_t m){
	char s[33];
	char l[32];
	char* gmpstr = NULL;
	for(int x = 0; x < 32; x++){
		s[x] = '0';
	}
	s[32] = '\0';
	gmpstr = mpz_get_str(gmpstr,-16,j);
	for(int x = 0; x < (int)strlen(gmpstr); x++){
		s[x + 32 - strlen(gmpstr)] = gmpstr[x];
	}

	fprintf(target_in, "%d\n", i); 
	fprintf(target_in, "%s\n", s); fflush( target_in );

	for(int x = 0; x < 32; x++){
		if ( 1 != fscanf( target_out, "%c", &l[x])){
			abort();
		} else {
			if(l[x] == ','){
				l[x] = '\0';
				break;
			} 
		}
	}

	int length = atoi(l);
	uint8_t t[length];

	for(int x = 0; x < length; x++){
		for( int y = 0; y < 32; y++){
			if( 1 != fscanf( target_out, "%c", &l[y])){
				abort();
			} else {
				if(l[y] == ',' || l[y] == '\n'){
					l[y] = '\0';
					break;
				}
			}
		}
		t[x] = atoi(l);
	}

	if ( 1 != fscanf( target_out, "%s", s) ){
		abort();
	}

	*tracePointer = t;
	*traceLength = length;
	mpz_set_str(m,s,16);
}

// calculate the hamming weight of a byte
int hamming(uint8_t temp){
	int output = 0;

	for(int i = 0; i < 8; i++){
		output = output + ((temp & (1 << i)) >> i);
	}

	return output;
}

// gives the correlation between all values of a key hypothesis
// and all values at a given time
double correlation(int h[SAMPLE_SIZE], uint8_t t[SAMPLE_SIZE]){
	double sx = 0.0;
	double sy = 0.0;
	double sxx = 0.0;
	double syy = 0.0;
	double sxy = 0.0;

	for(int i = 0; i < SAMPLE_SIZE; i++){
		double x = (double)h[i];
		double y = (double)t[i];

		sx += x;
		sy += y;
		sxx += x*x;
		syy += y*y;
		sxy += x*y;
	}

	double cov = sxy/SAMPLE_SIZE - sx*sy/SAMPLE_SIZE/SAMPLE_SIZE;
	double sigmax = sqrt(sxx/SAMPLE_SIZE - sx*sx/SAMPLE_SIZE/SAMPLE_SIZE);
	double sigmay = sqrt(syy/SAMPLE_SIZE - sy*sy/SAMPLE_SIZE/SAMPLE_SIZE);

	return cov/sigmax/sigmay;
}

// returns the byte hypothesis with the largest correlation
uint8_t getKeyByte(int h[256][SAMPLE_SIZE], uint8_t d[TRACE_SIZE][SAMPLE_SIZE]){
	double bestCor = 0;
	uint8_t bestByte = 0;
	for(int i = 0; i < 256; i++){
		for(int j = 0; j < TRACE_SIZE; j++){
			double cor = correlation(h[i],d[j]);
			if(cor > bestCor){
				bestCor = cor;
				bestByte = i;
			}
		}
	}
	printf("byte = %02x, with correlation = %f\n",bestByte,bestCor);
	return bestByte;
}

// populates hypothesis table h with the hamming weight of the relevent byte
void hypothesisTable(int h[256][SAMPLE_SIZE], mpz_t d[SAMPLE_SIZE], int byte){
	mpz_t temp,mask;
	mpz_init(temp);
	mpz_init(mask);
	mpz_set_ui(mask,255);
	mpz_mul_2exp(mask,mask,120-(byte*8));
	for(int x = 0; x < SAMPLE_SIZE; x++){
		mpz_and(temp,mask,d[x]);
		mpz_div_2exp(temp,temp,120-(byte*8));
		uint8_t j = mpz_get_ui(temp);
		for(int k = 0; k < 256; k++){
			uint8_t sb = subByte[j ^ k];
			h[k][x] = hamming(sb);
		}
	}
	mpz_clear(temp);
	mpz_clear(mask);
}

// OpenSSL aes-128 encryption
void enc(mpz_t output, mpz_t mpz_key, mpz_t mpz_m){
	mpz_t temp,mask;
	mpz_init(temp);
	mpz_init(mask);
	int len;
	unsigned char k[16];
	unsigned char m[16];
	unsigned char c[16];

	mpz_set_ui(mask,255);
	mpz_mul_2exp(mask,mask,120);
	for(int i = 0; i < 16; i++){
		mpz_and(temp,mask,mpz_m);
		mpz_div_2exp(temp,temp,120-(i*8));
		m[i] = (unsigned char)mpz_get_ui(temp);

		mpz_and(temp,mask,mpz_key);
		mpz_div_2exp(temp,temp,120-(i*8));
		k[i] = (unsigned char)mpz_get_ui(temp);
		mpz_div_2exp(mask,mask,8);
	}

	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	OPENSSL_config(NULL);

	EVP_CIPHER_CTX *ctx;
	ctx = EVP_CIPHER_CTX_new();
	EVP_EncryptInit_ex(ctx,EVP_aes_128_ecb(),NULL,k,NULL);
	EVP_EncryptUpdate(ctx,c,&len,m,16);
	EVP_EncryptFinal_ex(ctx,c+len,&len);
	EVP_CIPHER_CTX_free(ctx);

	EVP_cleanup();
	ERR_free_strings();

	mpz_set_ui(output,0);
	for(int i = 0; i < 16; i++){
		mpz_add_ui(output,output,c[i]);
		mpz_mul_2exp(output,output,8);
	}
	mpz_div_2exp(output,output,8);

	mpz_clear(temp);
	mpz_clear(mask);
}

void attack(){
	mpz_t k1,k2,maxSize,check;
	mpz_init(k1);
	mpz_init(k2);
	mpz_init(check);
	mpz_init(maxSize);
	mpz_t d[SAMPLE_SIZE];
	mpz_t c[SAMPLE_SIZE];
	uint8_t traces[TRACE_SIZE][SAMPLE_SIZE];
	uint8_t tailtraces[TRACE_SIZE][SAMPLE_SIZE];
	int h[256][SAMPLE_SIZE];
	uint64_t seed;
	mpz_set_ui(maxSize,2);
	mpz_pow_ui(maxSize,maxSize,128);
	for(int x = 0; x < SAMPLE_SIZE; x++){
		mpz_init(d[x]);
		mpz_init(c[x]);
	}
	int correct = 0;
	int loops = 0;

	while(correct == 0){
		printf("generating random XTS-AES tweaks\n");
		int randomData = open("/dev/urandom",O_RDONLY);
		int success = -1;
		while(success < 0){
			success = read(randomData,&seed,(sizeof(seed)));
		}
		gmp_randstate_t r_state;
		gmp_randinit_default(r_state);
		gmp_randseed_ui(r_state,seed);

		//get a set of traces covering the start of the algorithm to discover k2
		printf("recieving traces\n");
		uint8_t* t;
		int traceLength;
		for(int x = 0; x < SAMPLE_SIZE; x++){
			mpz_urandomm(d[x],r_state,maxSize);
			interact(0,d[x],&t,&traceLength,c[x]);
			for(int y = 0; y < TRACE_SIZE; y++){
				traces[y][x] = t[y];
				tailtraces[y][x] = t[traceLength-TRACE_SIZE+y];
			}
			printf("\rtraces recieved: %d",x+1);
			fflush(stdout);
		}
		printf("\n");
	
		// setting d[0] to a known value for checking
		mpz_set_str(d[0],"ffffffffffffffffffffffffffffffff",16);
		interact(0,d[0],&t,&traceLength,c[0]);
		for(int y = 0; y < TRACE_SIZE; y++){
			traces[y][0] = t[y];
			tailtraces[y][0] = t[traceLength-TRACE_SIZE+y];
		}

		//for byte 0->15
		//build hypothesis table
		//find correlations
		mpz_set_ui(k2,0);
		printf("generating k2\n");
		for(int b = 0; b < 16; b++){
			hypothesisTable(h,d,b);
			uint8_t keyByte = getKeyByte(h,traces);
			mpz_add_ui(k2,k2,keyByte);
			mpz_mul_2exp(k2,k2,8);
		}
		mpz_div_2exp(k2,k2,8);
		gmp_printf("k2 = %ZX\n",k2);
	
		for(int x = 0; x < SAMPLE_SIZE; x++){
			enc(d[x],k2,d[x]);
			mpz_xor(d[x],d[x],c[x]);
		}
	
		mpz_set_ui(k1,0);
		printf("\ngenerating k1\n");
		for(int b = 0; b < 16; b++){
			hypothesisTable(h,d,b);
			uint8_t keyByte = getKeyByte(h,tailtraces);
			mpz_add_ui(k1,k1,keyByte);
			mpz_mul_2exp(k1,k1,8);
		}
		mpz_div_2exp(k1,k1,8);
		gmp_printf("k1 = %ZX\n",k1);
		printf("\n");
		mpz_mul_2exp(k1,k1,128);
		mpz_add(k1,k1,k2);
		gmp_printf("complete key = %ZX\n",k1);
	
		mpz_set(check,c[0]);
		mpz_set_str(d[0],"ffffffffffffffffffffffffffffffff",16);
		enc(d[0],k2,d[0]);
		mpz_xor(check,check,d[0]);
		mpz_div_2exp(k1,k1,128);
		enc(check,k1,check);
		mpz_xor(check,check,d[0]);
		if(mpz_cmp_ui(check,0) == 0){
			correct = 1;
		} else {
			printf("incorrect hypothesis, trying again\n");
		}
		loops++;
	}

	printf("interactions with target: %d\n",SAMPLE_SIZE*loops);

	mpz_clear(k1);
	mpz_clear(k2);
	mpz_clear(maxSize);
	mpz_clear(check);
	for(int x = 0; x < SAMPLE_SIZE; x++){
		mpz_clear(d[x]);
		mpz_clear(c[x]);
	}
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

int main(int argc, char* argv[]) {
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
