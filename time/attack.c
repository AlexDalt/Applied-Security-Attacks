#include "attack.h"

#define BUFFER_SIZE ( 80 )
#define CIPHERTEXTS 10000

pid_t pid = 0;
int target_raw[ 2 ];
int attack_raw[ 2 ];

FILE* target_out = NULL;
FILE* target_in = NULL;

void interact(mpz_t c, mpz_t m, mpz_t time){
	char* s = NULL;
	
	s = mpz_get_str(s,-16,c);

	fprintf(target_in, "%s\n", s); fflush( target_in );
	if ( 1 != fscanf( target_out, "%s", s) ){
		abort();
	}

	mpz_set_str(time, s, 10);

	if ( 1 != fscanf( target_out, "%s", s) ){
		abort();
	}

	mpz_set_str(m, s, 16);
}

void cleanup( int s ){
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

int test(mpz_t m, mpz_t d, mpz_t e, mpz_t N){
	mpz_t temp1;
	int r = 0;
	mpz_init(temp1);
	mpz_powm(temp1,m,d,N);
	mpz_powm(temp1,temp1,e,N);
	if(mpz_cmp(temp1,m) == 0){
		r = 1;
	}
	mpz_clear(temp1);

	return r;
}

void ciphertextGeneration(mpz_t ciphertexts[ CIPHERTEXTS ], mpz_t N ){
	uint64_t seed;
	int randomData = open("/dev/urandom",O_RDONLY);
	int success = -1;
	while( success < 0){
		success = read(randomData, &seed, (sizeof(seed)));
	}
	
	gmp_randstate_t r_state;

	gmp_randinit_default(r_state);
	gmp_randseed_ui(r_state, seed);
	for( int i = 0; i < CIPHERTEXTS; i++){
		mpz_urandomm(ciphertexts[i], r_state, N);
	}
}

void montPreComp(mpz_t w, mpz_t pSq, mpz_t N){
	mpz_t zero, b;
	mpz_init(b);
	mpz_init(zero);

	mpz_set_ui(b,2);
	mpz_pow_ui(b,b,64);

	mpz_set_ui(w,1);
	for(int i = 1; i < 64; i++){
		mpz_mul(w,w,w);
		mpz_mul(w,w,N);
		mpz_mod(w,w,b);
	}
	mpz_set_ui(zero,0);
	mpz_sub(w,zero,w);
	mpz_mod(w,w,b);

	mpz_set_ui(pSq, 1);
	for(int i = 1; i <= 2 * mpz_size(N) * 64; i++){
		mpz_add(pSq,pSq,pSq);
		mpz_mod(pSq,pSq,N);
	}
	mpz_clear(zero);
	mpz_clear(b);
}

void montMul(mpz_t r, mpz_t in_x, mpz_t in_y, mpz_t w, mpz_t N, int* reduction){
	mpz_t temp1, temp2, yi_x, ui_N, ui, b, x, y;
	mpz_t r0, yi, x0;
	mpz_init(temp1);
	mpz_init(temp2);
	mpz_init(yi_x);
	mpz_init(ui_N);
	mpz_init(ui);
	mpz_init(b);
	mpz_init(r0);
	mpz_init(yi);
	mpz_init(x0);
	mpz_init(x);
	mpz_init(y);

	mpz_set(x,in_x);
	mpz_set(y,in_y);

	mpz_set_ui(temp1,0);
	mpz_mod(x,x,N);
	mpz_mod(y,y,N);
	mpz_set_ui(b,2);
	mpz_pow_ui(b,b,64);
	mpz_mod(x0,x,b);
	*reduction = 0;

	for(int i = 0; i < mpz_size(N); i++){
		mpz_mod(r0,temp1,b);
		mpz_set_ui(yi,mpz_getlimbn(y,i));
		mpz_mul(ui,yi,x0);
		mpz_add(ui,r0,ui);
		mpz_mul(ui,ui,w);
		mpz_mod(ui,ui,b);
		mpz_mul(yi_x,x,yi);
		mpz_mul(ui_N,N,ui);
		mpz_add(temp2,yi_x,ui_N);
		mpz_add(temp1,temp1,temp2);
		mpz_div(temp1,temp1,b);
	}

	if(mpz_cmp(temp1,N) >= 0){
		mpz_sub(temp1,temp1,N);
		*reduction = 1;
	}

	mpz_set(r,temp1);

	mpz_clear(temp1);
	mpz_clear(temp2);
	mpz_clear(yi_x);
	mpz_clear(ui_N);
	mpz_clear(ui);
	mpz_clear(b);
	mpz_clear(r0);
	mpz_clear(yi);
	mpz_clear(x0);
	mpz_clear(x);
	mpz_clear(y);
}

void oracles(mpz_t mem, mpz_t c, mpz_t d, mpz_t N, int* o1, int* o2, mpz_t pSq, mpz_t w){
	mpz_t a, b;
	mpz_init(a);
	mpz_init(b);

	// generate mtemp (memoised)
	montMul(mem,mem,mem,w,N,o1);
	if(mpz_tstbit(d,0)){
		montMul(mem,mem,c,w,N,o1);
	}
	montMul(a,mem,mem,w,N,o1);

	// oracle 1 (1 if a reduction took place in (mtemp * m)^2)
	montMul(b,mem,c,w,N,o1);
	if((*o1) != 1){
		montMul(b,b,b,w,N,o1);
	}

	// oracle 2 (1 if a reduction took place in (mtemp)^2)
	montMul(a,a,a,w,N,o2);

	mpz_clear(a);
	mpz_clear(b);
}

int getSecretBit(mpz_t mem[ CIPHERTEXTS], mpz_t ciphertexts[ CIPHERTEXTS ], mpz_t timings[ CIPHERTEXTS ], mpz_t d, mpz_t N, mpz_t pSq, mpz_t w){
	unsigned int size_m1 = 0;
	unsigned int size_m2 = 0;
	unsigned int size_m3 = 0;
	unsigned int size_m4 = 0;
	int o1, o2;
	int r = 1;
	mpz_t f1, f2, f3, f4, f1f2_diff, f3f4_diff;
	mpz_init(f1);
	mpz_init(f2);
	mpz_init(f3);
	mpz_init(f4);
	mpz_init(f1f2_diff);
	mpz_init(f3f4_diff);

	mpz_set_ui(f1,0);
	mpz_set_ui(f2,0);
	mpz_set_ui(f3,0);
	mpz_set_ui(f4,0);

	for(int i = 0; i < CIPHERTEXTS; i++){
		oracles(mem[ i ], ciphertexts[ i ], d, N, &o1, &o2, pSq, w);

		if(o1){
			mpz_add(f1,f1,timings[ i ]);
			size_m1++;
		} else {
			mpz_add(f2,f2,timings[ i ]);
			size_m2++;
		}

		if(o2){
			mpz_add(f3,f3,timings[ i ]);
			size_m3++;
		} else {
			mpz_add(f4,f4,timings[ i ]);
			size_m4++;
		}	
	}

	if(size_m1){
		mpz_fdiv_q_ui(f1,f1,size_m1);
	}
	if(size_m2){
		mpz_fdiv_q_ui(f2,f2,size_m2);
	}
	if(size_m3){
		mpz_fdiv_q_ui(f3,f3,size_m3);
	}
	if(size_m4){
		mpz_fdiv_q_ui(f4,f4,size_m4);
	}

	if(mpz_cmp(f1,f2) > 0){
		mpz_sub(f1f2_diff,f1,f2);
	} else {
		mpz_sub(f1f2_diff,f2,f1);
	}
	if(mpz_cmp(f3,f4) > 0){
		mpz_sub(f3f4_diff,f3,f4);
	} else {
		mpz_sub(f3f4_diff,f4,f3);
	}

	if(mpz_cmp(f3f4_diff,f1f2_diff) > 0){
		r = 0;
	}

	mpz_clear(f1);
	mpz_clear(f2);
	mpz_clear(f3);
	mpz_clear(f4);
	mpz_clear(f1f2_diff);
	mpz_clear(f3f4_diff);

	return r;
}

void attack(char* char_N, char* char_e){
	mpz_t N, e, d, temp, w, pSq;
	mpz_init(N);
	mpz_init(e);
	mpz_init(d);
	mpz_init(temp);
	mpz_init(w);
	mpz_init(pSq);

	mpz_t ciphertexts[ CIPHERTEXTS ];
	mpz_t timings[ CIPHERTEXTS ];
	mpz_t mem[ CIPHERTEXTS ];
	for(int i = 0; i < CIPHERTEXTS; i++){
		mpz_init(ciphertexts[ i ]);
		mpz_init(timings[ i ]);
		mpz_init(mem[ i ]);
	}

	mpz_set_str(N, char_N, 16);
	mpz_set_str(e, char_e, 16);
	mpz_set_ui(d, 1);
	int correct = 0;

	montPreComp(w,pSq,N);
	ciphertextGeneration(ciphertexts,N);
	printf("ciphertexts generated\n");

	for(int i = 0; i < CIPHERTEXTS; i++){
		interact(ciphertexts[ i ],temp,timings[ i ]);
	}
	printf("timings recieved\n");

	for(int i = 0; i < CIPHERTEXTS; i++){
		int reduction;
		montMul(ciphertexts[ i ],ciphertexts[ i ],pSq,w,N,&reduction);
		mpz_set_ui(mem[ i ], 1);
		montMul(mem[ i ], mem[ i ], pSq, w, N, &reduction);
	}

	while(!correct){
		int j = getSecretBit(mem,ciphertexts,timings,d,N,pSq,w);
		mpz_mul_2exp(d,d,1);
		if( j == 1 ){
			mpz_add_ui(d,d,1);
		}
		gmp_printf("current d = %ZX\n",d);
		mpz_mul_2exp(temp,d,1);
		if(test(ciphertexts[ 0 ], d, e, N)){
			mpz_set(d,temp);
			break;
		}
		mpz_add_ui(temp,temp,1);
		if(test(ciphertexts[ 0 ], d, e, N)){
			mpz_set(d,temp);
			break;
		}
	}
	
	printf("# interactions with target: %d\n", CIPHERTEXTS);
	gmp_printf("d = %ZX\n",d);

	mpz_clear(N);
	mpz_clear(e);
	mpz_clear(d);
	mpz_clear(temp);
	mpz_clear(w);
	mpz_clear(pSq);

	for(int i = 0; i < CIPHERTEXTS; i++){
		mpz_clear(ciphertexts[ i ]);
		mpz_clear(timings[ i ]);
		mpz_clear(mem[ i ]);
	}
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
		FILE *fp;
		size_t len = 0;
		ssize_t read;

		fp = fopen(argv[2],"r");
		if(fp == NULL){
			exit(EXIT_FAILURE);
		}
		
		char* N = NULL;
		char* e = NULL;
		
		if((read = getline(&N, &len, fp)) == -1){
			abort();
		}
		if((read = getline(&e, &len, fp)) == -1){
			abort();
		}

		N[strlen(N) - 1] = '\0';
		e[strlen(e) - 1] = '\0';

		fclose(fp);

		attack(N,e);

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
