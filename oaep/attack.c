#include "attack.h"

#define BUFFER_SIZE ( 80 )

pid_t pid = 0;
int target_raw[ 2 ];
int attack_raw[ 2 ];

FILE* target_out = NULL;
FILE* target_in = NULL;

void interact(int* r, mpz_t int_l, mpz_t int_c, mpz_t int_N){
	char* l = NULL;
	char* c = NULL;
	char* N = NULL;
	
	l = mpz_get_str(l,-16,int_l);
	c = mpz_get_str(c,-16,int_c);
	N = mpz_get_str(N,-16,int_N);

	if(strlen(l) % 2 == 1){
		memmove(l+1,l,strlen(l)+1);
		l[0] = '0';
	}

	if(strlen(c) % 2 == 1){
		memmove(c+1,c,strlen(c)+1);
		c[0] = '0';
	}

	while(strlen(c) < strlen(N)){
		memmove(c+1,c,strlen(c)+1);
		c[0] = '0';
	}

	fprintf(target_in, "%s\n", l);
	fprintf(target_in, "%s\n", c); fflush( target_in );
	if ( 1 != fscanf( target_out, "%d", r) ){
		abort();
	}

	//printf("=============== Interaction with 14737.D ===============\n");
	//printf("l = %s\n",l);
	//printf("c = %s\n",c);
	//printf("r = %d\n",*r);
}

int step1(mpz_t f1, mpz_t c, mpz_t l, mpz_t e, mpz_t N){
	int steps = 1;
	int result = -1;
	mpz_t f1_e;
	mpz_init(f1_e);
	
	// let f1 = 2;
	mpz_set_ui(f1,2);

	// try f1 with the oracle
	mpz_powm(f1_e,f1,e,N);
	mpz_mul(f1_e, f1_e, c);
	mpz_mod(f1_e, f1_e, N);
	interact(&result,l,f1_e,N);

	// if "< B", f1 = f1*2 and send to the oracle again
	while( result != 1 ){
		mpz_mul_ui(f1,f1,2);
		mpz_powm(f1_e,f1,e,N);
		mpz_mul(f1_e, f1_e, c);
		mpz_mod(f1_e, f1_e, N);
		interact(&result,l,f1_e,N);
		steps++;
	}

	gmp_printf("f1 = %ZX\n",f1);
	
	mpz_clear(f1_e);
	return steps;
}

int step2(mpz_t f1, mpz_t f2, mpz_t N, mpz_t B, mpz_t e, mpz_t l, mpz_t c){
	int steps = 1;
	int result = -1;
	mpz_t f2_e, half_f1;
	mpz_init(f2_e);
	mpz_init(half_f1);

	// f2 = floor((n+B)/B) * f1/2
	mpz_fdiv_q_ui(half_f1,f1,2);
	mpz_add(f2,N,B);
	mpz_fdiv_q(f2,f2,B);
	mpz_mul(f2,f2,half_f1);

	// try f2 with the oracle
	mpz_powm(f2_e,f2,e,N);
	mpz_mul(f2_e, f2_e, c);
	mpz_mod(f2_e, f2_e, N);
	interact(&result,l,f2_e,N);
	
	// if the oracle indicates ">= B"
	// f2 = f2 + f1/2
	while( result == 1 ){
		mpz_add(f2,f2,half_f1);
		mpz_powm(f2_e,f2,e,N);
		mpz_mul(f2_e, f2_e, c);
		mpz_mod(f2_e, f2_e, N);
		interact(&result,l,f2_e,N);
		steps++;
	}

	gmp_printf("f2 = %ZX\n",f2);
	
	mpz_clear(f2_e);
	mpz_clear(half_f1);
	
	return steps;
}

int step3(mpz_t f2, mpz_t N, mpz_t B, mpz_t e, mpz_t l, mpz_t c){
	int steps = 0;
	int result = -1;
	mpz_t m_min, m_max, f_tmp, m_diff, i, f3, f3_e;
	mpz_init(m_min);
	mpz_init(m_max);
	mpz_init(f_tmp);
	mpz_init(m_diff);
	mpz_init(i);
	mpz_init(f3);
	mpz_init(f3_e);

	// m_min = ceil(n/f2)
	// m_max = floor((n+B)/f2)
	mpz_cdiv_q(m_min, N, f2);
	mpz_add(m_max, N, B);
	mpz_fdiv_q(m_max, m_max, f2);	

	gmp_printf("m_min = %ZX\n",m_min);
	gmp_printf("m_max = %ZX\n",m_max);
	gmp_printf("B = %ZX\n",B);

	//for(int j = 0; j < 10; j++){
	while(mpz_cmp(m_min,m_max) != 0){

		// f_tmp = floor(2B/(m_max-m_min))
		mpz_mul_ui(f_tmp, B, 2);
		mpz_sub(m_diff, m_max, m_min);
		mpz_fdiv_q(f_tmp, f_tmp, m_diff);
		gmp_printf("f_tmp = %ZX\n",f_tmp);
		
		// i = floor((f_tmp * m_min)/N)
		mpz_mul(i, f_tmp, m_min);
		mpz_fdiv_q(i, i, N);
		gmp_printf("i = %ZX\n",i);

		// f3 = ceil((i * n)/m_min)
		mpz_mul(f3, i, N);
		gmp_printf("i_temp = %ZX\n",f3);
		mpz_cdiv_q(f3, f3, m_min);
		gmp_printf("f3 = %ZX\n",f3);

		// interact with the oracle
		mpz_powm(f3_e, f3, e, N);
		mpz_mul(f3_e, f3_e, c);
		mpz_mod(f3_e, f3_e, N);
		interact(&result, l, f3_e, N);
		steps++;
		
		// if ">= B", m_min = ceil((i * n + B)/f3)
		// else, 	  m_max = floor((i * n + B)/f3)
		if( result == 1 ){
			mpz_mul(m_min, i, N);
			mpz_add(m_min, m_min, B);
			mpz_cdiv_q(m_min, m_min, f3);
		} else if ( result == 2 ){
			mpz_mul(m_max, i, N);
			mpz_add(m_max, m_max, B);
			mpz_fdiv_q(m_max, m_max, f3);
		} else {
			printf("malformed input\n");
		}

		gmp_printf("m_min = %ZX\n", m_min);
		gmp_printf("m_max = %ZX\n", m_max);
	}

	gmp_printf("m = %ZX\n",m_min);

	mpz_clear(m_min);
	mpz_clear(m_max);
	mpz_clear(f_tmp);
	mpz_clear(m_diff);
	mpz_clear(i);
	mpz_clear(f3);
	mpz_clear(f3_e);

	return steps;
}

void attack(const char* str_N, const char* str_e, const char* str_l, const char* str_c){
	int steps;
	mpz_t int_N, int_e, int_l, int_c, B, k;
	mpz_t f1, f2;
	mpz_init(int_N);
	mpz_init(int_e);
	mpz_init(int_l);
	mpz_init(int_c);
	mpz_init(B);
	mpz_init(f1);
	mpz_init(f2);
	mpz_init(k);

	mpz_set_str(int_N, str_N, 16);
	mpz_set_str(int_e, str_e, 16);
	mpz_set_str(int_l, str_l, 16);
	mpz_set_str(int_c, str_c, 16);

	mpz_set_ui(k, mpz_sizeinbase(int_N,2));
	mpz_cdiv_q_ui(k,k,8);
	mpz_sub_ui(k,k,1);
	mpz_mul_ui(k,k,8);
	mpz_set_ui(B,2);
	mpz_powm(B,B,k,int_N);

	steps = step1(f1,int_c,int_l,int_e,int_N);
	steps += step2(f1,f2,int_N,B,int_e,int_l, int_c);
	steps += step3(f2, int_N, B, int_e, int_l, int_c);

	printf("%d interactions with the target\n", steps);
	
	mpz_clear(int_N);
	mpz_clear(int_e);
	mpz_clear(int_l);
	mpz_clear(int_c);
	mpz_clear(B);
	mpz_clear(f1);
	mpz_clear(f2);
	mpz_clear(k);
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
		char* l = NULL;
		char* c = NULL;
		
		if((read = getline(&N, &len, fp)) == -1){
			abort();
		}
		if((read = getline(&e, &len, fp)) == -1){
			abort();
		}
		if((read = getline(&l, &len, fp)) == -1){
			abort();
		}
		if((read = getline(&c, &len, fp)) == -1){
			abort();
		}

		N[strlen(N) - 1] = '\0';
		e[strlen(e) - 1] = '\0';
		l[strlen(l) - 1] = '\0';
		c[strlen(c) - 1] = '\0';

		fclose(fp);

		attack(N,e,l,c);

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
