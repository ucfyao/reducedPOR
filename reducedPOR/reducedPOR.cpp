/*
   Test program 
*/
extern "C"
{
#include "miracl.h"
}

#include <strstream>
#include <iostream>
#include <ctime>
#include "stdafx.h"
#include <string>
#include <fstream>
#include <cstring>
#include <time.h>
#include<windows.h>// QueryPerformanceFrequency,QueryPerformanceCounter头文件

#include<stdio.h>
//********* choose just one of these pairs **********
#define MR_PAIRING_CP      // AES-80 security   
#define AES_SECURITY 80

//#define MR_PAIRING_MNT	// AES-80 security
//#define AES_SECURITY 80

//#define MR_PAIRING_BN    // AES-128 or AES-192 security
//#define AES_SECURITY 128
//#define AES_SECURITY 192

//#define MR_PAIRING_KSS    // AES-192 security
//#define AES_SECURITY 192

//#define MR_PAIRING_BLS    // AES-256 security
//#define AES_SECURITY 256
//*********************************************

#include "pairing_3.h"
#include "big.h"

using namespace std;
//

#define kSecurityLevel 160
Miracl precison(kSecurityLevel, 0);

#define N 80//n
#define bunch_num 60
#define challenge_num 50
char a[] = "aasass";
char* b = a;

PFC *pfc = new PFC(AES_SECURITY);  // initialise pairing-friendly curve
Big order = pfc->order();  // get pairing-friendly group order

Big sk;//a
G1 pkG1[N];//g1
G2 pkG2g2_1[N+1];//g2 first n
G2 pkG2g2_2[N];//g2 second half

G2 pkG2h2_1[N+1];//h2 first n
G2 pkG2h2_2[N];//h2 second half

G2 tpk_1[N];
G2 tpk_2[N];
//int n;
G2 tsk;

Big M[bunch_num][N];
G1 tag[bunch_num][N];
G1 t[bunch_num];

Big F[bunch_num];

Big challenge_block[challenge_num] = { 0 };


Big response_mu;
Big response_HE;
GT response_E;



int KeyGen()
{
	miracl *mip = get_mip();  // get handle on mip (Miracl Instance Pointer)
	time_t seed;            // crude randomisation
	time(&seed);
	irand((long)seed);
	//printf("seed: %d\n",seed);

	Big  a;//alpha
	G1 g1;
	G2 g2,h2;

	int i;


	pfc->random(g1);
	pfc->random(g2);
	pfc->random(h2);
	pfc->precomp_for_mult(g1);
	pfc->precomp_for_mult(g2);  // Q is fixed, so precompute on it
	pfc->precomp_for_mult(h2);

	pfc->random(a);
	cout<<"a"<<a<<endl;
	sk = a;//store in pk,sk
	pkG1[0] = g1;
	pkG2g2_1[0] = g2;
	pkG2h2_1[0] = h2;
	
	Big tempa=1;
	Big x_temp,y_temp;
	
	clock_t start_setup=clock();//time start

	for (i = 1; i <= N; i++){
		//tempa = a;
		tempa = modmult(tempa,a,order);
		pkG2g2_1[i] = pfc->mult(g2,tempa);

		//pkG2g2_1[i].g.get(x_temp,y_temp);
		//cout<<"x"<<x_temp<<"y"<<y_temp<<endl;
		
		pkG2h2_1[i] = pfc->mult(h2,tempa);
	}
	
	tempa = modmult(tempa,a,order); //a^{n+1}

	pkG2h2_2[0] = pfc->mult(h2,tempa);//store h2^{a^{n+1}}
	for (i = 1; i < N; i++){
		tempa = modmult(tempa,a,order);//a^{n+2}
		pkG2g2_2[i] = pfc->mult(g2,tempa);

		//pkG2g2_2[i].g.get(x_temp,y_temp);
		//cout<<"h1x"<<x_temp<<"y"<<y_temp<<endl;

		pkG2h2_2[i] = pfc->mult(h2,tempa);
		//pkG2h2_2[i].g.get(x_temp,y_temp);
		//cout<<"h2x"<<x_temp<<"y"<<y_temp<<endl;
	}
	
	clock_t end_setup=clock();
	cout<<"KeyGen时间："<<end_setup-start_setup<<endl;

	/***************Tkeygen****/

		//G1 g1;
	//G2 g2,h2;
	//Big x_temp,y_temp;

	Big b = 0;
	G2 h2_1[N],h2_2[N];

	//g1	= pkG1[0];
	//g2 = pkG2g2_1[0];
	//h2 = pkG2h2_1[0];

	//int i;
	for (i = 0; i < N; i++)
	{
		h2_1[i] = pkG2h2_1[i];
		h2_2[i] = pkG2h2_2[i];
	}
	pfc->random(b);
	//cout<<"b"<<b<<endl;
	//b = randbits(160);
	cout<<"b"<<b<<endl;	
	
	clock_t start_keygen=clock();//time start
	/*
	for( i = 0; i < N; i++)
	{
		//pkG2h2_1[i].g.get(x_temp,y_temp);
		//cout<<"h2x"<<x_temp<<"y"<<y_temp<<endl;
		tpk_1[i] = pfc->mult(h2,b);
	}

	for(int i = 1; i < N; i++){
	tpk_2[i] = pfc->mult(h2,b);}
	*/
		for (i = 1; i < N; i++){
		//tempa = a;
		//tempa = modmult(tempa,a,order);
		pkG2g2_1[i] = pfc->mult(g2,b);

		//pkG2g2_1[i].g.get(x_temp,y_temp);
		//cout<<"x"<<x_temp<<"y"<<y_temp<<endl;
		
		pkG2h2_1[i] = pfc->mult(h2,b);
	}
	
	clock_t end_keygen=clock();
	cout<<"TKeyGen时间："<<end_keygen-start_keygen<<endl;

	//tsk = pfc->mult(h2_1[0],b);

	/***********************/

	return 0;
}
int TKeyGen(){
		G1 g1;
	G2 g2,h2;
	Big x_temp,y_temp;

	Big b = 0;
	G2 h2_1[N],h2_2[N];

	g1	= pkG1[0];
	g2 = pkG2g2_1[0];
	 h2 = pkG2h2_1[0];

	int i;
	for (i = 0; i < N; i++)
	{
		h2_1[i] = pkG2h2_1[i];
		h2_2[i] = pkG2h2_2[i];
	}
	pfc->random(b);
	//cout<<"b"<<b<<endl;
	//b = randbits(160);
	cout<<"b"<<b<<endl;	
	
	clock_t start_keygen=clock();//time start
	/*
	for( i = 0; i < N; i++)
	{
		//pkG2h2_1[i].g.get(x_temp,y_temp);
		//cout<<"h2x"<<x_temp<<"y"<<y_temp<<endl;
		tpk_1[i] = pfc->mult(h2,b);
	}

	for(int i = 1; i < N; i++){
	tpk_2[i] = pfc->mult(h2,b);}
	*/
		for (i = 1; i <= N; i++){
		//tempa = a;
		//tempa = modmult(tempa,a,order);
		pkG2g2_1[i] = pfc->mult(g2,b);

		//pkG2g2_1[i].g.get(x_temp,y_temp);
		//cout<<"x"<<x_temp<<"y"<<y_temp<<endl;
		
		pkG2h2_1[i] = pfc->mult(h2,b);
	}
	
	clock_t end_keygen=clock();
	cout<<"TKeyGen时间："<<end_keygen-start_keygen<<endl;

	tsk = pfc->mult(h2_1[0],b);
	return 0;
}
void TagGen()
{
	cout << "N:" <<N<<endl;
	cout << "bunch number:"<<bunch_num<<endl;
	cout<<"challenge num:"<<challenge_num<<endl;
	int i=0,j,k;
	G1 Hash_name,g1;
	const char* name= "filename";
	g1 = pkG1[0];
	
	for(i=0;i<bunch_num;i++)
	{
		for(j=0;j<N;j++)
		{
			// rand 此处rand需要两个参数
			M[i][j] = (Big)rand(0,160);
			//cout<<M[i][j]<<endl;
		}
	}			
	//pfc->precomp_for_mult(g1);

	
	Big tempa = 1;
	G1 temp;
	G1 temptag;
	Big a = sk;
	Big ak[N];
	Big temp_ak=1;
	for (k=0; k< N; k++){
		ak[k] = temp_ak;
		tempa = modmult(temp_ak,a,order);
	}
	clock_t start_tagGen_off=clock();
	for (i = 0; i < bunch_num; i++)
	{
		for(k = 0; k < N; k++)//bunch size
		{	
			temp = pfc->mult(g1, M[i][k]);//标签的第二部分
			// 在vs2019中定义char[] 在转为char*传入类型错误
			const char* constsrdd = "dd";
			char* dd = nullptr;
			dd = const_cast<char*>(constsrdd);

			pfc->hash_and_map(Hash_name, dd);//文件名叫a
			temp = Hash_name + temp;			//H(name)
			temp = pfc->mult(temp,ak[k]);

			tag[i][k] = temp;//block tag
			temptag = temptag + temp;
			//tempa = modmult(tempa,a,order);//a^{k+1}
		}
		
	}
		
	clock_t end_tagGen_off=clock();
	cout<<"TagGen运行时间："<<end_tagGen_off-start_tagGen_off<<endl;

	t[i] = temptag;
}
/*void TagGen()//normal
{
	cout << "N:" <<N<<endl;
	cout << "bunch number:"<<bunch_num<<endl;
	cout<<"challenge num:"<<challenge_num<<endl;
	int i=0,j,k;
	G1 Hash_name,g1;
	char *name = "filename";
	g1 = pkG1[0];
	
	for(i=0;i<bunch_num;i++)
	{
			F[i] = randbits(160);
			//cout<<M[i][j]<<endl;

	}			
	pfc->precomp_for_mult(g1);


	Big tempa = 1;
	G1 temp;
	G1 temptag;
	Big a = sk;
	Big ak[N];
	Big temp_ak=1;
	
	clock_t start_tagGen_off=clock();

		for (i = 0; i < bunch_num; i++)
	{
			
			temp = pfc->mult(g1, F[i]);//标签的第二部分
			pfc->hash_and_map(Hash_name,"a");//文件名叫a
			temp = Hash_name + temp;			//H(name)
			temp = pfc->mult(temp,tempa);

			tag[i][1] = temp;//block tag
			//temptag = temptag + temp;
			tempa = modmult(tempa,a,order);//a^{k+1}		
	}

	clock_t end_tagGen_off=clock();
	cout<<"TagGen运行时间："<<end_tagGen_off-start_tagGen_off<<endl;

	t[i] = temptag;
}*/
void Challenge()
{
	clock_t start = clock();
	int i;
	for (i = 0; i<challenge_num; ++i)
	{
		 challenge_block[i] = randbits(10);
		 //challenge_block[i] = randbits(10);   //V_i
		// cout << "挑战块：" << i << ":" << challenge_block[i] << endl;
	}
	clock_t end = clock();
	cout << "challenge运行时间：" << end - start << endl;

}
void Response()
{
		int i, j, k,l;//i is the bunch number and j is the block number. k=in+j
		GT tempGT;
		G1 tempG1, Hash_name;
		GT etag[challenge_num];
		G1 g1 = pkG1[0];
		GT g;
		Big x_temp,y_temp;

		//pfc->random(tempGT);

	//new without reduced storage


    //easy version (challenge the first block)
		pfc->precomp_for_mult(g1);

	//clock_t start = clock();//time starts

	for (i = 0; i < challenge_num; i++)
	{
		clock_t start1 = clock();//time starts/******one ei********************/
		tempG1 = pfc->mult(pkG1[0], M[1][0]);
		// 在vs2019中定义char[] 在转为char*传入类型错误
		const char* constsraa = "a";
		char* aa = nullptr;
		aa = const_cast<char*>(constsraa);
		pfc->hash_and_map(Hash_name,aa);//文件名叫a
		tempG1 = (Hash_name + tempG1);
		tempGT = pfc->pairing(tpk_1[0],tempG1);

		for (l = 2; l<N; l++)//one less
		{
			//for (i = 0; i<challenge_num; i++)
			//pfc->precomp_for_mult(pkG1[0]);  //分母左边
			tempG1 = pfc->mult(g1, M[1][l]);
			// 在vs2019中定义char[] 在转为char*传入类型错误
			const char* constsrbb = "a";
			char* bb = nullptr;
			bb = const_cast<char*>(constsrbb);
			pfc->hash_and_map(Hash_name, bb);//文件名叫a
			tempG1 = (Hash_name + tempG1);

			tempGT = tempGT * pfc->pairing(tpk_1[l],tempG1);

		}
		etag[i] = pfc->pairing(tpk_1[0],t[1])/tempGT;
	clock_t end1 = clock();
	cout << "一个ei：" << end1 - start1 << endl;


	}
	clock_t start = clock();//time starts
	for (i = 0; i < challenge_num; i++){

		response_mu = response_mu + modmult(M[i][1],challenge_block[i],order);
		//cout<<"mu"<<response_mu<<endl;
		response_E = response_E * pfc->power(etag[i],challenge_block[i]);
	}

	response_HE = pfc->hash_to_aes_key(response_E); 
		
	
	clock_t end = clock();
	cout << "aggregate时间：" << end - start << endl;
}
void Verify()
{
	int i;
	//Big temp_Big=0;
	//Big x_temp,y_temp;
	GT tmp_right;//验证式右边
	//GT tempGT,tmp1,tmp2,tmp3;
	G1 tempG1;
	G1 tempG2,Hash_name,temp,temp_Hashname;
	Big hashE;
	clock_t start = clock();
		for(i=0;i<challenge_num;i++)
		{	
			// 在vs2019中定义char[] 在转为char*传入类型错误
			const char* constsree = "ee";
			char* ee = nullptr;
			ee = const_cast<char*>(constsree);
			pfc->hash_and_map(Hash_name,ee);//文件名叫a
			//temp = Hash_name + commonG2[1];		//H(name)
			temp_Hashname = temp_Hashname + pfc->mult(Hash_name,challenge_block[i]);
		}
		temp = temp_Hashname + pfc->mult(pkG1[0],response_mu);//the first parameter in e()
		tmp_right = pfc->pairing(tsk,temp);
		hashE = pfc->hash_to_aes_key(tmp_right);

		
	clock_t end = clock();
	cout << "Verify 运行时间：" << end - start << endl;
	if(response_HE == hashE)
		cout<<"验证成功"<<endl;
	else
		cout<<"验证失败"<<endl;
}
int main()
{
	//printf("order: %d\n",order.getbig());//输出模数
//clock_t start = clock();
//for(int i=0;i<3;i++)
	//{		
	/*****************test pairing*********************
	G2 g2 = pkG2g2_1[0];
	G1 g1 = pkG1[0];
	Big alpha = sk;
	GT gT;
	gT = pfc->pairing(g2,g1);//pairing
	*/
	//clock_t start1 = clock();
	
//	pfc->power(gT,alpha);

	//alpha = modmult(alpha,alpha,order);
	//clock_t end1 = clock();
	//cout << "pairing运行时间：" << end1 - start1 <<"ms"<< endl;


	KeyGen();
	TKeyGen();
	TagGen();
	Challenge();
	Response();
	Verify();
	//clock_t end = clock();
	//cout << "Verify运行时间：" << end - start <<"ms"<< endl;
	/*a=randbits(900);
	cout<<a<<endl;
	cout<<sizeof(a)<<endl;
	cout<<randbits(160)<<endl;
	*/
	Big ccc;
	cin>>ccc;
	return 0;
}
