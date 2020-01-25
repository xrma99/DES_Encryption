#include<iostream>
#include<cstdlib>
#include<string>
#include<fstream>
#include "sbox.h"
#include "pbox.h"
#include "keyPbox.h"

#define N 64//bits
#define R 16//rounds
#define KN 48//bits: key size


//using std::cout;
using namespace std;

void pr(int* x,size_t n){
	for(int i=0;i<n;i++)
		cout<<x[i];
	cout<<endl;
}

void strTbit(string str,int* res){
	//int res[N]={0};
	int i,j;
	for(i=0;i<N;i++) res[i]=0;//初始化为0

	int len=8;
	if(str.length()<8) len=str.length();

	for(i=0;i<len;i++){
		res[8*i]=str[i];
	}
	for(i=0;i<N;i+=8){
		for(j=i+7;j>=i&&res[i]!=0;j--){
			res[j]=res[i]%2;
			res[i]/=2;
		}
	}//转换为bit流
	/*
	for(i=0;i<N;i++){
		cout<<res[i];
		if(i%8==7) cout<<" ";
	}
	*/
	
}

void IP(int* p){
	int tmp[N];
	int i;
	for(i=0;i<N;i++) tmp[i]=p[i];//copy一份
	for(i=0;i<N;i++) p[i]=tmp[ IPmatrix[i]-1 ];
}

void IIP(int* p){
	int tmp[N];
	int i;
	for(i=0;i<N;i++) tmp[i]=p[i];//copy一份
	for(i=0;i<N;i++) p[i]=tmp[ IIPmatrix[i]-1 ];
}

void expand(int* p,int* res){
	int i;
	for(i=0;i<KN;i++)
		res[i]=p[ EXmatrix[i]-1 ];
}

void Sboxhelp(int* p,int i,int* res){
	int r=p[0]*2+p[5];
	int c=p[1]*8+p[2]*4+p[3]*2+p[4];
	int data=0;
	switch(i){
	case 0:
		data=S1[r][c];
		break;
	case 1:
		data=S2[r][c];
		break;
	case 2:
		data=S3[r][c];
		break;
	case 3:
		data=S4[r][c];
		break;
	case 4:
		data=S5[r][c];
		break;
	case 5:
		data=S6[r][c];
		break;
	case 6:
		data=S7[r][c];
		break;
	case 7:
		data=S8[r][c];
		break;
	default: cout<<"error";
	}
	int k=3;
	while(data!=0){//data最大为15
		res[k]=data%2;
		data/=2;
		k--;
	}
	while(k>-1){
		res[k]=0;
		k--;
	}

}

void Sbox(int* lar,int* res){
	int i=0;
	for(i=0;i<8;i++){
		Sboxhelp(lar+i*6,i,res+i*4);
	}
}

void Pbox(int* p){
	int tmp[N/2];
	int i;
	for(i=0;i<N/2;i++) tmp[i]=p[i];//copy一份
	for(i=0;i<N/2;i++) p[i]=tmp[ Pmatrix[i]-1 ];
}

void Xor(int*,int*,int);

void func(int* p,int* key){
	int lar[KN]={0};
	expand(p,lar);
	Xor(key,lar,48);//异或运算，结果保存在lar里
	Sbox(lar,p);
	Pbox(p);
}

void Xor(int* L,int* h,int n){//异或运算
	int i;
	for(i=0;i<n;i++){
		h[i]=h[i]^L[i];
	}
}

void kPbox(int *k){
	int tmp[N];
	int i;
	for(i=0;i<N;i++) tmp[i]=k[i];//copy一份
	for(i=0;i<56;i++) k[i]=tmp[ kPmatrix[i]-1 ];
}

void kRotate(int *k,int r){
	int i,j;
	int tmp;
	for(i=0;i<r;i++){//一次左移1位，一共r次
		tmp=k[0];
		for(j=0;j<27;j++)
			k[j]=k[j+1];
		k[j]=tmp;
	}
}

void kPbox2(int *kini,int* k){
	int i;
	for(i=0;i<KN;i++){
		k[i]=kini[ kP2matrix[i]-1 ];
	}
}

int main(){
	string plaintext;//1 char=8 bits
	cout<<"Please input the plaintext:";
	cin>>plaintext;
	string Key;
	cout<<"Please input the key:";
	while(Key.length()!=8) cin>>Key;//密钥长度为8 Bytes=64 bits

	int i,j,k;

	int bp[N]={0};
	int tmp[N/2]={0};//暂时保存上一轮的R

	/*key initialized*/
	int keyini[N]={0};
	strTbit(Key,keyini);
	kPbox(keyini);//依然存到keyini的前56位里
	int *C=NULL,*D=NULL;
	int key[KN]={0};
	int keyinitial[56]={0};

	ofstream outfile("ciphertext.txt");

	for(i=0;i<plaintext.length();i=i+8){
		strTbit(&plaintext[i],bp);

		for(j=0;j<56;j++) keyinitial[j]=keyini[j];//每8个bytes加密的初始密钥都是相同的
		C=keyinitial,D=keyinitial+28;

		pr(bp,N);
		IP(bp);//初始置换
		pr(bp,N);

		for(j=0;j<R;j++){//16轮加密

			/*key generation*/
			kRotate(C,kRotation[j]);
			kRotate(D,kRotation[j]);
			kPbox2(keyinitial,key);


			memcpy(tmp,bp+32,sizeof(int)*32);

			func(bp+32,key);//R和k做函数运算f，得出来的值保存在bp的R
			Xor(bp,bp+32,32);//做异或运算，得出的值保存在R

			memcpy(bp,tmp,sizeof(int)*32);//把旧R移到新L
			pr(bp,64);
			//cout<<endl;
			
		}

		memcpy(tmp,bp+32,sizeof(int)*32);
		memcpy(bp+32,bp,sizeof(int)*32);
		memcpy(bp,tmp,sizeof(int)*32);//左右交换

		IIP(bp);//逆置换
		pr(bp,N);

		for(j=0;j<64;j++){
			//cout<<bp[j];
			outfile<<bp[j];
		}
			
	}

	outfile.close();
	//cout<<plaintext;
	std::system("pause");
	return 0;
}