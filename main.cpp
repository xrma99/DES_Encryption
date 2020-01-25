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
	for(i=0;i<N;i++) res[i]=0;//��ʼ��Ϊ0

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
	}//ת��Ϊbit��
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
	for(i=0;i<N;i++) tmp[i]=p[i];//copyһ��
	for(i=0;i<N;i++) p[i]=tmp[ IPmatrix[i]-1 ];
}

void IIP(int* p){
	int tmp[N];
	int i;
	for(i=0;i<N;i++) tmp[i]=p[i];//copyһ��
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
	while(data!=0){//data���Ϊ15
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
	for(i=0;i<N/2;i++) tmp[i]=p[i];//copyһ��
	for(i=0;i<N/2;i++) p[i]=tmp[ Pmatrix[i]-1 ];
}

void Xor(int*,int*,int);

void func(int* p,int* key){
	int lar[KN]={0};
	expand(p,lar);
	Xor(key,lar,48);//������㣬���������lar��
	Sbox(lar,p);
	Pbox(p);
}

void Xor(int* L,int* h,int n){//�������
	int i;
	for(i=0;i<n;i++){
		h[i]=h[i]^L[i];
	}
}

void kPbox(int *k){
	int tmp[N];
	int i;
	for(i=0;i<N;i++) tmp[i]=k[i];//copyһ��
	for(i=0;i<56;i++) k[i]=tmp[ kPmatrix[i]-1 ];
}

void kRotate(int *k,int r){
	int i,j;
	int tmp;
	for(i=0;i<r;i++){//һ������1λ��һ��r��
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
	while(Key.length()!=8) cin>>Key;//��Կ����Ϊ8 Bytes=64 bits

	int i,j,k;

	int bp[N]={0};
	int tmp[N/2]={0};//��ʱ������һ�ֵ�R

	/*key initialized*/
	int keyini[N]={0};
	strTbit(Key,keyini);
	kPbox(keyini);//��Ȼ�浽keyini��ǰ56λ��
	int *C=NULL,*D=NULL;
	int key[KN]={0};
	int keyinitial[56]={0};

	ofstream outfile("ciphertext.txt");

	for(i=0;i<plaintext.length();i=i+8){
		strTbit(&plaintext[i],bp);

		for(j=0;j<56;j++) keyinitial[j]=keyini[j];//ÿ8��bytes���ܵĳ�ʼ��Կ������ͬ��
		C=keyinitial,D=keyinitial+28;

		pr(bp,N);
		IP(bp);//��ʼ�û�
		pr(bp,N);

		for(j=0;j<R;j++){//16�ּ���

			/*key generation*/
			kRotate(C,kRotation[j]);
			kRotate(D,kRotation[j]);
			kPbox2(keyinitial,key);


			memcpy(tmp,bp+32,sizeof(int)*32);

			func(bp+32,key);//R��k����������f���ó�����ֵ������bp��R
			Xor(bp,bp+32,32);//��������㣬�ó���ֵ������R

			memcpy(bp,tmp,sizeof(int)*32);//�Ѿ�R�Ƶ���L
			pr(bp,64);
			//cout<<endl;
			
		}

		memcpy(tmp,bp+32,sizeof(int)*32);
		memcpy(bp+32,bp,sizeof(int)*32);
		memcpy(bp,tmp,sizeof(int)*32);//���ҽ���

		IIP(bp);//���û�
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