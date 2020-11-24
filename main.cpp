#include <iostream>
#include <fstream>
#include <stdio.h>

using namespace std;

int Data[64]={0},BasicKey[64]={0},Key[17][48]={0},Mode=0,IPcache[64]={0},L[17][32]={0},R[17][32]={0},C[17][28]={0},D[17][28]={0},add[17][56]={0};
int ext[48] = {0},S_Pcashe[32]={0},R_Lcache[64]={0},ciphertext[64]={0},cleartext[64]={0};
int ShiftBits[16] = {1 , 1 , 2 , 2 , 2 , 2 , 2 , 2 , 1 , 2 , 2 , 2 , 2 , 2 , 2 , 1}; //shift left bits of every turn
int convert[16][4] = {
    {0 , 0 , 0 , 0},
    {0 , 0 , 0 , 1},
    {0 , 0 , 1 , 0},
    {0 , 0 , 1 , 1},
    {0 , 1 , 0 , 0},
    {0 , 1 , 0 , 1},
    {0 , 1 , 1 , 0},
    {0 , 1 , 1 , 1},
    {1 , 0 , 0 , 0},
    {1 , 0 , 0 , 1},
    {1 , 0 , 1 , 0},
    {1 , 0 , 1 , 1},
    {1 , 1 , 0 , 0},
    {1 , 1 , 0 , 1},
    {1 , 1 , 1 , 0},
    {1 , 1 , 1 , 1},
}; //S --> int --> binary array
int IP_table[64] = {
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
	62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
	57, 49, 41, 33, 25, 17,  9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
	61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7
};
int E_table[48] = {
    32,  1,  2,  3,  4,  5,
     4,  5,  6,  7,  8,  9,
     8,  9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32,  1
};
int P_table[32] = {
    16, 7, 20, 21, 29, 12, 28, 17,  1, 15, 23, 26,  5, 18, 31, 10,
     2, 8, 24, 14, 32, 27,  3,  9, 19, 13, 30,  6, 22, 11,  4, 25
};
int IPinverse_table[64] = {
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41,  9, 49, 17, 57, 25
};
int K1_table[56] = {
    57, 49, 41, 33, 25, 17,  9,  1, 58, 50, 42, 34, 26, 18,
    10,  2, 59, 51, 43, 35, 27, 19, 11,  3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,  7, 62, 54, 46, 38, 30, 22,
    14,  6, 61, 53, 45, 37, 29, 21, 13,  5, 28, 20, 12,  4
}; //The table of key swap 0   Key(64) --> K1(56)
int K2_table[48] = {
    14, 17, 11, 24,  1,  5,  3, 28, 15,  6, 21, 10,
    23, 19, 12,  4, 26,  8, 16,  7, 27, 20, 13,  2,
    41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
}; //The table of key swap 1-16     k(56) --> k(48)
int S_table[8][4][16] = {
    {
        { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
        { 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
        { 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
        { 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}
    },
    {
        { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
        { 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
        { 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
        { 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}
    },
    {
        { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
        { 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
        { 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
        { 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}
    },
    {
        { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
        { 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
        { 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
        { 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}
    },
    {
        { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
        { 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
        { 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
        { 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}
    },
    {
        { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
        { 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
        { 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
        { 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}
    },
    {
        { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
        { 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
        { 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
        { 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}
    },
    {
        { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
        { 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
        { 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
        { 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}
    }
}; //S_table 4*16  6 --> 4
void input(){//done
    ifstream ReadKey,ReadData,ReadMode;
    char BasicInputKey[512] = {0}; //BasidInputKey has spaces and line break
    char BasicInputData[512] = {0}; //BasidInputData has spaces and line break
    char BasicInputMode[8] = {0};

    ReadKey.open("Key.txt");
    ReadKey.getline( BasicInputKey , 260 , 0 ); //Need to optimize
    for (int i = 0 ; i <= 126 ; i = i + 2){ //get basicKey from basicInput
        BasicKey[i/2] = BasicInputKey[i]-48;
    }
    ReadKey.close();//Get basicKey

    ReadData.open("Data.txt");
    ReadData.getline( BasicInputData , 260 , 0); //Need to optimize
    for (int i = 0 ; i <= 126 ; i = i + 2){
    	Data[i/2] = BasicInputData[i]-48;
	}
	ReadData.close();

    ReadMode.open("Mode.txt");
    ReadMode.getline( BasicInputMode , 2 , 0);
    Mode = BasicInputMode[0]-48;
    ReadMode.close();

    for (int i = 0 ; i < 56 ; i++){
        Key[0][i] = BasicKey[K1_table[i]-1];
    }//Get Key
}
void IPSwap(){//done
    for (int i = 0 ; i < 64 ; i++){
        IPcache[i] = Data[IP_table[i] - 1];
    } //Data --> IP
    for (int i = 0 ; i < 32 ; i++){
        L[0][i] = IPcache[i];
        R[0][i] = IPcache[i + 32];
    }//initialize L[0][i],R[0][i]
}
void KeySwap1(){
    for (int i = 0 ; i < 56 ; i++){
        add[0][i] = BasicKey[K1_table[i]-1];
    }
} //basicKey(64) --> add(56)
void KeySwap2(int n){//done n>=1
    for (int i = 0 ; i < 28 ; i++){
        C[n-1][i] = add[n-1][i];
        D[n-1][i] = add[n-1][i + 28];
    } //add(56) --> C(28) + D(28)
    for (int i = 0 ; i < ShiftBits[n-1] ; i++){
        for (int j = 0 ; j < 27 ; j++){
            C[n][j] = C[n-1][j+1];
            D[n][j] = D[n-1][j+1];
        }
        C[n][27] = C[n-1][0];
        D[n][27] = D[n-1][0];
    } //shift left   n --> n+1  2 --> 1    3 --> 2    ...    28 --> 27   1--> 28
    for (int i = 0 ; i < 28 ; i++){
        add[n][i] = C[n][i];
        add[n][i + 28] = D[n][i];
    } // add = C + D
    for (int i = 0 ; i < 48 ; i++){
        Key[n][i] = add[n][K2_table[i]-1];
    } //PC-2
}//Key[n]
void E(int n){ //n>=1
    for (int i = 0 ; i < 48 ; i++){
        ext[i] = R[n-1][E_table[i]-1]; //ext is extent
    }
}
int XOR(int m,int n){
    if (m != n)
        return 1;
    return 0;
}
void S(){
    int Snumber = 0;
    for (int i = 0 ; i < 8 ; i++){
        Snumber = S_table[i][2*ext[6*i] + ext[6*i+5]][8*ext[6*i+1] + 4*ext[6*i+2] + 2*ext[6*i+3] + ext[6*i+4]];
        for (int j = 0 ; j < 4 ; j++){
            S_Pcashe[4*i + j] = convert[Snumber][j];
        }
    }
}
void P(int n){
    for (int i = 0 ; i < 32 ; i++){
        R[n][i] = XOR(L[n-1][i],S_Pcashe[P_table[i]-1]);
    }
}
void function(int n){
    E(n);
    if (Mode == 0){
        for (int i = 0 ; i < 48 ; i++){
            ext[i] = XOR(ext[i],Key[n][i]);
        }//XOR ext and Key
    }
    else{
        for (int i = 0 ; i < 48 ; i++){
            ext[i] = XOR(ext[i],Key[17-n][i]);
        }//XOR ext and Key
    }
    S();
    P(n);
}
void IPInverseSwap(){
    for (int i = 0 ; i < 32 ; i++){
        R_Lcache[i] = R[16][i];
        R_Lcache[i+32] = L[16][i];
    } //R_Lcache = R + L
    for (int i = 0 ; i < 64 ; i++){
        ciphertext[i] = R_Lcache[IPinverse_table[i]-1];
    }
}
void output(){
    ofstream outputs;
    if (Mode == 0){
        outputs.open("ciphertext.txt");
    }
    else {
        outputs.open("cleartext.txt");
    }
    for (int i = 0 ; i < 8 ; i++){
        for (int j = 0 ; j < 8 ; j++){
            outputs<<ciphertext[i*8 + j]<<" ";
        }
    outputs<<endl;
    }
    outputs.close();
}
int main(){
    input();
    IPSwap();
    KeySwap1();
    for (int i = 1 ; i<=16 ; i++){
        KeySwap2(i);
    }                                   //get Key[1] to Key[16]
    for (int i = 1 ; i<=16 ; i++){
        for (int j = 0 ; j < 32 ; j++){
            L[i][j] = R[i-1][j];
        }                               //L[i] = R[i-1]
        function(i);                    // get R[i]
    }                                   //get L[16],R[16]
    IPInverseSwap();                    // ciphertext = IPInverseSwap(R[16]+L[16])
    output();
    system("PAUSE");
    return 0;
}