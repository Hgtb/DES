# DES
1.0
The Key,Data,Mode store in Key.txt,Data.txt,Mode.txt
Key : 64 bits
Data : 64 bits
Mode : 1 bit
store formate:
Key : a 8*8 matrix :
0 1 0 0 0 1 0 0
0 0 0 1 0 0 0 1
1 0 1 0 0 1 1 1
0 0 1 1 1 1 0 0
0 1 0 0 1 0 1 0
0 0 1 0 0 0 0 1
1 0 1 0 0 1 0 1
1 0 1 1 1 1 0 1
Data : a 8*8 matrix :
0 1 0 0 0 1 0 0
0 0 0 1 0 0 0 1
1 0 1 0 0 1 1 1
0 0 1 1 1 1 0 0
0 1 0 0 1 0 1 0
0 0 1 0 0 0 0 1
1 0 1 0 0 1 0 1
1 0 1 1 1 1 0 1
Mode : only one bit :
0
In the Mode.txt file , 0  means doing encryption  , 1 means doing decrypt

