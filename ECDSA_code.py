#Project on Cryptographic premitives of Blockchain
#Elliptic curve digital signature algorithm(ECDSA)

import hashlib  #hash function library which provides SHA-1 function
import ECOPs    #importing use defined functions from ECOPs(elliptic curve operations) file 


#ECDSA domain parameters

#Elliptic curve y^2 = x^3 + a*x + b
a = 0
b = 7
#y^2 = x^3 + b
p = pow(2, 256) - pow(2, 32) - pow(2, 9) - pow(2, 8) - pow(2, 7) - pow(2, 6) - pow(2, 4) - pow(2, 0) 
E = [a,b,p]
q = 115792089237316195423570985008687907852837564279074904382605163141518161494337
A = [55066263022277343669578718895168534326250603453777594175500187360389116729240,32670510020758816978083085130507043184471273380659243275938904335757337482424]

#Message for digital signature

M = b"Mathematics is the king of all sciences and Number theory is the Queen"
Hash_M = hashlib.sha1(M).hexdigest()
Hash_M = int(Hash_M,16)

print("Message: mathematics is the king of all sciences and Number theory is the Queen")
print("Digest: ",Hash_M)

#ECDSA signature generation algorithm:

k = 28695618543805844332113829720373285210420739438570883203839696518176414791234
m = 75263518707598184987916378021939673586055614731957507592904438851787542395619

BP = ECOPs.Double_and_Add(A,E,m)
B = ECOPs.Double_and_Add(A,E,k)   #B=kA
r = B[0]%q
s = (Hash_M + m*r)
s = s*ECOPs.mod_inverse(k,q)
s = s%q

signature = (r,s)
print("Signature: ",signature)

#ECDSA signature verification algorithm:
w = ECOPs.mod_inverse(s,q)
i = (w*Hash_M)%q
j = (w*r)%q
R = ECOPs.ADD(ECOPs.Double_and_Add(A,E,i),ECOPs.Double_and_Add(BP,E,j),E)
u = R[0]
v = R[1]

print("r: ",r)
print("u: ",u)
if r==u:
    print("r==u so signature is valid")
else:
    print("r!=u sp signature is invalid")