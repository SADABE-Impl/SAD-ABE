'''
C{\'{e}}cile Delerabl{\'{e}}e, L{\'{e}}na{\"{\i}}ck Gouriou, David Pointcheval

| From: "Key-Policy ABE with Switchable Attributes"
| Published in: 2022
| Available from: http://eprint.iacr.org/2021/867
| Notes: Implemented the scheme in Section 4.1
| Security Assumption: 1-linear
|
| type:           key-policy attribute-based encryption
| setting:        Pairing

#:Authors:         
#:Date:            10/2023
'''

from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.toolbox.ABEnc import ABEnc
from charm.toolbox.secretutil import SecretUtil

debug = False


class DGP22KPSADABE(ABEnc):
    def __init__(self, groupObj, assump_size, verbose=False):
        ABEnc.__init__(self)
        self.group = groupObj
        self.util = SecretUtil(groupObj, verbose=False)
        # self.util = MSP(self.group, verbose)

    def getMatrixMinor(self, m,i,j):
        return [row[:j] + row[j+1:] for row in (m[:i]+m[i+1:])]

    def getMatrixDeternminant(self, m):
        #base case for 2x2 matrix
        if len(m) == 2:
            return m[0][0]*m[1][1]-m[0][1]*m[1][0]

        determinant = 0
        for c in range(len(m)):
            determinant += ((-1)**c)*m[0][c]*self.getMatrixDeternminant(self.getMatrixMinor(m,0,c))
        return determinant

    def getMatrixInverseTranspose(self, m):
        determinant = self.getMatrixDeternminant(m)
        #special case for 2x2 matrix:
        if len(m) == 2:
            return [[m[1][1]/determinant, -1*m[0][1]/determinant],
                    [-1*m[1][0]/determinant, m[0][0]/determinant]]

        #find matrix of cofactors
        cofactors = []
        for r in range(len(m)):
            cofactorRow = []
            for c in range(len(m)):
                minor = self.getMatrixMinor(m,r,c)
                cofactorRow.append(((-1)**(r+c)) * self.getMatrixDeternminant(minor))
            cofactors.append(cofactorRow)
        #cofactors = self.transposeMatrix(cofactors)
        for r in range(len((cofactors))):
            for c in range(len((cofactors))):
                cofactors[r][c] = cofactors[r][c]/determinant
        return cofactors

    def setup(self):
        """
        Generates public key and master secret key.
        """

        if debug:
            print('Setup algorithm:\n')

        # B = B, B^* = Bi
        B = []
        for j1 in range(3):
            y = [] 
            for j2 in range(3):
                random = self.group.random(ZR)
                y.append(random)
            B.append(y)

        Bi = self.getMatrixInverseTranspose(B)

        '''
        test B,Bi
        A2 = {}
        for i in range(3):
            y = []
            for j1 in range(3):
                sum = 0
                for j2 in range(3):
                    sum += B[j2][i] * Bi[j2][j1]
                y.append(sum)
            A2[i] = y
        print(A2)
        '''

        # D = D, D^* = Di
        D = []
        for j1 in range(9):
            y = [] 
            for j2 in range(9):
                random = self.group.random(ZR)
                y.append(random)
            D.append(y)

        Di = self.getMatrixInverseTranspose(D)

        # pick a random element from the two source groups and pair them
        g = self.group.random(G1)
        h = self.group.random(G2)
        e_gh = pair(g, h)

        # now compute various parts of the public parameters

        g_B = []
        for j1 in range(3):
            y = []
            for j2 in range(3):
                y.append(g ** B[j2][j1])
            g_B.append(y)

        g_Bi = []
        for j1 in range(3):
            y = []
            for j2 in range(3):
                y.append(h ** Bi[j2][j1])
            g_Bi.append(y)

        g_D = []
        for j1 in range(9):
            y = []
            for j2 in range(9):
                y.append(g ** D[j2][j1])
            g_D.append(y)

        g_Di = []
        for j1 in range(9):
            y = []
            for j2 in range(9):
                y.append(h ** Di[j2][j1])
            g_Di.append(y)

        '''
        for i in range(9):
            if i == 0:
                y = []
                for j1 in range(9):
                    sum = 1
                    for j2 in range(9):
                        sum *= pair(g_D[i][j2], g_Di[j1][j2])
                    print('prod',sum)
        '''

        # the public key
        pk = {'g': g, 'g_B0': g_B[0], 'g_B2': g_B[2], 'g_Bi0': g_Bi[0], 'g_D0': g_D[0], 'g_D1': g_D[1], 'g_D2': g_D[2], 'g_Di0': g_Di[0], 'g_Di1': g_Di[1], 'g_Di2': g_Di[2], 'e_gh': e_gh}

        # the master secret key
        msk = {'h': h, 'g_Bi2': g_Bi[2], 'g_Di6': g_Di[6]}

        sk = {'g_D6': g_D[6]}

        return pk, msk, sk

    def keygen(self, pk, msk, policy_str, semi_list):
        """
        Generate a key for a set of attributes.
        """

        if debug:
            print('Key generation algorithm:\n')

        policy = self.util.createPolicy(policy_str)
        a_list = self.util.getAttributeList(policy)
        # a_0 = s, a_\lambda = shares[\lambda]
        s = self.group.random(ZR)
        shares = self.util.calculateSharesDict(s, policy)  


        # h0 is the zero element in G_2
        h0 = msk['h'] ** 0

        # compute k_\lambda^* for all leaves \lambda
        K1 = {}
        for attr in shares.keys():
            y = []

            # compute the first two components of k_\lambda^*
            pi = self.group.random(ZR)
            ri = self.group.random(ZR) 

            # transform (pi, pi * int(attr), shares[attr], 0, 0, 0, ri, 0, 0)_Di into the standard basis
            for j in range(9):
                if attr in semi_list:
                    prod = (pk['g_Di0'][j] ** pi) * (pk['g_Di1'][j] ** (pi * int(attr))) * (pk['g_Di2'][j] ** shares[attr]) * (msk['g_Di6'][j] ** ri)
                else:
                    prod = (pk['g_Di0'][j] ** pi) * (pk['g_Di1'][j] ** (pi * int(attr))) * (pk['g_Di2'][j] ** shares[attr])
                y.append(prod)

            K1[int(attr)] = y
                
        # K_0^* = K0
        K0 = []
        for j in range(3):
            prod = (pk['g_Bi0'][j] ** s) * (msk['g_Bi2'][j])
            K0.append(prod)

        return {'policy': policy, 'K_0': K0, 'K_1': K1}

    def encrypt(self, pk, msg, attr_list, sk, semi_list):
        """
        Encrypt a message M under a policy string.
        """

        if debug:
            print('Encryption algorithm:\n')

        # omega = w, zeta = z
        w = self.group.random(ZR)
        z = self.group.random(ZR)

        # g0 is the zero element in G_1
        g0 = pk['g'] ** 0

        C1 = {}
        for attr in attr_list:
            y = []
            sig = self.group.random(ZR)
            ui = self.group.random(ZR)
            # transform (sig * int(attr), -sig, w, 0, 0, 0, ui, 0, 0)_D into the standard basis
            for j in range(9):
                if attr in semi_list:
                    prod = (pk['g_D0'][j] ** (sig * int(attr))) * (pk['g_D1'][j] ** (-sig) ) * (pk['g_D2'][j] ** w ) * (sk['g_D6'][6] ** ui)
                else:
                    prod = (pk['g_D0'][j] ** (sig * int(attr))) * (pk['g_D1'][j] ** (-sig) ) * (pk['g_D2'][j] ** w )
                y.append(prod)

            C1[int(attr)] = y

        C0 = []
        for j in range(3):
            prod = (pk['g_B0'][j] ** w ) * (pk['g_B2'][j] ** z)
            C0.append(prod)

        # compute C
        C = pk['e_gh'] ** z
        C *= msg

        return {'attr_list': attr_list, 'C_0': C0, 'C_1': C1, 'C': C}

    def decrypt(self, pk, ctxt, key):
        """
        Decrypt ciphertext ctxt with key key.
        """

        if debug:
            print('Decryption algorithm:\n')

        nodes = self.util.prune(key['policy'], ctxt['attr_list'])
        if not nodes:
            print ("Policy not satisfied.")
            return None  
        z = self.util.getCoefficients(key['policy'])

        prod = 1
        for node in nodes:
            attr = node.getAttributeAndIndex()
            prod1 = 1
            for i in range(9):
                prod1 *= pair(ctxt['C_1'][int(attr)][i], key['K_1'][int(attr)][i])
            prod *= prod1 ** z[attr]

        prod0 = 1
        for i in range(3):
            prod0 *= pair(ctxt['C_0'][i], key['K_0'][i])

        K = prod0/prod
        return ctxt['C'] / K
                
