'''


 type:           ciphertext-policy attribute-based encryption
 setting:        Pairing

#:Authors:         
#:Date:            10/2023
'''

from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.toolbox.ABEnc import ABEnc
from ..msp import MSP

debug = False


class CPSADABE(ABEnc):
    def __init__(self, groupObj, assump_size, verbose=False):
        ABEnc.__init__(self)
        self.group = groupObj
        self.assump_size = assump_size  # size of the linear assumption
        self.util = MSP(self.group, verbose)

    #def transposeMatrix(self, m):
    #    return list(map(list,zip(*m)))

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

        # \tilde{A} = A0, (\tilde{A}^{-1})^\intercal = A0i
        A0 = [] 
        for j1 in range(4 * self.assump_size):
            y = []
            for j2 in range(4 * self.assump_size):
                y.append(self.group.random(ZR))
            A0.append(y)
        A0i = self.getMatrixInverseTranspose(A0)

        # A_1 = A1, A_4 = A4, A_4^\| = A4i
        A1 = []
        for j1 in range(4 * self.assump_size):
            y = [] 
            for j2 in range(self.assump_size):
                y.append(A0[j1][j2])
            A1.append(y)

        A4 = []
        for j1 in range(4 * self.assump_size):
            y = [] 
            for j2 in range(self.assump_size):
                y.append(A0[j1][3 * self.assump_size + j2])
            A4.append(y)

        A4i = []
        for j1 in range(4 * self.assump_size):
            y = [] 
            for j2 in range(self.assump_size):
                y.append(A0i[j1][3 * self.assump_size + j2])
            A4i.append(y)

        # B = B
        B = []
        for j1 in range(self.assump_size + 1):
            y = []
            for j2 in range(self.assump_size):
                y.append(self.group.random(ZR))
            B.append(y)

        # pick matrices that help to randomize basis
        # W = W[0], W_0 = W[1], W_1 = W[2]
        W = {}
        for i in range(3):
            x = []
            for j1 in range(4 * self.assump_size):
                y = []
                for j2 in range(self.assump_size + 1):
                    y.append(self.group.random(ZR))
                x.append(y)
            W[i] = x

        # U_0 = U
        U = []
        for j1 in range(4 * self.assump_size):
            y = []
            for j2 in range(self.assump_size + 1):
                y.append(self.group.random(ZR))
            U.append(y)

        # vector
        k = []
        for i in range(4 * self.assump_size):
            k.append(self.group.random(ZR))

        # pick a random element from the two source groups and pair them
        g = self.group.random(G1)
        h = self.group.random(G2)
        e_gh = pair(g, h)

        # now compute various parts of the public parameters

        # compute the [A]_1 term
        g_A = []
        for j1 in range(self.assump_size):
            y = []
            for j2 in range(4 * self.assump_size):
                y.append(g ** A1[j2][j1])
            g_A.append(y)

        # compute the [A_1^T W]_1, [A_1^T W_0]_1, [A_1^T W_1]  terms
        g_AW = {}
        for i in range(3):
            x = []
            for j1 in range(self.assump_size):
                y = []
                for j2 in range(self.assump_size + 1):
                    sum = 0
                    for j3 in range(4 * self.assump_size):
                        sum += A1[j3][j1] * W[i][j3][j2]
                    y.append(g ** sum)
                x.append(y)
            g_AW[i] = x

        g_AU = []
        for j1 in range(self.assump_size):
            y = []
            for j2 in range(self.assump_size + 1):
                sum = 0
                for j3 in range(4 * self.assump_size):
                    sum += A1[j3][j1] * U[j3][j2]
                y.append(g ** sum)
            g_AU.append(y)

        # compute the e([A]_1, [k]_2) term
        e_gh_Ak = []
        for i in range(self.assump_size):
            sum = 0
            for j in range(4 * self.assump_size):
                sum += A1[j][i] * k[j]
            e_gh_Ak.append(e_gh ** sum)

        # compute the [A4]_1, [A_4^T W]_1, [A_4^T W_0]_1, [A_4^T W_1] terms
        g_A4 = []
        for j1 in range(self.assump_size):
            y = []
            for j2 in range(4 * self.assump_size):
                y.append(g ** A4[j2][j1])
            g_A4.append(y)

        g_A4W = {}
        for i in range(3):
            x = []
            for j1 in range(self.assump_size):
                y = []
                for j2 in range(self.assump_size + 1):
                    sum = 0
                    for j3 in range(4 * self.assump_size):
                        sum += A4[j3][j1] * W[i][j3][j2]
                    y.append(g ** sum)
                x.append(y)
            g_A4W[i] = x


        # the public key
        pk = {'g': g, 'g_A': g_A, 'g_AW': g_AW, 'g_AU': g_AU, 'e_gh_Ak': e_gh_Ak}

        # the master secret key
        msk = {'h': h, 'k': k, 'B': B, 'W': W, 'U': U, 'A4i': A4i}

        sk = {'g_A4': g_A4, 'g_A4W': g_A4W}

        return pk, msk, sk

    def keygen(self, pk, msk, attr_list, semi_list):
        """
        Generate a key for a set of attributes.
        """

        if debug:
            print('Key generation algorithm:\n')

        h = msk['h']

        # pick randomness
        # d = d[0], d_j = d[j], V_j = V[j]
        r = []
        for i in range(self.assump_size):
            rand = self.group.random(ZR)
            r.append(rand)

        d = {}
        V = {}
        x = []
        for j1 in range(self.assump_size + 1):
            sum = 0
            for j2 in range(self.assump_size):
                sum += msk['B'][j1][j2] * r[j2]
            x.append(sum)
        d[0] = x

        for attr in attr_list:
            r = []
            x = []
            for i in range(self.assump_size):
                rand = self.group.random(ZR)
                r.append(rand)
            for j1 in range(self.assump_size + 1):
                sum = 0
                for j2 in range(self.assump_size):
                    sum += msk['B'][j1][j2] * r[j2]
                x.append(sum)
            d[int(attr)] = x

            # set V_j for semi-valid attributes
            if attr in semi_list:
                tmp = {}
                for i in range(self.assump_size + 1):
                    r = []
                    x = []
                    for j in range(self.assump_size):
                        rand = self.group.random(ZR)
                        r.append(rand)

                    for j1 in range(4 * self.assump_size):
                        sum = 0
                        for j2 in range(self.assump_size):
                            sum += msk['A4i'][j1][j2] * r[j2]
                        x.append(sum)
                    tmp[i] = x

                x = []
                for j2 in range(4 * self.assump_size):
                    y = []
                    for j1 in range(self.assump_size + 1):
                        y.append(tmp[j1][j2])
                    x.append(y)
                V[int(attr)] = x

        # compute K_0
        K_0 = []
        for i in range(4 * self.assump_size):
            sum = msk['k'][i]
            for j in range(self.assump_size + 1):
                sum += msk['U'][i][j] * d[0][j]
            K_0.append(h ** sum)

        # compute K_1
        K_1 = []
        for i in range(self.assump_size + 1):
            K_1.append(h ** d[0][i])

        # compute K_2
        K_2 = {}
        for attr in attr_list:
            key = []
            # randomize with V_j if it is a semi-valid attribute
            if attr in semi_list:
                for i in range(4 * self.assump_size):
                    sum = 0 
                    for j in range(self.assump_size + 1):
                        sum += msk['W'][0][i][j] * d[0][j] + (msk['W'][1][i][j] + int(attr) * msk['W'][2][i][j] + V[int(attr)][i][j]) * d[int(attr)][j]
                    key.append(h ** sum)
                K_2[int(attr)] = key
            else:
                for i in range(4 * self.assump_size):
                    sum = 0 
                    for j in range(self.assump_size + 1):
                        sum += msk['W'][0][i][j] * d[0][j] + (msk['W'][1][i][j] + int(attr) * msk['W'][2][i][j]) * d[int(attr)][j]
                    key.append(h ** sum)
                K_2[int(attr)] = key

        # compute K_3
        K_3 = {}
        for attr in attr_list:
            y = []
            for i in range(self.assump_size + 1):
                y.append(h ** d[int(attr)][i])
            K_3[int(attr)] = y

        return {'attr_list': attr_list, 'K_0': K_0, 'K_1': K_1, 'K_2': K_2, 'K_3': K_3}

    def encrypt(self, pk, msg, policy_str, sk, semi_list):
        """
        Encrypt a message M under a policy string.
        """

        if debug:
            print('Encryption algorithm:\n')

        g = pk['g']
    
        # num_cols is the number of columns of MSP
        # (attr, row) is the attribute and row vector of MSP
        policy = self.util.createPolicy(policy_str)
        mono_span_prog = self.util.convert_policy_to_msp(policy)
        num_cols = self.util.len_longest_row

        # pick randomness
        # c = c[0] = A_1 r[0], c_j = c[j] = A_1 r[j], U = Ur, v_j = v[j] =A_4 r4[j]
        r = {}
        y = []
        r4 = {}
        for i in range(self.assump_size):
            rand = self.group.random(ZR)
            y.append(rand)
        r[0] = y

        for attr, row in mono_span_prog.items():
            y = []
            for i in range(self.assump_size):
                rand = self.group.random(ZR)
                y.append(rand)
            r[int(attr)] = y

            # set v_j for semi-valid attributes
            if attr in semi_list:
                y = []
                for i in range(self.assump_size):
                    rand = self.group.random(ZR)
                    y.append(rand)
                r4[int(attr)] = y

        Ur = []
        for i in range(num_cols - 1):
            y = []
            for j in range(self.assump_size + 1):
                y.append(self.group.random(ZR))
            Ur.append(y)


        # compute C_0 = A_1 * r
        C_0 = []
        for i in range(4 * self.assump_size):
            prod = 1
            for j in range(self.assump_size):
                prod *= pk['g_A'][j][i] ** r[0][j]
            C_0.append(prod)

        # compute c^T * U_0 = A_1 * r * U_0 = r * (A_1 * U_0)
        g_cU = []
        for i in range(self.assump_size + 1):
            prod = 1
            for j in range(self.assump_size):
                prod *= pk['g_AU'][j][i] ** r[0][j]
            g_cU.append(prod)

        # compute C_1, C_2, C_3
        C_1 = {}
        C_2 = {}
        C_3 = {}
        for attr, row in mono_span_prog.items():
            #attr_stripped = self.util.strip_index(attr)
            y1 = []
            y2 = []
            y3 = []
            
            # randomize C_1, C_2, C_3 if it is a semi-valid attribute
            if attr in semi_list:
                for i in range(self.assump_size + 1):
                    prod = g_cU[i] ** row[0]
                    cols = len(row)
                    for j in range(1, cols):
                        prod *= g ** (row[j] * Ur[j - 1][i])
                    # c * W = A_1 * r * W = r * (A_1 * W)
                    for j2 in range(self.assump_size):
                        prod *= pk['g_AW'][0][j2][i] ** r[int(attr)][j2] * sk['g_A4W'][0][j2][i] ** r4[int(attr)][j2]
                    y1.append(prod)
                C_1[int(attr)] = y1

                for i in range(4 * self.assump_size):
                    prod = 1
                    for j in range(self.assump_size):
                        prod *= pk['g_A'][j][i] ** r[int(attr)][j] * sk['g_A4'][j][i] ** r4[int(attr)][j]
                    y2.append(prod)
                C_2[int(attr)] = y2

                for i in range(self.assump_size + 1):
                    prod = 1
                    for j in range(self.assump_size):
                        prod *= (pk['g_AW'][1][j][i] * (pk['g_AW'][2][j][i] ** int(attr))) ** r[int(attr)][j] * (sk['g_A4W'][1][j][i] * (sk['g_A4W'][2][j][i] ** int(attr))) ** r4[int(attr)][j]
                    y3.append(prod)
                C_3[int(attr)] = y3
            else:
                for i in range(self.assump_size + 1):
                    prod = g_cU[i] ** row[0]
                    cols = len(row)
                    for j in range(1, cols):
                        prod *= g ** (row[j] * Ur[j - 1][i])
                    # c * W = A_1 * r * W = r * (A_1 * W)
                    for j2 in range(self.assump_size):
                        prod *= pk['g_AW'][0][j2][i] ** r[int(attr)][j2]
                    y1.append(prod)
                C_1[int(attr)] = y1

                for i in range(4 * self.assump_size):
                    prod = 1
                    for j in range(self.assump_size):
                        prod *= pk['g_A'][j][i] ** r[int(attr)][j]
                    y2.append(prod)
                C_2[int(attr)] = y2

                for i in range(self.assump_size + 1):
                    prod = 1
                    for j in range(self.assump_size):
                        prod *= (pk['g_AW'][1][j][i] * (pk['g_AW'][2][j][i] ** int(attr))) ** r[int(attr)][j]
                    y3.append(prod)
                C_3[int(attr)] = y3

        # compute C
        C = 1
        for i in range(self.assump_size):
            C *= pk['e_gh_Ak'][i] ** r[0][i]
        C *= msg

        return {'policy': policy, 'C_0': C_0, 'C_1': C_1, 'C_2': C_2, 'C_3': C_3, 'C': C}

    def decrypt(self, pk, ctxt, key):
        """
        Decrypt ciphertext ctxt with key key.
        """

        if debug:
            print('Decryption algorithm:\n')

        nodes = self.util.prune(ctxt['policy'], key['attr_list'])
        if not nodes:
            print ("Policy not satisfied.")
            return None
        
        prod1 = 1
        for i in range(4 * self.assump_size):
            prod1 *= pair(ctxt['C_0'][i], key['K_0'][i])

        prod2 = 1
        prod3 = 1
        prod4 = 1
        for node in nodes:
            attr = node.getAttributeAndIndex()
      
            for i in range(self.assump_size + 1):
                prod2 *= pair(ctxt['C_1'][int(attr)][i], key['K_1'][i])

            for i in range(4 * self.assump_size):
                prod3 *= pair(ctxt['C_2'][int(attr)][i], key['K_2'][int(attr)][i])

            for i in range(self.assump_size + 1):
                prod4 *= pair(ctxt['C_3'][int(attr)][i], key['K_3'][int(attr)][i])

        K = ((prod1 / prod2) * prod3) / prod4
        return ctxt['C'] / K
                
