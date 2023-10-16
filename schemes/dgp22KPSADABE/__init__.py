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

    def setup(self):
        """
        Generates public key and master secret key.
        """

        if debug:
            print('Setup algorithm:\n')

        # for simplity, we define B_{i,j} = 0 if i != j, B_{i,j} = b_i if i = j
        #                         B^*_{i,j} = 0 if i != j, B_{i,j} = (b_i)^{-1} if i = j
        # B = B, B^* = Bi
        B = []
        Bi = []
        for j1 in range(3):
            x = []
            y = []
            for j2 in range(3):
                if j2 == j1:
                    random = self.group.random(ZR)
                    x.append(random)
                    y.append(random ** (-1))
                else:
                    x.append(0)
                    y.append(0)
            B.append(x)
            Bi.append(y)


        # D = D, D^* = Di
        D = []
        Di = []
        for j1 in range(9):
            x = []
            y = []
            for j2 in range(9):
                if j2 == j1:
                    random = self.group.random(ZR)
                    x.append(random)
                    y.append(random ** (-1))
                else:
                    x.append(0)
                    y.append(0)
            D.append(x)
            Di.append(y)

        # pick a random element from the two source groups and pair them
        g = self.group.random(G1)
        h = self.group.random(G2)
        e_gh = pair(g, h)

        # now compute various parts of the public parameters

        g_B = []
        for j1 in range(3):
            y = []
            for j2 in range(3):
                y.append(g ** B[j1][j2])
            g_B.append(y)

        g_Bi = []
        for j1 in range(3):
            y = []
            for j2 in range(3):
                y.append(h ** Bi[j1][j2])
            g_Bi.append(y)

        g_D = []
        for j1 in range(9):
            y = []
            for j2 in range(9):
                y.append(g ** D[j1][j2])
            g_D.append(y)

        g_Di = []
        for j1 in range(9):
            y = []
            for j2 in range(9):
                y.append(h ** Di[j1][j2])
            g_Di.append(y)

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
            # we make up the (msk['h'] ** 0) computation for the case that B, D are randomly chosen with B_{i,j} != 0
            prod1 = pk['g_Di0'][0] ** pi 
            prod2 = pk['g_Di1'][1] ** (pi * int(attr)) 
            y.append(prod1)
            y.append(prod2)

            # compute the third component
            prod = pk['g_Di2'][2] ** shares[attr] 
            y.append(prod)

            # components 4-6 are 0
            y.append(h0)
            y.append(h0)
            y.append(h0)

            # component 7 depends on whether it is valid
            if attr in semi_list:
                prod = msk['g_Di6'][6] ** self.group.random(ZR) 
                y.append(prod)
            else:
                y.append(h0)

            # components 8-9 are 0
            y.append(h0)
            y.append(h0)

            K1[int(attr)] = y
                
        # K_0^* = K0
        K0 = []
        prod = pk['g_Bi0'][0] ** s 
        K0.append(prod)
        K0.append(h0)
        K0.append(msk['g_Bi2'][2])

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
            # we make up the (pk['g'] ** 0) computation for the case that B, D are randomly chosen with B_{i,j} != 0
            prod1 = pk['g_D0'][0] ** (sig * int(attr)) 
            prod2 = pk['g_D1'][1] ** (-sig) * (pk['g'] ** 0) 
            y.append(prod1)
            y.append(prod2)
            prod = pk['g_D2'][2] ** (w) 
            y.append(prod)
            y.append(g0)
            y.append(g0)
            y.append(g0)
            if attr in semi_list:
                prod = sk['g_D6'][6] ** self.group.random(ZR) 
                y.append(prod)
            else:
                y.append(g0)
            y.append(g0)
            y.append(g0)
            C1[int(attr)] = y

        C0 = []
        prod = pk['g_B0'][0] ** w 
        C0.append(prod)
        C0.append(g0)
        prod = pk['g_B2'][2] ** z 
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
                
