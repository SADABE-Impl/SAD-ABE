'''
:Authors:         
:Date:            10/2023
'''

from charm.toolbox.pairinggroup import PairingGroup, GT
from schemes.dgp22KPSADABE import DGP22KPSADABE


def main():
    # instantiate a bilinear pairing map
    pairing_group = PairingGroup('MNT224')

    # 1-linear assumption with 5 attributes
    abe = DGP22KPSADABE(pairing_group, 1, 5)

    # run the set up
    #(pk, msk) = abe.setup()
    (pk, msk, sk) = abe.setup()

    attr_list = ['1', '2', '3', '5']
    attr_semi_list = ['3', '5']
    #attr_semi_list = []
    policy_str = '((1 and 2) or (3 and 4))'
    policy_semi_list = ['1', '2']
    #policy_semi_list = []

    # generate a key
    #key = abe.keygen(pk, msk, policy_str)
    key = abe.keygen(pk, msk, policy_str, policy_semi_list)

    # choose a random message
    msg = pairing_group.random(GT)

    # generate a ciphertext
    #ctxt = abe.encrypt(pk, msg, attr_list)
    ctxt = abe.encrypt(pk, msg, attr_list, sk, attr_semi_list)

    # decryption
    rec_msg = abe.decrypt(pk, ctxt, key)
    if debug:
        if rec_msg == msg:
            print ("Successful decryption.")
        else:
            print ("Decryption failed.")


if __name__ == "__main__":
    debug = True
    main()
