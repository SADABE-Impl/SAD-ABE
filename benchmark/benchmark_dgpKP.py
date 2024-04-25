from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from schemes.dgp22KPSADABE import DGP22KPSADABE
import sys
#size of policy/attribute set
n = 0
trials = 10
type = "dec"
if(len(sys.argv)==2):
    type = sys.argv[1]

print("Benchmarks for ", type, " with ", trials, " trials.")

pairing_group = PairingGroup('MNT224')
abe = DGP22KPSADABE(pairing_group, 1, 100)

(pk, msk, sk) = abe.setup()

for k in range(10):
    n += 10
    policy_str = '(0'
    attr_list = ['0']
    for i in range(1, n):
        policy_str += " and " + str(i)
        attr_list.append(str(i))
    policy_str += ')'
    attr_semi_list = []
    policy_semi_list = []

    msg = pairing_group.random(GT)

    ctxt = abe.encrypt(pk, msg, attr_list, sk, attr_semi_list)

    key = abe.keygen(pk, msk, policy_str, policy_semi_list)

    assert pairing_group.InitBenchmark(), "failed to initialize benchmark"
    pairing_group.StartBenchmark(["RealTime"])
    for a in range(trials):
	    if type == "setup":
	        abe.setup()
        if type == "enc":
            abe.encrypt(pk, msg, attr_list, sk, attr_semi_list)
        if type == "keygen":
            abe.keygen(pk, msk, policy_str, policy_semi_list)
        if type == "dec":
            abe.decrypt(pk, ctxt, key)
    pairing_group.EndBenchmark()

    msmtDict = pairing_group.GetGeneralBenchmarks()
    # granDict = pairing_group.GetGranularBenchmarks()
    print("Attribute no := ", n, ", Time  := ", msmtDict['RealTime'])
# print("<=== Granular Benchmarks ===>")
# print("G1 mul   := ", granDict["Mul"][G1])
# print("G2 exp   := ", granDict["Exp"][G2])
