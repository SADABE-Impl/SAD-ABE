from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from schemes.acns24submissionKPSADABE import KPSADABE

#size of policy/attribute set
n = 20

trials = 1

pairing_group = PairingGroup('MNT224')
abe = KPSADABE(pairing_group, 1, 100)

policy_str = '(0'
attr_list = ['0']
for i in range(1, n):
    policy_str += " and " + str(i)
    attr_list.append(str(i))
policy_str += ')'
attr_semi_list = []
policy_semi_list = []

msg = pairing_group.random(GT)

(pk, msk, sk) = abe.setup()

ctxt = abe.encrypt(pk, msg, attr_list, sk, attr_semi_list)

key = abe.keygen(pk, msk, policy_str, policy_semi_list)

assert pairing_group.InitBenchmark(), "failed to initialize benchmark"
pairing_group.StartBenchmark(["RealTime"])
for a in range(trials):
    # abe.encrypt(pk, msg, attr_list, sk, attr_semi_list)
    # abe.keygen(pk, msk, policy_str, policy_semi_list)
    abe.decrypt(pk, ctxt, key)
pairing_group.EndBenchmark()

msmtDict = pairing_group.GetGeneralBenchmarks()
# granDict = pairing_group.GetGranularBenchmarks()
print("<=== General Benchmarks ===>")
print("Time  := ", msmtDict['RealTime'])
# print("<=== Granular Benchmarks ===>")
# print("G1 mul   := ", granDict["Mul"][G1])
# print("G2 exp   := ", granDict["Exp"][G2])
