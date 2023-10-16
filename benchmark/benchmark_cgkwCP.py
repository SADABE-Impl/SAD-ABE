from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from schemes.cgkw18CPABE import CGKW18CPABE

#size of policy/attribute set
n = 20

trials = 1

pairing_group = PairingGroup('MNT224')
abe = CGKW18CPABE(pairing_group, 1, 100)

policy_str = '(0'
attr_list = ['0']
for i in range(1, n):
    policy_str += " and " + str(i)
    attr_list.append(str(i))
policy_str += ')'

msg = pairing_group.random(GT)

(pk, msk) = abe.setup()

ctxt = abe.encrypt(pk, msg, policy_str)

key = abe.keygen(pk, msk, attr_list)

assert pairing_group.InitBenchmark(), "failed to initialize benchmark"
pairing_group.StartBenchmark(["RealTime"])
for a in range(trials):
    # abe.encrypt(pk, msg, policy_str)
    # abe.keygen(pk, msk, attr_list)
    abe.decrypt(pk, ctxt, key)
pairing_group.EndBenchmark()

msmtDict = pairing_group.GetGeneralBenchmarks()
# granDict = pairing_group.GetGranularBenchmarks()
print("<=== General Benchmarks ===>")
print("Time  := ", msmtDict['RealTime'])
# print("<=== Granular Benchmarks ===>")
# print("G1 mul   := ", granDict["Mul"][G1])
# print("G2 exp   := ", granDict["Exp"][G2])
