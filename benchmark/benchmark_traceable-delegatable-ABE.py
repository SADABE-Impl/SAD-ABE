from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from schemes.OurKPSADABE import KPSADABE
import sys
#size of policy/attribute set
n = 100
#n1 is the number of type_I attr: len*2
n1 = 0
#n2 is the required number of type_II attr: p*tau*len
n2 = 0
#n3 is the number of type_II attr: p*z*len
n3 = 0
q=96
p=4
z=60
tau=36
trials = 1
type = "dec"
if(len(sys.argv)==2):
    type = sys.argv[1]

print("Benchmarks for ", type, " with ", trials, " trials.")

pairing_group = PairingGroup('MNT224')
abe = KPSADABE(pairing_group, 1, 100)

(pk, msk, sk) = abe.setup()

#k is len
for k in range(3):
    #n += p * z + 2
    n1 += 2
    n2 += p*tau
    n3 += p*z
    policy_str = '(0'
    attr_list = ['0']
    attr_semi_list = []
    policy_semi_list = []
    for i in range(1, n):
        policy_str += " and " + str(i)
        attr_list.append(str(i))
    for i in range(n+1, n+n1):
        policy_str += " and " + str(i)
        attr_list.append(str(i))
        policy_semi_list.append(str(i))
    for i in range(n+n1+1, n+n1+n2):
        policy_str += " and " + str(i)
        attr_list.append(str(i))
    for i in range(n+n1+n2+1, n+n1+n3):
        policy_str += " or " + str(i)
        attr_list.append((str(i+1000)))
    policy_str += ')'
	
    msg = pairing_group.random(GT)
	
	
    ctxt = abe.encrypt(pk, msg, attr_list, sk, attr_semi_list)
	
    key = abe.keygen(pk, msk, policy_str, policy_semi_list)
	
    assert pairing_group.InitBenchmark(), "failed to initialize benchmark"
    pairing_group.StartBenchmark(["RealTime"])
    for a in range(trials):
        if type == "enc":
            abe.encrypt(pk, msg, attr_list, sk, attr_semi_list)
        if type == "keygen":
            abe.keygen(pk, msk, policy_str, policy_semi_list)
        if type == "dec":
            abe.decrypt(pk, ctxt, key)
    pairing_group.EndBenchmark()
	
    msmtDict = pairing_group.GetGeneralBenchmarks()
	# granDict = pairing_group.GetGranularBenchmarks()
    print("Identity length := ", n, ", Time  := ", msmtDict['RealTime'])
# print("<=== Granular Benchmarks ===>")
# print("G1 mul   := ", granDict["Mul"][G1])
# print("G2 exp   := ", granDict["Exp"][G2])	
