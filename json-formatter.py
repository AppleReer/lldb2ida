import json

with open("/Users/bliss_ddo/Desktop/1.json",'r') as f:
	jdict = json.load(f)
	a = jdict["aslr"]
	sa = jdict["func_start"]
	ea = jdict["func_end"]
	arr = jdict["instruction_arr"]
	s = sa - a
	e = ea - a
	i = 0
	for each in arr:
		print("[%d][%d] 0x%0x 0x%0x %s %s(%s)"%(i,each["hitcounter"],each["addr"],each["addr"]-a,each["mnemonic"],each["operands"],each["dd2"]))
		i+=1
