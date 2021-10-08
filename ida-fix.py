# coding:utf-8
import json
# exec(open('/Users/bliss_ddo/Desktop/lldb2ida/ida-fix.py').read())


class Fixer(object):
	def __init__(self,jsonpath):
		self._jsonpath = jsonpath
		self._dict = None
	
	def processJSON(self):
		with open(self._jsonpath,'r') as f:
			self._dict = json.load(f)
			print(self._dict)

	def fix_function_range(self):
		a = self._dict["aslr"]
		sa = self._dict["func_start"]
		ea = self._dict["func_end"]
		s = sa - a
		e = ea - a
		print("make unknow")
		for i in xrange(s,e,4):
			idc.MakeUnkn(i,0)
		print("make code")
		for i in xrange(s,e,4):
			idc.MakeCode(i)
		print("make funct at 0x%x - 0x%x"%(s,e))
		idc.MakeFunction(s,e)

	def fix_unknow_as_nop(self):
		a = self._dict["aslr"]
		sa = self._dict["func_start"]
		ea = self._dict["func_end"]
		arr = self._dict["instruction_arr"]
		for each in arr:
			if each["comment"] == "unknown opcode":
				print("try to fix unknow opcode at 0x%x"%(each["addr"]-a));
				idc.PatchDword(each["addr"]-a, 0xd503201f)
		s = sa - a
		e = ea - a
		print("make code")
		for i in xrange(s,e,4):
			idc.MakeCode(i)


	
	def fix_br(self):
		print("fix br...")
		a = self._dict["aslr"]
		sa = self._dict["func_start"]
		ea = self._dict["func_end"]
		arr = self._dict["instruction_arr"]
		for each in arr:
			if each["mnemonic"] == "br":
				print("br")
				br2 = each["br2"]
				if br2 is not 0:
					abspc = each["addr"] - a
					print("br address is 0x%x"%(abspc))
					if br2 >= sa and br2 <= ea:
						print("br is inner func ")
						relativeAddr = br2 - each["addr"]
						print("======")
						print(relativeAddr)
						print("======")
						b_opcode_fixed = self.b(relativeAddr)
						print("fix address at 0x%x to 0x%x"%(abspc,b_opcode_fixed))
				        idc.PatchDword(each["addr"]-a, b_opcode_fixed)


	def fix_unexec_as_nop(self):
		print("fix br...")
		a = self._dict["aslr"]
		sa = self._dict["func_start"]
		ea = self._dict["func_end"]
		arr = self._dict["instruction_arr"]
		for i in range(1,len(arr)):
			each = arr[i]
			if each["hitcounter"] == 0:
				abspc = each["addr"] - a
				print("fix unexec inst as nop 0x%0x"%(abspc))
				idc.PatchDword(abspc,0xd503201f)

	def restore(self):
		print("restore from json")
		a = self._dict["aslr"]
		sa = self._dict["func_start"]
		ea = self._dict["func_end"]
		s = sa - a
		e = ea - a
		arr = self._dict["instruction_arr"]
		for each in arr:
			abspc = each["addr"] - a
			value = int(each["dd2"],16)
			print("restore value at 0x%0x for value 0x%0x"%(abspc,value))
			idc.PatchDword(abspc,value)
		for i in xrange(s,e,4):
			idc.MakeCode(i)



	def b(self,op):
		return 0b00010100000000000000000000000000|(int(op/4) & 0b00000011111111111111111111111111)

	@property
	def jsonpath(self):
		return self._jsonpath
	@jsonpath.setter
	def jsonpath(self, value):
		self._jsonpath = value
		self.processJSON()

fixer = Fixer("/Users/bliss_ddo/Desktop/1.json")
fixer.processJSON()
fixer.fix_function_range()
fixer.fix_br()
fixer.fix_unknow_as_nop()
# fixer.fix_unexec_as_nop()
# fixer.restore()