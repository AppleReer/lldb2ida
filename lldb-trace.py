# coding:utf-8
import threading
import lldb
import logging
import sys
import io
import time
import json

print("* Script Begin ")
# exec(open('/Users/bliss_ddo/Desktop/lldb2ida/lldb-trace.py').read())
# Tracer().tracehere(True)
def trace_callback(frame, bp_loc, extra_args, internal_dict):
	Tracer().onTrace(bp_loc.GetAddress().load_addr)
	# if Tracer().frame.IsEqual(frame):
	# 	Tracer().onTrace(bp_loc.GetAddress().load_addr)
	# else:
	# 	print("hit breakpoint on other frame 0x%x, dont trace"%(bp_loc.GetAddress().load_addr))
	# 	Tracer().resume()


def finish_callback(frame, bp_loc, extra_args, internal_dict):
	print("function finish")
	json_str = json.dumps(Tracer().assemJSON())
	print(json_str)
	filename = "/Users/bliss_ddo/Desktop/%d.json"%(time.time())
	print("file name is %s"%filename)
	with open(filename,"w",encoding="utf-8") as f2:
		f2.write(json_str)
	Tracer().clean()


class InstructionNode(object):

	def __init__(self,sbinstruction):
		self.hitcounter = 0;
		self.addr = sbinstruction.GetAddress().load_addr
		self.comment = sbinstruction.comment
		self.is_branch = sbinstruction.is_branch;
		self.mnemonic = sbinstruction.mnemonic
		self.operands = sbinstruction.operands;
		self.data = (sbinstruction.GetData(lldb.target).uint32)[0]
		tmpdata8 = sbinstruction.GetData(lldb.target).uint8;
		self.dd1 = "%02x%02x%02x%02x"%(tmpdata8[0],tmpdata8[1],tmpdata8[2],tmpdata8[3]);
		self.dd2 = "%02x%02x%02x%02x"%(tmpdata8[3],tmpdata8[2],tmpdata8[1],tmpdata8[0]);
		self.br2 = 0

	def todict(self):
		d = {}
		d["hitcounter"]=self.hitcounter
		d["addr"]=self.addr
		d["comment"]=self.comment
		d["is_branch"]=self.is_branch
		d["mnemonic"]=self.mnemonic
		d["operands"]=self.operands
		d["data"]=self.data
		d["datahex"]=hex(self.data)
		d["dd1"]=self.dd1
		d["dd2"]=self.dd2
		d["br2"]=self.br2
		return d

	def record_br_opend(self,regname):
		# self.br2 = "oooooo"
		returnObject = lldb.SBCommandReturnObject()
		lldb.debugger.GetCommandInterpreter().HandleCommand('po $%s'%(regname), returnObject)
		output = returnObject.GetOutput()
		self.br2 = int(output)

	@property
	def addr(self):
		return self._addr
	@addr.setter
	def addr(self, value):
		self._addr = value

	@property
	def comment(self):
		return self._comment
	@comment.setter
	def comment(self, value):
		self._comment = value

	@property
	def is_branch(self):
		return self._is_branch
	@is_branch.setter
	def is_branch(self, value):
		self._is_branch = value

	@property
	def mnemonic(self):
		return self._mnemonic
	@mnemonic.setter
	def mnemonic(self, value):
		self._mnemonic = value

	@property
	def operands(self):
		return self._operands
	@operands.setter
	def operands(self, value):
		self._operands = value

	@property
	def data(self):
		return self._data
	@data.setter
	def data(self, value):
		self._data = value

	@property
	def dd1(self):
		return self._dd1
	@dd1.setter
	def dd1(self, value):
		self._dd1 = value

	@property
	def dd2(self):
		return self._dd2
	@dd2.setter
	def dd2(self, value):
		self._dd2 = value

	@property
	def hitcounter(self):
		return self._hitcounter
	@hitcounter.setter
	def hitcounter(self, value):
		self._hitcounter = value

	@property
	def br2(self):
		return self._br2
	@br2.setter
	def br2(self, value):
		self._br2 = value

	def increase(self):
		self._hitcounter+=1;

	def __repr__(self):
		return "[%d][0x%x] %6s %12s %s %s %s"%(self.hitcounter ,self.addr,self.mnemonic,self.operands,hex(self.data),self.dd1,self.dd2);



class SingletonType(type):
	_instance_lock = threading.Lock()
	def __call__(cls, *args, **kwargs):
		if not hasattr(cls, "_instance"):
			with SingletonType._instance_lock:
				if not hasattr(cls, "_instance"):
					cls._instance = super(SingletonType,cls).__call__(*args, **kwargs)
		return cls._instance


class Tracer(metaclass=SingletonType):
	def __init__(self):
		self._traceCounter = 0
		self._instructionarr = [];
		self._starttime = 0
		self._brkfinish = None
		self._aslr = 0

	def onFinish(self,addr):
		pass


	def onTrace(self,addr):
		self._traceCounter+=1;
		idx = int((addr-self.functionStart)/4)
		node = self._instructionarr[idx][0]
		if(node.mnemonic == "br"):
			print("br!!!!!")
			node.record_br_opend(node.operands)
		node.increase();
		# print("* Breakpoint tracing ==> %s"%(node))
		self.resume()

	def processASLR(self):
		print("[*] process ASLR")
		returnObject = lldb.SBCommandReturnObject()
		lldb.debugger.GetCommandInterpreter().HandleCommand('image list -o', returnObject)
		output = returnObject.GetOutput()
		match = re.match(r'.+(0x[0-9a-fA-F]+)', output)
		if match:
			ASLRHexStr:str = match.group(1)
			ASLR = int(ASLRHexStr,16)
			self._aslr = ASLR



	def processrecordframe(self):
		print("[*] record frame ",lldb.process.selected_thread.GetSelectedFrame())
		self.frame = lldb.process.selected_thread.GetSelectedFrame()

	def processFunctionBeginEnd(self):
		self.functionStart = lldb.process.selected_thread.GetSelectedFrame().GetSymbol().GetStartAddress().load_addr
		self.functionEnd = lldb.process.selected_thread.GetSelectedFrame().GetSymbol().GetEndAddress().load_addr
		instructionCount = (self.functionEnd-self.functionStart)/4;
		print("[*] Function range 0x%x~0x%x,there are %d instructions in this function" % (self.functionStart,self.functionEnd,instructionCount));

	def processFinishPoint(self):
		lr = lldb.process.selected_thread.GetSelectedFrame().FindRegister("lr")
		print("[*] lr value is 0x%x,set the finish breakpoint here" % (lr.unsigned))
		finishbrk = lldb.target.BreakpointCreateByAddress(lr.unsigned)
		finishbrk.SetScriptCallbackFunction("finish_callback")
		self._brkfinish = finishbrk


	def makeTraceBreakpoint(self):
		print("[*] ready to make trace breakpoint")
		for each in lldb.process.selected_thread.GetSelectedFrame().GetSymbol().instructions:
			brk = lldb.target.BreakpointCreateBySBAddress(each.GetAddress())
			brk.SetScriptCallbackFunction("trace_callback")
			brk.SetAutoContinue(True)
			inode = InstructionNode(each)
			self._instructionarr.append((inode,brk))
			print("[*] make trace breakpoint at address %s"%(hex(each.GetAddress().load_addr)))


	def clean(self):
		print("[*] clean all others break point,set starttime to zero, set traceCounter to zero")
		# lldb.target.DeleteAllBreakpoints()
		for each in self._instructionarr:
			brk = each[1]
			lldb.target.BreakpointDelete(brk.id)
		if self._brkfinish is not None:
			lldb.target.BreakpointDelete(self._brkfinish.id)
		self._traceCounter = 0
		self._instructionarr = []
		self._starttime = 0
		self._aslr = 0


	def resume(self):
		# print("resume")
		lldb.target.process.Continue()


	def tracehere(self,autoresume):
		self.clean()
		self.processASLR()
		self.processrecordframe()
		self.processFunctionBeginEnd()
		self.processFinishPoint()
		self.makeTraceBreakpoint()
		if autoresume:
			self.resume()

	def assemJSON(self):
		retdict = {}
		tarr = []
		for each in self.instructionarr:
			inode = each[0]
			brk = each[1]
			inode.hitcounter = brk.GetHitCount()
			print(inode)
			tarr.append(inode.todict())
		retdict["aslr"] = self._aslr
		retdict["func_start"] = self.functionStart
		retdict["func_end"] = self.functionEnd
		retdict["instruction_arr"] = tarr
		return retdict


	@property
	def frame(self):
		return self._frame

	@frame.setter
	def frame(self, value):
		self._frame = value


	@property
	def functionStart(self):
		return self._functionStart

	@functionStart.setter
	def functionStart(self, value):
		self._functionStart = value

	@property
	def functionEnd(self):
		return self._functionEnd

	@functionEnd.setter
	def functionEnd(self, value):
		self._functionEnd = value

	@property
	def instructionarr(self):
		return self._instructionarr

	@instructionarr.setter
	def instructionarr(self, value):
		self._instructionarr = value

