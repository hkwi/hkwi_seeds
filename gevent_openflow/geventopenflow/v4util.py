import binascii
import json
import struct
import collections
import warnings
import traceback

RAW_VIEW = 0
PARSED_VIEW = 1
DUMP_VIEW = 2

def struct_count(packstr):
	return len(struct.unpack(packstr, "\x00"*struct.calcsize(packstr)))

class Context(dict):
	def __setattr__(self, name, value):
		if name == "view" and not hasattr(self, "value_view"):
			self.value_view = self.view
		super(Context, self).__setattr__(name, value)
	
	def __getitem__(self, name):
		try:
			return super(Context, self).__getitem__(name)
		except KeyError:
			if name == "view":
				return PARSED_VIEW
			elif name == "version":
				return 4
			raise
	
	def __getattr__(self, name):
		try:
			return self[name]
		except KeyError:
			raise AttributeError(name)
	
	@property
	def parsed(self):
		return True if self.view in (1,2) else False
	
	@property
	def dump(self):
		return True if self.view == 2 else False

class Show(object):
	def __init__(self, context, view):
		self.context = context
		self.view = view
	
	def __enter__(self):
		self.saved_view = self.context.view
		self.context.view = self.view
	
	def __exit__(self, exc_type, exc_value, traceback):
		self.context.view = self.saved_view

class Base(object):
	def __init__(self, **kwargs):
		# offset is object specific
		self._offset = 0
		if "offset" in kwargs:
			self._offset = kwargs["offset"]
			del(kwargs["offset"])
		
		# share the context
		parent = kwargs.get("parent", None)
		context = kwargs.get("_context", None)
		if parent is not None:
			context = parent._context
		elif not context:
			context = Context(kwargs)
		self._context = context
		
		# keys rule
		self._keys = [] 
		self._packs = [] # pack/unpack hint
		self._auto_vals = {}
		self._show_rule = {}
		
		self._cache = {}
	
	def __getattr__(self, name):
		if name.startswith("_") or name not in self._keys:
			raise AttributeError(name)
		
		try:
			value = self._cache[name] # cache may be used.
		except KeyError:
			try:
				value = self._context[name]
				if name in self._show_rule:
					with self.show(self._context.value_view):
						if self._context.parsed:
							value = self._show_rule[name](value, inverse=True)
			except KeyError:
				if name in self._keys and hasattr(self._context, "message"):
					hit = False
					idx = 0
					offset = self._offset
					for p in self._packs:
						if isinstance(p, str):
							assert struct.calcsize("!"+p)+offset <= len(self._context.message), "pack=%s offset=%d message len=%d" % (p, offset, len(self._context.message))
							vs = struct.unpack_from("!"+p, self._context.message, offset)
							sub_keys = self._keys[idx:idx+len(vs)]
							for k,v in zip(sub_keys, vs):
								self._cache[k] = v
							if name in sub_keys:
								value = vs[sub_keys.index(name)]
								hit = True
								break
							idx += len(vs)
							offset += struct.calcsize("!"+p)
						elif callable(p):
							k = self._keys[idx]
							v,consumed = p(self._context.message, offset)
							self._cache[k] = v
							if k == name:
								value = v
								hit = True
								break
							idx += 1
							offset += consumed
						else:
							raise TypeError("packs must be str or callable")
					if not hit:
						raise AttributeError(name)
				elif name in self._auto_vals:
					value = self._auto_vals[name](self)
				else:
					raise AttributeError(name)
		
		if name in self._show_rule and self._context.parsed:
			value = self._show_rule[name](value, obj=self)
		
		if self._context.dump and isinstance(value, str):
			try:
				json.dumps(value)
			except:
				warnings.warn("%s.%s returned binary" % (self.__class__.__name__, name))
				value = binascii.b2a_hex(value)
		return value
	
	def serialize(self):
		with self.show(RAW_VIEW):
			ret = []
			
			idx = 0
			offset = self._offset
			for p in self._packs:
				if isinstance(p, str):
					idx_end = idx + struct_count(p)
					ret.append(struct.pack("!"+p, *[getattr(self,k) for k in self._keys[idx:idx_end]]))
					idx = idx_end
				elif callable(p):
					value = getattr(self, self._keys[idx])
					if isinstance(value, str):
						ret.append(value)
					elif isinstance(value, Base):
						ret.append(value.serialize())
					elif isinstance(value, list) or isinstance(value, tuple):
						ret += [o.serialize() for o in value]
					else:
						raise TypeError("Could not serialize %s" % value)
					idx += 1
				else:
					raise TypeError("packs must be str or callable")
			
			return "".join(ret)
	
	def plain(self):
		ret = collections.OrderedDict()
		for k in self._keys:
			if k.startswith("_"):
				continue
			v = getattr(self, k)
			if isinstance(v, Base):
				v = v.plain()
			elif isinstance(v, list) or isinstance(v, tuple):
				vr = []
				for w in v:
					if isinstance(w, Base):
						vr.append(w.plain())
					else:
						vr.append(w)
				v = vr
			ret[k] = v
		return ret
	
	def _append_packdef(self, packs, keys, show_rule):
		if self._packs and isinstance(self._packs[-1], str):
			self._packs[-1] += packs
		else:
			self._packs.append(packs)
		self._keys += keys
		self._show_rule.update(show_rule)
	
	def _append_vlendef(self, *vlendefs):
		for (key, vlen_read, convert) in vlendefs:
			self._keys.append(key)
			self._packs.append(vlen_read)
			if convert:
				self._show_rule[key] = convert
	
	def show(self, mode):
		return Show(self._context, mode)
	
	def __repr__(self):
		# NOTE: json can only handle direct subclass of dict, not one from collections.Mapping.
		with self.show(DUMP_VIEW):
			try:
				return json.dumps(self.plain())
			except:
				traceback.print_exc()
				return "json dump failed"

class Message(Base):
	def __init__(self, message=None, offset=0, **kwargs):
		if message:
			kwargs["message"] = message
			kwargs["offset"] = offset
		super(Message, self).__init__(**kwargs)
		
		with self.show(PARSED_VIEW):
			self._parsed_init()
	
	def _parsed_init(self):
		self._append_packdef("BBHI", ("version", "type", "length", "xid"), {
			"type": enum_convert("HELLO", "ERROR", "ECHO_REQUEST", "ECHO_REPLY", "EXPERIMENTER",
				"FEATURES_REQUEST", "FEATURES_REPLY", "GET_CONFIG_REQUEST", "GET_CONFIG_REPLY", "SET_CONFIG", 
				"PACKET_IN", "FLOW_REMOVED", "PORT_STATUS", 
				"PACKET_OUT", "FLOW_MOD", "GROUP_MOD", "PORT_MOD", "TABLE_MOD", 
				"MULTIPART_REQUEST", "MULTIPART_REPLY", 
				"BARRIER_REQUEST", "BARRIER_REPLY", 
				"QUEUE_GET_CONFIG_REQUEST", "QUEUE_GET_CONFIG_REPLY", 
				"ROLE_REQUEST", "ROLE_REPLY", 
				"GET_ASYNC_REQUEST", "GET_ASYNC_REPLY", "SET_ASYNC", 
				"METER_MOD"),
			"xid": hex_convert})
		
		self._auto_vals["length"] = self._auto_length
		
		if self.type == "HELLO":
			self._append_vlendef(("elements", self._hello_elements, None),)
		elif self.type == "ERROR":
			self._append_packdef("H", ("etype",), {
				"etype": enum_convert("HELLO_FAILED", "BAD_REQUEST", "BAD_ACTION", "BAD_INSTRUCTION", "BAD_MATCH", "FLOW_MOD_FAILED",
					"GROUP_MOD_FAILED", "PORT_MOD_FAILED", "QUEUE_OP_FAILED", "SWITCH_CONFIG_FAILED", "ROLE_REQUEST_FAILED",
					"METER_MOD_FAILED", "TABLE_FEATURES_FAILED", EXPERIMENTER=0xffff)})
			if self.etype == "EXPERIMENTER":
				self._append_packdef("HI", ("exp_type", "experimenter"))
			else:
				idx = {
					"HELLO_FAILED":
						"INCOMPATIBLE EPERM",
					"BAD_REQUEST":
						'''BAD_VERSION BAD_TYPE BAD_MULTIPART BAD_EXPERIMENTER BAD_EXP_TYPE EPERM
						BAD_LEN BUFFER_EMPTY BUFFER_UNKNOWN BAD_TABLE_ID IS_SLAVE BAD_PORT BAD_PACKET MULTIPART_BUFFER_OVERFLOW''',
					"BAD_ACTION":
						'''BAD_TYPE BAD_LEN BAD_EXPERIMENTER BAD_EXP_TYPE BAD_OUT_PORT BAD_ARGUMENT EPERM
						TOO_MANY BAD_QUEUE BAD_OUT_GROUP MATCH_INCONSISTENT UNSUPPORTED_ORDER BAD_TAG BAD_SET_TYPE BAD_SET_LEN BAD_SET_ARGUMENT''',
					"BAD_INSTRUCTION":
						'UNKNOWN_INST UNSUP_INST BAD_TABLE_ID UNSUP_METADATA UNSUP_METADATA_MASK BAD_EXPERIMENTER BAD_EXP_TYPE BAD_LEN EPERM',
					"BAD_MATCH":
						'BAD_TYPE BAD_LEN BAD_TAG BAD_DL_ADDR_MASK BAD_NW_ADDR_MASK BAD_WILDCARDS BAD_FIELD BAD_VALUE BAD_MASK BAD_PREREQ DUP_FIELD EPERM',
					'FLOW_MOD_FAILED':
						"UNKNOWN TABLE_FULL BAD_TABLE_ID OVERLAP EPERM BAD_TIMEOUT BAD_COMMAND BAD_FLAGS",
					"GROUP_MOD_FAILED":
						'''GROUP_EXISTS INVALID_GROUP WEIGHT_UNSUPPORTED OUT_OF_GROUPS OUT_OF_BUCKETS CHAINING_UNSUPPORTED WATCH_UNSUPPORTED
						LOOP UNKNOWN_GROUP CHAINED_GROUP BAD_TYPE BAD_OMMAND BAD_BUCKET BAD_WATCH EPERM''',
					"PORT_MOD_FAILED":
						"BAD_PORT BAD_HW_ADDR BAD_CONFIG BAD_ADVERTISE EPERM",
					"TABLE_MOD_FAILED":
						"BAD_TABLE BAD_CONFIG EPERM",
					"QUEUE_OP_FAILED":
						"BAD_PORT BAD_QUEUE EPERM",
					"SWITCH_CONFIG_FAILED":
						"BAD_FLAGS BAD_LEN EPERM",
					"ROLE_REQUEST_FAILED":
						"STALE UNSUP BAD_ROLE",
					"METER_MOD_FAILED":
						'''UNKNOWN METER_EXISTS INVALID_METER UNKNOWN_METER BAD_COMMAND BAD_FLAGS BAD_RATE BAD_BURST 
						BAD_BAND BAD_BAND_VALUE OUT_OF_METERS OUT_OF_BANDS''',
					"TABLE_FEATURES_FAILED":
						"BAD_TABLE BAD_METADATA BAD_TYPE BAD_LEN BAD_ARGUMENT EPERM"
				}[self.etype].split()
				self._append_packdef("H", ("code",), {"code": enum_convert(*idx)})
			self._append_vlendef(("data", self._data, data_convert),)
			self._auto_vals["data"] = lambda s: ""
		elif self.type == "FEATURES_REPLY":
			self._append_packdef("QIBB2xII",
				("datapath_id", "n_buffers", "n_tables", "auxiliary_id", "capabilities", "reserved"), {
				"datapath_id":datapath_convert,
				"capabilities": bit_convert("FLOW_STATS", "TABLE_STATS", "PORT_STATS", "GROUP_STATS",
					IP_REASM=5, QUEUE_STATS=6, PORT_BLOCKED=8)
				})
		elif self.type == "PACKET_IN":
			self._append_packdef("IHBBQ", ("buffer_id", "total_len", "reason", "table_id", "cookie"), {
				"reason": enum_convert("NO_MATCH", "ACTION", "INVALID_TTL")
				})
			self._append_vlendef(("match", self._match, None), ("_p2", pad(2), None), ("data", self._data, data_convert))
			self._auto_vals["data"] = lambda s: ""
		elif self.type == "PACKET_OUT":
			self._append_packdef("IIH6x", ("buffer_id", "in_port", "actions_len"), {
				"in_port": port_convert
				})
			self._auto_vals["actions_len"] = lambda s: sum([len(a.serialize()) for a in s.actions])
			self._append_vlendef(("actions", self._actions, None), ("data", self._data, data_convert))
			self._auto_vals["data"] = lambda s: ""
		elif self.type == "PORT_STATUS":
			self._append_packdef("B7x", ("reason", ), {
				"reason": enum_convert("ADD", "DELETE", "MODIFY")
				})
			self._append_vlendef(("desc", self._port, None),)
		elif self.type == "MULTIPART_REQUEST":
			self._append_packdef("HH4x", ("mtype", "flags"), {
				"mtype": enum_convert(*'''DESC FLOW AGGREGATE TABLE PORT_STATS QUEUE GROUP
					GROUP_DESC GROUP_FEATURES METER METER_CONFIG METER_FEATURES PORT_DESC'''.split(),
					EXPERIMENTER=0xffff),
				"flags": bit_convert("REQ_MORE")})
			self._append_vlendef(("body", self._multi_body, None),)
		elif self.type == "FLOW_MOD":
			self._append_packdef("QQBBHHHIIIH2x", ("cookie", "cookie_mask", "table_id", "command",
				"idle_timeout", "hard_timeout", "priority", "buffer_id", "out_port", "out_group",
				"flags"), {
				"out_port": port_convert,
				"command": enum_convert("ADD","MODIFY","MODIFY_STRICT","DELETE","DELETE_STRICT")})
			self._append_vlendef(("match", self._match, None),("instructions", self._instructions, None))
	
	def _auto_length(self, s):
		self.length = 0
		self.length = len(self.serialize())
		return self.length
	
	def _hello_elements(self, message, offset=0):
		value = []
		while offset < len(message):
			element = HelloElement(offset=offset, parent=self)
			value.append(element)
			offset += element.length
			assert element.length != 0
		# check sum length and message end match
		return value, sum([x.length for x in value])
	
	def _data(self, message, offset=0):
		value = message[offset:]
		if self._context.dump:
			value = binascii.b2a_hex(value)
		return value, len(message)-offset
	
	def _match(self, message, offset):
		m = Match(offset=offset, parent=self)
		return m, (m.length+7)/8*8
	
	def _instructions(self, message, offset):
		value = []
		while offset < len(message):
			i = Instruction(offset=offset, parent=self)
			value.append(i)
			offset += i.len
			assert i.len != 0
		return value, sum([i.len for i in value])
	
	def _actions(self, message, offset):
		end = len(message)
		if self.type == "PACKET_OUT":
			end = offset + self.actions_len
		
		value = []
		while offset < end:
			a = Action(offset=offset, parent=self)
			value.append(a)
			offset += a.len
			assert a.len != 0
		return value, sum([a.len for a in value])
	
	def _port(self, message, offset):
		p = Port(offset=offset, parent=self)
		assert len(p.serialize())==64
		return p, 64
	
	def _multi_body(self, message, offset):
		return None, 0

class HelloElement(Base):
	def __init__(self, **kwargs):
		super(HelloElement, self).__init__(**kwargs)
		with self.show(PARSED_VIEW):
			self._parsed_init()
	
	def _parsed_init(self):
		self._append_packdef("HH", ("type", "length"), {
			"type": enum_convert(VERSIONBITMAP=1,),
			})
		self._auto_vals["length"] = self._auto_length
		if self.type=="VERSIONBITMAP":
			self._append_vlendef(("bitmaps", self._bitmaps, hello_bitmaps_convert),)
	
	def _auto_length(self, s):
		self.length = 0
		self.length = len(self.serialize())
		return self.length
	
	def _bitmaps(self, message, offset):
		return message[offset:offset+self.length-4], self.length-4

class Match(Base):
	def __init__(self, **kwargs):
		super(Match, self).__init__(**kwargs)
		with self.show(PARSED_VIEW):
			self._parsed_init()
	
	def _parsed_init(self):
		self._append_packdef("HH", ("type", "length"), {
			"type": enum_convert("STANDARD","OXM") })
		self._append_vlendef(("fields", self._oxm_fields, None),)
	
	def _oxm_fields(self, message, offset):
		value = []
		end = offset + self.length - 4
		while offset < end:
			f = MatchField(offset=offset, parent=self)
			value.append(f)
			offset += (4 + f.length)
		return value, sum([4+f.length for f in value])

class MatchField(Base):
	def __init__(self, **kwargs):
		super(MatchField, self).__init__(**kwargs)
		with self.show(PARSED_VIEW):
			self._parsed_init()
	
	def _parsed_init(self):
		self._append_packdef("I", ("header",), {})
		self._append_vlendef(
			("type", self._read_type, hex_convert),
			("clazz", self._read_class, enum_convert(NXM_0=0x0000, NXM_1=0x0001, OPENFLOW_BASIC=0x8000, EXPERIMENTER=0xffff)),
			("field", self._read_field, enum_convert(*'''IN_PORT IN_PHY_PORT METADATA
				ETH_DST ETH_SRC ETH_TYPE VLAN_VID VLAN_PCP
				IP_DSCP IP_ECN IP_PROTO
				IPV4_SRC IPV4_DST TCP_SRC TCP_DST UDP_SRC UDP_DST
				SCTP_SRC SCTP_DST ICMPV4_TYPE ICMPV4_CODE
				ARP_OP ARP_SPA ARP_TPA ARP_SHA ARP_THA
				IPV6_SRC IPV6_DST IPV6_FLABEL
				ICMPV6_TYPE ICMPV6_CODE
				IPV6_ND_TARGET IPV6_ND_SLL IPV6_ND_TLL
				MPLS_LABEL MPLS_TC MPLS_BOS PBB_ISID TUNNEL_ID IPV6_EXTHDR'''.split())),
			("hasmask", self._read_hasmask, None),
			("length", self._read_length, None))
		
		value_len = self.length
		if self.hasmask:
			value_len = value_len/2
		
		if self.field in ("IN_PORT", "IN_PHY_PORT"):
			self._append_packdef("I", ("value",), { "port": port_convert })
			assert value_len == 4
			assert not self.hasmask
		elif self.field in ("ETH_DST", "ETH_SRC"):
			self._append_packdef("6s6s", ("value", "mask"), { "value":mac_convert, "mask":mac_convert })
			assert value_len == 6
			assert self.hasmask
		else:
			if self.hasmask:
				self._append_packdef("%ds%ds" % (value_len, value_len), ("value", "mask"), {
					"value":data_convert,
					"mask":data_convert})
			else:
				self._append_packdef("%ds" % (value_len,), ("value",), {
					"value":data_convert})
	
	def _read_type(self, message, offset):
		return self.header>>9, 0
	
	def _read_class(self, message, offset):
		return self.header>>16, 0
	
	def _read_field(self, message, offset):
		return (self.header>>9)&0x7F, 0
	
	def _read_hasmask(self, message, offset):
		return (self.header>>8)&1, 0
	
	def _read_length(self, message, offset):
		return self.header&0xFF, 0
	
	def _read_payload(self, message, offset):
		return message[offset:offset+self.length], self.length

class Action(Base):
	def __init__(self, **kwargs):
		super(Action, self).__init__(**kwargs)
		with self.show(PARSED_VIEW):
			self._parsed_init()
	
	def _parsed_init(self):
		self._append_packdef("HH", ("type","len"), {
			"type": enum_convert(*'''OUTPUT COPY_TTL_OUT COPY_TTL_IN SET_MPLS_TTL DEC_MPLS_TTL
				PUSH_VLAN POP_FLAN PUSH_MPLS POP_MPLS SET_QUEUE GROUP SET_NW_TTL DEC_NW_TTL
				SET_FIELD PUSH_PBB POP_PBB'''.split(),
				EXPERIMENTER=0xffff)})
		if self.type == "OUTPUT":
			self._append_packdef("IH6x", ("port","max_len"), {
				"port": port_convert,
				"max_len": enum_convert(MAX=0xffe5, NOBUFFER=0xffff)})
		elif self.type == "SET_QUEUE":
			self._append_packdef("I", ("queue_id",), {})
		elif self.type == "SET_MPLS_TTL":
			self._append_packdef("B3x", ("mpls_ttl",), {})
		elif self.type == "SET_NW_TTL":
			self._append_packdef("B3x", ("nw_ttl",), {})
		elif self.type in ("PUSH_VLAN", "PUSH_MPLS", "PUSH_PBB", "POP_MPLS"):
			self._append_packdef("H2x", ("ethertype",), {})
		elif self.type == "SET_FIELD":
			self._append_vlendef(("fields", self._oxm_fields, None),)
		elif self.type == "EXPERIMENTER":
			self._append_packdef("I", ("experimenter",), {})
		else:
			self._append_packdef("4x", (), {})
	
	def _oxm_fields(self, message, offset):
		value = []
		end = offset + self.length - 4
		while offset < end:
			f = MatchField(offset=offset, parent=self)
			value.append(f)
			offset += (4 + f.length)
		return value, sum([4+f.length for f in value])

class Instruction(Base):
	def __init__(self, **kwargs):
		super(Instruction, self).__init__(**kwargs)
		with self.show(PARSED_VIEW):
			self._parsed_init()
	
	def _parsed_init(self):
		self._append_packdef("HH", ("type","len"), {
			"type": enum_convert(*"GOTO_TABLE WRITE_METADATA WRITE_ACTIONS APPLY_ACTIONS CLEAR_ACTIONS".split(),
				EXPERIMENTER=0xffff)})
		if self.type == "GOTO_TABLE":
			self._append_packdef("B3x", ("table_id",), {})
		elif self.type == "WRITE_METADATA":
			self._append_packdef("4xQQ", ("metadata","metadata_mask"), {})
		elif self.type in ("WRITE_ACTIONS", "APPLY_ACTIONS", "CLEAR_ACTIONS"):
			self._append_packdef("4x", (), {})
			self._append_vlendef(("actions", self._actions, None),)
		elif self.type == "METER":
			self._append_packdef("I", ("meter_id",), {})
		else:
			raise TypeError("type unknown : %s" % self.type)
	
	def _actions(self, message, offset):
		value = []
		while offset < len(message):
			a = Action(offset=offset, parent=self)
			value.append(a)
			offset += a.len
			assert a.len != 0
		return value, sum([a.len for a in value])

class Port(Base):
	def __init__(self, **kwargs):
		super(Port, self).__init__(**kwargs)
		with self.show(PARSED_VIEW):
			self._parsed_init()
	
	def _parsed_init(self):
		self._append_packdef("I4x6s2x16sIIIIIIII",
			("port_no", "hw_addr", "name", "config", "state", "curr", "advertised", "supported", "peer", "curr_speed", "max_speed"), {
			"port_no": port_convert,
			"hw_addr": mac_convert,
			"name": str_convert})

class pad(object):
	def __init__(self, length):
		self.length = length
	
	def __call__(self, message, offset):
		return None, self.length

class bit_convert:
	def __init__(self, *idx, **jump):
		self.idx = idx
		self.jump = jump
	
	def __call__(self, value, obj=None, inverse=False):
		if inverse:
			ret = 0
			for n in value:
				if n in self.jump:
					ret |= (1<<self.jump[n])
				else:
					ret |= (1<<self.idx.index(n.upper()))
			return ret
		
		ret = [self.idx[i] for i in range(len(self.idx)) if (value>>i)&1]
		for k,v in self.jump.items():
			if (value>>v)&1:
				ret.append(k)
		return ret

class enum_convert:
	def __init__(self, *idx, **jump):
		''' jump for gapped index for example, 0xffff as key. '''
		self.idx = idx
		self.jump = jump # NOTE string is the key
	
	def __call__(self, value, obj=None, inverse=False):
		if inverse:
			if value in  self.jump:
				return self.jump[value]
			return self.idx.index(value)
		else:
			for k,v in self.jump.items():
				if value == v:
					return k
			return self.idx[value]

def hex_convert(value, obj=None, inverse=False):
	if inverse:
		if isinstance(value, int):
			return value
		elif isinstance(value, str):
			if value.lower().startswith("0x"):
				return int(value, 16)
			else:
				return int(value)
		else:
			raise TypeError
	else:
		return "%#x" % value

def data_convert(value, obj=None, inverse=False):
	if inverse:
		if isinstance(value, str):
			try:
				return binascii.a2b_hex(value)
			except TypeError:
				return value
		else:
			raise TypeError("must be a binary sequence")
	return binascii.b2a_hex(value)

def port_convert(value, obj=None, inverse=False):
	v4port = {0xffffff00:"MAX", 0xfffffff8:"IN_PORT", 0xfffffff9:"TABLE", 0xfffffffa:"NORMAL",
		0xfffffffb:"FLOOD", 0xfffffffc:"ALL", 0xfffffffd:"CONTROLLER", 0xfffffffe:"LOCAL", 0xffffffff:"ANY"}
	if inverse:
		if isinstance(value, int):
			return value
		elif isinstance(value, str):
			for k,v in v4port.items():
				if v==value.upper():
					return k
			if value.lower().startswith("0x"):
				return int(value, 16)
			else:
				return int(value)
		else:
			raise TypeError("accepts int or str : %s" % value)
	return v4port.get(value, value)

def hello_bitmaps_convert(value, obj=None, inverse=False):
	if inverse:
		if isinstance(value, list) or isinstance(value, tuple):
			ret = [0,] * ((max(value)+31)/32)
			for v in value:
				ret[v/32] |= 1<<(v%32)
			return struct.pack("!%dI" % len(ret), *ret)
		else:
			raise TypeError("accepts list or tuple : %s" % value)
	else:
		o = 0
		ret = []
		for idx in struct.unpack("!%dI" % (len(value)/4), value):
			for x in range(32):
				if (idx>>x) & 1:
					ret.append(x+o)
			o += 32
		return ret

def datapath_convert(value, obj=None, inverse=False):
	if inverse:
		return int(value, 16)
	return "%016x" % value

def mac_convert(value, obj=None, inverse=False):
	if inverse:
		if isinstance(value, str):
			p = value.split(":")
			if len(p) == 6:
				return struct.pack("!6B", *[int(o,16) for o in p])
			elif len(value) == 6:
				return value
			elif len(value) == 12:
				return binascii.a2b_hex(value)
			else:
				raise TypeError("unknown mac spec")
		else:
			raise TypeError("unknown mac spec")
	
	return ":".join(["%02x" % s for s in struct.unpack("!6B", value)])

def str_convert(value, obj=None, inverse=False):
	return value.partition("\00")[0]
