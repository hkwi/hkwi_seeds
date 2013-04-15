import binascii
import collections
import datetime
import json
import struct

RAW_VIEW = 0
PARSED_VIEW = 1
DUMP_VIEW = 2

def align8(num):
	'''64 bit alignment'''
	return (num+7)/8*8

class View(object):
	def __init__(self):
		self.level = 1
		self._saved_level = None
	
	@property
	def raw(self): # 0
		return True if self.level==0 else False
	
	@property
	def parsed(self): # 1,2
		return True if self.level in (1,2) else False
	
	@property
	def dump(self): # 2
		return True if self.level>1 else False
	
	def show(self, level):
		return Show(self, level)

class Show:
	def __init__(self, view, level):
		self.view = view
		self.level = level
		self.saved_level = view.level
	
	def __enter__(self):
		self.view.level = self.level
	
	def __exit__(self, exc_type, exc_value, traceback):
		self.view.level = self.saved_level

class SerializeException(Exception):
	pass

class Common(dict):
	_tail = None
	def __init__(self, **kwargs):
		self._view = View()
		self._packs = "!"
		self._keys = []
		self._tail = None
		self._readable = {}
		self._version = 1
		for key in ("version", "view"):
			if key in kwargs:
				setattr(self, "_"+key, kwargs[key])
	
	def _append_packdef(self, packs, keys, readable):
		self._packs += packs
		self._keys += keys
		self._readable.update(readable)
	
	def _append_tail(self, key, value, readable={}):
		assert self._tail is None
		self._tail = key
		self[key] = value
		self._readable.update(readable)
	
	def _unpack(self, message, offset=0):
		for key, value in zip(self._keys, struct.unpack_from(self._packs, message, offset=offset)):
			super(Common, self).__setitem__(key, value)
		return struct.calcsize(self._packs)
	
	def __getattr__(self, name):
		try:
			return self[name]
		except KeyError:
			raise AttributeError("%s.%s" % (self.__class__.__name__, name))
	
	def __setattr__(self, name, value):
		if name.startswith("_"):
			super(Common, self).__setattr__(name, value)
		elif name == "data" and self._view.dump: # data is commonly used thurough the spec
			self[name] = binascii.a2b_hex(value)
		elif name == self._tail or name in self._keys:
			if name in self._readable and self._view.parsed:
				self[name] = self._readable[name](value, self, True)
			else:
				self[name] = value
		else:
			super(Common, self).__setattr__(name, value)
	
	def __getitem__(self, name):
		if name.startswith("_"):
			raise KeyError(name)
		
		value = super(Common, self).__getitem__(name)
		
		if self._view.raw:
			return value
		if name == "data" and self._view.dump:
			return binascii.b2a_hex(value)
		if name in self._readable and self._view.parsed:
			return self._readable[name](value, self, False)
		return value
	
	def __iter__(self):
		visible_keys = [key for key in self._keys if not key.startswith("_")]
		if self._tail:
			visible_keys.append(self._tail)
		return iter(visible_keys)
	
	def serialize_tail(self):
		if not self._tail:
			return ''
		else:
			with self.show(RAW_VIEW):
				obj = self[self._tail]
				if isinstance(obj, str):
					return obj
				elif isinstance(obj, Common):
					return obj.serialize()
				elif isinstance(obj, list) or isinstance(obj, tuple):
					return "".join([o.serialize() for o in obj])
				else:
					raise SerializeException("Unknown serialization for %s" % self._tail)
	
	def serialize(self):
		with self.show(RAW_VIEW):
			try:
				ret = struct.pack(self._packs, *["" if k.startswith("_") else self[k] for k in self._keys])
			except Exception, e:
				logging.error(repr((self._packs, ["" if k.startswith("_") else self[k] for k in self._keys])))
				raise e
			
			return ret + self.serialize_tail()
	
	def show(self, mode):
		return Show(self._view, mode)
	
	def __repr__(self):
		with self.show(DUMP_VIEW):
			return json.dumps(self)

class Message(Common):
	def __init__(self, message=None, **kwargs):
		super(Message, self).__init__(**kwargs)
		
		self._append_packdef("BBHI", ("version", "type", "length", "xid"), {"type":type_readable, "xid":hexify})
		
		if message:
			self._unpack(message, offset=kwargs.get("offset", 0))
			self._version = self.version
		if "type" in kwargs:
			self.type = kwargs["type"]
		
		with self._view.show(PARSED_VIEW):
			oftype = self.type
		
		tail = None
		packsize = struct.calcsize(self._packs)
		if oftype == "HELLO":
			tail = "elements"
		elif oftype == "ERROR":
			if self.version==1:
				self._append_packdef(*v1error)
			elif self.version==4:
				self._append_packdef("H", ("etype",), {"etype":v4error_etype_readable})
				if message:
					packsize = self._unpack(message, offset=kwargs.get("offset", 0))
				if "etype" in kwargs:
					self.etype = kwargs["etype"]
				with self._view.show(PARSED_VIEW):
					if self.etype == "EXPERIMENTER":
						self._append_packdef("HI", ("exp_type", "experimenter"))
					else:
						self._append_packdef("H", ("code",), {"code":v4error_code_readable})
			tail = "data"
		elif oftype == "FEATURES_REPLY":
			if self.version==1:
				self._append_packdef(*v1features_reply)
				tail = "ports"
			elif self.version==4:
				self._append_packdef(*v4features_reply)
		elif oftype == "PACKET_IN":
			if self.version==1:
				self._append_packdef(*v1packet_in)
				tail = "data"
			elif self.version==4:
				self._append_packdef(*v4packet_in)
				tail = "match"
		elif oftype == "PACKET_OUT":
			if self.version==1:
				self._append_packdef(*v1packet_out)
			elif self.version==4:
				self._append_packdef(*v4packet_out)
			
			if message:
				packsize = self._unpack(message, offset=kwargs.get("offset", 0))
			if "buffer_id" in kwargs:
				self.buffer_id = kwargs["buffer_id"]
		
			if self.buffer_id == 0xffffffff: # -1
				tail = "data"
			else:
				tail = "actions"
		elif oftype == "PORT_STATUS":
			self._append_packdef(*v1port_status) # same in v1.3
			tail = "port"
		elif oftype == "MULTIPART_REQUEST":
			self._append_packdef("HH4s", ("mtype", "flags", "_pad"), {
				"mtype": v4multipart_request_type_readable,
				"flags": bit_readable("REQ_MORE")})
			tail = "body"
		elif oftype == "FLOW_MOD":
			if self.version==4:
				self._append_packdef("QQBBHHHIIIH2s", ("cookie", "cookie_mask", "table_id", "command",
					"idle_timeout", "hard_timeout", "priority", "buffer_id", "out_port", "out_group",
					"flags", "_pad"), {
					"out_port": v4port_readable,
					"command": enum_readable("ADD","MODIFY","MODIFY_STRICT","DELETE","DELETE_STRICT")})
				tail = "match"
		
		if message and packsize != struct.calcsize(self._packs):
			packsize = self._unpack(message, offset=kwargs.get("offset", 0))
		
		for key in self._keys:
			if not key.startswith("_") and key in kwargs:
				setattr(self, key, kwargs[key])
		
		if tail:
			if message:
				self._message_tail(tail, message, kwargs.get("offset", 0)+packsize)
			if tail in kwargs:
				self._append_tail(tail, kwargs[tail])
	
	def __getitem__(self, name):
		try:
			return super(Message, self).__getitem__(name)
		except KeyError as e:
			if name=="length":
				ret = struct.calcsize(self._packs)
				if self._tail:
					ret += len(self.serialize_tail())
				return ret
			elif name == "xid":
				return None
			raise
	
	def _message_tail(self, tail, message, offset):
		with self._view.show(PARSED_VIEW):
			oftype = self.type
		
		value = None
		if oftype == "HELLO":
			value = []
			while offset < len(message):
				element = HelloElement(message, offset=offset, view=self._view)
				value.append(element)
				offset += element.length
		elif oftype == "ERROR":
			value = message[offset:]
		elif oftype == "FEATURES_REPLY":
			value = []
			while offset < len(message):
				value.append(Port(message, offset=offset, view=self._view))
				offset += 48
		elif oftype == "PACKET_IN":
			if tail=="data":
				value = message[offset:]
			elif tail=="match":
				value = Match(message, offset=offset, version=self._version, view=self._view)
		elif oftype == "PACKET_OUT":
			if self.buffer_id == 0xffffffff: # -1
				value = message[offset:]
			else:
				value = []
				while offset < len(message):
					action = Action(message, offset=offset, version=self.version, view=self._view)
					value.append(action)
					offset += action.len
		elif oftype == "PORT_STATUS":
			assert offset==16
			value = Port(message, offset=offset, version=self.version, view=self._view)
		elif oftype == "MULTIPART_REQUEST":
			with self._view.show(PARSED_VIEW):
				mtype = self.mtype
			if mtype == "FLOW":
				value = []
				while offset < len(message):
					value.append(FlowStatsRequest(message, offset=offset, view=self._view))
					offset += 40
		elif oftype == "FLOW_MOD":
			if tail == "match":
				value = Match(message, offset=offset, version=self._version, view=self._view)
				# instructions
# 				if offset+align8(value.length) < len(message):
# 					print binascii.b2a_hex(message[offset+align8(value.length):])
		
		if value:
			self._append_tail(tail, value)

class MatchField(Common):
	def __init__(self, message=None, **kwargs):
		# TODO
		pass

class Match(Common):
	def __init__(self, message=None, **kwargs):
		super(Match, self).__init__(**kwargs)
		
		offset = kwargs.get("offset",0)
		self._append_packdef("HH", ("type", "length"), {"type": enum_readable("STANDARD", "OXM")})
		if message:
			self._unpack(message, offset=offset)
		
		with self._view.show(PARSED_VIEW):
			mtype = self.type
		
		if message:
			payload_end = offset + self.length
			offset += struct.calcsize(self._packs)
			if mtype == "OXM":
				value = []
				while offset < payload_end:
					(x,) = struct.unpack_from("I", message, offset)
					length = (x & 0x7f) + 4 # 4 for header
					value.append(message[offset:offset+length])
					offset += length
				self._append_tail("oxm_fields", value)


def v4multipart_request_type_readable(value, obj, inverse=False):
	idx = '''DESC FLOW AGGREGATE TABLE PORT_STATS QUEUE GROUP GROUP_DESC FEATURES
		METER METER_CONFIG METER_FEATURES TABLE_FEATURES PORT_DESC'''.split() # EXPERIMENTER 0xffff
	if inverse:
		if value == "EXPERIMENTER":
			return 0xffff
	else:
		if value == 0xffff:
			return "EXPERIMENTER"
	
	if inverse:
		return idx.index(value)
	else:
		return idx[value]

class FlowStatsRequest(Common):
	def __init__(self, message=None, **kwargs):
		super(FlowStatsRequest, self).__init__(**kwargs)
		
		self._append_packdef("B3sII4sQQ",
			("table_id", "_p1", "out_port", "out_group", "_p2", "cookie", "cookie_mask"), {
			"out_port": v4port_readable})
		
		if message:
			offset = kwargs.get("offset", 0)
			self._unpack(message, offset=offset)
			self._append_tail("match", Match(message, offset=offset+struct.calcsize(self._packs),
				version=self._version, view=self._view))

v1action_types = ("OUTPUT", "SET_VLAN_VID", "SET_VLAN_PCP", "STRIP_VLAN", "SET_DL_SRC", "SET_DL_DST", 
	"SET_NW_SRC", "SET_NW_DST", "SET_NW_TOS", "SET_TP_SRC", "SET_TP_DST", "ENQUEUE") # VENDOR=0xffff
v4action_types = ("OUTPUT", "_", "_", "_", "_", "_", "_", "_", "_", "_", "_", 
	"COPY_TTL_OUT", "COPY_TTL_IN", "_13", "_14", "SET_MPLS_TTL", "DEC_MPLS_TTL", "PUSH_VLAN", "POP_VLAN",
	"PUSH_MPLS", "POP_MPLS", "SET_QUEUE", "GROUP", "SET_NW_TTL", "DEC_NW_TTL", "SET_FIELD", "PUSH_PBB", "POP_PBB") # EXPERIMENTER=0xffff

def action_type_readable(value, obj, inverse=False):
	if obj._version == 1:
		if inverse:
			if value == "VENDOR":
				return 0xffff
		else:
			if value == 0xffff:
				return "VENDOR"
		action_types = v1action_types
	elif obj._version == 4:
		if inverse:
			if value == "EXPERIMENTER":
				return 0xffff
		else:
			if value == 0xffff:
				return "EXPERIMENTER"
		action_types = v4action_types
	
	if inverse:
		return action_types.index(value)
	else:
		return action_types[value]

def v4action_output_max_len(value, obj, inverse=False):
	idx = {0xffe5:"MAX", 0xffff:"NO_BUFFER"}
	if inverse:
		for num,s in idx.items():
			if value == s:
				return num
		return hexify(value, obj, inverse)
	else:
		try:
			idx[value]
		except:
			str(value)

class Action(Common):
	def __init__(self, message=None, **kwargs):
		super(Action, self).__init__(**kwargs)
		
		if self._version==1:
			self._append_packdef("HH", ("type", "len"), {"type":action_type_readable})
		elif self._version==4:
			self._append_packdef("HH4s", ("type", "len", "_pad4"), {"type":action_type_readable})
		
		if message:
			self._unpack(message, offset=kwargs.get("offset", 0))
		elif "type" in kwargs:
			type_upper = kwargs["type"].upper()
			typeval = v1action_types.index(type_upper)
			if typeval != -1:
				self["type"] = typeval
			elif type_upper == "VENDOR":
				self["type"] = 0xffff
		
		with self._view.show(PARSED_VIEW):
			type = self.type
		
		pakdef = None
		if self._version==1:
			if type == "OUTPUT":
				packdef = ("HH", ("port", "max_len"), {"port":v1port_readable})
			elif type == "ENQUEUE":
				packdef = ("H6sI", ("port", "_", "queue_id"), {"port":v1port_readable})
			elif type == "SET_VLAN_VID":
				packdef = ("H", ("vlan_vid",), {})
			elif type == "SET_VLAN_PCP":
				packdef = ("B", ("vlan_pcp",), {})
			elif type in ("SET_DL_SRC", "SET_DL_DST"):
				packdef = ("6s", ("dl_addr",), {"dl_addr":mac_readable})
			elif type in ("SET_NW_SRC", "SET_NW_DST"):
				packdef = ("4s", ("nw_addr",), {"nw_addr":nw_addr_readable})
			elif type == "SET_TW_TOS":
				packdef = ("B", ("nw_tos",), {})
			elif type in ("SET_TP_SRC", "SET_TP_DST"):
				packdef = ("H", ("tp_port",), {})
			elif type == "VENDOR":
				packdef = ("I", ("vendor",), {})
		elif self._version==4:
			if type == "OUTPUT":
				packdef = ("IH6s", ("port", "max_len", "_pad6"), {"port":v4port_readable, "max_len":v4action_output_max_len})
			elif type == "GROUP":
				packdef = ("I", ("group_id",), {})
			elif type == "QUEUE":
				packdef = ("I", ("queue_id",), {})
			elif type == "SET_MPLS_TTL":
				packdef = ("B3s", ("mpls_ttl", "_pad3"), {})
			elif type == "SET_NW_TTL":
				packdef = ("B3s", ("nw_ttl", "_pad3"), {})
			elif type in ("PUSH_VLAN", "PUSH_MPLS", "PUSH_PBB", "POP_MPLS"):
				packdef = ("H2s", ("ethertype", "_pad2"), {})
			elif type == "SET_FIELD":
				packdef = ("4s", ("field",), {})
			elif type == "EXPERIMENTER":
				packdef = ("I", ("experimenter",), {})
				# have tail
		
		if packdef:
			self._append_packdef(*packdef)
		
		if message:
			self._unpack(message, offset=kwargs.get("offset", 0))
		
		for key in self._keys:
			if not key.startswith("_") and key in kwargs:
				setattr(self, key, kwargs[key])
	
	def serialize(self):
		self.len = struct.calcsize(self._packs)
		return super(Action, self).serialize()

class Port(Common):
	def __init__(self, message=None, **kwargs):
		super(Port, self).__init__(**kwargs)
		
		if self._version == 1:
			port_features = ("10MB_HD", "10MB_FD", "100MB_HD", "100MB_FD", "1GB_HD", "1GB_FD", "10GB_FD", 
				"COPPER", "FIBER", "AUTONEG", "PAUSE", "PAUSE_ASYM")
			
			self._append_packdef("H6s16sIIIIII", ("port_no", "hw_addr", "name", "config", "state", "curr", "advertised", "supported", "peer"), {
				"port_no": v1port_readable,
				"hw_addr": mac_readable,
				"name": lambda v,o,i: v.partition("\0")[0],
				"config": bit_readable("PORT_DOWN", "NO_STP", "NO_RECV", "NO_RECV_STP", "NO_FLOOD", "NO_FWD", "NO_PACKET_IN"),
				"state": v1port_state_readable,
				"curr": bit_readable(*port_features),
				"advertised": bit_readable(*port_features),
				"supported": bit_readable(*port_features),
				"peer": bit_readable(*port_features)
				})
		elif self._version == 4:
			port_features = ("10MB_HD", "10MB_FD", "100MB_HD", "100MB_FD", "1GB_HD", "1GB_FD", "10GB_FD", "40GB_FD", "100GB_FD", "1TB_FD", "OTHER",
				"COPPER", "FIBER", "AUTONEG", "PAUSE", "PAUSE_ASYM")
			
			self._append_packdef("I4s6s2s16sIIIIIIII",
				("port_no", "_pad4", "hw_addr", "_pad2", "name", "config", "state", "curr", "advertised", "supported", "peer", "curr_speed", "max_speed"), {
				"port_no": v4port_readable,
				"hw_addr": mac_readable,
				"name": lambda v,o,i: v.partition("\0")[0],
				"config": bit_readable("PORT_DOWN", "_1", "NO_RECV", "_3", "_4", "NO_FWD", "NO_PACKET_IN"),
				"state": bit_readable("LINK_DOWN", "BLOCKED", "LIVE"),
				"curr": bit_readable(*port_features),
				"advertised": bit_readable(*port_features),
				"supported": bit_readable(*port_features),
				"peer": bit_readable(*port_features)
				})
		
		if message:
			self._unpack(message, offset=kwargs.get("offset", 0))
		
		for key in self._keys:
			if not key.startswith("_") and key in kwargs:
				setattr(self, key, kwargs[key])

class HelloElement(Common):
	def __init__(self, message=None, **kwargs):
		super(HelloElement, self).__init__(**kwargs)
		
		self._append_packdef("HH", ("type", "length"), {"type": enum_readable("", "VERSIONBITMAP")})
		
		offset = kwargs.get("offset",0)
		if message:
			self._unpack(message, offset=offset)
		else:
			if "type" in kwargs:
				self.type = kwargs["type"].upper()
		
		with self._view.show(PARSED_VIEW):
			htype = self.type
		
		if htype=="VERSIONBITMAP":
			if message:
				value = message[offset+4:offset+self.length]
			else:
				value = v4hello_bitmaps_readable(kwargs.get("bitmaps",[]), self, True)
			self._append_tail("bitmaps", value, {"bitmaps":v4hello_bitmaps_readable})
	
	def __getitem__(self, name):
		try:
			return super(HelloElement, self).__getitem__(name)
		except KeyError as e:
			if name=="length":
				ret = struct.calcsize(self._packs)
				if self._tail:
					ret += len(self.serialize_tail())
				return ret
			elif name == "bitmaps":
				return []
			raise
	
	def serialize(self):
		self.length = 4
		if self.type == "VERSIONBITMAP":
			with self._view.show(RAW_VIEW):
				self.length += len(self.bitmaps)
		return super(HelloElement, self).serialize()


def v4hello_bitmaps_readable(value, obj, inverse=False):
	if inverse:
		if isinstance(value, list) or isinstance(value, tuple):
			mx = max(value)
			rows = mx/32
			if mx%32 != 0:
				rows += 1
			ret = [0,]*rows
			for v in value:
				ret[v/32] += 1<<(v%32)
			return struct.pack("!%dI" % len(ret), *ret)
		return value
	else:
		o = 0
		ret = []
		for idx in struct.unpack("!%dI" % (len(value)/4), value):
			for x in range(32):
				if (idx>>x) & 1:
					ret.append(x+o)
			o += 32
		return ret

def v1port_state_readable(value, obj, inverse=False):
	state_index = ("STP_LISTEN", "STP_LEARN", "STP_FORWARD", "STP_BLOCK")
	if inverse:
		ret = 0
		if "LINK_DOWN" in value:
			ret = 1
		for s in state_index:
			if s in value:
				ret += (state_index.index(s)<<8)
	else:
		ret = []
		if value & 1:
			ret.append("LINK_DOWN")
		ret.append(state_index[(value>>8)&3])
	return ret

class enum_readable:
	def __init__(self, *idx):
		self.idx = idx
	
	def __call__(self, target, obj, inverse=False):
		if inverse:
			i = self.idx.index(target.upper())
			assert i>=0, "unknown %s" % target
			return i
		else:
			return self.idx[target]

class bit_readable:
	def __init__(self, *bits):
		self.idx = bits
	
	def __call__(self, target, obj, inverse=False):
		if inverse:
			ret = 0
			for i in set(target):
				s = self.idx.index(i.upper())
				assert s >= 0, "unknown %s" % i
				ret += (1<<s)
			return ret
		else:
			return [self.idx[i] for i in range(len(self.idx)) if (target>>i)&1]

def hexify(value, obj, inverse=False):
	if inverse:
		if isinstance(value, str):
			if value.lower().startswith("0x"):
				return int(value, 16)
			else:
				return int(value)
		else:
			return value
	else:
		return "%#x" % value

def mac_readable(value, obj, inverse=False):
	if inverse:
		return struct.pack("!6B", *[int(mac, 16) for mac in value.split(":")])
	else:
		return ":".join(["%02x" % mac for mac in struct.unpack("!6B", value)])

def nw_addr_readable(value, obj, inverse=False):
	if inverse:
		return struct.pack("!4B", *[int(v) for v in value.split(".")])
	else:
		return "%d.%d.%d.%d" % struct.unpack("!4B", value)

def type_readable(value, obj, inverse=False):
	if obj._version==1:
		types = ("HELLO", "ERROR", "ECHO_REQUEST", "ECHO_REPLY", "VENDOR", 
			"FEATURES_REQUEST", "FEATURES_REPLY", "GET_CONFIG_REQUEST", "GET_CONFIG_REPLY", "SET_CONFIG", 
			"PACKET_IN", "FLOW_REMOVED", "PORT_STATUS", 
			"PACKET_OUT", "FLOW_MOD", "PORT_MOD", 
			"STATS_REQUEST", "STATS_REPLY",
			"BARRIER_REQUEST", "BARRIER_REPLY",
			"QUEUE_GET_CONFIG_REQUEST", "QUEUE_GET_CONFIG_REPLY")
	elif obj._version==4:
		types = ("HELLO", "ERROR", "ECHO_REQUEST", "ECHO_REPLY", "EXPERIMENTER",
			"FEATURES_REQUEST", "FEATURES_REPLY", "GET_CONFIG_REQUEST", "GET_CONFIG_REPLY", "SET_CONFIG", 
			"PACKET_IN", "FLOW_REMOVED", "PORT_STATUS", 
			"PACKET_OUT", "FLOW_MOD", "GROUP_MOD", "PORT_MOD", "TABLE_MOD", 
			"MULTIPART_REQUEST", "MULTIPART_REPLY", 
			"BARRIER_REQUEST", "BARRIER_REPLY", 
			"QUEUE_GET_CONFIG_REQUEST", "QUEUE_GET_CONFIG_REPLY", 
			"ROLE_REQUEST", "ROLE_REPLY", 
			"GET_ASYNC_REQUEST", "GET_ASYNC_REPLY", "SET_ASYNC", 
			"METER_MOD")
	if inverse:
		return types.index(value)
	else:
		return types[value]

v1features_reply = ("QIB3sII", ("datapath_id", "n_buffers", "n_tables", "_pad", "capabilities", "actions"), {
	"datapath_id":lambda v,o,i: int(v,16) if i else "%016x" % v,
	"capabilities": bit_readable("FLOW_STATS", "TABLE_STATS", "PORT_STATS", "STP", "RESERVED", "IP_REASM", "QUEUE_STATS", "ARP_MATCH_IP"),
	"actions": bit_readable(*v1action_types)
	})
v4features_reply = ("QIBB2sII", ("datapath_id", "n_buffers", "n_tables", "auxiliary_id", "_pad", "capabilities", "_reserved"), {
	"datapath_id":lambda v,o,i: int(v,16) if i else "%016x" % v,
	"capabilities": bit_readable("FLOW_STATS", "TABLE_STATS", "PORT_STATS", "GROUP_STATS", "_4", "IP_REASM", "QUEUE_STATS", "_7", "PORT_BLOCKED")
	})

def v1error_code_readable(value, obj, inverse=False):
	with obj._view.show(PARSED_VIEW):
		etype = obj.etype
	
	if etype == "HELLO_FAILED":
		idx = ("INCOMPATIBLE", "EPERM")
	elif etype == "BAD_REQUEST":
		idx = ("BAD_VERSION", "BAD_TYPE", "BAD_STAT", "BAD_VENDOR", "BAD_SUBTYPE", "EPERM", "BAD_LEN", "BUFFER_EMPTY", "BUFFER_UNKNOWN")
	elif etype == "BAD_ACTION":
		idx = ("BAD_TYPE", "BAD_LEN", "BAD_VENDOR", "BAD_VENDOR_TYPE", "BAD_OUT_PORT", "BAD_ARGUMENT", "EPERM", "TOO_MANY", "BAD_QUEUE")
	elif etype == "FLOW_MOD_FAILED":
		idx = ("ALL_TABLES_FULL", "OVERLAP", "EPERM", "BAD_EMERG_TIMEOUT", "BAD_COMMAND", "UNSUPPORTED")
	elif etype == "PORT_MOD_FAILED":
		idx = ("BAD_PORT", "BAD_HW_ADDR")
	elif etype == "QUEUE_OP_FAILED":
		idx = ("BAD_PORT", "BAD_QUEUE", "EPERM")
	
	if inverse:
		return idx.index(value)
	
	try:
		return idx[value]
	except:
		return hexify(value, obj)

def v4error_etype_readable(value, obj, inverse=False):
	idx = ("HELLO_FAILED", "BAD_REQUEST", "BAD_ACTION", "BAD_INSTRUCTION", "BAD_MATCH", "FLOW_MOD_FAILED",
		"GROUP_MOD_FAILED", "PORT_MOD_FAILED", "QUEUE_OP_FAILED", "SWITCH_CONFIG_FAILED", "ROLE_REQUEST_FAILED",
		"METER_MOD_FAILED", "TABLE_FEATURES_FAILED") # EXPERIMENTER=0xffff
	if inverse:
		if value=="EXPERIMENTER":
			return 0xffff
		return idx.index(value)
	
	if value == 0xffff:
		return "EXPERIMENTER"
	try:
		return idx[value]
	except:
		hexify(value, obj)

def v4error_code_readable(value, obj, inverse=False):
	with obj._view.show(PARSED_VIEW):
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
				"UNKNOWN METER_EXISTS INVALID_METER UNKNOWN_METER BAD_COMMAND BAD_FLAGS BAD_RATE BAD_BURST BAD_BAND BAD_BAND_VALUE OUT_OF_METERS OUT_OF_BANDS",
			"TABLE_FEATURES_FAILED":
				"BAD_TABLE BAD_METADATA BAD_TYPE BAD_LEN BAD_ARGUMENT EPERM",
			"EXPERIMENTER":
				""
		}[obj.etype].split()
	
	if idx:
		if inverse:
			return idx.index(value)
		try:
			return idx[value]
		except:
			pass
	
	return hexify(value, obj, inverse)

v1error = ("HH", ("etype", "code"), {
	"etype": enum_readable("HELLO_FAILED", "BAD_REQUEST", "BAD_ACTION", "FLOW_MOD_FAILED", "PORT_MOD_FAILED", "QUEUE_OP_FAILED"),
	"code": v1error_code_readable
	})

def v1port_readable(value, obj, inverse=False):
	v1port = {0xff00:"MAX", 0xfff8:"IN_PORT", 0xfff9:"TABLE", 0xfffa:"NORMAL", 0xfffb:"FLOOD", 
		0xfffc:"ALL", 0xfffd:"CONTROLLER", 0xfffe:"LOCAL", 0xffff:"NONE"}
	if inverse:
		if isinstance(value, str):
			for k,v in v1port.items():
				if v==value.upper():
					return k
			if value.lower().startswith("0x"):
				return int(value, 16)
			else:
				return int(value)
		return value
	return v1port.get(value, value)

def v4port_readable(value, obj, inverse=False):
	v4port = {0xffffff00:"MAX", 0xfffffff8:"IN_PORT", 0xfffffff9:"TABLE", 0xfffffffa:"NORMAL",
		0xfffffffb:"FLOOD", 0xfffffffc:"ALL", 0xfffffffd:"CONTROLLER", 0xfffffffe:"LOCAL", 0xffffffff:"ANY"}
	if inverse:
		if isinstance(value, str):
			for k,v in v4port.items():
				if v==value.upper():
					return k
			if value.lower().startswith("0x"):
				return int(value, 16)
			else:
				return int(value)
		return value
	return v4port.get(value, value)

v1packet_in = ("IHHBB", ("buffer_id", "total_len", "in_port", "reason", "_p"), {
	"in_port": v1port_readable,
	"reason": enum_readable("NO_MATCH", "ACTION")
	})
v4packet_in = ("IHBBQ", ("buffer_id", "total_len", "reason", "table_id", "cookie"), {
	"reason": enum_readable("NO_MATCH", "ACTION", "INVALID_TTL")
	})

v1packet_out = ("IHH", ("buffer_id", "in_port", "actions_len"), {
	"in_port": v1port_readable
	})
v4packet_out = ("IIH6s", ("buffer_id", "in_port", "actions_len", "_pad"), {
	"in_port": v4port_readable
	})

v1port_status = ("B7s", ("reason","_p7"), {
	"reason": enum_readable("ADD", "DELETE", "MODIFY")
	})

####################### 

def ofptuple_bare(etherframe):
	'''
	returns an openflow v1.0 12 tuple without the first in_port
	'''
	(ethernet_dst, ethernet_src, ethernet_type, tci, inner_type) = struct.unpack_from("!6s6sHHH", etherframe)
	if ethernet_type == 0x8100:
		vlan_id = tci&0x0FFF
		vlan_priority = tci>>13
		ethernet_type = inner_type
		offset = 4
	else:
		vlan_id = None
		vlan_priority = None
		offset = 0
	
	if ethernet_type < 0x05DC:
		(llc_dsap, llc_ssap, llc_ctl, snap_oui, snap_type) = struct.unpack_from("!BBB3sH", etherframe, offset=14)
		if llc_dsap==0xAA and llc_ssap==0xAA and snap_oui=="0x00"*3:
			ethernet_type = snap_type
			offset = 8
	
	ip_tos = ip_protocol = ip_src = ip_dst = None
	transport_src_port_or_icmp_type = None
	transport_dst_port_or_icmp_code = None
	if ethernet_type == 0x0800: # IP
		(u1, ip_tos, u2, ip_protocol, u3, ip_src, ip_dst, src_port, dst_port) = struct.unpack_from("!sB7sB2s4s4sHH", etherframe, offset=14+offset)
		if ip_protocol == 1: # ICMP
			transport_src_port_or_icmp_type = src_port>>8
			transport_dst_port_or_icmp_code = src_port&0xFF
		elif ip_protocol in (6, 17): # TCP, UDP
			transport_src_port_or_icmp_type = src_port
			transport_dst_port_or_icmp_code = dst_port
	elif ethernet_type == 0x0806: # ARP
		(u1, ip_protocol, u2, ip_src, u3, ip_dst) = struct.unpack_from("!6sH6s4s6s4s", etherframe, offset=14+offset)
	
	return (
		ethernet_src,
		ethernet_dst,
		ethernet_type,
		vlan_id,
		vlan_priority,
		ip_src,
		ip_dst,
		ip_protocol,
		ip_tos,
		transport_src_port_or_icmp_type,
		transport_dst_port_or_icmp_code
		)

def ofptuple_readable(etherframe):
	t = list(ofptuple_bare(etherframe))
	t[0] = mac_readable(t[0], None)
	t[1] = mac_readable(t[1], None)
	t[2] = "0x%04x" % t[2]
	if t[5]: t[5] = nw_addr_readable(t[5], None)
	if t[6]: t[6] = nw_addr_readable(t[6], None)
	return tuple(t)

def ofptuple(etherframe):
	fields = ("dl_src", "dl_dst", "dl_type", "dl_vlan", "dl_vlan_pcp", "nw_src", "nw_dst", "nw_proto", "ip_tos", "tp_src", "tp_dst")
	return collections.namedtuple("OfpTuple", fields)(*ofptuple_readable(etherframe))

####################### 

def hms_hex_xid():
	'''Xid looks readable datetime like format when logged as hex.'''
	now = datetime.datetime.now()
	candidate = struct.unpack("!I", binascii.a2b_hex("%02d"*4 % (now.hour, now.minute, now.second, now.microsecond/10000)))[0]
	if hasattr(hms_hex_xid, "dedup"):
		if hms_hex_xid.dedup >= candidate:
			candidate = hms_hex_xid.dedup+1
	setattr(hms_hex_xid, "dedup", candidate)
	return candidate
