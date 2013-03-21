import binascii
import collections
import datetime
import json
import struct

RAW_VIEW = 0
PARSED_VIEW = 1
DUMP_VIEW = 2

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

class Common(dict):
	_tail = None
	def __init__(self, **kwargs):
		self._view = View()
		self._packs = "!"
		self._keys = []
		self._tail = None
		self._readable = {}
		self._version = 1
# 		if isinstance(message, Common):
# 			for attr in ("_binary", "_view", "_keys", "_readable", "_version", "_parse_body_run"):
# 				setattr(self, attr, getattr(message, attr))
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
	
	def __getattr__(self, name):
		try:
			return self[name]
		except KeyError:
			raise AttributeError(name)
	
	def __setattr__(self, name, value):
		if name.startswith("_"):
			super(Common, self).__setattr__(name, value)
		elif name == "data" and self._view.dump:
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
	
	def serialize(self):
		with self.show(RAW_VIEW):
			return struct.pack(self._packs, *["" if k.startswith("_") else self[k] for k in self._keys])
	
	def show(self, mode):
		return Show(self._view, mode)
	
	def __repr__(self):
		with self.show(DUMP_VIEW):
			return json.dumps(self)

class Message(Common):
	def __init__(self, message=None, **kwargs):
		super(Message, self).__init__(**kwargs)
		
		self._append_packdef(*header)
		
		if message:
			self._unpack(message, offset=kwargs.get("offset", 0))
		elif "type" in kwargs:
			typeval = v1header_types.index(kwargs["type"].upper())
			if typeval != -1:
				self["type"] = typeval
		
		with self._view.show(PARSED_VIEW):
			oftype = self.type
		
		packsize = struct.calcsize(self._packs)
		if oftype == "ERROR":
			self._append_packdef(*v1error)
		elif oftype == "FEATURES_REPLY":
			self._append_packdef(*v1features_reply)
		elif oftype == "PACKET_IN":
			self._append_packdef(*v1packet_in)
		elif oftype == "PACKET_OUT":
			self._append_packdef(*v1packet_out)
		elif self.type == "PORT_STATUS":
			self._append_packdef(*v1port_status)
		
		if message:
			if packsize != struct.calcsize(self._packs):
				self._unpack(message, offset=kwargs.get("offset", 0))
			self._message_tail(message, kwargs.get("offset", 0))
		else:
			for key in self._keys:
				if not key.startswith("_") and key in kwargs:
					setattr(self, key, kwargs[key])
	
	def _message_tail(self, message, offset):
		with self._view.show(PARSED_VIEW):
			oftype = self.type
		
		if oftype == "ERROR":
			assert struct.calcsize(self._packs) == 12
			self._append_tail("data", message[offset+12:])
		elif oftype == "FEATURES_REPLY":
			assert struct.calcsize(self._packs) == 32, "%s" % self._packs
			offset_in = offset+ 32
			ports = []
			while offset_in<len(message):
				ports.append(Port(message, offset=offset_in, view=self._view))
				offset_in += 48
			self._append_tail("ports", ports)
		elif oftype == "PACKET_IN":
			assert struct.calcsize(self._packs) == 18
			self._append_tail("data", message[offset+18:])
		elif oftype == "PACKET_OUT":
			assert struct.calcsize(self._packs) == 16
			if self.buffer_id == 0xffffffff: # -1
				self._append_tail("data", message[offset+16:])
			else:
				offset_in = offset + 16
				actions = []
				while offset_in<len(message):
					action = Action(message, offset=offset_in, view=self._view)
					actions.append(action)
					offset_in += action.len
				self._append_tail("actions", actions)
		elif self.type == "PORT_STATUS":
			assert struct.calcsize(self._packs) == 16
			self._append_tail("port", Port(message, offset=offset+16, view=self._view))

	def serialize(self):
		with self._view.show(PARSED_VIEW):
			oftype = self.type
		
		tail = ""
		if oftype == "PACKET_OUT":
			if "data" in self._keys:
				self.buffer_id = 0xffffffff
				with self.show(RAW_VIEW):
					tail = self.data
			else:
				with self.show(RAW_VIEW):
					tail = "".join([a.serialize() for a in self.actions])
				self.actions_len = len(tail)
				self.length = struct.calcsize(self._packs) + len(tail)
		
		if "version" not in self:
			self.version = 1
		
		self.length = struct.calcsize(self._packs)+len(tail)
		return super(Message,self).serialize()+tail

v1action_types = ("OUTPUT", "SET_VLAN_VID", "SET_VLAN_PCP", "STRIP_VLAN", "SET_DL_SRC", "SET_DL_DST", 
	"SET_NW_SRC", "SET_NW_DST", "SET_NW_TOS", "SET_TP_SRC", "SET_TP_DST", "ENQUEUE") # VENDOR=0xffff

def v1action_type_readable(value, obj, inverse=False):
	if inverse:
		if value == "VENDOR":
			return 0xffff
		return v1action_types.index(value)
	else:
		if value == 0xffff:
			return "VENDOR"
		return v1action_types[value]

class Action(Common):
	def __init__(self, message=None, **kwargs):
		super(Action, self).__init__(**kwargs)
		
		self._append_packdef("HH", ("type", "len"), {"type":v1action_type_readable})
		
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
		if type == "OUTPUT":
			packdef = ("HH", ("port", "max_len"), {"port":v1port_readable})
		elif type == "ENQUEUE":
			packdef = ("H6sI", ("port", "_", "queue_id"), {"port":v1port_readable})
		elif type == "SET_VLAN_VID":
			packdef = ("H", ("vlan_vid",), {})
		elif type == "SET_VLAN_PCP":
			packdef = ("B", ("vlan_pcp",), {})
		elif type in ("SET_DL_SRC", "SET_DL_DST"):
			packdef = ("6s", ("dl_addr",), {})
		elif type in ("SET_NW_SRC", "SET_NW_DST"):
			packdef = ("I", ("nw_addr",), {})
		elif type == "SET_TW_TOS":
			packdef = ("B", ("nw_tos",), {})
		elif type in ("SET_TP_SRC", "SET_TP_DST"):
			packdef = ("H", ("tp_port",), {})
		elif type == "VENDOR":
			packdef = ("I", ("vendor",), {})
		
		if packdef:
			self._append_packdef(*packdef)
		
		if message:
			self._unpack(message, offset=kwargs.get("offset", 0))
		else:
			for key in self._keys:
				if not key.startswith("_") and key in kwargs:
					setattr(self, key, kwargs[key])
	
	def serialize(self):
		self.len = struct.calcsize(self._packs)
		return super(Action, self).serialize()

class Port(Common):
	def __init__(self, message=None, **kwargs):
		super(Port, self).__init__(**kwargs)
		
		v1port_features = ("10MB_HD", "10MB_FD", "100MB_HD", "100MB_FD", "1GB_HD", "1GB_FD", "10GB_FD", 
			"COPPER", "FIBER", "AUTONEG", "PAUSE", "PAUSE_ASYM")
		
		self._append_packdef("H6s16sIIIIII", ("port_no", "hw_addr", "name", "config", "state", "curr", "advertised", "supported", "peer"), {
			"hw_addr": mac,
			"name": lambda v,o,i: v.partition("\0")[0],
			"config": bit_readable("PORT_DOWN", "NO_STP", "NO_RECV", "NO_RECV_STP", "NO_FLOOD", "NO_FWD", "NO_PACKET_IN"),
			"state": v1port_state_readable,
			"curr": bit_readable(*v1port_features),
			"advertised": bit_readable(*v1port_features),
			"supported": bit_readable(*v1port_features),
			"peer": bit_readable(*v1port_features)
			})
		
		if message:
			self._unpack(message, offset=kwargs.get("offset", 0))
		else:
			for key in self._keys:
				if not key.startswith("_") and key in kwargs:
					setattr(self, key, kwargs[key])

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
			return int(value, 16)
		else:
			return value
	else:
		return "%#x" % value

def mac(value, obj, inverse=False):
	if inverse:
		return struct.pack("!6B", [int(mac, 16) for mac in value.split(":")])
	else:
		return ":".join(["%02x" % mac for mac in struct.unpack("!6B", value)])

# pack_string, field_names, translators

v1header_types = ("HELLO", "ERROR", "ECHO_REQUEST", "ECHO_REPLY", "VENDOR", 
	"FEATURES_REQUEST", "FEATURES_REPLY", "GET_CONFIG_REQUEST", "GET_CONFIG_REPLY", "SET_CONFIG", 
	"PACKET_IN", "FLOW_REMOVED", "PORT_STATUS", 
	"PACKET_OUT", "FLOW_MOD", "PORT_MOD", 
	"STATS_REQUEST", "STATS_REPLY",
	"BARRIER_REQUEST", "BARRIER_REPLY",
	"QUEUE_GET_CONFIG_REQUEST", "QUEUE_GET_CONFIG_REPLY")

def type_readable(value, obj, inverse=False):
	if inverse:
		return v1header_types.index(value)
	else:
		return v1header_types[value]

header = ("BBHI", ("version", "type", "length", "xid"), {"type":type_readable, "xid":hexify})

v1features_reply = ("QIB3sII", ("datapath_id", "n_buffers", "n_tables", "_pad", "capabilities", "actions"), {
	"datapath_id":lambda v,o,i: int(v,16) if i else "%016x" % v,
	"capabilities": bit_readable("FLOW_STATS", "TABLE_STATS", "PORT_STATS", "STP", "RESERVED", "IP_REASM", "QUEUE_STATS", "ARP_MATCH_IP"),
	"actions": bit_readable(*v1action_types)
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

v1error = ("HH", ("etype", "code"), {
	"etype": enum_readable("HELLO_FAILED", "BAD_REQUEST", "BAD_ACTION", "FLOW_MOD_FAILED", "PORT_MOD_FAILED", "QUEUE_OP_FAILED"),
	"code": v1error_code_readable
	})

def v1port_readable(value, obj, inverse=False):
	v1port = {0xff00:"MAX", 0xfff8:"IN_PORT", 0xfff9:"TABLE", 0xfffa:"NORMAL", 0xfffb:"FLOOD", 
		0xfffc:"ALL", 0xfffd:"CONTROLLER", 0xfffe:"LOCAL", 0xffff:"NONE"}
	if inverse:
		for k,v in v1port.items():
			if v==value:
				return k
		if isinstance(value, str):
			return int(value, 16)
		return value
	return v1port.get(value, hexify(value, obj))

v1packet_in = ("IHHBB", ("buffer_id", "total_len", "in_port", "reason", "_p"), {
	"in_port": v1port_readable,
	"reason": enum_readable("NO_MATCH", "ACTION")
	})

v1packet_out = ("IHH", ("buffer_id", "in_port", "actions_len"), {
	"in_port": v1port_readable
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
	t[0] = mac(t[0], None)
	t[1] = mac(t[1], None)
	t[2] = "0x%04x" % t[2]
	if t[5]: t[5] = "%d.%d.%d.%d" % struct.unpack("BBBB", t[5])
	if t[6]: t[6] = "%d.%d.%d.%d" % struct.unpack("BBBB", t[6])
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
