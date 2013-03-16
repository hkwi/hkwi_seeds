import binascii
import collections
import json
import struct

class AttrDumper(json.JSONEncoder):
	def default(self, o):
		if hasattr(o, "_bare"):
			return o._as_dict()
		
		return super(AttrDumper,self).default(o)

class Common(object):
	def __init__(self, version=1, raw=False):
		self._bare = []
		self._readable = {}
		self._raw = raw
		self.version=version
	
	def _as_dict(self):
		return dict([(k, getattr(self,k)) for k in dict(self._bare).keys() if not k.startswith("_")])
	
	def __getattr__(self, name):
		if name not in dict(self._bare):
			self._parse_nonheader()
		try:
			value = dict(self._bare)[name]
			if not self._raw and name in self._readable:
				return self._readable[name](value, self)
			return value
		except Exception as e:
			raise AttributeError("no %s attribute: %s" % (name, e))
	
	def __repr__(self):
		return json.dumps(self, cls=AttrDumper, separators=(", ",":"))

class Action(Common):
	pass

class Port(Common):
	pass

class Message(Common):
	def __init__(self, message, raw=False):
		self._bare = []
		self._readable = {}
		self._message = message
		self._parse_nonheader_run = False
		self._raw = raw
		_bare_and_readable(self, header, message, 0)
		assert self.version == 1, "not supported yet"
	
	def _parse_nonheader(self):
		if self._parse_nonheader_run: return
		
		if self.type == "ERROR":
			_bare_and_readable(self, v1error, self._message, 8)
			self._bare.append(("data", self._message[12:]))
		elif self.type == "FEATURES_REPLY":
			_bare_and_readable(self, v1features_reply, self._message, 8)
			self._bare.append(("ports", v1ports(self._message, 32, self._raw)))
		elif self.type == "PACKET_IN":
			_bare_and_readable(self, v1packet_in, self._message, 8)
			self._bare.append(("data", self._message[18:]))
		elif self.type == "PACKET_OUT":
			_bare_and_readable(self, v1packet_out, self._message, 8)
			if self.buffer_id == 0xffffffff: # -1
				self._bare.append(("data", self._message[16:]))
			else:
				self._bare.append(("actions", v1actions(self._message, 16, self._raw)))
		elif self.type == "PORT_STATUS":
			_bare_and_readable(self, v1port_status, self._message, 8)
			self._bare.append(("port", v1port(self._message, 16, self._raw)))
		self._parse_nonheader_run = True
	
	def _as_dict(self):
		self._parse_nonheader()
		ret = super(Message, self)._as_dict()
		if not self._raw and "data" in ret:
			ret["data"] = binascii.b2a_hex(ret["data"])
		return ret

def _bare_and_readable(obj, packdef, message, offset):
	obj._bare.extend(zip(packdef[1], struct.unpack_from(packdef[0], message, offset)))
	obj._readable.update(packdef[2])

v1action_types = ("OUTPUT", "SET_VLAN_VID", "SET_VLAN_PCP", "STRIP_VLAN", "SET_DL_SRC", "SET_DL_DST", 
	"SET_NW_SRC", "SET_NW_DST", "SET_NW_TOS", "SET_TP_SRC", "SET_TP_DST", "ENQUEUE") # VENDOR=0xffff

def v1actions(message, offset, raw):
	actions = []
	while offset<len(message):
		a = Action(raw=raw)
		(a.type, a.len) = struct.unpack_from("!HH", message, offset)
		if a.type != 0xffff: # VENDOR
			sub = v1action_types[a.type]
		
		if sub == "OUTPUT":
			(a.port, a.max_len) = struct.unpack_from("!HH", message, offset+4)
		elif sub == "ENQUEUE":
			(a.port, u1, a.queue_id) = struct.unpack_from("!H6sI", message, offset+4)
		elif sub == "SET_VLAN_VID":
			(a.vlan_vid,) = struct.unpack_from("!H", message, offset+4)
		elif sub == "SET_VLAN_PCP":
			(a.vlan_pcp,) = struct.unpack_from("!B", message, offset+4)
		elif sub in ("SET_DL_SRC", "SET_DL_DST"):
			(a.dl_addr,) = struct.unpack_from("!6s", message, offset+4)
		elif sub in ("SET_NW_SRC", "SET_NW_DST"):
			(a.nw_addr,) = struct.unpack_from("!I", message, offset+4)
		elif sub == "SET_TW_TOS":
			(a.nw_tos,) = struct.unpack_from("!B", message, offset+4)
		elif sub in ("SET_TP_SRC", "SET_TP_DST"):
			(a.tp_port,) = struct.unpack_from("!H", message, offset+4)
		else: # VENDOR
			assert a.type == 0xffff, "unknown action type %d" % a.type
			(a.vendor,) = struct.unpack_from("!I", message, offset+4)
		actions.append(a)
		offset += a.len
	return actions

def v1port_state_readable(value, obj):
	ret = []
	if value & 1:
		ret.append("LINK_DOWN")
	ret.append(("STP_LISTEN", "STP_LEARN", "STP_FORWARD", "STP_BLOCK")[(value>>8)&3])
	return ret

def v1ports(message, offset, raw):
	ret = []
	while offset<len(message):
		ret.append(v1port(message, offset, raw))
		offset += 48
	return ret

def v1port(message, offset, raw):
	p = Port(raw=raw)
	v1port_features = ("10MB_HD", "10MB_FD", "100MB_HD", "100MB_FD", "1GB_HD", "1GB_FD", "10GB_FD", 
		"COPPER", "FIBER", "AUTONEG", "PAUSE", "PAUSE_ASYM")
	packdef = ("!H6s16sIIIIII", ("port_no", "hw_addr", "name", "config", "state", "curr", "advertised", "supported", "peer"), {
		"hw_addr": mac,
		"name": lambda v,o: v.partition("\0")[0],
		"config": lambda v,o: bitlist(v, ("PORT_DOWN", "NO_STP", "NO_RECV", "NO_RECV_STP", "NO_FLOOD", "NO_FWD", "NO_PACKET_IN")),
		"state": v1port_state_readable,
		"curr": lambda v,o: bitlist(v, v1port_features),
		"advertised": lambda v,o: bitlist(v, v1port_features),
		"supported": lambda v,o: bitlist(v, v1port_features),
		"peer": lambda v,o: bitlist(v, v1port_features)
		})
	_bare_and_readable(p, packdef, message, offset)
	return p

def bitlist(target, idx):
	return [idx[i] for i in range(len(idx)) if (target>>i)&1]

def hexify(value, obj):
	return "%#x" % value

def mac(value, obj):
	return ":".join(["%02x" % mac for mac in struct.unpack("!6B", value)])

# pack_string, field_names, translators

def type_readable(value, obj):
	assert obj.version==1, "not supported yet"
	return ("HELLO", "ERROR", "ECHO_REQUEST", "ECHO_REPLY", "VENDOR", 
		"FEATURES_REQUEST", "FEATURES_REPLY", "GET_CONFIG_REQUEST", "GET_CONFIG_REPLY", "SET_CONFIG", 
		"PACKET_IN", "FLOW_REMOVED", "PORT_STATUS", 
		"PACKET_OUT", "FLOW_MOD", "PORT_MOD", 
		"STATS_REQUEST", "STATS_REPLY",
		"BARRIER_REQUEST", "BARRIER_REPLY",
		"QUEUE_GET_CONFIG_REQUEST", "QUEUE_GET_CONFIG_REPLY")[value]

header = ("!BBHI", ("version", "type", "length", "xid"), {"type":type_readable, "xid":hexify})

v1features_reply = ("!QIB3sII", ("datapath_id", "n_buffers", "n_tables", "_pad", "capabilities", "actions"), {
	"datapath_id":lambda v,o: "%016x" % v,
	"capabilities":lambda v,o: bitlist(v, ("FLOW_STATS", "TABLE_STATS", "PORT_STATS", "STP", "RESERVED", "IP_REASM", "QUEUE_STATS", "ARP_MATCH_IP")),
	"actions":lambda v,o: bitlist(v, v1action_types)
	})

def v1error_code_readable(value, obj):
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
		id = ("BAD_PORT", "BAD_QUEUE", "EPERM")
	try:
		return idx[value]
	except:
		return hexify(value, obj)

v1error = ("!HH", ("etype", "code"), {
	"etype":lambda v,o:("HELLO_FAILED", "BAD_REQUEST", "BAD_ACTION", "FLOW_MOD_FAILED", "PORT_MOD_FAILED", "QUEUE_OP_FAILED")[v],
	"code": v1error_code_readable
	})

def v1port_readable(value, obj):
	v1port = {0xff00:"MAX", 0xfff8:"IN_PORT", 0xfff9:"TABLE", 0xfffa:"NORMAL", 0xfffb:"FLOOD", 
		0xfffc:"ALL", 0xfffd:"CONTROLLER", 0xfffe:"LOCAL", 0xffff:"NONE"}
	return v1port.get(value, hexify(value, obj))

v1packet_in = ("!IHHB", ("buffer_id", "total_len", "in_port", "reason"), {
	"in_port":v1port_readable,
	"reason":lambda v,o:("NO_MATCH", "ACTION")[v]
	})

v1packet_out = ("!IHH", ("buffer_id", "in_port", "actions_len"), {
	"in_port":v1port_readable
	})

v1port_status = ("!B", ("reason",), {
	"reason":lambda v,o:("ADD", "DELETE", "MODIFY")[v]
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

