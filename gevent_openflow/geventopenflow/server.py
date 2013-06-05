import binascii
import datetime
import logging
import os.path
import random
import struct
import warnings
import gevent
from gevent import socket
from gevent import subprocess
from gevent.queue import Queue
from gevent.server import StreamServer

def parse_ofp_header(message):
	return struct.unpack_from("!BBHI", message)

def ofp_header_only(oftype, version=1, xid=None):
	if xid is None:
		xid = hms_xid()
	return struct.pack("!BBHI", version, oftype, 8, xid)

def hms_hex_xid():
	'''Xid looks readable datetime like format when logged as hex.'''
	now = datetime.datetime.now()
	candidate = struct.unpack("!I", binascii.a2b_hex("%02d"*4 % (now.hour, now.minute, now.second, now.microsecond/10000)))[0]
	if hasattr(hms_hex_xid, "dedup"):
		if hms_hex_xid.dedup >= candidate:
			candidate = hms_hex_xid.dedup+1
	setattr(hms_hex_xid, "dedup", candidate)
	return candidate

def hms_xid():
	'''Xid looks readable datetime like format when logged as int.'''
	now = datetime.datetime.now()
	candidate = int(("%02d"*3+"%04d") % (now.hour, now.minute, now.second, now.microsecond/100))
	if hasattr(hms_xid, "dedup"):
		if hms_xid.dedup >= candidate:
			candidate = hms_xid.dedup+1
	setattr(hms_xid, "dedup", candidate)
	return candidate

class Handle(object):
	'''
	Server handle function that can have some configurations.
	The signature for connection_class is func(socket, address, **kwargs)
	'''
	def __init__(self, connection_class, **kwargs):
		self.connection_class = connection_class
		self.kwargs = kwargs
		self.connections = set()
	
	def __call__(self, socket, address):
		con = self.connection_class(socket, address, **self.kwargs)
		self.connections.add(con)
		try:
			con.handle()
		finally:
			self.connections.remove(con)
	
	def __enter__(self):
		return self
	
	def __exit__(self, exc_type, exc_value, traceback):
		self.close()
	
	def close(self):
		for con in self.connections:
			con.close()

class Connection(object):
	io_logger = None
	io_log_suppress_echo = None
	io_log_suppress_barrier = None
	negotiated_version = None # negotiated openflow protocol version
	
	def __init__(self, socket, address, **kwargs):
		self.socket = socket
		self.address = address
		
		self.logger = logging.getLogger(kwargs.get("logger_name"))
		io_logger_name = kwargs.get("io_logger_name")
		if io_logger_name:
			self.io_logger = logging.getLogger(io_logger_name)
		self.io_log_suppress_echo = kwargs.get("io_log_suppress_echo")
		self.io_log_suppress_barrier = kwargs.get("io_log_suppress_barrier")
		
		self.sendq = Queue()
		self.messageq = Queue()
	
	@property
	def closed(self):
		return self.socket.closed
	
	def close(self):
		if not self.closed:
			try:
				self.socket.close()
			except:
				self.logger.error("socket close error", exc_info=True)
	
	def handle(self):
		gevent.spawn(self._send_loop)
		gevent.spawn(self._handle_message_loop)
		self.send_hello()
		self.negotiated_version = None
		self._recv_loop()
	
	def _recv_loop(self): # main thread
		OFP_HEADER_LEN = 8 # sizeof(struct ofp_header)
		while not self.closed:
			message = bytearray()
			try:
				while len(message) < OFP_HEADER_LEN and not self.closed:
					ext = self.socket.recv(OFP_HEADER_LEN-len(message))
					if len(ext) == 0:
						break
					message += ext
				if len(message) == 0: # normal shutdown
					break
				assert len(message) == OFP_HEADER_LEN, "Read error in openflow message header."
				
				(version,oftype,message_len,x) = parse_ofp_header(bytes(message))
				while len(message) < message_len and not self.closed:
					ext = self.socket.recv(message_len-len(message))
					if len(ext) == 0:
						break
					message += ext
				assert len(message) == message_len, "Read error in openflow message body."
				
				message = bytes(message) # freeze the message for ease in dump
				if self.io_logger:
					if oftype in (2,3) and self.io_log_suppress_echo:
						pass
					elif ((oftype in (18,19) and version==1) or (oftype in (20,21) and version!=1)) and self.io_log_suppress_barrier:
						pass
					else:
						self._log_io("recv", message)
				self._handle_message(message)
			except:
				self.logger.error("Openflow message read error.", exc_info=True)
				break
		self.close()
	
	def _send_loop(self): # runs in another thread
		while not self.closed:
			try:
				message = self.sendq.get()
				if self.io_logger:
					(version, oftype, length, xid) = parse_ofp_header(message)
					if oftype in (2,3) and self.io_log_suppress_echo:
						pass
					elif ((oftype in (18,19) and version==1) or (oftype in (20,21) and version!=1)) and self.io_log_suppress_barrier:
						pass
					else:
						self._log_io("send", message)
				self.socket.sendall(message)
			except:
				self.logger.error("Openflow message write error.", exc_info=True)
				self.close()
				break
	
	def _log_io(self, direction, message):
		zdata = self._ofp_common_fields(message)
		self.io_logger.info("%s(%x)%s %s" % (self.__class__.__name__, id(self), direction, zdata))
	
	def _ofp_common_fields(self, message):
		reqseq = list(parse_ofp_header(message))
		reqseq.append(message[8:])
		return zip(("version", "type", "length", "xid", "payload"), reqseq)
	
	def send(self, message):
		self.sendq.put(message)
	
	def send_header_only(self, oftype, version=None, xid=None):
		if version is None:
			if self.negotiated_version is not None:
				version = self.negotiated_version
			else:
				version = 1
		self.send(ofp_header_only(oftype, version=version, xid=xid))
	
	def send_hello(self):
		# subclass may replace this, to change openflow version.
		self.send_header_only(0) # send OFP_HELLO
	
	def on_echo(self, message):
		# Convenient method to responding to ofp echo_request. Subclass may use this.
		#
		# Both controller and switch will send echo reply.
		# If subclass don't want the default behavior, just set this method to None.
		# If you override this method, don't invoke I/O in this method, if you'd like 
		# to do I/O with echo request, put it in handle_message method.
		(version, oftype, length, xid) = parse_ofp_header(message)
		self.send(struct.pack("!BBHI", version, 3, 8+length, xid)+message)
	
	def on_error(self, message):
		self.logger.error("ofp_error %s", binascii.b2a_hex(message))
	
	def _handle_message(self, message):
		(version, oftype, length, xid) = parse_ofp_header(message)
		if oftype==2 and self.on_echo:
			self.on_echo(message)
		elif oftype==1 and self.on_error:
			self.on_error(message)
		self.messageq.put(message)
	
	def _handle_message_loop(self): # runs in another thread
		# This runs in another thread, because handle_message sometimes
		# invokes another I/O in its processing.
		while not self.closed:
			try:
				self.handle_message(self.messageq.get())
			finally:
				self.close()
	
	def handle_message(self, message):
		warnings.warn("subclass must override this method")

class Controller(Connection):
	def __init__(self, *args, **kwargs):
		super(Controller, self).__init__(*args, **kwargs)
	
	def on_packet(self, message):
		'''
		Default on_packet handler for openvswitch use this for heartbeat check.
		'''
		(version, oftype, length, xid) = parse_ofp_header(message)
		(buffer_id, ) = struct.unpack_from("!I", message, offset=8)
		# default action "DROP"
		if version==1:
			msg = struct.pack("!IHH", buffer_id, 0xffff, 0) # OFPP_NONE=0xffff
		else:
			msg = struct.pack("!IIHHI", buffer_id, 0xffffffff, 0, 0, 0) # OFPP_CONTROLLER=0xffffffff
		
		self.send(struct.pack("!BBHI", version, 13, 8+len(msg), xid)+msg) # OFPT_PACKET_OUT=13
	
	def handle_message(self, message):
		(version, oftype, length, xid) = parse_ofp_header(message)
		
		if oftype == 10 and self.on_packet: # OFPT_PACKET_IN=10
			self.on_packet(message)

class Barrier(object):
	def __init__(self, xid, next_callback=None, this_callback=None):
		self.xid = xid
		self.next_callback = next_callback
		self.this_callback = this_callback
	
	def __call__(self, message):
		if self.this_callback:
			self.this_callback(message)

class BarrieredController(Controller):
	def __init__(self, *args, **kwargs):
		super(BarrieredController, self).__init__(*args, **kwargs)
		self.callback = self.handle_message # default callback
		self.barriers = []
		self.last_callback = None
		self.active_callback = None # Active responder callback. This may be None, _handle_message will take care
		
		self._datapath = None
		self._feature_req_sent = False
	
	@property
	def datapath(self):
		if self._datapath is None and not self._feature_req_sent:
			self.send_header_only(5) # OFPT_FEATURES_REQUEST
		return self._datapath
	
	def send(self, message, callback=None):
		(version, oftype, length, xid) = parse_ofp_header(message)
		if oftype==5:
			self._feature_req_sent = True
		if (oftype==18 and version==1) or (oftype==20 and version!=1): # OFPT_BARRIER_REQUEST
			self.barriers.append(Barrier(xid, this_callback=callback))
		else:
			if self.last_callback != callback: # auto-generate a barrier
				barrier = Barrier(hms_xid(), next_callback=callback)
				self.barriers.append(barrier)
				if self.negotiated_version==1:
					msg = ofp_header_only(18, version=1, xid=barrier.xid) # OFPT_BARRIER_REQUEST=18 (v1.0)
				else:
					msg = ofp_header_only(20, version=self.negotiated_version, xid=barrier.xid) # OFPT_BARRIER_REQUEST=20 (v1.3)
				super(BarrieredController, self).send(msg) # NOTE: don't use send_header_only here, because it will call this method again.
		
		super(BarrieredController, self).send(message)
		self.last_callback = callback
	
	def detach(self, callback):
		for barrier in self.barriers:
			if barrier.this_callback == callback:
				barrier.this_callback = None
			if barrier.next_callback == callback:
				barrier.next_callback = None
		if self.last_callback == callback:
			self.last_callback = None
		if self.active_callback == callback:
			self.active_callback = None
	
	def send_header_only(self, oftype, version=None, xid=None, callback=None):
		if version is None:
			if self.negotiated_version is not None:
				version = self.negotiated_version
			else:
				version = 1
		self.send(ofp_header_only(oftype, version=version, xid=xid), callback=callback)
	
	def _handle_message(self, message):
		(version, oftype, length, xid) = parse_ofp_header(message)
		
		if (oftype==19 and version==1) or (oftype==21 and version!=1):
			assert xid == self.barriers[0].xid, "switch replied to unknown barrier request or barrier is out of order."
		
		if oftype==2 and self.on_echo:
			self.on_echo(message)
		elif oftype==1 and self.on_error:
			self.on_error(message)
		elif oftype == 6: # OFPT_FEATURES_REPLY
			self._datapath = struct.unpack_from("!Q", message, offset=8)[0]
		
		if len(self.barriers) and xid == self.barriers[0].xid:
			barrier = self.barriers.pop(0)
			barrier(message)
			if barrier.next_callback:
				self.active_callback = barrier.next_callback
		else:
			callback = self.active_callback
			if self.active_callback is None:
				self.messageq.put(message)
			else:
				callback(message)
	
	def close(self):
		super(BarrieredController, self).close()

class Switch(Connection):
	def handle_message(self, message):
		(version, oftype, length, xid) = parse_ofp_header(message)
		if oftype in (0, 2): # OFPT_HELLO, OFPT_ECHO_REQUEST we don't need check
			pass
		elif (version==1 and oftype==18):
			self.send_header_only(19, xid=xid) # OFPT_BARRIER_REPLY=19 (v1.0)
		elif (version!=1 and oftype==20):
			self.send_header_only(21, version=version, xid=xid) # OFPT_BARRIER_REPLY=21
		else:
			self.logger.warn("unhandled %s" % self._ofp_common_fields(message), exc_info=True)

class ProxySwitch(Switch):
	def __init__(self, *args, **kwargs):
		super(ProxySwitch, self).__init__(*args, **kwargs)
		self.upstream = kwargs["upstream"]
		assert isinstance(self.upstream, Controller), "upstream Controller instance is required."
		
		self.relay_echo = kwargs.get("relay_echo")
		if self.relay_echo:
			self.on_echo = None # upstream will be respond to echo
		
		self.upstream_hello = kwargs.get("upstream_hello") # upstream hello message bytes if available
	
	def send_hello(self,):
		if self.upstream_hello: # relay upstream hello message (may contain protocol negotiation info)
			self.send(self.upstream_hello)
		else:
			super(ProxySwitch, self).send_hello()
	
	def handle_message(self, message):
		'''
		handles a message coming from downstream.
		send will send a message to downstream.
		'''
		(version, oftype, length, xid) = parse_ofp_header(message)
		if oftype==0: # ignore OFPT_HELLO, because upstream proxy already connected.
			pass
		elif oftype==2 and not self.relay_echo: # OFPT_ECHO_REQUEST
			pass # don't relay to upstream
		else:
			self.upstream.send(message, callback=self.send_by_proxy)
	
	def send_by_proxy(self, message):
		(version, oftype, length, xid) = parse_ofp_header(message)
		if oftype==3 and not self.relay_echo:
			pass # don't relay to downstream
		else:
			self.send(message)
	
	def close(self,):
		self.upstream.detach(self.send_by_proxy)
		super(ProxySwitch, self).close()


class OvsController(BarrieredController):
	ofctl_logger = None
	ofctl_proxy = None
	def __init__(self, *args, **kwargs):
		super(OvsController, self).__init__(*args, **kwargs)
		self.socket_dir = kwargs.get("socket_dir")
		if kwargs.get("ofctl_logger_name"):
			self.ofctl_logger = logging.getLogger(kwargs.get("ofctl_logger_name"))
		self.ofctl_io_logger_name = kwargs.get("ofctl_io_logger_name")
	
	def _handle_message(self, message):
		(version, oftype, length, xid) = parse_ofp_header(message)
		if oftype == 0:
			self.switch_hello = message
		
		super(OvsController, self)._handle_message(message)
	
	def handle_message(self, message):
		(version, oftype, length, xid) = parse_ofp_header(message)
		
		if oftype == 10:
			self.on_packet(message)
		elif oftype == 6: # OFPT_FEATURES_REPLY
			result = self.ofctl("dump-flows")
			result = self.ofctl("dump-tables")
	
	def add_flow(self, flow):
		return self.ofctl("add-flow", flow)
	
	def del_flows(self, flow=None):
		if flow is None:
			return self.ofctl("del-flows")
		else:
			return self.ofctl("del-flows", flow)
	
	def ofctl(self, action, *args, **options):
		pstdout = None
		
		socket_file = None
		try:
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			s.bind(("127.0.0.1", 0))
			socket_path = "tcp:%s:%d" % s.getsockname()
		except socket.error:
			if hasattr(socket, "AF_UNIX") and self.datapath:
				s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
				socket_path = "dp_%x_internal_%d.sock" % (self.datapath, 1000*random.random())
				if self.socket_dir:
					socket_path = os.path.join(self.socket_dir, socket_path)
				socket_path = os.path.abspath(socket_path)
				s.bind(socket_path)
				
				socket_file = socket_path
			else:
				raise
		
		s.listen(1)
		
		try:
			server = StreamServer(s, handle=Handle(ProxySwitch, upstream=self, io_logger_name=self.ofctl_io_logger_name, upstream_hello=self.switch_hello)) # may pass ofctl_io_logger_name
			server.start()
		
			if self.negotiated_version != 1:
				if "O" in options or "protocols" in options:
					pass
				else:
					options["O"] = ("OpenFlow10","OpenFlow11","OpenFlow12","OpenFlow13")[self.negotiated_version - 1]
		
			cmd = ["ovs-ofctl",]
			cmd.extend(self._make_ofctl_options(options))
			cmd.append(action)
			cmd.append(socket_path)
			cmd.extend(args)
			if self.ofctl_logger:
				self.ofctl_logger.debug("call: %s" % " ".join(cmd))
			p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
			(pstdout, pstderr) = p.communicate()
			if self.ofctl_logger:
				self.ofctl_logger.debug("stdout: %s" % pstdout)
			if p.poll():
				self.logger.error("stderr: %s" % pstderr, exc_info=True)
		
			server.stop()
			
			return pstdout
		finally:
			if socket_file:
				os.remove(socket_file)
	
	def _make_ofctl_options(self, options):
		# key name, double hyphn, take arg type, join with equal
		fields = ("name", "detail", "argtype", "joinWithEqual")
		option_list = (
			("strict", True, None, False),
			("O", False, str, False), ("protocols", True, str, True),
			("F", False, str, False), ("flow_format", True, str, True),
			("P", False, str, False), ("packet_in_format", True, str, True),
			("timestamp", True, None, False),
			("m", False, None, False), ("more", True, None, False),
			("sort", True, str, True),
			("rsort", True, str, True),
			("pidfile", True, str, True),
			("overwrite_pidfile", True, None, False),
			("detach", True, None, False),
			("monitor", True, None, False),
			("no_chdir", True, None, False),
			("p", False, str, False), ("private_key", True, str, True),
			("c", False, str, False), ("certificate", True, str, True),
			("C", False, str, False), ("ca_cert", True, str, True),
			("v", False, str, False), ("verbose", True, str, True),
			("log_file", True, str, True),
			("h", False, None, False), ("help", True, None, False),
			("V", False, None, False), ("version", True, None, False),
			("idle_timeout", True, int, True),
			("hard_timeout", True, int, True),
			("send_flow_rem", True, None, False),
			("check_overlap", True, None, False)
			)
		known_opts = dict()
		for option_item in option_list:
			known_opts[option_item[0]] = dict(zip(fields, option_item))
		
		ret = []
		for (option,value) in options.items():
			assert option in known_opts, "unknown ovs-ofctl option %s" % option
			opt_info = known_opts[option]
			
			tmp = "-"+option.replace("_", "-")
			if opt_info["detail"]:
				tmp = "-"+tmp
			
			if opt_info["argtype"] is None or value is None:
				ret.append(tmp)
			else:
				sval = str(opt_info["argtype"](value))
				if opt_info["joinWithEqual"] and len(sval):
					ret.append(tmp+"="+sval)
				else:
					ret.append(tmp)
					ret.append(sval)
		
		return ret

class InverseController(OvsController):
	'''
	Creates a unix domain socket that accepts controller access (inverse connection direction).
	'''
	downstream_handle = None
	downstream_server = None
	downstream_file = None
	def __init__(self, *args, **kwargs):
		super(InverseController, self).__init__(*args, **kwargs)
		self.socket_dir = kwargs.get("socket_dir")
		self.inverse_io_logger_name = kwargs.get("inverse_io_logger_name")
	
	def _handle_message(self, message):
		super(InverseController, self)._handle_message(message)
		if self.downstream_server is None and hasattr(socket, "AF_UNIX") and self.datapath:
			socket_fname = "dp_%x.sock" % (self.datapath,)
			if self.socket_dir:
				socket_fname = os.path.join(self.socket_dir, socket_fname)
			
			s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
			s.bind(socket_fname)
			s.listen(8)
			
			handle = Handle(ProxySwitch, upstream=self, io_logger_name=self.inverse_io_logger_name, upstream_hello=self.switch_hello)
			server = StreamServer(s, handle=handle)
			server.start()
			
			self.downstream_handle = handle
			self.downstream_server = server
			self.downstream_file = socket_fname
	
	def handle_message(self, message):
		(version, oftype, length, xid) = parse_ofp_header(message)
		if oftype in (0, 2, 3, 6): # we know those will be used.
			pass
		elif oftype == 10 and self.on_packet: # OFPT_PACKET_IN=10
			self.on_packet(message)
		else:
			self.logger.warn("unhandled %s" % self._ofp_common_fields(message), exc_info=True)
	
	def close(self,):
		if self.downstream_handle:
			self.downstream_handle.close()
			self.downstream_handle = None
		if self.downstream_server:
			self.downstream_server.stop()
			self.downstream_server = None
		if self.downstream_file:
			os.remove(self.downstream_file)
			self.downstream_file = None
		super(InverseController, self).close()

class HeartbeatController(InverseController):
	def send_hello(self):
		super(HeartbeatController, self).send_hello()
		gevent.spawn(self.heartbeat)

	def heartbeat(self):
		while not self.closed:
			self.send_header_only(2)
			gevent.sleep(14)

if __name__ == "__main__":
	logging.basicConfig(level=0)
#	with Handle(OvsController, io_logger_name="root", ofctl_logger_name="root") as handle:
#	with Handle(Controller, io_logger_name="root") as handle:
	with Handle(HeartbeatController, io_logger_name="root", io_log_suppress_echo=False, socket_dir=".") as handle:
		StreamServer(("0.0.0.0",6633), handle=handle).serve_forever()
