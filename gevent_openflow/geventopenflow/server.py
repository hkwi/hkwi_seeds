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
from gevent.event import AsyncResult
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

class ConnectionException(Exception):
	'''
	AsyncResult failed due to connection close.
	'''
	pass

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
		con.handle()
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
	def __init__(self, socket, address, **kwargs):
		self.socket = socket
		self.address = address
		
		self.logger = logging.getLogger(kwargs.get("logger_name"))
		io_logger_name = kwargs.get("io_logger_name")
		if io_logger_name:
			self.io_logger = logging.getLogger(io_logger_name)
		self.io_log_suppress_echo = kwargs.get("io_log_suppress_echo")
		
		self.sendq = Queue()
	
	@property
	def closed(self):
		return self.socket.closed
	
	def close(self):
		if not self.closed:
			try:
				self.socket.close()
			except:
				self.logger.error("socket close error", exc_info=True)
		self.sendq = None
	
	def _log_io(self, direction, message):
		zdata = self._ofp_common_fields(message)
		self.io_logger.info("%s(%x)%s %s" % (self.__class__.__name__, id(self), direction, zdata))
	
	def _ofp_common_fields(self, message):
		reqseq = list(parse_ofp_header(message))
		reqseq.append(message[8:])
		return zip(("version", "type", "length", "xid", "payload"), reqseq)
	
	def send(self, message):
		self.sendq.put(message)
	
	def send_header_only(self, oftype, version=1, xid=None):
		self.send(ofp_header_only(oftype, version=version, xid=xid))
	
	def send_hello(self):
		# subclass may replace this, to change openflow version.
		self.send_header_only(0) # send OFP_HELLO
	
	def handle(self):
		g = gevent.spawn(self._send_loop)
		self.send_hello()
		self._recv_loop()
	
	def _recv_loop(self):
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
				
				(v,oftype,message_len,x) = parse_ofp_header(bytes(message))
				while len(message) < message_len and not self.closed:
					ext = self.socket.recv(message_len-len(message))
					if len(ext) == 0:
						break
					message += ext
				assert len(message) == message_len, "Read error in openflow message body."
				
				message = bytes(message)
				if self.io_logger:
					if oftype in (2,3) and self.io_log_suppress_echo:
						pass
					else:
						self._log_io("recv", message)
				gevent.spawn(self._handle_message, message)
			except:
				self.logger.error("Openflow message read error.", exc_info=True)
				break
		self.close()
	
	def echo_reply(self, message):
		# Convenient method for ofp echo_reply. Subclass may use this.
		#
		# Both controller and switch will send echo reply
		(version, oftype, length, xid) = parse_ofp_header(message)
		self.send(struct.pack("!BBHI", version, 3, 8+length, xid)+message)
	
	def _handle_message(self, message):
		(version, oftype, length, xid) = parse_ofp_header(message)
		if oftype==2 and self.echo_reply:
			self.echo_reply(message)
		self.handle_message(message)
	
	def handle_message(self, message):
		warnings.warn("subclass must override this method")
	
	def _send_loop(self): # runs in another thread
		while not self.closed:
			try:
				message = self.sendq.get()
				if self.io_logger:
					(version, oftype, length, xid) = parse_ofp_header(message)
					if oftype in (2,3) and self.io_log_suppress_echo:
						pass
					else:
						self._log_io("send", message)
				self.socket.sendall(message)
			except:
				self.logger.error("Openflow message write error.", exc_info=True)
				self.close()
				break

class Controller(Connection):
	def __init__(self, *args, **kwargs):
		super(Controller, self).__init__(*args, **kwargs)
		self.barriered = False
	
	def packet_in(self, message):
		'''
		Default packet_in handler for openvswitch use this for heartbeat check.
		'''
		(version, oftype, length, xid) = parse_ofp_header(message)
		(buffer_id, ) = struct.unpack_from("!I", message, offset=8)
		# default action "do nothing about that buffer"
		if version==1:
			msg = struct.pack("!IHH", buffer_id, 0xffff, 0) # OFPP_NONE=0xffff
		else:
			msg = struct.pack("!IIHHI", buffer_id, 0xffffffff, 0, 0, 0) # OFPP_CONTROLLER=0xffffffff
		
		self.send(struct.pack("!BBHI", version, 13, 8+len(msg), xid)+msg) # OFPT_PACKET_OUT=13
	
	def handle_message(self, message):
		(version, oftype, length, xid) = parse_ofp_header(message)
		
		if oftype == 10 and self.packet_in: # OFPT_PACKET_IN=10
			self.packet_in(message)

class Barrier(object):
	def __init__(self, xid, next_callback=None, this_callback=None):
		self.xid = xid
		self.next_callback = next_callback
		self.this_callback = this_callback
	
	def __call__(self, message):
		if self.this_callback:
			(version, oftype, length, xid) = parse_ofp_header(message)
			assert xid == self.xid, "Message in barrier gap: %s" % binascii.b2a_hex(message)
			assert (oftype==19 and version==1) or (oftype==21 and version!=1), "barrier failed: %s" % binascii.b2a_hex(message)

class BarrieredController(Controller):
	featuresAsyncResult = None
	def __init__(self, *args, **kwargs):
		super(BarrieredController, self).__init__(*args, **kwargs)
		self.callback = self.handle_message # default callback
		self.barriers = []
		self.last_callback = None
		self.active_callback = None # Active responder callback. This may be None, _handle_message will take care
	
	def datapath(self, wait=True):
		if self.featuresAsyncResult is None:
			self.featuresAsyncResult = AsyncResult()
			self.send_header_only(5) # OFPT_FEATURES_REQUEST
		
		if wait or self.featuresAsyncResult.value:
			(datapath,) = struct.unpack_from("!Q", self.featuresAsyncResult.get(), offset=8)
			return datapath
		return None
	
	def send(self, message, callback=None):
		(version, oftype, length, xid) = parse_ofp_header(message)
		if (oftype==18 and version==1) or (oftype==20 and version!=1): # OFPT_BARRIER_REQUEST
			self.barriers.append(Barrier(xid, this_callback=callback))
		else:
			if self.last_callback != callback:
				barrier = Barrier(hms_xid(), next_callback=callback)
				self.barriers.append(barrier)
				super(BarrieredController, self).send(ofp_header_only(18, xid=barrier.xid)) # OFPT_BARRIER_REQUEST=18 (v1.0)
		
		super(BarrieredController, self).send(message)
		self.last_callback = callback
	
	def detach(self, callback):
		for barrier in self.barriers:
			if barrier.this_callback == callback:
				barrier.this_callback = None
			if barrier.next_callback == callback:
				barrier.this_callback = None
		if self.last_callback == callback:
			self.last_callback = None
		if self.active_callback == callback:
			self.active_callback = None
	
	def send_header_only(self, oftype, version=1, xid=None, callback=None):
		self.send(ofp_header_only(oftype, version=version, xid=xid), callback=callback)
	
	def _handle_message(self, message):
		(version, oftype, length, xid) = parse_ofp_header(message)
		
		if (oftype==19 and version==1) or (oftype==21 and version!=1):
			assert xid == self.barriers[0].xid, "switch replied to unknown barrier request or barrier is out of order."
		
		if oftype==2 and self.echo_reply:
			self.echo_reply(message)
		
		if oftype == 6: # OFPT_FEATURES_REPLY
			self.featuresAsyncResult.set(message)
		
		if len(self.barriers) and xid == self.barriers[0].xid:
			barrier = self.barriers.pop(0)
			barrier(message)
			self.active_callback = barrier.next_callback
		else:
			callback = self.active_callback
			if self.active_callback is None:
				callback = self.handle_message
			callback(message)

	def close(self):
		if self.featuresAsyncResult and self.featuresAsyncResult.value is None:
			self.featuresAsyncResult.set_exception(ConnectionException("connection closed."))
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
		self.relay_echo = kwargs.get("relay_echo")
		if self.relay_echo:
			self.echo_reply = None # upstream will be respond to echo
	
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
	
	def _handle_message(self, message):
		super(OvsController, self)._handle_message(message)
	
	def handle_message(self, message):
		(version, oftype, length, xid) = parse_ofp_header(message)
		
		if oftype == 10:
			self.packet_in(message)
		elif oftype == 6: # OFPT_FEATURES_REPLY
			result = self.ofctl("dump-flows")
			result = self.ofctl("dump-tables")
	
	def ofctl(self, action, *args, **options):
		pstdout = None
		
		if hasattr(socket, "AF_UNIX"):
			s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
			socket_path = "dp_%x_internal_%d.sock" % (self.datapath(), 1000*random.random())
			if self.socket_dir:
				socket_path = os.path.join(self.socket_dir, socket_fname)
			s.bind(socket_fname)
		else:
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			s.bind(("127.0.0.1", 0))
			socket_path = "tcp:%s:%d" % s.getsockname()
		s.listen(1)
		
		server = StreamServer(s, handle=Handle(ProxySwitch, upstream=self)) # may pass ofctl_io_logger_name
		server.start()
		
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
		if hasattr(socket, "AF_UNIX"):
			os.remove(socket_path)
		
		return pstdout
	
	def _make_ofctl_options(self, options):
		# key name, double hyphn, take arg type, join with equal
		fields = ("name", "detail", "argtype", "joinByEqual")
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
				if opt_info["joinByEqual"] and len(sval):
					ret.append(tmp+"="+sval)
				else:
					ret.append(tmp)
					ret.append(sval)
		
		return ret

class InverseController(OvsController):
	'''
	Creates a unix domain socket that accepts controller access (inverse connection direction).
	'''
	downstream_server = None
	downstream_file = None
	def __init__(self, *args, **kwargs):
		super(InverseController, self).__init__(*args, **kwargs)
		self.socket_dir = kwargs.get("socket_dir")
	
	def _handle_message(self, message):
		super(InverseController, self)._handle_message(message)
		
		if self.downstream_server is None and hasattr(socket, "AF_UNIX"):
			socket_fname = "dp_%x.sock" % (self.datapath(),)
			if self.socket_dir:
				socket_fname = os.path.join(self.socket_dir, socket_fname)
			
			s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
			s.bind(socket_fname)
			s.listen(8)
			
			handle = Handle(ProxySwitch, upstream=self, io_logger_name="root")
			server = StreamServer(s, handle=handle) # may pass inverse_io_logger_name
			server.start()
			
			self.downstream_handle = handle
			self.downstream_server = server
			self.downstream_file = socket_fname
	
	def handle_message(self, message):
		(version, oftype, length, xid) = parse_ofp_header(message)
		if oftype in (0, 2, 6): # we know those will be used.
			pass
		elif oftype == 10 and self.packet_in: # OFPT_PACKET_IN=10
			self.packet_in(message)
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

if __name__ == "__main__":
	logging.basicConfig(level=0)
#	with Handle(OvsController, io_logger_name="root", ofctl_logger_name="root") as handle:
#	with Handle(Controller, io_logger_name="root") as handle:
	with Handle(InverseController, io_logger_name="root", io_log_suppress_echo=True, socket_dir=".") as handle:
		StreamServer(("0.0.0.0",6633), handle=handle).serve_forever()
