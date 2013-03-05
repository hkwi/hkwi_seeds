import array
import binascii
import datetime
import logging
import os.path
import random
import struct
import sys
import time
import traceback
import warnings
import gevent
from gevent import socket
from gevent import subprocess
from gevent.event import AsyncResult
from gevent.lock import RLock
from gevent.queue import Queue
from gevent.server import StreamServer

def parse_ofp_header(message):
	return list(struct.unpack_from("!BBHI", message))

def ofp_header_only(oftype, version=1, xid=None):
	if xid is None:
		xid = hms_xid()
	return struct.pack("!BBHI", version, oftype, 8, xid)

def hms_hex_xid():
	now = datetime.datetime.now()
	return struct.unpack("!I", binascii.a2b_hex("%02d"*4 % (now.hour, now.minute, now.second, now.microsecond/10000)))[0]

def hms_xid():
	now = datetime.datetime.now()
	return int(("%02d"*3+"%04d") % (now.hour, now.minute, now.second, now.microsecond/100))

def barrier_xid():
	return long("f%07x" % (random.random()*0xFFFFFFF), 16)

class Bus(object):
	def __init__(self, connection_class, **kwargs):
		self.connection_class = connection_class
		self.kwargs = kwargs
	
	def __call__(self, socket, address):
		self.connection_class(socket, address, self, **self.kwargs).handle()

class BarrieredBus(Bus):
	def __init__(self, connection_class, **kwargs):
		super(BarrieredBus, self).__init__(connection_class, **kwargs)
		self.upstream_send = kwargs["upstream_send"]
		self.barriers = dict()
		self.connections = set()
		self.current_connection = None
		self.barriered = False
	
	def proxy_up(self, connection, message):
		assert connection is not None, "you must provide connection(yourself)"
		
		if not self.barriered and self.current_connection != connection:
			xid = barrier_xid()
			self.upstream_send(ofp_header_only(18, xid=xid))
			lock = AsyncResult()
			self.barriers[xid] = lock
			try:
				assert lock.get(), "barrier failed"
			finally:
				del(self.barriers[xid])
		
		self.current_connection = connection
		self.upstream_send(message)
		
		(v,oftype,l,xid) = parse_ofp_header(message)
		if oftype==18 and v==1:
			self.barriered = True
		else:
			self.barriered = False
	
	def proxy_down(self, message):
		(v,t,l,xid) = parse_ofp_header(message)
		
		if self.current_connection:
			self.current_connection.send(message)
		
		lock = self.barriers.get(xid)
		if lock:
			lock.set(t==19) # check if that was barrier reply, or error
	
	def __call__(self, socket, address):
		con = self.connection_class(socket, address, self, **self.kwargs)
		self.connections.add(con)
		con.handle()
		self.connections.remove(con)
		
		if self.current_connection is con:
			self.current_connection = None
	
	def close(self):
		for (xid, barrier) in self.barriers.items():
			barrier.set(False)
		assert len(self.barriers)==0, "cleanup failed"

class Connection(object):
	io_logger = None
	def __init__(self, socket, address, bus, **kwargs):
		self.socket = socket
		self.address = address
		self.bus = bus
		
		self.logger = logging.getLogger(kwargs.get("logger_name"))
		io_logger_name = kwargs.get("io_logger_name")
		if io_logger_name:
			self.io_logger = logging.getLogger(io_logger_name)
		
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
		self.io_logger.info("%s %s" % (direction,zdata))
	
	def _ofp_common_fields(self, message):
		reqseq = parse_ofp_header(message)
		reqseq.append(message[8:])
		return zip(("version", "type", "length", "xid", "payload"), reqseq)
	
	def send(self, message):
		self.sendq.put(message)
	
	def send_header_only(self, oftype, version=1, xid=None):
		self.send(ofp_header_only(oftype, version=version, xid=xid))
	
	def send_hello(self):
		# subclass may replace this.
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
					return
				assert len(message) == OFP_HEADER_LEN, "Read error in openflow message header."
				
				(v,t,message_len,x) = parse_ofp_header(bytes(message))
				while len(message) < message_len and not self.closed:
					ext = self.socket.recv(message_len-len(message))
					if len(ext) == 0:
						break
					message += ext
				assert len(message) == message_len, "Read error in openflow message body."
				
				message = bytes(message)
				if self.io_logger:
					self._log_io("recv", message)
				gevent.spawn(self.handle_message, message)
			except:
				self.logger.error("Openflow message read error.", exc_info=True)
				self.close()
				break
	
	def echo_reply(self, message):
		# Convenient method for ofp echo_reply. Subclass may use this.
		#
		# Both controller and switch will send echo reply
		(v,t,l,x) = parse_ofp_header(message)
		self.send(struct.pack("!BBHI", v, 3, l+8, x)+message)
	
	def handle_message(self, message):
		warnings.warn("subclass must override this method")
	
	def _send_loop(self): # runs in another thread
		while not self.closed:
			try:
				message = self.sendq.get()
				if self.io_logger:
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
		(v,t,l,x) = parse_ofp_header(message)
		(buffer_id,total_len,in_port,reason,pad) = struct.unpack_from("!IHHBB", message, offset=8)
		idx = ("buffer_id", "total_len", "in_port", "reason", "pad")
		
		msg = struct.pack("!IHH", buffer_id, 0xffff, 0) # default action "do nothing about that buffer"
		self.send(struct.pack("!BBHI", 0x01, 13, 8+len(msg), x)+msg)
	
	def handle_message(self, message):
		# default handle
		(v,oftype,l,x) = parse_ofp_header(message)
		
		if oftype == 2 and self.echo_reply: # OFPT_ECHO_REQUEST is 2 in all versions of openflow (v1.0 to v1.3)
			self.echo_reply(message)
		elif oftype == 10 and self.packet_in:
			self.packet_in(message)
		else:
			self.logger.warn("unhandled %s" % self._ofp_common_fields(), exc_info=True)

class Switch(Connection):
	def handle_message(self, message):
		reqseq = parse_ofp_header(message)
		if reqseq[1] == 2 and hasattr(self, "echo_reply") and self.echo_reply: # OFPT_ECHO_REQUEST is 2 in all versions of openflow (v1.0 to v1.3)
			self.echo_reply(message)
		elif reqseq[1] == 18 and hasattr(self, "barrier_reply") and self.barrier_reply:
			self.send_header_only(19, xid=x) # barrier_reply
		else:
			self.logger.warn("unhandled %s" % self._ofp_common_fields(), exc_info=True)

class ProxySwitch(Switch):
	def __init__(self, *args, **kwargs):
		super(ProxySwitch, self).__init__(*args, **kwargs)
		assert self.bus.proxy_up, "ProxySwitch will use bus#proxy_up"
	
	def handle_message(self, message):
		'''
		handles a message coming from downstream.
		send will send a message to downstream.
		'''
		(v,oftype,l,x) = parse_ofp_header(message)
		if oftype==0: # ignore hello, because upstream proxy already connected.
			pass
		else:
			self.bus.proxy_up(self, message)

class OvsController(Controller):
	ofctl_logger = None
	ofctl_proxy = None
	ofctl_lock = None
	def __init__(self, *args, **kwargs):
		super(OvsController, self).__init__(*args, **kwargs)
		self.socket_dir = kwargs.get("socket_dir")
		if kwargs.get("ofctl_logger_name"):
			self.ofctl_logger = logging.getLogger(kwargs.get("ofctl_logger_name"))
		self.ofctl_lock = RLock()
	
	def handle_message(self, message):
		(version, oftype, length, xid) = parse_ofp_header(message)
		
		if self.ofctl_proxy:
			self.ofctl_proxy.proxy_down(message)
			return
		
		if oftype == 2: # OFPT_ECHO_REQUEST is 2 in all versions of openflow (v1.0 to v1.3)
			self.echo_reply(message)
		elif oftype == 10:
			self.packet_in(message)
		elif oftype == 0:
			self.send_header_only(5)  # features_request
		elif oftype == 6: # features_reply
			(self.datapath, n_buffers, n_tables, a1,a2,a3, capabilities, actions) = struct.unpack_from("!QIBBBBII", message, offset=8)
			result = self.ofctl("dump-flows")
			result = self.ofctl("dump-tables")
	
	def ofctl(self, action, *args, **options):
		assert self.datapath is not None, "Not ready for communication."
		pstdout = None
		
		s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
		socket_fname = "dp_%x_internal_%d.sock" % (self.datapath, 1000*random.random())
		if self.socket_dir:
			socket_fname = os.path.join(self.socket_dir, socket_fname)
		s.bind(socket_fname)
		s.listen(1)
		with self.ofctl_lock:
			self.ofctl_proxy = BarrieredBus(ProxySwitch, upstream_send=self._send_by_ofctl)
			server = StreamServer(s, handle=self.ofctl_proxy)
			server.start()
			
			cmd = ["ovs-ofctl",]
			cmd.extend(self._make_ofctl_options(options))
			cmd.append(action)
			cmd.append(socket_fname)
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
			self.ofctl_proxy = None
		os.remove(socket_fname)
		
		return pstdout
	
	def _send_by_ofctl(self, message):
		# subclass may replace this
		self.send(message)
	
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



if __name__ == "__main__":
	logging.basicConfig(level=0)
	server = StreamServer(("0.0.0.0",6633), handle=Bus(OvsController, io_logger_name="root", ofctl_logger_name="root"))
	server.serve_forever()
