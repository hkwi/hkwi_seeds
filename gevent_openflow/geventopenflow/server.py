import array
import binascii
import logging
import struct
import sys
import traceback
import warnings
import gevent
from gevent.server import StreamServer
from gevent.queue import Queue

def parse_ofp_header(message):
	return list(struct.unpack_from("!BBHI", message))

class Bus(object):
	io_logger = None
	def __init__(self, logger_name=None, io_logger_name=None):
		self.logger = logging.getLogger(logger_name)
		if io_logger_name:
			self.io_logger = logging.getLogger(io_logger_name)
	
	def __call__(self, socket, address):
		self.socket = socket
		self.address = address
		
		self.sendq = Queue()
		g = gevent.spawn(self._send_loop)
		self.send_hello()
		self._recv_loop()
	
	def send(self, message):
		self.sendq.put(message)
	
	@property
	def closed(self):
		return self.socket is None
	
	def _close(self):
		if not self.closed:
			try:
				self.socket.close()
			finally:
				self.socket = None
	
	def send_hello(self):
		# Default ofp hello packet. Subclass may replace this.
		# version: 0x01
		# type: OFP_HELLO 0
		# length: 8
		# xid: 9
		#
		# Both controller and switch will send send hello
		self.send(struct.pack("!BBHI", 0x01, 0, 8, 9))
	
	def echo_reply(self, message):
		# Convenient method for ofp echo_reply. Subclass may use this.
		#
		# Both controller and switch will send echo reply
		(v,t,l,x) = parse_ofp_header(message)
		self.send(struct.pack("!BBHI", v, 3, l+8, x)+message)
	
	def handle_message(self, message):
		warnings.warn("subclass must override this method")
	
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
				self.handle_message(message)
			except:
				self.logger.error("Openflow message read error.", exc_info=True)
				self._close()
				break
	
	def _send_loop(self): # runs in another thread
		while not self.closed:
			try:
				message = self.sendq.get()
				if self.io_logger:
					self._log_io("send", message)
				self.socket.sendall(message)
			except:
				self.logger.error("Openflow message write error.", exc_info=True)
				self._close()
				break
	
	def _log_io(self, direction, message):
		reqseq = parse_ofp_header(message)
		reqseq.append(message[8:])
		zdata = zip(("version", "type", "length", "xid", "payload"), reqseq)
		self.io_logger.info("%s %s" % (direction,zdata))

class Controller(Bus):
	def packet_in(self, message):
		(v,t,l,x) = parse_ofp_header(message)
		(buffer_id,total_len,in_port,reason,pad) = struct.unpack("!IHHBB", message[8:18])
		idx = ("buffer_id", "total_len", "in_port", "reason", "pad")
		
		msg = struct.pack("!IHH", buffer_id, 0xffff, 0)
		self.send(struct.pack("!BBHI", 0x01, 13, 8+len(msg), x)+msg)
	
	def handle_message(self, message):
		reqseq = parse_ofp_header(message)
		if reqseq[1] == 2 and self.echo_reply: # OFPT_ECHO_REQUEST is 2 in all versions of openflow (v1.0 to v1.3)
			self.echo_reply(message)
		elif reqseq[1] == 10 and self.packet_in:
			self.packet_in(message)

class Switch(Bus):
	def barrier_reply(self, message):
		(v,t,l,x) = parse_ofp_header(message)
		self.send(struct.pack("!BBHI", v, 19, 8, x))
	
	def handle_message(self, message):
		reqseq = parse_ofp_header(message)
		if reqseq[1] == 2 and hasattr(self, "echo_reply") and self.echo_reply: # OFPT_ECHO_REQUEST is 2 in all versions of openflow (v1.0 to v1.3)
			self.echo_reply(message)
		elif reqseq[1] == 18 and hasattr(self, "barrier_reply") and self.barrier_reply:
			self.barrier_reply(message)

if __name__ == "__main__":
	logging.basicConfig(level=0)
	server = StreamServer(("0.0.0.0",6633), handle=Controller(io_logger_name="root"))
	server.serve_forever()
