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

class DatapathBase(object):
	def __init__(self, logger_name=None):
		self.logger = logging.getLogger(logger_name)
	
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
		self.send(struct.pack("!BBHI", 0x01, 0, 8, 9))
	
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
				
				self.handle_message(bytes(message))
			except:
				self.logger.error("Openflow message read error.", exc_info=True)
				self._close()
				break
	
	def _send_loop(self): # runs in another thread
		while not self.closed:
			try:
				message = self.sendq.get()
				if hasattr(self, "log_send"):
					self.log_send(message)
				self.socket.sendall(message)
			except:
				self.logger.error("Openflow message write error.", exc_info=True)
				self._close()
				break

class Datapath(DatapathBase):
	def echo_reply(self, message):
		# Default ofp echo_reply. Subclass may replace this.
		(v,t,l,x) = parse_ofp_header(message)
		self.send(struct.pack("!BBHI", 0x01, 3, l+8, x)+message)
	
	def packet_in(self, message):
		(v,t,l,x) = parse_ofp_header(message)
		(buffer_id,total_len,in_port,reason,pad) = struct.unpack("!IHHBB", message[8:18])
		idx = ("buffer_id", "total_len", "in_port", "reason", "pad")
		
		msg = struct.pack("!IHH", buffer_id, 0xffff, 0)
		self.send(struct.pack("!BBHI", 0x01, 13, 8+len(msg), x)+msg)
	
	def handle_message(self, message):
		reqseq = parse_ofp_header(message)
		reqseq.append(message[8:])
		zdata = zip(("version", "type", "length", "xid", "payload"), reqseq)
		self.logger.info("recv "+repr(zdata))
		
		if reqseq[1] == 2 and self.echo_reply: # OFPT_ECHO_REQUEST is 2 in all versions of openflow (v1.0 to v1.3)
			self.echo_reply(message)
		elif reqseq[1] == 10 and self.packet_in:
			self.packet_in(message)
	
	def log_send(self, message):
		reqseq = parse_ofp_header(message)
		reqseq.append(message[8:])
		zdata = zip(("version", "type", "length", "xid", "payload"), reqseq)
		self.logger.info("send "+repr(zdata))

if __name__ == "__main__":
	logging.basicConfig(level=0)
	server = StreamServer(("0.0.0.0",6633), handle=Datapath())
	server.serve_forever()
