import logging
from geventopenflow.server import HeartbeatController, Handle, hms_hex_xid
from geventopenflow import v4util as util
from gevent.server import StreamServer
import binascii

class V4Controller(HeartbeatController):
	def _log_io(self, direction, message):
		self.io_logger.info("%s(%x)%s %s" % (self.__class__.__name__, id(self), direction, util.Message(message)))
	
	def send_hello(self):
		m = util.Message(
			type="HELLO",
			version=4,
			xid = hms_hex_xid(),
			elements=[util.HelloElement(type="VERSIONBITMAP", bitmaps=[4,]),])
		self.send(m.serialize())
	
	def handle_message(self, message):
		msg = util.Message(message)
		if msg.type == "HELLO":
			try:
				if 4 in msg.elements[0].bitmaps:
					self.negotiated_version = 4
			except:
				raise # disconnect
		elif msg.type == "PACKET_IN":
			print msg
			m = util.Message(
				type="PACKET_OUT",
				version=4,
				xid = msg.xid,
				buffer_id=msg.buffer_id,
				in_port=0xffffffff,
				actions=[])
			self.send(m.serialize())

if __name__=="__main__":
	logging.basicConfig(level=0)
	openflow = Handle(V4Controller, io_logger_name="root", io_log_suppress_echo=True, socket_dir=".")
	with openflow:
		server = StreamServer(("0.0.0.0",6633), handle=openflow)
		server.serve_forever()
