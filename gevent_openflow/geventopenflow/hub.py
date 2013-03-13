import binascii
import logging
import gevent
from gevent.queue import Queue
from gevent.server import StreamServer
from geventopenflow.server import Handle, InverseController, parse_ofp_header

class Connect(object):
	def __init__(self, connection):
		self.connection = connection
	
	def __repr__(self):
		return "Connect(%s)" % self.connection

class Disconnect(object):
	def __init__(self, connection):
		self.connection = connection
	
	def __repr__(self):
		return "Disconnect(%s)" % self.connection

class OpenflowMessage(object):
	def __init__(self, connection, message):
		self.connection = connection
		self.message = message
	
	def __repr__(self):
		return "OpenflowMessage(%s, %s)" % (self.connection, binascii.b2a_hex(self.message))

class HubHandle(Handle):
	def __init__(self, connection_class, **kwargs):
		super(HubHandle, self).__init__(connection_class, **kwargs)
		self.hub_queue = kwargs.get("hub")
	
	def __call__(self, socket, address):
		con = self.connection_class(socket, address, **self.kwargs)
		self.connections.add(con)
		if self.hub_queue:
			self.hub_queue.put(Connect(con))
		con.handle()
		if self.hub_queue:
			self.hub_queue.put(Disconnect(con))
		self.connections.remove(con)
	
	def __enter__(self):
		return self
	
	def __exit__(self, exc_type, exc_value, traceback):
		for con in self.connections:
			con.close()

class HubController(InverseController):
	def __init__(self, *args, **kwargs):
		super(HubController, self).__init__(*args, **kwargs)
		self.hub_queue = kwargs.get("hub")
	
	def _handle_message(self, message):
		super(HubController, self)._handle_message(message)
		if self.hub_queue:
			self.hub_queue.put(OpenflowMessage(self, message))
	
	def handle_message(self, message):
		(version, oftype, length, xid) = parse_ofp_header(message)
		if oftype in (0, 2, 6): # we know those will be used.
			pass
		elif oftype == 10 and self.packet_in: # OFPT_PACKET_IN=10
			self.packet_in(message)
		else:
			self.logger.warn("unhandled %s" % self._ofp_common_fields(message), exc_info=True)

def pull_queue(queue):
	while True:
		print queue.get()

if __name__=="__main__":
	logging.basicConfig(level=0)
	queue = Queue()
	q = gevent.spawn(pull_queue, queue)
	with HubHandle(HubController, hub=queue, io_logger_name="root", io_log_suppress_echo=True, socket_dir=".") as handle:
		server = StreamServer(("0.0.0.0",6633), handle=handle)
		server.serve_forever()
