import binascii
import logging
import gevent
from gevent.queue import Queue
from gevent.server import StreamServer
from geventopenflow.server import Handle, InverseController

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
		if self.hub_queue:
			self.hub_queue.put(Connect(con))
		con.handle()
		if self.hub_queue:
			self.hub_queue.put(Disconnect(con))

class HubController(InverseController):
	def __init__(self, *args, **kwargs):
		super(HubController, self).__init__(*args, **kwargs)
		self.hub_queue = kwargs.get("hub")
	
	def _handle_message(self, message):
		super(HubController, self)._handle_message(message)
		if self.hub_queue:
			self.hub_queue.put(OpenflowMessage(self, message))

def pull_queue(queue):
	while True:
		print queue.get()

if __name__=="__main__":
	logging.basicConfig(level=0)
	queue = Queue()
	q = gevent.spawn(pull_queue, queue)
	server = StreamServer(("0.0.0.0",6633), handle=HubHandle(HubController, hub=queue))
	server.serve_forever()
	q.join()
