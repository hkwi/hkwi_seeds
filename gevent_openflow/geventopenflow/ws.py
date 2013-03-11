from flask import Flask
from geventwebsocket.handler import WebSocketHandler
from geventopenflow.hub import HubHandle, HubController
from gevent.event import Queue

class HubService(object):
	def __init__(self):
		self.connections = set()
		self.listeners = set()
		self.hub = Queue()
	
	def __call__(self):
		gevent.spawn(self.pull)
	
	def pull(self):
		while True:
			ev = self.hub.get()
			if isinstance(ev, Connect):
				datapath = ev.connection.datapath(wait=False):
				if datapath:
					self.connections.add(ev.connection)
				else:
					gevent.spawn(self.datapath_delay, ev.connection)
			elif isinstance(ev, Disconnect):
				try:
					self.connections.remove(ev.connection)
				except:
					pass
			elif isinstance(ev, Message):
				ev.message
	
	def datapath_delay(self, connection):
		try:
			connection.datapath()
			self.connections.add(ev.connection)
		except:
			pass

# XXX: define a message format over websocket.

app = Flask(__name__)

hub = HubService()

@app.route("/switches")
def switches():
	global hub
	return json.dumps([sw.datapath for sw in hub.connections])

@app.route("/switch_events")
def switch_events():
	global hub
	# XXX: filter with query string

if __name__=="__main__":
	logging.basicConfig(level=0)
	hub()
	openflow = StreamServer(("0.0.0.0",6633), handle=Handle(EasyController, io_logger_name="root", io_log_suppress_echo=True, socket_dir=".", hub=hub.hub))
	ws = WsgiServer
