import logging
import json
import os
from flask import Flask, request, render_template
from gevent import pywsgi
from gevent.event import Event
from gevent.greenlet import Greenlet
from gevent.server import StreamServer
from geventwebsocket.handler import WebSocketHandler
from geventopenflow.server import InverseController, Handle
from geventopenflow.util import Message

def serve_forever(*servers, **opts):
	for server in servers:
		server.start()
	try:
		Event().wait()
	finally:
		stop_timeout=opts.get("stop_timeout")
		for th in [Greenlet.spawn(x.stop, timeout=stop_timeout) for x in servers]:
			th.join()

class WsController(InverseController):
	def __init__(self, *args, **kwargs):
		super(WsController, self).__init__(*args, **kwargs)
		self.ws_datapath = kwargs.get("ws_datapath")
	
	def handle_message(self, message):
		datapath = "%016x" % self.datapath()
		if datapath in self.ws_datapath:
			for ws in self.ws_datapath[datapath]:
				ws.send("%s" % Message(message))

app = Flask(__name__)

openflow = None
ws_datapath = {}

@app.route("/switch")
def switches():
	env = request.environ
	return render_template("switches.html",
		datapaths=["%016x" % con.datapath() for con in openflow.connections],
		server=env["HTTP_HOST"])

@app.route("/switch/<datapath>")
def switch_event(datapath):
	ws = request.environ["wsgi.websocket"]
	datapath = datapath.decode("UTF-8")
	if datapath not in ws_datapath:
		ws_datapath[datapath] = set()
	ws_datapath[datapath].add(ws)
	while True:
		ws.receive()
	ws_datapath[datapath].remove(ws)

if __name__=="__main__":
	logging.basicConfig(level=0)
	openflow = Handle(WsController, io_logger_name="root", io_log_suppress_echo=True, socket_dir=".", ws_datapath=ws_datapath)
	with openflow:
		ofserver = StreamServer(("0.0.0.0",6633), handle=openflow)
		wsserver = pywsgi.WSGIServer(("0.0.0.0", 8080), app, handler_class=WebSocketHandler)
		serve_forever(ofserver, wsserver)
