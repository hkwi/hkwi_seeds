import logging
import json
import os
from flask import Flask, request, render_template
from gevent import pywsgi, spawn
from gevent.event import Event
from gevent.greenlet import Greenlet
from gevent.server import StreamServer
from geventwebsocket.handler import WebSocketHandler
from geventopenflow.server import HeartbeatController, Handle
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

class WsController(HeartbeatController):
	def __init__(self, *args, **kwargs):
		super(WsController, self).__init__(*args, **kwargs)
		self.ws_datapath = kwargs.get("ws_datapath")
		self.ws_global = kwargs.get("ws_global")
		self.ofcons = kwargs.get("ofcons")
	
	def send_hello(self):
		super(WsController, self).send_hello()
		self.ofcons.add(self)
		spawn(self.send_hello_ws)
	
	def send_hello_ws(self):
		msg = json.dumps({"datapath":"%016x" % self.datapath(), "action":"connect"})
		for ws in self.ws_global:
			spawn(ws.send, msg)
	
	def close(self):
		super(WsController, self).close()
		if self in self.ofcons:
			self.ofcons.remove(self)
			spawn(self.close_ws)
	
	def close_ws(self):
		msg = json.dumps({"datapath":"%016x" % self.datapath(), "action":"disconnect"})
		for ws in self.ws_global:
			spawn(ws.send, msg)
	
	def _log_io(self, direction, message):
		self.io_logger.info("%s(%x)%s %s" % (self.__class__.__name__, id(self), direction, Message(message)))
	
	def handle_message(self, message):
		datapath = "%016x" % self.datapath()
		if datapath in self.ws_datapath:
			for ws in self.ws_datapath[datapath]:
				ws.send("%s" % Message(message))

app = Flask(__name__)

ofcons = set()
ws_global = set()
ws_datapath = {}

@app.route("/")
def top():
	env = request.environ
	return render_template("index.html",
		server=env["HTTP_HOST"])

@app.route("/switch")
def switch():
	ws = request.environ["wsgi.websocket"]
	ws_global.add(ws)
	if ofcons:
		for con in ofcons:
			ws.send(json.dumps({"datapath":"%016x" % con.datapath(), "action":"connect"}))
	while True:
		if not ws.receive():
			break
	ws_global.remove(ws)
	return ""

@app.route("/switch/<datapath>")
def switch_event(datapath):
	ws = request.environ["wsgi.websocket"]
	datapath = datapath.decode("UTF-8")
	if datapath not in ws_datapath:
		ws_datapath[datapath] = set()
	ws_datapath[datapath].add(ws)
	while True:
		if not ws.receive():
			break
	ws_datapath[datapath].remove(ws)
	return ""

if __name__=="__main__":
	logging.basicConfig(level=0)
	openflow = Handle(WsController, io_logger_name="root", io_log_suppress_echo=True, socket_dir=".", ws_datapath=ws_datapath, ws_global=ws_global, ofcons=ofcons)
	with openflow:
		ofserver = StreamServer(("0.0.0.0",6633), handle=openflow)
		wsserver = pywsgi.WSGIServer(("0.0.0.0", 8080), app, handler_class=WebSocketHandler)
		serve_forever(ofserver, wsserver)
