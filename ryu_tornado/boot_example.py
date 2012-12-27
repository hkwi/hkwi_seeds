import os.path
from ryu.base.app_manager import AppManager
from tornado.ioloop import IOLoop
from tornado.web import Application
from tornado.websocket import WebSocketHandler
from tornado.netutil import bind_sockets
from tornado.process import fork_processes
from ryu_tornado import OpenflowController

import logging
logging.basicConfig(level=logging.DEBUG)

class Echo(WebSocketHandler):
    def initialize(self, clients=[]):
        super(Echo, self).initialize()
        self.clients = clients
    def open(self):
        self.clients.append(self)
    def on_message(self, message):
        for client in self.clients:
            client.write_message("hello")
    def close(self):
        print "bye"

ws_clients = []
Application([
    ("/echo", Echo, {"clients":ws_clients}),
    ], 
    static_path=os.path.join(os.path.dirname(__file__), "html")).listen(8888)

apps = AppManager()
apps.load_apps(["ryu.controller.ofp_handler", "ryu.app.simple_switch", "ofc2ws"])
contexts = apps.create_contexts()
contexts["ws_clients"] = ws_clients
apps.instantiate_apps(**contexts)

OpenflowController().listen(6633)

IOLoop.instance().start()
