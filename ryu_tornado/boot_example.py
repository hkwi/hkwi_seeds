from ryu.base.app_manager import AppManager
from tornado.ioloop import IOLoop
from tornado.web import Application
from tornado.websocket import WebSocketHandler
from tornado.netutil import bind_sockets
from tornado.process import fork_processes
from ryu_tornado import EventOpenflowController

class Echo(WebSocketHandler):
    def open(self):
        print "hello"
    def on_message(self, message):
        print message
    def close(self):
        print "bye"

Application([("/", Echo),],).listen(8888)

apps = AppManager()
apps.load_apps(["ryu.controller.ofp_handler",])
contexts = apps.create_contexts()
apps.instantiate_apps(**contexts)

EventOpenflowController().listen(6633)

IOLoop.instance().start()
