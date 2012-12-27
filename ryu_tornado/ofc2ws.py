# ryu AppManager limitation : Only one class can be loaded from single python module.
import logging
from ryu.base import app_manager
from ryu.controller import dispatcher
from ryu.controller.handler import set_ev_cls

class WsNotify(app_manager.RyuApp):
    def __init__(self, *args, **kwargs):
        super(WsNotify, self).__init__(*args, **kwargs)
        self.ws_clients = kwargs["ws_clients"]
        for ev_q in dispatcher.EventQueue.all_instances():
            if ev_q == dispatcher.QUEUE_EV_Q:
                continue
            self._register_dump_handler(ev_q, ev_q.dispatcher)

    @staticmethod
    def _need_dump(name, name_list):
        return len(name_list) == 0 or name in name_list

    def _register_dump_handler(self, ev_q, dispatcher):
        dispatcher.register_all_handler(self._dump_event)

    @set_ev_cls(dispatcher.EventQueueCreate, dispatcher.QUEUE_EV_DISPATCHER)
    def queue_create(self, ev):
        self._dump_event(ev)
        self._register_dump_handler(ev.ev_q, ev.dispatcher)

    @set_ev_cls(dispatcher.EventDispatcherChange,
                dispatcher.QUEUE_EV_DISPATCHER)
    def dispatcher_change(self, ev):
        self._dump_event(ev)
        self._register_dump_handler(ev.ev_q, ev.new_dispatcher)

    def _dump_event(self, ev):
        for client in self.ws_clients:
            client.write_message(str(ev))
        logging.info('%s: event %s', __name__, ev)
