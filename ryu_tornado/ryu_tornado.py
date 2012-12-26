import logging
import random
from tornado import stack_context
from tornado.netutil import TCPServer
from ryu.ofproto import ofproto_common, ofproto_parser, nx_match
from ryu.ofproto import ofproto_v1_0, ofproto_v1_0_parser
from ryu.ofproto import ofproto_v1_2, ofproto_v1_2_parser
from ryu.ofproto import ofproto_v1_3, ofproto_v1_3_parser
from ryu.controller import dispatcher, handler, ofp_event

class DatapathBase(object):
    supported_ofp_version = {
        ofproto_v1_0.OFP_VERSION: (ofproto_v1_0, ofproto_v1_0_parser),
        ofproto_v1_2.OFP_VERSION: (ofproto_v1_2, ofproto_v1_2_parser),
        ofproto_v1_3.OFP_VERSION: (ofproto_v1_3, ofproto_v1_3_parser)
    }

    def __init__(self, stream, address):
        self.stream = stream
        self.address = address
        self.set_version(max(self.supported_ofp_version))
        self.xid = random.randint(0, self.ofproto.MAX_XID)

    def close(self):
        self.stream.close()

    def send(self, buf):
        if not self.stream.closed():
            self.stream.write(str(buf))

    def set_version(self, version):
        '''negotiate openflow protocol version'''
        self.ofproto, self.ofproto_parser = self.supported_ofp_version[version]

    def set_xid(self, msg):
        '''fetch a new xid and set bind it to msg'''
        self.xid = (self.xid + 1) & self.ofproto.MAX_XID
        msg.set_xid(self.xid)
        return self.xid

    def send_msg(self, msg):
        assert isinstance(msg, self.ofproto_parser.MsgBase)
        xid = msg.xid
        if xid is None:
            xid = self.set_xid(msg)
        msg.serialize()
        logging.getLogger("openflow").debug("SEND %s %s" % (self.address, msg))
        self.send(msg.buf)
        return xid

    def start(self):
        self.send_msg(self.ofproto_parser.OFPHello(self))
        if not self.stream.closed():
            self.stream.read_bytes(ofproto_common.OFP_HEADER_SIZE, stack_context.wrap(self._on_header))

    def _on_header(self, data):
        assert len(data) == ofproto_common.OFP_HEADER_SIZE
        self._msg_header = data
        (version, msg_type, msg_len, xid) = ofproto_parser.header(data)
        assert msg_len >= ofproto_common.OFP_HEADER_SIZE
        if not self.stream.closed():
            self.stream.read_bytes(msg_len-ofproto_common.OFP_HEADER_SIZE, stack_context.wrap(self._on_message))

    def _on_message(self, data):
        (version, msg_type, msg_len, xid) = ofproto_parser.header(self._msg_header)
        assert len(data) == msg_len - ofproto_common.OFP_HEADER_SIZE
        msg = ofproto_parser.msg(self, version, msg_type, msg_len, xid, self._msg_header+data)
        logging.getLogger("openflow").debug("RECV %s %s" % (self.address, msg))
        self.dispatch(msg)
        if not self.stream.closed():
            self.stream.read_bytes(ofproto_common.OFP_HEADER_SIZE, stack_context.wrap(self._on_header))

    def dispatch(self, msg):
        raise Exception("Subclass must implement this")

class Datapath(DatapathBase):
    def __init__(self, stream, address):
        super(Datapath, self).__init__(stream, address)
        self.flow_format = ofproto_v1_0.NXFF_OPENFLOW10

    def send_packet_out(self, buffer_id=0xffffffff, in_port=None,
                        actions=None, data=None):
        if in_port is None:
            in_port = self.ofproto.OFPP_NONE
        packet_out = self.ofproto_parser.OFPPacketOut(
            self, buffer_id, in_port, actions, data)
        self.send_msg(packet_out)

    def send_flow_mod(self, rule, cookie, command, idle_timeout, hard_timeout,
                      priority=None, buffer_id=0xffffffff,
                      out_port=None, flags=0, actions=None):
        if priority is None:
            priority = self.ofproto.OFP_DEFAULT_PRIORITY
        if out_port is None:
            out_port = self.ofproto.OFPP_NONE
        flow_format = rule.flow_format()
        assert (flow_format == ofproto_v1_0.NXFF_OPENFLOW10 or
                flow_format == ofproto_v1_0.NXFF_NXM)
        if self.flow_format < flow_format:
            self.send_nxt_set_flow_format(flow_format)
        if flow_format == ofproto_v1_0.NXFF_OPENFLOW10:
            match_tuple = rule.match_tuple()
            match = self.ofproto_parser.OFPMatch(*match_tuple)
            flow_mod = self.ofproto_parser.OFPFlowMod(
                self, match, cookie, command, idle_timeout, hard_timeout,
                priority, buffer_id, out_port, flags, actions)
        else:
            flow_mod = self.ofproto_parser.NXTFlowMod(
                self, cookie, command, idle_timeout, hard_timeout,
                priority, buffer_id, out_port, flags, rule, actions)
        self.send_msg(flow_mod)

    def send_flow_del(self, rule, cookie, out_port=None):
        self.send_flow_mod(rule=rule, cookie=cookie,
                           command=self.ofproto.OFPFC_DELETE,
                           idle_timeout=0, hard_timeout=0, priority=0,
                           out_port=out_port)

    def send_delete_all_flows(self):
        rule = nx_match.ClsRule()
        self.send_flow_mod(
            rule=rule, cookie=0, command=self.ofproto.OFPFC_DELETE,
            idle_timeout=0, hard_timeout=0, priority=0, buffer_id=0,
            out_port=self.ofproto.OFPP_NONE, flags=0, actions=None)

    def send_barrier(self):
        barrier_request = self.ofproto_parser.OFPBarrierRequest(self)
        self.send_msg(barrier_request)

    def send_nxt_set_flow_format(self, flow_format):
        assert (flow_format == ofproto_v1_0.NXFF_OPENFLOW10 or
                flow_format == ofproto_v1_0.NXFF_NXM)
        if self.flow_format == flow_format:
            # Nothing to do
            return
        self.flow_format = flow_format
        set_format = self.ofproto_parser.NXTSetFlowFormat(self, flow_format)
        # FIXME: If NXT_SET_FLOW_FORMAT or NXFF_NXM is not supported by
        # the switch then an error message will be received. It may be
        # handled by setting self.flow_format to
        # ofproto_v1_0.NXFF_OPENFLOW10 but currently isn't.
        self.send_msg(set_format)
        self.send_barrier()

class EventDatapath(Datapath):
    def __init__(self, stream, address):
        super(EventDatapath, self).__init__(stream, address)
        self.ev_q = dispatcher.EventQueue(handler.QUEUE_NAME_OFP_MSG,
                                handler.HANDSHAKE_DISPATCHER, self)

    def dispatch(self, msg):
        self.ev_q.queue(ofp_event.ofp_msg_to_ev(msg))

    def close(self):
        super(EventDatapath, self).close()
        self.ev_q.set_dispatcher(handler.DEAD_DISPATCHER)
        self.ev_q.close()

class OpenflowController(TCPServer):
    def handle_stream(self, stream, address):
        EventDatapath(stream, address).start()
