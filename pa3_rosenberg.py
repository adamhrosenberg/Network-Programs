# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4

current_out_flag = 0  # 0 is 5, 1 is 6.


class pa3_rosenberg(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # we are starting on host server 5 w/ ip of 10.0.0.5, mac addy of :05, port # 5
    # as stated in discussions we are only testing for 10.0.0.10, this will not work
    # if that is not true
    current_server_ip = '10.0.0.5'
    current_server_mac = '00:00:00:00:00:05'
    current_server_port = 5
    current_server_virtual_ip = '10.0.0.10'
    # all f's for a mac address is inicative of it being the first request looking
    # for who has something
    initial_mac = 'ff:ff:ff:ff:ff:ff'

    def __init__(self, *args, **kwargs):
        super(pa3_rosenberg, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):

        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        # get the ethernet type packets
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        # get the datapath
        # get the arp packet
        arp_pkt = pkt.get_protocols(arp.arp)
        # get the ipv4 packet
        ip_pkt = pkt.get_protocols(ipv4.ipv4)
        # get dpid
        dpid = datapath.id

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        if arp_pkt:
            arp_pkt = arp_pkt[0]
            if (eth.dst == self.initial_mac and arp_pkt.dst_ip == self.current_server_virtual_ip):
                # match actions and match for the intial and second flows. need 2 flows since
                # its two arp packets from the switch
                first_match = parser.OFPMatch(in_port=in_port,
                                               eth_type=0x0800,
                                               ipv4_dst=self.current_server_virtual_ip)
                first_action = [parser.OFPActionSetField(ipv4_dst=self.current_server_ip),
                                  parser.OFPActionOutput(self.current_server_port)]

                second_match = parser.OFPMatch(in_port=self.current_server_port,
                                               eth_type=0x0800,
                                               ipv4_src=self.current_server_ip,
                                               ipv4_dst=arp_pkt.src_ip)
                second_action = [parser.OFPActionSetField(ipv4_src=self.current_server_virtual_ip),
                                  parser.OFPActionOutput(in_port)]

                # add flows
                self.add_flow(datapath, 1, first_match, first_action)
                self.add_flow(datapath, 1, second_match, second_action)

                new_arp = packet.Packet()
                # add the ethernet protocol
                new_arp.add_protocol(ethernet.ethernet(dst=dst, src=self.current_server_mac, ethertype=eth.ethertype))
                # add the arp protocol
                new_arp.add_protocol(arp.arp(hwtype=1, proto=0x800,
                                             hlen=6, plen=4, opcode=2,
                                             src_mac=self.current_server_mac, src_ip=self.current_server_virtual_ip,
                                             dst_mac=src, dst_ip=arp_pkt.src_ip))
                # encode the packet
                new_arp.serialize()

                response = [parser.OFPActionOutput(ofproto.OFPP_IN_PORT)]
                outgoing = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=in_port,
                                               actions=response, data=new_arp.data)

                datapath.send_msg(outgoing)
                # CHANGE SERVERS

                if self.current_server_port == 6:
                    # change to to other server
                    self.current_server_mac = '00:00:00:00:00:05'
                    self.current_server_port = 5
                    self.current_server_ip = '10.0.0.5'
                elif self.current_server_port == 5:
                    # change to other server
                    self.current_server_mac = '00:00:00:00:00:06'
                    self.current_server_port = 6
                    self.current_server_ip = '10.0.0.6'
            else:
                self.mac_to_port.setdefault(dpid, {})

                self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

                # learn a mac address to avoid FLOOD next time.
                self.mac_to_port[dpid][src] = in_port

                if dst in self.mac_to_port[dpid]:
                    out_port = self.mac_to_port[dpid][dst]
                else:
                    out_port = ofproto.OFPP_FLOOD

                actions = [parser.OFPActionOutput(out_port)]

                # install a flow to avoid packet_in next time
                if out_port != ofproto.OFPP_FLOOD:
                    match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
                    # verify if we have a valid buffer_id, if yes avoid to send both
                    # flow_mod & packet_out
                    if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                        self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                        return
                    else:
                        self.add_flow(datapath, 1, match, actions)
                data = None
                if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                    data = msg.data

                out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                          in_port=in_port, actions=actions, data=data)
                datapath.send_msg(out)

