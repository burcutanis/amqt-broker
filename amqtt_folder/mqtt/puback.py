# Copyright (c) 2015 Nicolas JOUANIN
#
# See the file license.txt for copying permission.
from amqtt_folder.mqtt.packet import (
    MQTTPacket,
    MQTTFixedHeader,
    PUBACK,
    PacketIdVariableHeader,
    MQTTPayload,
    MQTTVariableHeader,
)
from amqtt_folder.errors import AMQTTException
from amqtt_folder.errors import AMQTTException, NoDataException
from amqtt_folder.adapters import ReaderAdapter
from amqtt_folder.codecs import bytes_to_int, int_to_bytes, read_or_raise
from cryptography.hazmat.primitives import hashes, hmac
import logging



class PubackPayload(MQTTPayload):

    __slots__ = ("mac")

    def __init__(self, mac_received):
        super().__init__()
        self.mac = mac_received
        self.logger = logging.getLogger(__name__)
        
    def to_bytes(
        self, fixed_header: MQTTFixedHeader, variable_header: MQTTVariableHeader
    ):
        out = b""

        self.logger.info("Signature of puback packet: %s", self.mac)
        self.logger.info("###PUBACK WAS SENT###")

        if self.mac != None:
            out += b"::::" + self.mac 

        return out

  
class PubackPacket(MQTTPacket):
    VARIABLE_HEADER = PacketIdVariableHeader
    PAYLOAD = PubackPayload

    @property
    def packet_id(self):
        return self.variable_header.packet_id

    @packet_id.setter
    def packet_id(self, val: int):
        self.variable_header.packet_id = val

    def __init__(
        self,
        fixed: MQTTFixedHeader = None,
        variable_header: PacketIdVariableHeader = None,
        payload: PubackPayload  = None,
    ):
        if fixed is None:
            header = MQTTFixedHeader(PUBACK, 0x00)
        else:
            if fixed.packet_type is not PUBACK:
                raise AMQTTException(
                    "Invalid fixed packet type %s for PubackPacket init"
                    % fixed.packet_type
                )
            header = fixed
        super().__init__(header)
        self.variable_header = variable_header
        self.payload = payload

    @classmethod
    def build(cls, packet_id: int, client_unique_session_key = None):
        v_header = PacketIdVariableHeader(packet_id)
        if client_unique_session_key != None:
            byte_packet_id = bytes(str(packet_id), 'utf-8')
            to_be_signed =  byte_packet_id 
            #print("*******************puback******************************", to_be_signed)


            h = hmac.HMAC(client_unique_session_key, hashes.SHA256())
            h.update(to_be_signed)
            mac = h.finalize()
            
            #print("************************puback*************************", mac)
            payload_v = PubackPayload(mac_received=mac)
            #print("************************puback*************************", payload_v)
            packet = PubackPacket(variable_header=v_header, payload=payload_v)
            #packet = PubackPacket(variable_header=v_header)
        else: 
            packet = PubackPacket(variable_header=v_header)

        
        return packet
