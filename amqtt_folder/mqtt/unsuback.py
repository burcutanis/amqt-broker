# Copyright (c) 2015 Nicolas JOUANIN
#
# See the file license.txt for copying permission.
from amqtt_folder.mqtt.packet import (
    MQTTPacket,
    MQTTFixedHeader,
    UNSUBACK,
    PacketIdVariableHeader,
    MQTTPayload,
    MQTTVariableHeader,
)
from amqtt_folder.errors import AMQTTException
from cryptography.hazmat.primitives import hashes, hmac
from django.utils.encoding import force_bytes, force_str
import logging


class UnsubackPayload(MQTTPayload):

    __slots__ = ("mac")

    def __init__(self, mac_received=None):
        super().__init__()
        self.mac = mac_received
        self.logger = logging.getLogger(__name__)

    def __repr__(self):
        return type(self).__name__ + "(mac={})".format(repr(self.mac))

    def to_bytes(
        self, fixed_header: MQTTFixedHeader, variable_header: MQTTVariableHeader
    ):
        self.logger.info("###UBSUBACK WILL BE SENT###")
        
        self.logger.info("Signature of unsuback packet : %s", self.mac)
        self.logger.info("###UBSUBACK WAS SENT###")

        out = b'::::' + self.mac
        return out

class UnsubackPacket(MQTTPacket):
    VARIABLE_HEADER = PacketIdVariableHeader
    PAYLOAD = None

    def __init__(
        self,
        fixed: MQTTFixedHeader = None,
        variable_header: PacketIdVariableHeader = None,
        payload=None,
    ):
        if fixed is None:
            header = MQTTFixedHeader(UNSUBACK, 0x00)
        else:
            if fixed.packet_type is not UNSUBACK:
                raise AMQTTException(
                    "Invalid fixed packet type %s for UnsubackPacket init"
                    % fixed.packet_type
                )
            header = fixed

        super().__init__(header)
        self.variable_header = variable_header
        self.payload = payload

    @classmethod
    def build(cls, packet_id, client_unique_session_key = None):

        mac_content = None

        if client_unique_session_key != None:
            str_packet_id = str(packet_id)

            bytes_packet_id = bytes(str_packet_id, 'utf-8')


            #DISTORTION ON PURPOSE
            #bytes_packet_id = bytes("dummyText", 'utf-8')


            h = hmac.HMAC(client_unique_session_key, hashes.SHA256())
            h.update(bytes_packet_id)
            mac_content = h.finalize()



        variable_header = PacketIdVariableHeader(packet_id)
        mac = UnsubackPayload(mac_received=mac_content)
        return cls(variable_header=variable_header, payload=mac)
