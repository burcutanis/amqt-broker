# Copyright (c) 2015 Nicolas JOUANIN
#
# See the file license.txt for copying permission.
from amqtt_folder.mqtt.packet import (
    MQTTPacket,
    MQTTFixedHeader,
    SUBACK,
    PacketIdVariableHeader,
    MQTTPayload,
    MQTTVariableHeader,
)
from amqtt_folder.errors import AMQTTException, NoDataException
from amqtt_folder.adapters import ReaderAdapter
from amqtt_folder.codecs import bytes_to_int, int_to_bytes, read_or_raise
from cryptography.hazmat.primitives import hashes, hmac
import logging

global_logger = logging.getLogger(__name__)

class SubackPayload(MQTTPayload):

    __slots__ = ("return_codes","mac")

    RETURN_CODE_00 = 0x00
    RETURN_CODE_01 = 0x01
    RETURN_CODE_02 = 0x02
    RETURN_CODE_80 = 0x80

    def __init__(self, mac_received, return_codes=None ):
        super().__init__()
        self.return_codes = return_codes or []
        self.mac = mac_received
        self.logger = logging.getLogger(__name__)
        

    def __repr__(self):
        return type(self).__name__ + "(return_codes={})".format(repr(self.return_codes))

    def to_bytes(
        self, fixed_header: MQTTFixedHeader, variable_header: MQTTVariableHeader
    ):
        out = b""
        for return_code in self.return_codes:
            out += int_to_bytes(return_code, 1)  
            #Burcu: subscribe edilen her topic için return code'u out'a ekliyor

        #bilgesu:modification adding mac to the payload

        self.logger.info("Signature of suback packet padded to payload with the return codes: %s", self.mac)

        if self.mac != None:
            out += b"::::" + self.mac 

        return out

    @classmethod
    async def from_stream(
        cls,
        reader: ReaderAdapter,
        fixed_header: MQTTFixedHeader,
        variable_header: MQTTVariableHeader,
    ):
        return_codes = []
        bytes_to_read = fixed_header.remaining_length - variable_header.bytes_length
        for i in range(0, bytes_to_read):
            try:
                return_code_byte = await read_or_raise(reader, 1) #Burcu: 1 byte okuyor
                return_code = bytes_to_int(return_code_byte)  # Burcu: return code'u integer'a dönüştürüyor
                return_codes.append(return_code) #Burcu:return code'u array'e ekliyor
            except NoDataException:
                break
        return cls(return_codes)


class SubackPacket(MQTTPacket):
    VARIABLE_HEADER = PacketIdVariableHeader
    PAYLOAD = SubackPayload

    def __init__(
        self,
        fixed: MQTTFixedHeader = None,
        variable_header: PacketIdVariableHeader = None,
        payload=None,
    ):
        if fixed is None:
            header = MQTTFixedHeader(SUBACK, 0x00)
        else:
            if fixed.packet_type is not SUBACK:
                raise AMQTTException(
                    "Invalid fixed packet type %s for SubackPacket init"
                    % fixed.packet_type
                )
            header = fixed

        super().__init__(header)
        self.variable_header = variable_header
        self.payload = payload

    '''@classmethod
    def build(cls, packet_id, return_codes):
        variable_header = cls.VARIABLE_HEADER(packet_id)
        payload = cls.PAYLOAD(return_codes)
        return cls(variable_header=variable_header, payload=payload)'''
    
    #bilgesu: modification
    @classmethod
    def build(cls, packet_id, return_codes, client_unique_session_key = None):

        variable_header = cls.VARIABLE_HEADER(packet_id)
        

        if client_unique_session_key != None:
            byte_packet_id = bytes(str(packet_id), 'utf-8')


            return_codes_str = ""
            for i in range(len(return_codes)):
                str_code = str(return_codes[i])
                if i>0:
                    return_codes_str += ":"
                return_codes_str += str_code

            return_codes_appended_byte = bytes(return_codes_str, 'utf-8')

            to_be_signed = byte_packet_id + b'::::' + return_codes_appended_byte



            #DISTORTED ON PURPOSE:
            #to_be_signed = b'randomBytes' + b'::::' + return_codes_appended_byte

            print("*************************************************", to_be_signed)


            h = hmac.HMAC(client_unique_session_key, hashes.SHA256())
            h.update(to_be_signed)
            mac = h.finalize()
            print("*************************************************", mac)
            payload = SubackPayload(mac_received=mac, return_codes=return_codes)

        
        else:
            payload = SubackPayload(mac_received=None, return_codes=return_codes)

        return cls(variable_header=variable_header, payload=payload)

