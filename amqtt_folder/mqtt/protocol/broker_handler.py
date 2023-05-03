# Copyright (c) 2015 Nicolas JOUANIN
#
# See the file license.txt for copying permission.
from asyncio import futures, Queue
from amqtt_folder.mqtt.protocol.handler import ProtocolHandler
from amqtt_folder.mqtt.connack import (
    CONNECTION_ACCEPTED,
    UNACCEPTABLE_PROTOCOL_VERSION,
    IDENTIFIER_REJECTED,
    BAD_USERNAME_PASSWORD,
    NOT_AUTHORIZED,
    ConnackPacket,
)
from amqtt_folder.mqtt.connect import ConnectPacket
from amqtt_folder.mqtt.pingreq import PingReqPacket
from amqtt_folder.mqtt.pingresp import PingRespPacket
from amqtt_folder.mqtt.subscribe import SubscribePacket
from amqtt_folder.mqtt.publish import PublishPacket
from amqtt_folder.mqtt.suback import SubackPacket
from amqtt_folder.mqtt.unsubscribe import UnsubscribePacket
from amqtt_folder.mqtt.unsuback import UnsubackPacket
from amqtt_folder.utils import format_client_message
from amqtt_folder.session import Session
from amqtt_folder.plugins.manager import PluginManager
from amqtt_folder.adapters import ReaderAdapter, WriterAdapter
from amqtt_folder.errors import MQTTException
from .handler import EVENT_MQTT_PACKET_RECEIVED, EVENT_MQTT_PACKET_SENT


#new imports
from diffiehellman import DiffieHellman
from amqtt_folder.clientconnection import pushRowToDatabase, updateRowFromDatabase, getStatementFromChoiceTokens, pushRowToChoiceTokenTable, updateRowFromChoiceTokens, deleteRowFromChoiceTokens, getStatementFromWildChoiceTokens
from amqtt_folder.codecs import (
    encode_string,
    bytes_to_hex_str, 
    decode_string, encode_data_with_length
)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509 import load_pem_x509_certificate
from diffiehellman import DiffieHellman
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as padding2
from cryptography.hazmat.backends import default_backend
from django.utils.encoding import force_bytes, force_str
import secrets
import binascii
from binascii import unhexlify


#bilgesu: modification: flags might be needed
WILL_RETAIN_FLAG = 0x20  
WILL_FLAG = 0x04    
WILL_QOS_MASK = 0x18        
CLEAN_SESSION_FLAG = 0x02    
RESERVED_FLAG = 0x01
QOS_0 = 0x00
QOS_1 = 0x01
QOS_2 = 0x02

#needed flags to be reached
'''clientId, dupFlag, QoS, retainFlag, packetIDentifier'''
#bilgesu: modificaiton end



class BrokerProtocolHandler(ProtocolHandler):
    def __init__(
        self, plugins_manager: PluginManager, session: Session = None, loop=None
    ):
        super().__init__(plugins_manager, session, loop)
        self._disconnect_waiter = None
        self._pending_subscriptions = Queue()
        self._pending_unsubscriptions = Queue()

    async def start(self):
        await super().start()
        if self._disconnect_waiter is None:
            self._disconnect_waiter = futures.Future()

    async def stop(self):
        await super().stop()
        if self._disconnect_waiter is not None and not self._disconnect_waiter.done():
            self._disconnect_waiter.set_result(None)

    async def wait_disconnect(self):
        return await self._disconnect_waiter

    def handle_write_timeout(self):
        pass

    def handle_read_timeout(self):
        if self._disconnect_waiter is not None and not self._disconnect_waiter.done():
            self._disconnect_waiter.set_result(None)

    async def handle_disconnect(self, disconnect):
        self.logger.debug("Client disconnecting")
        self.logger.info("Client disconnecting")
        if self._disconnect_waiter and not self._disconnect_waiter.done():
            self.logger.debug("Setting waiter result to %r" % disconnect)
            self._disconnect_waiter.set_result(disconnect)

    async def handle_connection_closed(self):
        await self.handle_disconnect(None)

    async def handle_connect(self, connect: ConnectPacket):
        # Broker handler shouldn't received CONNECT message during messages handling
        # as CONNECT messages are managed by the broker on client connection
        self.logger.error(
            "%s [MQTT-3.1.0-2] %s : CONNECT message received during messages handling"
            % (self.session.client_id, format_client_message(self.session))
        )
        if self._disconnect_waiter is not None and not self._disconnect_waiter.done():
            self._disconnect_waiter.set_result(None)

    async def handle_pingreq(self, pingreq: PingReqPacket):
        await self._send_packet(PingRespPacket.build())
    
    async def handle_subscribe(self, subscribe: SubscribePacket):
        self.logger.debug("Session client ID %s", self.session.client_id) #Burcu
        subscription = {
            "packet_id": subscribe.variable_header.packet_id,
            "topics": subscribe.payload.topics,
        }
        self.logger.debug("Inside hande_subscribe in broker_handler.py" )
        await self._pending_subscriptions.put(subscription)
    
    """START: 4 Nisan'da eklendi"""

    #bilgesu modification
    async def sendBadMAC(self):

        message_str = self.session.session_info.client_id
        message = bytes(message_str, 'utf-8')

        h = hmac.HMAC(self.session.session_info.session_key, hashes.SHA256())
        h.update(message)
        signature = h.finalize()

        topicName = message + b'::::' + signature

        backend = default_backend() 
        encryptor = Cipher(algorithms.AES(self.session.session_info.session_key), modes.ECB(), backend).encryptor()
        padder = padding2.PKCS7(algorithms.AES(self.session.session_info.session_key).block_size).padder()
        padded_data = padder.update(topicName) + padder.finalize()
        topicNameEncryptedByte = encryptor.update(padded_data) + encryptor.finalize()
        topicNameEncryptedHex = topicNameEncryptedByte.hex()


        payload_send = b''
        #also add dummy mac
        payload_send += bytes(self.session.session_info.client_id, 'utf-8') + b'::::' + b'signVerifyFailed' + b'::::' + b'MACReplacer'


        encryptor = Cipher(algorithms.AES(self.session.session_info.session_key), modes.ECB(), backend).encryptor()
        padder = padding2.PKCS7(algorithms.AES(self.session.session_info.session_key).block_size).padder()
        padded_data = padder.update(payload_send) + padder.finalize()
        payloadByte = encryptor.update(padded_data) + encryptor.finalize()
        self.logger.debug("alldatabeforepublish: %s", payloadByte)

        await self.mqtt_publish(topicNameEncryptedHex, data = encode_data_with_length(payloadByte), qos=2, retain= False)

    #bilgesu: modification



    async def sendChoiceToken(self, topicnamehex, payload, quality, retain, mid):
    
    
        self.logger.info("----FUNCTION: PUBLISH MESSAGE IS RECEIVED FROM CLIENT %s FOR REQUESTED CHOICE TOKEN (step 2 of choice token scheme)----" , self.session.client_id)
        self.logger.info("CLIENT: %s, ENCRYPTED TOPIC of the 'choiceToken' (step 2 of choice token scheme):  %s "  , self.session.client_id, topicnamehex)
        self.logger.info("CLIENT: %s, ENCRYPTED DATA FROM CLIENT TO REQUEST CHOICE TOKEN (step 2 of choice token scheme): %s" , self.session.client_id, payload)
        
        #Decrypt the topic name and learn the topic name
        topicnamebyte = unhexlify(topicnamehex)
        backend = default_backend()
        decryptor = Cipher(algorithms.AES(self.session.session_info.session_key), modes.ECB(), backend).decryptor()
        padder = padding2.PKCS7(algorithms.AES(self.session.session_info.session_key).block_size).unpadder()
        decrypted_data = decryptor.update(topicnamebyte) 
        unpadded = padder.update(decrypted_data) + padder.finalize()
        index1 = unpadded.index(b'::::')
        topicname = unpadded[0:index1]
        macCode = unpadded[index1+4:]

       

        
        h = hmac.HMAC(self.session.session_info.session_key, hashes.SHA256())
        h.update(topicname)
        signature = h.finalize()
        self.logger.info("CLIENT: %s, RECEIVED MAC OF PUBLISHED TOPIC: %s ", self.session.client_id, macCode  )
        self.logger.info("CLIENT: %s, CALCULATED MAC OF PUBLISHED TOPIC: %s ", self.session.client_id, signature  )

        if (signature == macCode):
            self.logger.info("CLIENT: %s, MAC OF THE TOPIC 'choiceToken' IS SAME ", self.session.client_id )
            self.logger.debug("MAC of the topic name is same")
            decryptor = Cipher(algorithms.AES(self.session.session_info.session_key), modes.ECB(), backend).decryptor()
            padder = padding2.PKCS7(algorithms.AES(self.session.session_info.session_key).block_size).unpadder()
            decrypted_data = decryptor.update(payload) 
            unpadded = padder.update(decrypted_data) + padder.finalize()
            self.logger.debug("unpadded: %s", unpadded)
            
            

            indexMAC = unpadded.rfind(b'::::')
            mac_unchecked = unpadded[indexMAC+4:]
            payload_topics = unpadded[0:indexMAC]
            self.logger.debug("indexMAC: %s", indexMAC)
            self.logger.debug("payload_topics: %s", payload_topics)
            
           

            #splitting for subscription requests of multiple topics in one message
            topics_list = payload_topics.split(b'::::')
            self.logger.info("topics_list: %s", topics_list)
            #self.logger.info("CLIENT: %s, DECRYPTED DATA FROM CLIENT TO REQUEST CHOICE TOKEN %s" , self.session.client_id, topics_list)

            messagex = bytes.decode(payload_topics, 'utf-8') + self.session.client_id + str(quality) + str(retain) + str(mid)
            self.logger.info("messagex: %s" , messagex )

            message_byte = force_bytes(messagex)

            h = hmac.HMAC(self.session.session_info.session_key, hashes.SHA256())
            h.update(message_byte)
            signature = h.finalize()
           
            self.logger.info("CLIENT: %s, RECEIVED MAC OF PAYLOAD: %s ", self.session.client_id, mac_unchecked  )
            self.logger.info("CLIENT: %s, CALCULATED MAC OF PAYLOAD: %s ", self.session.client_id, signature  )

            
            

            
            if (mac_unchecked == signature):
                self.logger.debug("MAC of the payload is same")
                self.logger.info("CLIENT: %s, MAC OF THE PAYLOAD IS SAME", self.session.client_id )
                
                payload_send = b''

                #loop for getting a choice token for all asked topics by the client
                for topicName in topics_list:
                    #self.logger.debug("topicName: %s ", topicName)
                    

                    topicName_str = bytes.decode(topicName)
                    rows = getStatementFromChoiceTokens(topicName_str)
                    self.logger.info("CLIENT: %s, DECRYPTED TOPIC FOR WHICH CHOICE TOKEN IS REQUESTED: %s ", self.session.client_id, topicName_str )
                    if (rows == None or len(rows) == 0 or rows == []): 
                        choiceToken = secrets.token_hex() #256 bitlik bir token oluşturuyor
                        pushRowToChoiceTokenTable(choiceToken, topicName_str)
                        rows = getStatementFromChoiceTokens(topicName_str)
                    else:
                        self.logger.debug("got token from database")

                    tupleobj = rows[0]
                    topic = tupleobj[0]
                    choiceHex = tupleobj[1]
                    self.logger.info("CLIENT: %s, TOPIC: %s, AND ITS CORRESPONDING CHOICE TOKEN: %s ", self.session.client_id, topicName_str, choiceHex )
                    #self.logger.debug("Topic: %s", topic)
                    #self.logger.debug("ChoiceHex  (182) in broker: %s", choiceHex)
                    choiceByte = unhexlify(choiceHex)
                    #self.logger.debug("ChoiceByte  (184) in broker: %s", choiceByte)

                    #append topics and choideToken bytes for payload
                    payload_send += topicName + b'::::' + choiceByte + b'::::'

                message_str = self.session.session_info.client_id
                message = bytes(message_str, 'utf-8')
                self.logger.info("----FUNCTION: PREPARATION OF PUBLISH MESSAGE FOR CLIENT %s FOR REQUESTED CHOICE TOKEN (step 4 of choice token scheme)----" , self.session.client_id)

                

                h = hmac.HMAC(self.session.session_info.session_key, hashes.SHA256())
                h.update(message)
                signature = h.finalize()

                topicName = message + b'::::' + signature

                backend = default_backend() 
                encryptor = Cipher(algorithms.AES(self.session.session_info.session_key), modes.ECB(), backend).encryptor()
                padder = padding2.PKCS7(algorithms.AES(self.session.session_info.session_key).block_size).padder()
                padded_data = padder.update(topicName) + padder.finalize()
                topicNameEncryptedByte = encryptor.update(padded_data) + encryptor.finalize()
                topicNameEncryptedHex = topicNameEncryptedByte.hex()

                payload_send_without_last_divider = payload_send[0 : len(payload_send)-4]

                msgid = self.session.next_packet_id
                msgid_str = str(msgid)
                qos = 1
                retainFlag = False
                message_str = str(qos) + str(retainFlag)
                message_bytes = payload_send_without_last_divider  + force_bytes(message_str)+ force_bytes(msgid_str)
                self.logger.info("message_bytes: %s ", message_bytes)


                h = hmac.HMAC(self.session.session_info.session_key, hashes.SHA256())
                h.update(message_bytes)
                signature = h.finalize()

                payload_mac_merged = payload_send + signature 

                #bilgesu: modification
                self.logger.debug("*************************payload_mac_merged: %s", payload_mac_merged)

                encryptor = Cipher(algorithms.AES(self.session.session_info.session_key), modes.ECB(), backend).encryptor()
                padder = padding2.PKCS7(algorithms.AES(self.session.session_info.session_key).block_size).padder()
                padded_data = padder.update(payload_mac_merged) + padder.finalize()
                payloadByte = encryptor.update(padded_data) + encryptor.finalize()
                self.logger.debug(payloadByte)
                
                self.logger.debug("alldatabeforepublish:%s", payloadByte)
                self.logger.info("CLIENT: %s, ENCRYPTED TOPIC NAME: %s ", self.session.client_id, topicNameEncryptedHex )
                self.logger.info("CLIENT: %s, ENCRYPTED PAYLOAD SEND FOR CHOICE TOKEN: %s ", self.session.client_id, payloadByte  )
              
               
                await self.mqtt_publish(topicNameEncryptedHex, data = encode_data_with_length(payloadByte), qos=1, retain= False, msgid=msgid )
                self.logger.info("REQUESTED CHOICE TOKEN IS SENT TO CLIENT (step 4 of choice token schema): %s ", self.session.client_id  )

                
            else:
                self.logger.info("CLIENT: %s, MAC OF THE PAYLOAD IS DIFFERENT", self.session.client_id )
                self.logger.debug("sendBadMAC called")
                await self.sendBadMAC()
        else:
            self.logger.info("CLIENT: %s, MAC OF THE TOPIC NAME IS DIFFERENT", self.session.client_id )
            self.logger.debug("sendBadMAC called")
            await self.sendBadMAC()

 
    """END: 4 Nisan'da eklendi"""


    async def sendChoiceTokenWildcards(self, topicName_str):
      
        self.logger.info("----FUNCTION: send_choice_token_wildcards %s topicname %s ----" , self.session.client_id,topicName_str)
        self.logger.info("----FUNCTION: PREPARATION OF PUBLISH MESSAGE FOR CLIENT %s FOR CHOICE TOKEN ----" , self.session.client_id)              
        payload_send = b''
        #2may2023
                   
        self.logger.debug("topicName: %s ", topicName_str)
                  

        self.logger.info("346")
        self.logger.info(topicName_str)
        rows = getStatementFromChoiceTokens(topicName_str)
        self.logger.info("CLIENT: %s, topicname_str: %s ", self.session.client_id, topicName_str )
        self.logger.info("349")
        if (rows == None or len(rows) == 0 or rows == []): 
            choiceToken = secrets.token_hex() #256 bitlik bir token oluşturuyor
            pushRowToChoiceTokenTable(choiceToken, topicName_str)
            rows = getStatementFromChoiceTokens(topicName_str)
            self.logger.info("354")
        else:
            self.logger.debug("got token from database")
            self.logger.info("355")

        #self.session.session_info.subscribed_topics.add (topicName,1)

        tupleobj = rows[0]
        topic = tupleobj[0]
        choiceHex = tupleobj[1]
        self.logger.info(choiceHex)
        self.logger.info("CLIENT: %s, TOPIC: %s, AND ITS CORRESPONDING CHOICE TOKEN: %s ", self.session.client_id, topicName_str, choiceHex )
        #self.logger.debug("Topic: %s", topic)
        #self.logger.debug("ChoiceHex  (182) in broker: %s", choiceHex)
        choiceByte = unhexlify(choiceHex)
        self.logger.debug("ChoiceByte  (184) in broker: %s", choiceByte)
        topicName_byte = force_bytes(topicName_str)

        #append topics and choideToken bytes for payload
        payload_send += topicName_byte + b'::::' + choiceByte + b'::::'

        message_str = self.session.session_info.client_id
        message = bytes(message_str, 'utf-8')
        self.logger.info("----FUNCTION: PREPARATION OF PUBLISH MESSAGE FOR CLIENT %s FOR REQUESTED CHOICE TOKEN (step 4 of choice token scheme)----" , self.session.client_id)

                

        h = hmac.HMAC(self.session.session_info.session_key, hashes.SHA256())
        h.update(message)
        signature = h.finalize()

        topicName = message + b'::::' + signature

        backend = default_backend() 
        encryptor = Cipher(algorithms.AES(self.session.session_info.session_key), modes.ECB(), backend).encryptor()
        padder = padding2.PKCS7(algorithms.AES(self.session.session_info.session_key).block_size).padder()
        padded_data = padder.update(topicName) + padder.finalize()
        topicNameEncryptedByte = encryptor.update(padded_data) + encryptor.finalize()
        topicNameEncryptedHex = topicNameEncryptedByte.hex()

        payload_send_without_last_divider = payload_send[0 : len(payload_send)-4]

        msgid = self.session.next_packet_id
        msgid_str = str(msgid)
        qos = 1
        retainFlag = False
        message_str = str(qos) + str(retainFlag)
        message_bytes = payload_send_without_last_divider  + force_bytes(message_str)+ force_bytes(msgid_str)
        self.logger.info("message_bytes: %s ", message_bytes)


        h = hmac.HMAC(self.session.session_info.session_key, hashes.SHA256())
        h.update(message_bytes)
        signature = h.finalize()

        payload_mac_merged = payload_send + signature 

        #bilgesu: modification
        self.logger.debug("*************************payload_mac_merged: %s", payload_mac_merged)

        encryptor = Cipher(algorithms.AES(self.session.session_info.session_key), modes.ECB(), backend).encryptor()
        padder = padding2.PKCS7(algorithms.AES(self.session.session_info.session_key).block_size).padder()
        padded_data = padder.update(payload_mac_merged) + padder.finalize()
        payloadByte = encryptor.update(padded_data) + encryptor.finalize()
        self.logger.debug(payloadByte)
                
        self.logger.debug("alldatabeforepublish:%s", payloadByte)
        self.logger.info("CLIENT: %s, ENCRYPTED TOPIC NAME: %s ", self.session.client_id, topicNameEncryptedHex )
        self.logger.info("CLIENT: %s, ENCRYPTED PAYLOAD SEND FOR CHOICE TOKEN: %s ", self.session.client_id, payloadByte  )
              
               
        await self.mqtt_publish(topicNameEncryptedHex, data = encode_data_with_length(payloadByte), qos=1, retain= False, msgid=msgid )
        self.logger.info("REQUESTED CHOICE TOKEN IS SENT TO CLIENT (step 4 of choice token schema): %s ", self.session.client_id  )

                
    """END: 2 mayis'da eklendi"""


    async def sendChoiceTokenWildDB(self, topicName_wild):
      
        self.logger.info("----FUNCTION: send_choice_token_wildDB %s topicname %s ----" , self.session.client_id,topicName_wild)
        self.logger.info("----FUNCTION: PREPARATION OF PUBLISH MESSAGE FOR CLIENT %s FOR CHOICE TOKEN ----" , self.session.client_id)              
        payload_send = b''
        #2may2023
                   
        self.logger.debug("topicName: %s ", topicName_wild)
        topicName_wild_str = bytes.decode(topicName_wild, 'utf-8')

        tokenDict = {}

              
        if '+' in topicName_wild_str: 
            index = topicName_wild_str.index('+')
            topicName_without_wild = topicName_wild_str[0:index]
            topicName_exact = None

        elif '#' in topicName_wild_str: 
            index = topicName_wild_str.index('#')
            topicName_without_wild = topicName_wild_str[0:index]
            topicName_exact = topicName_wild_str[0:index-1]
      
        
        self.logger.info("346")
        
        rows = getStatementFromWildChoiceTokens(topicName_without_wild)
        self.logger.info("CLIENT: %s, topicname_str: %s ", self.session.client_id, topicName_wild_str )
        self.logger.info("CLIENT: %s, topicname_str without wild: %s ", self.session.client_id, topicName_without_wild )
        self.logger.info("349")
        if (rows == None or len(rows) == 0 or rows == []): 
            self.logger.debug("there is no choice token")
        else:
            for tupleobj in rows:
                topic = tupleobj[0]
                choiceHex = tupleobj[1]
                #self.logger.info("CLIENT: %s, TOPIC: %s, AND ITS CORRESPONDING CHOICE TOKEN: %s ", self.session.client_id, topic, choiceHex )
                tokenDict[topic] = choiceHex


        if topicName_exact != None:
            rows = getStatementFromChoiceTokens(topicName_exact)
            self.logger.info("CLIENT: %s, topicname_str_exact: %s ", self.session.client_id, topicName_exact )
            if (rows == None or len(rows) == 0 or rows == []): 
                self.logger.debug("there is no choice token")
            else:
                tupleobj = rows[0]
                topic = tupleobj[0]
                choiceHex = tupleobj[1]
                #self.logger.info("CLIENT: %s, TOPIC: %s, AND ITS CORRESPONDING CHOICE TOKEN: %s ", self.session.client_id, topic, choiceHex )
                tokenDict[topic] = choiceHex
                
        for topic in tokenDict:
            self.logger.info("CLIENT: %s, TOPIC: %s, AND ITS CORRESPONDING CHOICE TOKEN: %s ", self.session.client_id, topic, tokenDict[topic] )
            choiceHex = tokenDict[topic]
            choiceByte = unhexlify(choiceHex)
            self.logger.debug("ChoiceByte  (184) in broker: %s", choiceByte)
            topicName_byte = force_bytes(topic)
            payload_send = topicName_byte + b'::::' + choiceByte 
            
            message_str = self.session.session_info.client_id
            message = bytes(message_str, 'utf-8')
            self.logger.info("----FUNCTION: PREPARATION OF PUBLISH MESSAGE FOR CLIENT %s FOR REQUESTED CHOICE TOKEN (step 4 of choice token scheme)----" , self.session.client_id)
            
            h = hmac.HMAC(self.session.session_info.session_key, hashes.SHA256())
            h.update(message)
            signature = h.finalize()

            topicName = message + b'::::' + signature

            backend = default_backend() 
            encryptor = Cipher(algorithms.AES(self.session.session_info.session_key), modes.ECB(), backend).encryptor()
            padder = padding2.PKCS7(algorithms.AES(self.session.session_info.session_key).block_size).padder()
            padded_data = padder.update(topicName) + padder.finalize()
            topicNameEncryptedByte = encryptor.update(padded_data) + encryptor.finalize()
            topicNameEncryptedHex = topicNameEncryptedByte.hex()

            msgid = self.session.next_packet_id
            msgid_str = str(msgid)
            qos = 1
            retainFlag = False
            message_str = str(qos) + str(retainFlag)
            message_bytes = payload_send  + force_bytes(message_str)+ force_bytes(msgid_str)
            self.logger.info("message_bytes: %s ", message_bytes)

            h = hmac.HMAC(self.session.session_info.session_key, hashes.SHA256())
            h.update(message_bytes)
            signature = h.finalize()

            payload_mac_merged = b'wildcardChoiceToken' + b'::::' + payload_send + b'::::' + signature 


            encryptor = Cipher(algorithms.AES(self.session.session_info.session_key), modes.ECB(), backend).encryptor()
            padder = padding2.PKCS7(algorithms.AES(self.session.session_info.session_key).block_size).padder()
            padded_data = padder.update(payload_mac_merged) + padder.finalize()
            payloadByte = encryptor.update(padded_data) + encryptor.finalize()
            self.logger.debug(payloadByte)
                    
            self.logger.debug("alldatabeforepublish:%s", payloadByte)
            self.logger.info("CLIENT: %s, ENCRYPTED TOPIC NAME: %s ", self.session.client_id, topicNameEncryptedHex )
            self.logger.info("CLIENT: %s, ENCRYPTED PAYLOAD SEND FOR CHOICE TOKEN: %s ", self.session.client_id, payloadByte  )
                
                
            await self.mqtt_publish(topicNameEncryptedHex, data = encode_data_with_length(payloadByte), qos=1, retain= False, msgid=msgid )
            self.logger.info("REQUESTED CHOICE TOKEN IS SENT TO CLIENT (step 4 of choice token schema): %s ", self.session.client_id  )

     
                
    """END: 2 mayis'da eklendi"""


    """START 29mart2023 te eklendi """  
    async def send_publish_step_8(self):
        try:
            
            self.logger.info("----FUNCTION: PREPARATION OF THE PUBLISH MESSAGE AT STEP 8 OF DH FOR CLIENT:  %s----" , self.session.client_id)
            nonce2 = secrets.token_urlsafe()
            self.session.session_info.n2 = bytes(nonce2, 'UTF-8')
           
            self.logger.info("CLIENT: %s, NONCE 2: %s ", self.session.client_id, nonce2)
            value_str = nonce2 + "::::" + self.session.client_id
            value = force_bytes(value_str)
            dh1_shared = self.session.session_info.dh_shared_key
            sessionkey = self.session.session_info.session_key

            backend = default_backend()
            encryptor = Cipher(algorithms.AES(sessionkey), modes.ECB(), backend).encryptor()
            padder = padding2.PKCS7(algorithms.AES(sessionkey).block_size).padder()
            padded_data = padder.update(value) + padder.finalize()
            encrypted_text = encryptor.update(padded_data) + encryptor.finalize()

            
            self.logger.info("CLIENT: %s ENCRYPTED TEXT: %s", self.session.client_id, encrypted_text)

            await self.mqtt_publish(self.session.client_id, data = encode_data_with_length(encrypted_text), qos=2, retain= False )
            self.logger.info("PUBLISH MESSAGE OF STEP 8 OF DH IS SENT TO CLIENT: %s ", self.session.client_id)
            

            self.session.session_info.key_establishment_state = 8
        except:
            
            self.logger.info("Exception from second publish from broker")
                            

    async def broker_df_publish (self, topicname, data, x509, x509_private_key):
        if (topicname == self.session.client_id):
            
            self.logger.info("----FUNCTION: PREPARATION OF THE PUBLISH MESSAGE AT STEP 5 OF DH for CLIENT ID: %s----" , self.session.client_id)
            self.logger.info("TOPIC NAME (client ID):  %s", topicname )
            try:
                dh1 = DiffieHellman(group=14, key_bits=2048)    #bilgesu: key size increased to 2048
                dh1_public = dh1.get_public_key()
                
                
                self.logger.info("BROKER DH PUBLIC KEY: %s", dh1_public)
                self.session.session_info.dh = dh1

            except Exception as e:
                self.logger.warning("Exception: %r", e.args)

            try:
                nonce1 = secrets.token_urlsafe()
                self.session.session_info.n1 =  bytes(nonce1, 'UTF-8')
                
                self.logger.info("CLIENT: %s, NONCE 1: %s ",  self.session.client_id, nonce1)

                client_ID_byte = bytes(self.session.client_id, 'UTF-8')
                message = dh1_public + b'::::' + self.session.session_info.n1 + b'::::' + client_ID_byte #nonce added
                signature = x509_private_key.sign(
                        message,
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH
                        ),
                        hashes.SHA256()
                    )
                
                self.logger.info("CLIENT: %s, RSA SIGN: %s  ",self.session.client_id,  signature)
                
                

            except Exception as e3:
               self.logger.warning("ERROR %r ", e3.args)

            try:
                
                pem = x509.public_bytes(encoding=serialization.Encoding.PEM)
                sent_data = pem + b'::::' + dh1_public + b'::::' + self.session.session_info.n1 + b'::::' + signature   #nonce added
                await self.mqtt_publish(topicname, data = encode_data_with_length(sent_data), qos=2, retain= False )
               
                self.logger.info("PUBLISH MESSAGE OF STEP 5 OF DH IS SENT TO CLIENT: %s ", self.session.client_id)
                
                self.session.session_info.key_establishment_state = 5

                #modification start
                """
                is_successs = updateRowFromDatabase(self.session.session_info.client_id, self.session.session_info.key_establishment_state,
                                      self.session.session_info.client_spec_pub_key, self.session.session_info.client_spec_priv_key,
                                      None, self.session.session_info.n1, self.session.session_info.n2, 
                                      self.session.session_info.n3)
                if is_successs:
                    self.logger.debug("state update successfull")
                else:
                    self.logger.debug("state update issue")
                """
                #modification end
                
            except Exception as e2:
                self.logger.warning("Exception: %r ", e2.args)
   
            #self.logger.debug("#######session state %s", self.session.session_info.key_establishment_state)

        elif (topicname == "AuthenticationTopic"):
            if (self.session.session_info.key_establishment_state == 5):
                
                self.logger.info("----FUNCTION: PUBLISH MESSAGE AT STEP 6 OF DH WAS RECEIVED FROM CLIENT: %s----" , self.session.client_id)
                #self.logger.debug("TOPIC NAME: , %s", topicname , "AUTHENTICATED ENCYPTION VERSION OF DATA: %s", data )
                #self.logger.debug("CLIENT DH PUBLIC KEY:  %s", data)

                index = data.index(b'::::')
                client_x509_pem = data[0:index]

                client_pub_nonce_and_sign = data[index+4:]

                index2 = client_pub_nonce_and_sign.index(b'::::')
                client_dh_public_key = client_pub_nonce_and_sign[0:index2]
                nonce_rsa_sign = client_pub_nonce_and_sign[index2+4:]

                index3 = nonce_rsa_sign.index(b'::::')
                nonce = nonce_rsa_sign[0:index3]

                client_rsa_sign = nonce_rsa_sign[index3+4:]

                dh1 = self.session.session_info.dh
                dh1_shared = dh1.generate_shared_key(client_dh_public_key)

                
                self.logger.info("CLIENT: %s, X509 CLIENT CERTIFICATE:  %s",self.session.client_id, client_x509_pem)
                self.logger.info("CLIENT: %s, CLIENT DH PUBLIC KEY: %s",self.session.client_id, client_dh_public_key)
                self.logger.info("CLIENT: %s, CLIENT RSA SIGN: %s", self.session.client_id, client_rsa_sign)
                self.logger.info("CLIENT: %s, RECEIVED NONCE 1: %s",self.session.client_id, nonce)

                client_x509_bytes = bytes(client_x509_pem)
                client_x509 = load_pem_x509_certificate(client_x509_bytes )
                self.session.session_info.client_x509 = client_x509
                client_x509_public_key = client_x509.public_key()

                client_x509_public_key_pem = client_x509_public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )

                
                self.logger.info("CLIENT: %s, X509 CLIENT PUBLIC KEY: %s", self.session.client_id, client_x509_public_key_pem)

                client_ID_byte = bytes(self.session.client_id, 'UTF-8')
                message = client_dh_public_key + b'::::' + nonce + b'::::' + client_ID_byte
                message_bytes = bytes(message)
                client_rsa_sign_bytes = bytes(client_rsa_sign)

                
                

                self.session.session_info.key_establishment_state = 6

                try:
                    
                    client_x509_public_key.verify(
                        client_rsa_sign_bytes,
                        message_bytes,
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH
                        ),
                        hashes.SHA256()
                    )  
                   
                    self.logger.info("CLIENT: %s, SIGN VERIFIED, nonce not checked yet",  self.session.client_id)

                    if(nonce == self.session.session_info.n1):

                        
                        self.logger.info("CLIENT: %s, Nonces are matching, sign was verified, will send publish step 8.",  self.session.client_id)                            
                        self.session.session_info.dh_shared_key = dh1_shared
                        
                        self.logger.info("CLIENT: %s, DH SHARED KEY: %s", self.session.client_id, dh1_shared)
                        sessionkey = force_bytes(base64.urlsafe_b64encode(force_bytes(dh1_shared))[:32])
                        self.session.session_info.session_key = sessionkey
                        self.logger.info("CLIENT: %s, 256 BIT SESSION KEY DERIVED FROM DH SHARED KEY: %s", self.session.client_id, sessionkey)
                        await self.send_publish_step_8()
                    else:

                        #siganture verified but nonces are not matching so key extablishment is rejected at this stage
                        #sending publish to notify the client bout the disconnect
                        
                        self.logger.info("CLIENT: %s, Nonces are not matching, client not authenticated, key establishment will stop.", self.session.client_id)
                        self.session.session_info.disconnect_flag = True

                        notAuthMessage = self.session.session_info.client_id + "::::" + "notAuthenticated"
                        value = force_bytes(notAuthMessage)
                        backend = default_backend()
                        encryptor = Cipher(algorithms.AES(self.session.session_info.session_key), modes.ECB(), backend).encryptor()
                        padder = padding2.PKCS7(algorithms.AES(self.session.session_info.session_key).block_size).padder()
                        padded_data = padder.update(value) + padder.finalize()
                        encrypted_text = encryptor.update(padded_data) + encryptor.finalize()
                        await self.mqtt_publish(self.session.client_id, data = encode_data_with_length(encrypted_text), qos=2, retain= False )
                    

                        await self.handle_connection_closed()

                except:
                    #sign not verified
                    
                    self.logger.info("CLIENT: %s, SIGN NOT VERIFIED", self.session.client_id )
                    self.session.session_info.disconnect_flag = True

                    #send some message as not authenticated to stop paho from reconnnecting

                    notAuthMessage = self.session.session_info.client_id +  "::::" + "notAuthenticated"
                    value = force_bytes(notAuthMessage)
                    backend = default_backend()
                    encryptor = Cipher(algorithms.AES(self.session.session_info.session_key), modes.ECB(), backend).encryptor()
                    padder = padding2.PKCS7(algorithms.AES(self.session.session_info.session_key).block_size).padder()
                    padded_data = padder.update(value) + padder.finalize()
                    encrypted_text = encryptor.update(padded_data) + encryptor.finalize()
                    await self.mqtt_publish(self.session.client_id, data = encode_data_with_length(encrypted_text), qos=2, retain= False )
                   

                    await self.handle_connection_closed()

               

            elif (self.session.session_info.key_establishment_state == 8):
                
                self.logger.info("----FUNCTION: PUBLISH MESSAGE AT STEP 9 OF DH WAS RECEIVED FROM CLIENT: %s----" , self.session.client_id)
                self.logger.info("CLIENT: %s, DATA OF STEP 9 OF DH  :  %s", self.session.client_id, data)                
                backend = default_backend()
                decryptor = Cipher(algorithms.AES(self.session.session_info.session_key), modes.ECB(), backend).decryptor()
                padder = padding2.PKCS7(algorithms.AES(self.session.session_info.session_key).block_size).unpadder()
                decrypted_data = decryptor.update(data) 
                unpadded = padder.update(decrypted_data) + padder.finalize()
                
                self.logger.info("CLIENT: %s, DECRYPTED DATA OF STEP 9 OF DH :  %s", self.session.client_id, unpadded)              
                index1 = unpadded.index(b'::::')
                sent_nonce2 = unpadded[0:index1]
                nonce3_clientID = unpadded[index1+4:]
                index2 = nonce3_clientID.index(b'::::')
                coming_nonce3 = nonce3_clientID[0:index2]

                self.session.session_info.n3 = coming_nonce3 #nonce set

                #current_client_id = nonce3_clientID[index2+2:] #WRONG VERSION FOR NOT AUTH TESTING
                current_client_id = nonce3_clientID[index2+4:] #CORRECT VERSION 
                
                self.logger.info("CLIENT ID RECEIVED %s AND SESSION CLIENT ID : %s", current_client_id, self.session.client_id)
                self.logger.info("CLIENT: %s, NONCE 2 RECEIVED %s NONCE 2 SEND : %s", self.session.client_id, sent_nonce2, self.session.session_info.n2)
                self.logger.info("CLIENT: %s, NONCE 3 RECEIVED %s:", self.session.client_id, coming_nonce3)
             
                if current_client_id == force_bytes(self.session.client_id) and sent_nonce2 == force_bytes(self.session.session_info.n2):
                    
                    self.logger.info("CLIENT: %s, NONCES AND CLIENT IDs are the same", self.session.client_id)
                    self.logger.info("CLIENT: %s, CLIENT IS AUTHENTICATED", self.session.client_id)
                    self.logger.info("----FUNCTION: PREPARATION OF THE PUBLISH MESSAGE AT STEP 10 OF DH for CLIENT ID: %s----" , self.session.client_id)
                    self.session.session_info.authenticated = True
                    self.session.session_info.key_establishment_state = 9
                    value_str = force_str(coming_nonce3) + "::::" + self.session.client_id
                    value = force_bytes(value_str)
                    backend = default_backend()
                    encryptor = Cipher(algorithms.AES(self.session.session_info.session_key), modes.ECB(), backend).encryptor()
                    padder = padding2.PKCS7(algorithms.AES(self.session.session_info.session_key).block_size).padder()
                    padded_data = padder.update(value) + padder.finalize()
                    encrypted_text = encryptor.update(padded_data) + encryptor.finalize()
                   
                    self.logger.info("CLIENT: %s, ENCRYPTED TEXT TO BE SEND: %s", self.session.client_id, encrypted_text)
                    await self.mqtt_publish(self.session.client_id, data = encode_data_with_length(encrypted_text), qos=2, retain= False )
                   
                    self.logger.info("PUBLISH MESSAGE OF STEP 10 OF DH IS SENT TO CLIENT: %s ", self.session.client_id)


                    self.session.session_info.key_establishment_state = 10 #final state

                else: 
                    
                    self.logger.info("CLIENT: %s, CLIENT CANNOT AUTHENTICATED", self.session.client_id)
                    self.session.session_info.disconnect_flag = True

                    
                    notAuthMessage = self.session.session_info.client_id +  "::::" + "notAuthenticated"
                    value = force_bytes(notAuthMessage)
                    backend = default_backend()
                    encryptor = Cipher(algorithms.AES(self.session.session_info.session_key), modes.ECB(), backend).encryptor()
                    padder = padding2.PKCS7(algorithms.AES(self.session.session_info.session_key).block_size).padder()
                    padded_data = padder.update(value) + padder.finalize()
                    encrypted_text = encryptor.update(padded_data) + encryptor.finalize()
                    await self.mqtt_publish(self.session.client_id, data = encode_data_with_length(encrypted_text), qos=2, retain= False )
                   

                    await self.handle_connection_closed()
                    #send some message as not authenticated to stop paho from reconnnecting



   
    """ START 29mart2023 te eklendi """    

    async def handle_unsubscribe(self, unsubscribe: UnsubscribePacket):


        self.logger.info("WILL HANDLE UNSUBSCRIBE NOW")

        #assuming topic names
        topics_list = unsubscribe.payload.topics

        topics_decoded_list = []

        if self.session.session_info.authenticated:
            continue_decrypt = True
            for topic_mac_encrypted_hex in topics_list:
                if continue_decrypt:

                    topicn_mac_enc_byte = unhexlify(topic_mac_encrypted_hex)
                    backend = default_backend()
                    decryptor = Cipher(algorithms.AES(self.session.session_info.session_key), modes.ECB(), backend).decryptor()
                    padder = padding2.PKCS7(algorithms.AES(self.session.session_info.session_key).block_size).unpadder()
                    decrypted_data = decryptor.update(topicn_mac_enc_byte) 
                    unpadded = padder.update(decrypted_data) + padder.finalize()

                    index1 = unpadded.index(b'::::')
                    topic_name = unpadded[0:index1]
                    mac_unchecked = unpadded[index1+4:]

                    qos = str(1)

                    topic_concat_qos = topic_name + b'::::' + bytes(qos, 'utf-8')

                    h = hmac.HMAC(self.session.session_info.session_key, hashes.SHA256())
                    h.update(topic_concat_qos)
                    mac_duplicate_to_check = h.finalize()
                    
                    if (mac_duplicate_to_check == mac_unchecked):
                        self.logger.debug("MAC of this topic is same")
                        self.logger.info("CLIENT: %s, MAC OF THIS TOPIC (%s) IS SAME", self.session.client_id, topic_name)


                        topics_decoded_list.append(bytes.decode(topic_name, 'utf-8'))
                    else:
                        continue_decrypt = False
                        self.logger.info("CLIENT: %s, MAC OF THIS TOPIC (%s) IS NOT SAME", self.session.client_id, topic_name)
                        await self.sendBadMAC()


                else:
                    self.logger.debug("MAC of this topic is not the same")
                    self.logger.info("CLIENT: %s, MAC OF THIS TOPIC (%s) IS NOT THE SAME, WONT UNSUBSCRIBE THE CLIENT", self.session.client_id, topic_name)
                    #send bad mac if the macs do not match in order to inform the client
                    await self.sendBadMAC()

        list_to_set_unsub = []
        if self.session.session_info.authenticated:
            if continue_decrypt:
                list_to_set_unsub = topics_decoded_list
        else:
            list_to_set_unsub = topics_list


        unsubscription = {
            "packet_id": unsubscribe.variable_header.packet_id,
            "topics": list_to_set_unsub
        }
        await self._pending_unsubscriptions.put(unsubscription)

    async def get_next_pending_subscription(self):
        subscription = await self._pending_subscriptions.get()
        return subscription

    async def get_next_pending_unsubscription(self):
        unsubscription = await self._pending_unsubscriptions.get()
        return unsubscription

    async def mqtt_acknowledge_subscription(self, packet_id, return_codes):


        #bilgesu: modification
        if self.session.session_info.authenticated == True: 
            suback = SubackPacket.build(packet_id, return_codes, self.session.session_info.session_key) #build the packet with the signed version
            
            
        #bilgesu: modification end

        suback = SubackPacket.build(packet_id, return_codes, None) #build the packet in its default version
        await self._send_packet(suback)

    async def mqtt_acknowledge_unsubscription(self, packet_id):
        unsuback = UnsubackPacket.build(packet_id)
        await self._send_packet(unsuback)

    async def mqtt_connack_authorize(self, authorize: bool):
        if authorize:
            connack = ConnackPacket.build(self.session.parent, CONNECTION_ACCEPTED)
        else:
            connack = ConnackPacket.build(self.session.parent, NOT_AUTHORIZED)
        await self._send_packet(connack)

    @classmethod
    async def init_from_connect(
        cls, reader: ReaderAdapter, writer: WriterAdapter, plugins_manager, loop=None
    ):
        """

        :param reader:
        :param writer:
        :param plugins_manager:
        :param loop:
        :return:
        """
        remote_address, remote_port = writer.get_peer_info()
        connect = await ConnectPacket.from_stream(reader)
        await plugins_manager.fire_event(EVENT_MQTT_PACKET_RECEIVED, packet=connect)
        # this shouldn't be required anymore since broker generates for each client a random client_id if not provided
        # [MQTT-3.1.3-6]
        if connect.payload.client_id is None:
            raise MQTTException("[[MQTT-3.1.3-3]] : Client identifier must be present")

        if connect.variable_header.will_flag:
            if (
                connect.payload.will_topic is None
                or connect.payload.will_message is None
            ):
                raise MQTTException(
                    "will flag set, but will topic/message not present in payload"
                )

        if connect.variable_header.reserved_flag:
            raise MQTTException("[MQTT-3.1.2-3] CONNECT reserved flag must be set to 0")
        if connect.proto_name != "MQTT":
            raise MQTTException(
                '[MQTT-3.1.2-1] Incorrect protocol name: "%s"' % connect.proto_name
            )

        connack = None
        error_msg = None
        if connect.proto_level != 4:
            # only MQTT 3.1.1 supported
            error_msg = "Invalid protocol from %s: %d" % (
                format_client_message(address=remote_address, port=remote_port),
                connect.proto_level,
            )
            connack = ConnackPacket.build(
                0, UNACCEPTABLE_PROTOCOL_VERSION
            )  # [MQTT-3.2.2-4] session_parent=0
        elif not connect.username_flag and connect.password_flag:
            connack = ConnackPacket.build(0, BAD_USERNAME_PASSWORD)  # [MQTT-3.1.2-22]
        elif connect.username_flag and connect.username is None:
            error_msg = "Invalid username from %s" % (
                format_client_message(address=remote_address, port=remote_port)
            )
            connack = ConnackPacket.build(
                0, BAD_USERNAME_PASSWORD
            )  # [MQTT-3.2.2-4] session_parent=0
        elif connect.password_flag and connect.password is None:
            error_msg = "Invalid password %s" % (
                format_client_message(address=remote_address, port=remote_port)
            )
            connack = ConnackPacket.build(
                0, BAD_USERNAME_PASSWORD
            )  # [MQTT-3.2.2-4] session_parent=0
        elif connect.clean_session_flag is False and (
            connect.payload.client_id_is_random
        ):
            error_msg = (
                "[MQTT-3.1.3-8] [MQTT-3.1.3-9] %s: No client Id provided (cleansession=0)"
                % (format_client_message(address=remote_address, port=remote_port))
            )
            connack = ConnackPacket.build(0, IDENTIFIER_REJECTED)
        if connack is not None:
            await plugins_manager.fire_event(EVENT_MQTT_PACKET_SENT, packet=connack)
            await connack.to_stream(writer)
            await writer.close()
            raise MQTTException(error_msg)

        incoming_session = Session()
        incoming_session.client_id = connect.client_id
        incoming_session.clean_session = connect.clean_session_flag
        incoming_session.will_flag = connect.will_flag
        incoming_session.will_retain = connect.will_retain_flag
        incoming_session.will_qos = connect.will_qos
        incoming_session.will_topic = connect.will_topic
        incoming_session.will_message = connect.will_message
        incoming_session.username = connect.username
        incoming_session.password = connect.password

        #modification --> client info added, ke state is currently equal to 0, other fields are none right now.
        incoming_session.session_info.client_id = connect.client_id
        #Burcu-29Mart

        #call push to database from clientconnection.py to create the record of this session with the related key pairs, session states and created session keys
        pushRowToDatabase(incoming_session.session_info.client_id, incoming_session.session_info.key_establishment_state, 
                          incoming_session.session_info.client_spec_pub_key, incoming_session.session_info.client_spec_priv_key)

        if connect.keep_alive > 0:
            incoming_session.keep_alive = connect.keep_alive
        else:
            incoming_session.keep_alive = 0

        handler = cls(plugins_manager, loop=loop)
        return handler, incoming_session
