from OpenSSL import crypto, SSL
from cryptography import x509
from OpenSSL.crypto import (load_certificate, dump_privatekey, dump_certificate, X509, X509Name, PKey)
from OpenSSL.crypto import (TYPE_DSA, TYPE_RSA, FILETYPE_PEM, FILETYPE_ASN1 )
from datetime import datetime
import textwrap
import os


#bilgesu: for now, certificstes can be hold in /certificates, a better solution can be generated later on

def create_certificate( handler_obj, pub_key = None, priv_key = None, client_id: str = None):

    handler_obj.logger.debug("in create_certificate, certificate_operations.py")

    folder_path = "certificates"  # Replace with the actual folder path
    file_name = "cert_" + str(client_id) + ".crt" #client specific certificate

    if not os.path.exists(os.path.join(folder_path, file_name)):
        handler_obj.logger.debug("no such file: %s", file_name)
        open(os.path.join(folder_path, file_name), 'a').close()
    else:
        handler_obj.logger.debug("file exists: %s.", file_name)

        #delete file
        os.remove(os.path.join(folder_path, file_name))

        handler_obj.logger.debug("file deleted, new empty file is to be created with the same name: %s.", file_name)
        open(os.path.join(folder_path, file_name), 'a').close()

    
    #create the certificate


    return


def read_certificate(handler_obj, file_name: str = None, pem_inf0 = None):

    handler_obj.logger.debug("in read_certificate, certificate_operations.py")


    return