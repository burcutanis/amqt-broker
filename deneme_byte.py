import os
from OpenSSL import crypto, SSL
from diffiehellman import DiffieHellman



def cert_gen(
    dh_obj: DiffieHellman,
    CERT_FILE,
    emailAddress="emailAddress",
    commonName="commonName",
    countryName="TR",
    localityName="localityName",
    stateOrProvinceName="stateOrProvinceName",
    organizationName="organizationName",
    organizationUnitName="organizationUnitName",
    serialNumber=0,
    validityStartInSeconds=0,
    validityEndInSeconds=2*365*24*60*60):
    #can look at generated file using openssl:
    #openssl x509 -inform pem -in selfsigned.crt -noout -text
    # create a key pair
    
    pub_key = dh_obj.get_public_key()
    priv_key = dh_obj.get_private_key()
    

    # create a self-signed cert


    try:
        cert = crypto.X509()
        cert.get_subject().C = countryName
        cert.get_subject().ST = stateOrProvinceName
        cert.get_subject().L = localityName
        cert.get_subject().O = organizationName
        cert.get_subject().OU = organizationUnitName
        cert.get_subject().CN = commonName
        cert.get_subject().emailAddress = emailAddress
        cert.set_serial_number(serialNumber)
        cert.gmtime_adj_notBefore(validityStartInSeconds)
        cert.gmtime_adj_notAfter(validityEndInSeconds)
        cert.set_issuer(cert.get_subject())
        
        try:
            cert.set_pubkey(pub_key)
            cert.sign(priv_key, 'sha512')

            try:
                with open(CERT_FILE, "wt") as f:
                    f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8"))

            except Exception as e:
                print(e.args)

        
        except Exception as e1:
            print("2nd inner exception")
            print(e1.args)

    except:
        print("exception occured (outer exception).")
        


folder_path = "certificates"  # Replace with the actual folder path
file_name = "cert_sample.crt"

if not os.path.exists(os.path.join(folder_path, file_name)):
    print("no such file", file_name)
    open(os.path.join(folder_path, file_name), 'a').close()
else:
    print("file exists: %s.", file_name)

    #delete file
    os.remove(os.path.join(folder_path, file_name))

    print("file deleted, creating new file")

    open(os.path.join(folder_path, file_name), 'a').close()


dh1 = DiffieHellman(group=14, key_bits=2048)    #bilgesu: key size increased to 2048

cert_gen(dh1, file_name)


