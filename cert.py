# ssl imports
from socket import socket
import ssl
import OpenSSL

# sqlalchemy imports
from sqlalchemy import Column, Integer, Unicode, UnicodeText, String, Boolean
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base

engine = create_engine('sqlite:///./cert.db') # , echo=True)
Base = declarative_base(bind=engine)

# describe certificate fields
class Certificate(Base):
    __tablename__ = 'certificates'
    id = Column(Integer, primary_key=True)
    
    server_address = Column(UnicodeText)
    server_port = Column(Integer)
    
    pem = Column(UnicodeText)
    
    subject = Column(UnicodeText())
    c = Column(String(30))
    l = Column(String(30))
    o = Column(String(30))
    st = Column(String(200))
    cn = Column(String(200))

    notAfter = Column(UnicodeText) # TODO to date
    notBefore = Column(UnicodeText) # TODO to date
    expired = Column(Boolean)
    
    version = Column(Integer)

    def __init__(self, server_address, server_port):
        self.server_address = server_address
        self.server_port = server_port

Base.metadata.create_all()

def get_session():
    Session = sessionmaker(bind=engine)
    return Session()


#
# ! need a ca-bundle.crt file
#
def get_certicate(server):
    
    certificate = Certificate(server[0], server[1])

    certificate.pem = ssl.get_server_certificate(server)

    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certificate.pem)

    # x509 object
    # https://pyopenssl.org/en/stable/api/crypto.html#x509-objects

    subject = ""
    for component, value in x509.get_subject().get_components():
        subject += "{}:{}\n".format(component.decode("utf-8"), value.decode("utf-8"))

    #certificate.cn = x509.get_subject().get_components()['CN']
    #certificate.o  = x509.get_subject().get_components()["O"]
    #certificate.l  = x509.get_subject().get_components()["L"]
    #certificate.c  = x509.get_subject().get_components()["C"]
    #certificate.st = x509.get_subject().get_components()["ST"]
    certificate.subject = subject

    
    certificate.notBefore = x509.get_notBefore()
    certificate.notAfter = x509.get_notAfter()
    certificate.expired = x509.has_expired()

    certificate.version = x509.get_version()    

    return certificate


SERVERS = [("google.fr", 443), ("twitter.fr", 443)]


if __name__ == "__main__":
    s = get_session()

    for server in SERVERS:
        s.add(get_certicate(server))

    s.commit()

