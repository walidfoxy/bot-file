import time
import socket
import threading
import select



print("Hello World")

benfit = False
spams = False
spampacket= b''
recordmode= False
sendpackt=False
spy = False
inviteD=False
global statues
statues= True
SOCKS_VERSION = 5
packet =b''
spaming =False
op = None
def spam(server,packet):
    while True:
     

        time.sleep(0.009)
  
   
        server.send(packet)
        if  statues == False:


            break
            
class Proxy:

    def __init__(self):
        self.username = "username"
        self.password = "username"
        self.packet = b''
        self.sendmode = 'client-0-'
    def handle_client(self, connection):
    
    
        version, nmethods = connection.recv(2)
        methods = self.get_available_methods(nmethods, connection)
 
  

        if 2   in set(methods):
            if 2 in set(methods):

                connection.sendall(bytes([SOCKS_VERSION, 2]))
            else:
                connection.sendall(bytes([SOCKS_VERSION, 0]))
                
    

   

        if not self.verify_credentials(connection,methods):
            return
        version, cmd, _, address_type = connection.recv(4)
        
        

        if address_type == 1:
            address = socket.inet_ntoa(connection.recv(4))
        elif address_type == 3:
            domain_length = connection.recv(1)[0]
            address = connection.recv(domain_length)
            address = socket.gethostbyname(address)
            name= socket.gethostname()
        


        port = int.from_bytes(connection.recv(2), 'big', signed=False)
        port2 = port
        try:
        
            remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote.connect((address, port))
            bind_address = remote.getsockname()

            addr = int.from_bytes(socket.inet_aton(
                bind_address[0]), 'big', signed=False)
            port = bind_address[1]
            
           # print(f"address {address}\n")

            reply = b''.join([
                SOCKS_VERSION.to_bytes(1, 'big'),
                int(0).to_bytes(1, 'big'),
                int(0).to_bytes(1, 'big'),
                int(1).to_bytes(1, 'big'),
                addr.to_bytes(4, 'big'),
                port.to_bytes(2, 'big')

            ])
        except Exception as e:
        

            reply = self.generate_failed_reply(address_type, 5)
         

        connection.sendall(reply)

        
        self.botdev(connection, remote,address)
     

    def generate_failed_reply(self, address_type, error_number):
        return b''.join([
            SOCKS_VERSION.to_bytes(1, 'big'),
            error_number.to_bytes(1, 'big'),
            int(0).to_bytes(1, 'big'),
            address_type.to_bytes(1, 'big'),
            int(0).to_bytes(4, 'big'),
            int(0).to_bytes(4, 'big')
        ])

    def verify_credentials(self, connection,methods):

        if 2 in methods:
            global spy,inviteD,spaming,inviteE
     
            
            version = ord(connection.recv(1))
        

            username_len = ord(connection.recv(1))
            data = connection.recv(username_len).decode('utf-8')

            password_len = ord(connection.recv(1))
            password = connection.recv(password_len).decode('utf-8')
            length_data= len(data)
            length_data = int(length_data)
            #print(data,password)

            if data == self.username and password == self.password:

                response = bytes([version, 0])
                connection.sendall(response)
         
 
                return True
            
            response = bytes([version, 0])
            connection.sendall(response)
      
            return True
        else:
       
          
            
            version =1 
            response = bytes([version, 0])
            connection.sendall(response)
            
 
            return True

    def get_available_methods(self, nmethods, connection):
        methods = []
        for i in range(nmethods):
            methods.append(ord(connection.recv(1)))
        return methods

    def runs(self, host, port):
        

     
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind((host, port))
        s.listen()
        
        #print(' \n \n \n fffffffffffffff')
     
        while True:
        
            conn, addr = s.accept()
            running = False
            t = threading.Thread(target=self.handle_client, args=(conn,))
            t.start()



     



#  

    def botdev(self, client, remote,addr):

    
            
            
  
        while True:
            r, w, e = select.select([client, remote], [], [])
            if client in r or remote in r:
                if client in r:
                    global packet
                    global op
                    dataC = client.recv(99999)
                    global hide
                    hide =False
                    global recordmode                    
                    global timer
                    global spy

                        
                    if '1215' in dataC.hex()[0:4] and recordmode ==True:
                        #print('catch packet ')
                        for i in range(10):
                            remote.send(dataC)
                        global spampacket
                        spampacket =dataC
                        #print(spampacket)
                        recordmode=False
                        global statues
                        statues= True
                        #print('closeing record ')
                        b = threading.Thread(target=spam, args=(remote,spampacket))
                        b.start()
                        #InviteD
                    if '0515' in dataC.hex()[0:4] and len(dataC.hex()) >=820 and inviteD==True  :
                        var = 0
                        for i in range(1):

                            

                            for i in range(50):
                                
                                var= var+1
                                print(' "\033[1;33m"  The  "\033[1;31m"a [{}] "\033[1;34m" Foxy '.format(var))
                                time.sleep(0.0012)
                                for i in range(10):
                                    
                                    remote.send(dataC)
                            time.sleep(0.5)
      
                 
                    if '0515' in dataC.hex()[0:4] and len(dataC.hex()) >= 141:
                        print('Donee')

                        
                        hide = True
                        print(len(dataC.hex()))
                        print(dataC.hex())
                        if hide == True:
                            print('done')
                        
                                                                                                         #inviteE


                    if '0515' in dataC.hex()[0:4] or '23.90.158.22' in addr :
                        #print(dataC)
                    #    print("succes get")
                        
                      #  print(f"addres {addr}\n")
                        op = remote
                        od=dataC
                    if remote.send(dataC) <= 0:
                        break
                if remote in r:
                    dataS = remote.recv(999999)
                    if '1200' in dataS.hex()[0:4]:
                        if b'/Foxy' in dataS:
                            spy=True
                        if b'/-Foxy' in dataS:
                            
                            spy=False
                            pass

#5sqoud

                    if '1200' in dataS.hex()[0:4] and '6135' in dataS.hex()[0:900]:
                    
                        #invite.send(b'\x05\x03\x00\x00\x00 \x8b\x14\xe3`7rI\xde\x8f7t\x8e\x84i\xc0\x06\xb9o\xee\xb2{.\xbd\xed\x8cS\xd0n\n#\xc0\xb8')
                        op.send(bytes.fromhex("0503000001d01fb578313150905babcef51dd24ed75fd0a24b024bd1429646114bc22e604afd35a96fbc48710b2d9cfec4378287ec829e33a78608fd2dd138d4d24a19c00fbfdc9f15c77ff86d638b34de95bd886e3075e82d3f4a3888f9b6943463022c43fb90e229f0eaf8a788f6f766d891d99eb2c37b277144923212810b3c80d1c521790154ed270f5241adc136f2a22816e0bc84fcaf79386b27559de966aa788c184d35bbbfaa03a5f08746f8db0e73b2c91ec4515d61f689a0cad30a7cbd6c325151e879dabc43d506b3240abe41bc0d6b4416c18f68ef4af2d04c381be6bf586f6b25727c0c85c03a579137e4a6c602ef6d833dabdab3eba3a5266e5a4731fbfb1720b60f124cd8fd4fa26cc7a9fb6e0a218d8809f57b204d22fa97520aeb99007c7b71c709e53ecc688c9963e0786909152fa93f06dc93085468dae34e1609f33f7dee228fb058c6efd6846b50ac54db0aebb8f5bc2f6751f9e2886dbab41cbaf5a1d8cd88e6c13a2a2a56b613a2d32179dc3f781493a5027322ac0cb1a2d3c79d49fb12ed26230e1561df43d315a27be17b5debdba757803305252b5443f3d77cd319dde9c49a72c636d93d02bdd9597168f378aa6e41d0fd545abf8bc0883f3dac11ea27166683c7111a0f329bf6b6a5"))
                    if '1200' in dataS.hex()[0:4] and b'a4' in dataS:
                      
                        op.send(b'\x05\x15\x00\x00\x00 \xf3\x7f\x06i,\x9d\xbe$Z\xf3|\xb3\xdfO\xc5\xf4\x8bT\x8b\xf7Y\x1b\xe3\x8cY \x93:\x88\xa6\xfd\\')
                    if '1200' in dataS.hex()[0:4] and '2f73' in dataS.hex()[0:900] :
                        recordmode = True
                        #print('recording now ')
                    if '1200' in dataS.hex()[0:4] and '2f66' in dataS.hex()[0:900]:
                    
                    
                        statues= False
                        #print('done break')
                        #print(statues)
                    if  '0500' in dataS.hex()[0:4] and spams == True :
                        if '050000000' in dataS.hex():
                            benfit = True   
                   
                     
                    if  '0500' in dataS.hex()[0:4] and hide == True and benfit == False :
                    
                    
                        if len(dataS.hex())<=30:
                            #print("packet is not True")
                            hide =True
                        if len(dataS.hex())>=31:
                            packet = dataS
                            #print('[{}]'.format(packet.hex()))
                            hide = False
                    if  '0f00' in dataS.hex()[0:4] and spy==True :
                    
                    
                        client.send(packet)
                        print(packet)
                    if '1808' in dataS.hex()[26:30]:
                            print('  the team capacity is full  stop ')

                    if client.send(dataS) <= 0:
                        break
        




def go():

       


    Proxy().runs('127.0.0.1',3000)
            
        
        



  

    
	    
    
   







    



m = threading.Thread(target=go, args=())
m.start()
