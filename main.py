


spams = False

spampacket= b''
recordmode= False

sendpackt=False
global vares
vares = 0
spy = False
inviteD=False
inviteE=False
global statues
statues= True
SOCKS_VERSION = 5
packet =b''
spaming =True
import os
import sys


def spam(server,packet):
    while True:


        time.sleep(0.015)


        server.send(packet)
        if   recordmode ==False:

            break

def destroy(remote,dataC):

    var= 0
    for i in range(50):

        var= var+1

        time.sleep(0.010)
        for i in range(10):

            remote.send(dataC)
    time.sleep(0.5)




def timesleep():
    time.sleep(60)
    #print(istarted)
    if istarted == True:
        serversocket.send(start)


def enter_game_and_RM():
    global listt
    for data in listt:
        print(f'number of gameplayed ![{gameplayed}]')
        C.send(data)
        listt.remove(data)
    time.sleep(10)

    print("start the game ....")

    istarted =False
    serversocket.send(start)

    t = threading.Thread(target=timesleep, args=())
    t.start()
def break_the_matchmaking(server):
    global is_start
    global isrun

    server.send(stop)


    server.send(stop)

    server.send(stop)
    print('sending stop')
    is_start =True

    t = threading.Thread(target=enter_game_and_RM, args=())
    t.start()


import time

import socket
import threading
import select
SOCKS_VERSION= 5


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
            #print(" connect to {} \n \n \n ".format(address))
            bind_address = remote.getsockname()

            addr = int.from_bytes(socket.inet_aton(
                bind_address[0]), 'big', signed=False)
            port = bind_address[1]

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


        self.botdev(connection, remote,port2)


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


            version = ord(connection.recv(1))


            username_len = ord(connection.recv(1))
            username = connection.recv(username_len).decode('utf-8')

            password_len = ord(connection.recv(1))
            password = connection.recv(password_len).decode('utf-8')
            #   print(username,password)
            if username == self.username and password == self.password:

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
        try:
            var =  0







            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            #s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((host, port))
            s.listen()



            while True:
                var =var+1


                conn, addr = s.accept()
                running = False

                t = threading.Thread(target=self.handle_client, args=(conn,))
                t.start()
        except Exception as e:
            sxaes=2323
            restart()









    #
    def botdev(self, client, remote, port):
        
            while True:
                r, w, e = select.select([client, remote], [], [])

                od= b''
                global start
                if client in r or remote in r:
                    global invite
                    global invite2
                    global s
                    global x
                    global serversocket
                    global isconn ,inviteD ,des
                    if client in r:



                        dataC = client.recv(999999)


                        if port ==39800 or port ==39698:
                            isconn=True
                        if  "39698" in str(remote) :
                            self.op = remote
                
                        if '0515' in dataC.hex()[0:4] and len(dataC.hex()) >= 141  :                  
                            self.data_join=dataC

                            
                        
                        if '0515' in dataC.hex()[0:4] and len(dataC.hex()) <50  :  
                            print(remote)                
                            self.data_back=dataC

                        if  port ==39698:
                            #print(" catch a socket sir ")
                            #  print(f"{dataC}\n")
                            invite= remote
                        global hide
                        hide =False
                        global recordmode
                        if '1215' in dataC.hex()[0:4] and recordmode ==True:

                            global spampacket
                            spampacket =dataC

                            #recordmode=False
                            global statues
                            statues= True
                            time.sleep(5)

                            b = threading.Thread(target=spam, args=(remote,spampacket))
                            b.start()



                        if '0515' in dataC.hex()[0:4] and len(dataC.hex()) >=900 and inviteD==True and hide ==False :
                            var = 0
                            m = threading.Thread(target=destroy, args=(remote,dataC))
                            m.start()
                            global spams
                            spams =True

                        if '0515' in dataC.hex()[0:4] and len(dataC.hex()) >= 141:

                            hide = True


                            global benfit
                            benfit = False
                        global inviteE
                        #inviteE
                        if '0515' in dataC.hex()[0:4] and len(dataC.hex()) ==108 or  len(dataC.hex()) ==108 and hide ==True and inviteE==True:

                            hide =False
                            for i in range(100):

                                for i in range(20):

                                    remote.send(dataC)
                        if '0515' in dataC.hex()[0:4] and len(dataC.hex()) ==140 or  len(dataC.hex()) ==140 and hide ==True and inviteE==True:

                            hide =False
                            for i in range(100):

                                for i in range(20):

                                    remote.send(dataC)
                        if '0315' in dataC.hex()[0:4]:
                            if len(dataC.hex()) >=300:
                                start = dataC
                                print(dataC)
                            is_start =False

                            serversocket =remote
                            print("socket is defined suucesfuly !..")
                            t = threading.Thread(target=timesleep, args=())
                            t.start()


                        if remote.send(dataC) <= 0:
                            break
                    if remote in r:

                        global opb
                        global listt
                        global C
                        global istarted
                        global gameplayed
                        global packet
                        global socktion
                        global increase ,des
                        dataS = remote.recv(999999)
                        
                        print("respons ---->[{}]".format(dataS.hex()[26:30]))
                        if '1809' in dataS.hex()[26:30] or "1802" in dataS.hex()[26:30] or "1808" in dataS.hex()[26:30]:
                            #des=False
                            print(dataC.hex()[0:4])
                            print('  the team ')
                            #hackg.send(hackw
                        

                        if '0300' in dataS.hex()[0:4] :
                            #print('yes')
                            C = client
                            print(dataS)
                            socketsender =client

                            if b'Ranked Mode' in dataS:
                                #print("w")
                                client.send(dataS)
                            else:



                                if b'catbarq' in dataS:
                                    vdsf=3
                                else:
                                    #
                                    hackw= dataS
                                    hackg= client

                                    if len(dataS.hex()) <= 100:
                                        e=2
                                    #  print("anti detect !")


                                    else:
                                        if increase ==True:

                                            print("Enter game packet founded")
                                            #      start = dataC
                                            #      print(dataC)
                                            gameplayed =gameplayed+1
                                            istarted = True
                                            #      print(f"{dataS} \n")
                                            listt.append(dataS)
                                            #rint(listt)
                                            t = threading.Thread(target=break_the_matchmaking, args=(serversocket,))
                                            t.start()
                                        else:
                                            client.send(dataS)

                        else:
                            #  if '0000' !in dataS.hex()[:4] and '1200' !in dataS.hex()[:4] and '1700' !in dataS.hex()[:4]:
                            #  print(dataS.hex(),"\n")
                            if '0500' in dataS.hex()[:4] and b'\x05\x15\x00\x00\x00\x10Z\xca\xf5&T;\x0cA\x01\x16\xe0\x05\xb2\xea\xe4\x0b' in dataC:
                                f=2
                                #serversocket.send(b'\x05\x15\x00\x00\x00\x10\x9b@x\xd7\x15\x9e\x0f\xfaZ+\x88\xe5\xac\x18\x9fw')

                            else:
                                
                                if '1200' in dataS.hex()[0:4] and '2f696e76' in dataS.hex()[0:900] :
                                    client.send(bytes.fromhex(gen_msgv2(dataS.hex() ,"[E0FF00]Destroy Group : [00FF00]ON")))
                                    client.send(bytes.fromhex(str(gen_msgv2_clan(dataS.hex() ,"[E0FF00]Destroy Group : [00FF00]ON"))))
                                    inviteD =False
                                if '1200' in dataS.hex()[0:4] and '2f2d696e76' in dataS.hex()[0:900] :
                                    inviteD =False
                                    client.send(bytes.fromhex(gen_msgv2(dataS.hex() ,"[E0FF00]Destroy Group : [00FF00]OFF")))
                                    client.send(bytes.fromhex(str(gen_msgv2_clan(dataS.hex() ,"[E0FF00]Destroy Group : [00FF00]OFF"))))                                  
                                if '1200' in dataS.hex()[0:4] and '2f6c766c' in dataS.hex()[0:900] :
                                    increase =True
                                    print("bb")
                                    client.send(bytes.fromhex(gen_msgv2(dataS.hex() ,"[E0FF00]LEVEL UP : [00FF00]ON")))
                                    client.send(bytes.fromhex(str(gen_msgv2_clan(dataS.hex() ,"[E0FF00]LEVEL UP : [00FF00]ON"))))
                                #stop:cs :
                                if '1200' in dataS.hex()[0:4] and '2f2d6c766c' in dataS.hex()[0:900] :
                                    increase =False
                                    client.send(bytes.fromhex(gen_msgv2(dataS.hex() ,"[E0FF00]LEVEL UP : [00FF00]OFF")))
                                    client.send(bytes.fromhex(str(gen_msgv2_clan(dataS.hex() ,"[E0FF00]LEVEL UP : [00FF00]OFF"))))
                                    print("bb")
                                #/back :
                                if '1200' in dataS.hex()[0:4] and '2f6261636b' in dataS.hex()[0:900] :

                                    client.send(bytes.fromhex(gen_msgv2(dataS.hex() ,"[00FF00]Return ok!")))
                                    client.send(bytes.fromhex(str(gen_msgv2_clan(dataS.hex() ,"[00FF00]Return ok!"))))
                                    socktion.send(packet)
                                #  /5
                                if '1200' in dataS.hex()[0:4] and '6635' in dataS.hex()[0:900]:
                                    client.send(bytes.fromhex(gen_msgv2(dataS.hex() ,"[00FF00]تشكيل لفريق لوضح 5 ")))
                                    client.send(bytes.fromhex(str(gen_msgv2_clan(dataS.hex() ,"[00FF00]تشكيل لفريق لوضح 5"))))
                                    invite.send(bytes.fromhex("0503000001d01fb578313150905babcef51dd24ed75fd0a24b024bd1429646114bc22e604afd35a96fbc48710b2d9cfec4378287ec829e33a78608fd2dd138d4d24a19c00fbfdc9f15c77ff86d638b34de95bd886e3075e82d3f4a3888f9b6943463022c43fb90e229f0eaf8a788f6f766d891d99eb2c37b277144923212810b3c80d1c521790154ed270f5241adc136f2a22816e0bc84fcaf79386b27559de966aa788c184d35bbbfaa03a5f08746f8db0e73b2c91ec4515d61f689a0cad30a7cbd6c325151e879dabc43d506b3240abe41bc0d6b4416c18f68ef4af2d04c381be6bf586f6b25727c0c85c03a579137e4a6c602ef6d833dabdab3eba3a5266e5a4731fbfb1720b60f124cd8fd4fa26cc7a9fb6e0a218d8809f57b204d22fa97520aeb99007c7b71c709e53ecc688c9963e0786909152fa93f06dc93085468dae34e1609f33f7dee228fb058c6efd6846b50ac54db0aebb8f5bc2f6751f9e2886dbab41cbaf5a1d8cd88e6c13a2a2a56b613a2d32179dc3f781493a5027322ac0cb1a2d3c79d49fb12ed26230e1561df43d315a27be17b5debdba757803305252b5443f3d77cd319dde9c49a72c636d93d02bdd9597168f378aa6e41d0fd545abf8bc0883f3dac11ea27166683c7111a0f329bf6b6a5"))

                                #/4
                                #   invite.send(b'\x05\x15\x00\x00\x00\x104\xc3\xa2"\xdf\xc4\x8c\x93\x81|\xc4\x8d\xe5\xe8\xbe\xb1')
                                if '1200' in dataS.hex()[0:4] and '6634' in dataS.hex()[0:900]:
                                    #    print("cmake 4 in squad sir ")
                                    client.send(bytes.fromhex(gen_msgv2(dataS.hex() ,"[00FF00]Send 4 Mode ok!")))
                                    client.send(bytes.fromhex(str(gen_msgv2_clan(dataS.hex() ,"[00FF00]send 4 Mode ok!"))))
                                    invite.send(b'\x05\x15\x00\x00\x00 \xf3\x7f\x06i,\x9d\xbe$Z\xf3|\xb3\xdfO\xc5\xf4\x8bT\x8b\xf7Y\x1b\xe3\x8cY \x93:\x88\xa6\xfd\\')

                                if '1200' in dataS.hex()[0:4] and '2f7370616d' in dataS.hex()[0:900] and spaming:
                                    client.send(bytes.fromhex(gen_msgv2(dataS.hex() ,"[E0FF00]Write Your Message : ")))
                                    client.send(bytes.fromhex(str(gen_msgv2_clan(dataS.hex() ,"[E0FF00]Write Your Message :"))))

                                    recordmode = False

                                if '1200' in dataS.hex()[0:4] and '2f2d7370616d' in dataS.hex()[0:900]:
                                    recordmode=False
                                    client.send(bytes.fromhex(gen_msgv2(dataS.hex() ,"[E0FF00]Spam Chat : [00FF00]Stopped")))
                                    client.send(bytes.fromhex(str(gen_msgv2_clan(dataS.hex() ,"[E0FF00]Spam Chat : [00FF00]Stopped"))))
                                if '1200' in dataS.hex()[0:4]:
                                    if b"/des" in dataS:
                                        des=False
                                        threading.Thread(target=self.spam , args=(self.data_join,)).start()
                                        
                                        client.send(bytes.fromhex(str(gen_msgv2_clan(dataS.hex() ,"[E0FF00]Antikick : [00FF00]ON"))))


                                    statues= False
                                if "1200" in dataS.hex()[0:4]:
                        
                                    if b"3sby" in dataS:
                                        print(dataS.hex())
                                        try:
                                            user_id= (bytes.fromhex(re.findall(r'33736279(.*?)28' , dataS.hex()[50:])[0])).decode("utf-8")
                                            print(user_id)
                                            threading.Thread(target=getinfobyid , args=(dataS.hex() , user_id , client)).start()  
                                        except:
                                            pass

                                if  '0500' in dataS.hex()[0:4] and hide == True  :
                                    socktion =client


                                    if len(dataS.hex())<=30:

                                        hide =True
                                    if len(dataS.hex())>=31:
                                        packet = dataS

                                        hide = False

                                if client.send(dataS) <= 0:
                                    break
        
    def spam( self , data_join):
        global des
        print(data_join)
        
        while des==True:
            try:
                self.op.send(data_join)
                time.sleep(0.4)
                self.op.send(self.data_back)
                #                           0515000000104903408b9e91774e75b990038dddee49
            except Exception as e:
                
                pass

def start_bot():
    try :
        Proxy().runs('127.0.0.1',3000)
    except Exception as e:
        restart()
        sea=2
start_bot():