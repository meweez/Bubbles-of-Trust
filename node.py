from flask import Flask, render_template, redirect, request,send_file
import datetime
import json
import requests
from tkinter import *
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
import zipfile,os
from werkzeug.utils import secure_filename 




node = None
app = None
name = None
server = None
miner = None
port = None
category = None
ip = None
group = None
ticket = None

def clicked():
    global node
    global  app
    global  name,server,port,miner
    name = txt1.get().strip()
    server = txt2.get().strip()
    port = txt3.get().strip()
    miner = txt4.get().strip()
    if name != "" and server != "" and port != "" and miner != "" :
        app = Flask(__name__)
        window.destroy()
       

window = Tk()
window.title("Welcome")
window.geometry('350x200')
lbl = Label(window, text="please type your name",font=("Arial Bold", 10))
lbl.grid(column=0, row=0)
txt1 = Entry(window, width=10)
txt1.grid(column=1, row=0)
txt1.focus()
lbl = Label(window, text="please type your block chain address",font=("Arial Bold", 10))
lbl.grid(column=0, row=1)
txt2 = Entry(window, width=10)
txt2.grid(column=1, row=1)
lbl = Label(window, text="please type your port number",font=("Arial Bold", 10))
lbl.grid(column=0, row=2)
txt3 = Entry(window, width=10)
txt3.grid(column=1, row=2)
lbl = Label(window, text="please type miner address",font=("Arial Bold", 10))
lbl.grid(column=0, row=3)
txt4 = Entry(window, width=10)
txt4.grid(column=1, row=3)

btn = Button(window, text="OK", command=clicked)
btn.grid(column=1, row=4)
window.mainloop()
#--------------------------------------------------------------------------
#master key 
# key length must be a multiple of 256 and >= 2048
modulus_length = 256*8
privatekey_master = RSA.generate(modulus_length, Random.new().read)
publickey_master = privatekey_master.publickey()


#--------------------------------------------------------------------------
#routes	
@app.route('/registerform')
def regform():
    return render_template('reg.html',
                           title='REGISTER')

@app.route('/register', methods=['POST','Get'])
def reg():
    global category,ip,group
    ip = request.form["ip"]
    category = request.form["category"]
    group = request.form["group"]
    #time to make a transaction and create this group
    #onja  bayad unique bodan ha check beshe ha !!!!!
    #print(category)
    #-----------------------------register master----------------------------
    if request.method == 'POST' and ip!="" and category!="" and group!="":
        global port,name
        if(category == "master"):           

            ticket = {
                "group" : group,
                "name" : name,
                "Pubaddress": publickey_master.exportKey('PEM').decode()
            }
        
            f = open("pubkey.pem" ,'wb')
            public_key = publickey_master.exportKey('PEM')
            f.write(public_key)
            f.close()

            ff = open("prkey.pem" ,'wb')
            private_key = privatekey_master.exportKey('PEM')
            ff.write(private_key)
            ff.close()

            fff = open("ticket.txt" ,'w')
            fff.write(json.dumps(ticket))
            fff.close()

            zf = zipfile.ZipFile("master_keys.zip",mode='w')
            zf.write("pubkey.pem")
            zf.write("prkey.pem")
            zf.write("ticket.txt")
            zf.close()
            # save key of master
            	

            post_object = {
                        'type' : "register",
                        'ip' : ip,
                        'port' : port,
                        'category': category,
                        'group': group,
                        'name' : name,
                        'ticket' : json.dumps(ticket)
                        }

            # Submit a transaction
            new_tx_address = "{}/new_transaction".format(miner)

        
            requests.post(new_tx_address,
                      json=post_object,
                      headers={'Content-type': 'application/json'})
    #----------------------------register follower---------------------------
        elif (category == "follower"):
            #bayad ticketesh ro as master on group begire bede khodesh 
        
            
            if 'ticket' not in request.files:
                return redirect('/registerform')
            ticket_txt = request.files.get('ticket')
            ticket = ticket_txt.read()
            #print(ticket)

            post_object = {
                        "type" : "register",
                        "ip" : ip,
                        "port" : port,
                        "category": category,
                        "group": group,
                        "name" : name,
                        "ticket" : ticket.decode()
                        }

        
            # Submit a transaction
            new_tx_address = "{}/new_transaction".format(miner)

        
            requests.post(new_tx_address,
                      json=post_object,
                      headers={'Content-type': 'application/json'})


    #request to mine
    mine_address = "{}/mine".format(miner)
    response = requests.get(mine_address)
    #print(response.json())
    if response.json()=="True" :
        if category == "master":
            return redirect('/master')
        else:
            return redirect('/follower')
    else :
        return redirect('/registerform')


@app.route('/getticket')
def get_ticket():
    return render_template('ticket.html',
                           title='GET TICKET')

@app.route('/ticket', methods=['POST','Get'])
def ticket():
    name = request.form["name"]
    global category 
    if name == "" :
        return render_template('show_ticket.html',
                           title='please type your name')
    if category != "master" :
        return render_template('show_ticket.html',
                           title='I AM NOT ROOT')  
 
    # key length must be a multiple of 256 and >= 2048
    #felan farz konim master ke ticket nemikhad berim jelo
    #bayad ba private e master ramz beshe ha na khodesh
    # felan be hame mide in ticketo
    modulus_length = 256*8
    privatekey = RSA.generate(modulus_length, Random.new().read)
    publickey = privatekey.publickey()
    

    ticket = {
                "group" : group,
                "name" : name,
                "Pubaddress": publickey.exportKey('PEM').decode()
    }
    json_dumps = json.dumps(ticket,sort_keys=True)
    h = SHA256.new(json_dumps.encode())  
    K =''
    master_sign = privatekey_master.sign(h.digest(),K)
    ticket["master_sign"] = master_sign

    json_dumps2 = json.dumps(ticket,sort_keys=True)
    h2 = SHA256.new(json_dumps2.encode())  
    K =''
    follower_sign = privatekey.sign(h2.digest(),K)
    ticket["follower_sign"] = follower_sign
    #bayad key ha ra be sorat file .pem bedaham behesh ke betune estefade kobe
    
    f = open("pubkey.pem" ,'wb')
    public_key = publickey.exportKey('PEM')
    f.write(public_key)
    f.close()

    ff = open("prkey.pem" ,'wb')
    private_key = privatekey.exportKey('PEM')
    ff.write(private_key)
    ff.close()

    fff = open("ticket.txt" ,'w')
    fff.write(json.dumps(ticket))
    fff.close()

    zf = zipfile.ZipFile("keys.zip",mode='w')
    zf.write("pubkey.pem")
    zf.write("prkey.pem")
    zf.write("ticket.txt")
    zf.close()
    return send_file("keys.zip")


@app.route('/verify', methods=['POST','Get'])
def verify_ticket():
    #ticket ra darim bayad verify konim ba master pub key 
    ticket = request.get_json()
    #ticket = json.loads(ticket_string)
    master_sign = ticket['master_sign']
    del ticket['master_sign']
    dump_ticket = json.dumps(ticket,sort_keys=True)
    h = SHA256.new(dump_ticket.encode())
    Mpubkey = RSA.importKey(publickey_master.exportKey('PEM'))
    v = Mpubkey.verify(h.digest(),master_sign)
    print("result of verify   "+ str(v))
    return json.dumps(str(v))


@app.route('/submit', methods=['POST','Get'])
def submit():

    content = request.form["content"]
    receiver = request.form["receiver"]

    global category,name,group
    if 'prkey' not in request.files or content=="" or receiver=="" :
        if category == "master" :
            return redirect('/master')
        else :
            return redirect('/follower')
    
    post_object = {
        "type" : "pm",
        "sender" : name,
        "group" : group,
        "receiver" : receiver,
        "content" : content
    }

    prkey = request.files.get('prkey')
    privatekey = RSA.importKey(prkey.read())
    json_dumps = json.dumps(post_object,sort_keys=True)
    #print("post object  "+json_dumps)
    h = SHA256.new(json_dumps.encode()) 
    #print("hash   " + str(h.digest())) 
    K =''
    sign = privatekey.sign(h.digest(),K)
    post_object["sign"] = sign
    # Submit a transaction
    new_tx_address = "{}/new_transaction".format(miner)

    requests.post(new_tx_address,
                  json=post_object,
                  headers={'Content-type': 'application/json'})

    #request to mine
    mine_address = "{}/mine".format(miner )
    response = requests.get(mine_address)
    #print(response.json())
    if response.json()=="True" :
        if category == "master":
            return redirect('/master')

        else:
            return redirect('/follower')
    else :
        return render_template('pm.html',
                           title='Your pm did not  mine successfully')



send = []
receive = []
def fetch_posts():
    """
    Function to fetch the chain from a blockchain node, parse the
    data and store it locally.
    """
    get_chain_address = "{}/chain".format(server)#from full node which is herself
    response = requests.get(get_chain_address)
    if response.status_code == 200:
        global name,send,receive
        send = []
        receive = []
        chain = response.json()
        for block in chain["chain"]:
            for tx in block["transactions"]:
                if tx["type"]=="pm" and tx["receiver"] == name:
                    tx["index"] = block["index"]
                    tx["hash"] = block["previous_hash"]
                    receive.append(tx)
                elif tx["type"]=="pm" and tx["sender"] == name:
                    tx["index"] = block["index"]
                    tx["hash"] = block["previous_hash"]
                    send.append(tx)
                        

@app.route('/resync')
def regform1():
    if category == "master" :
        return redirect('/master')
    else :
        return redirect('/follower')
  
@app.route('/master')
def regform2():
    if category != "master" and category != "follower"  :
        return render_template('show_ticket.html',
                           title='YOU MUST FIRST REGISTER')  
    fetch_posts()
    return render_template('pm.html',
                           title='MASTER',
                           send = send,
                           receive = receive)

@app.route('/follower')
def regform3():
    if category != "master" and category != "follower"  :
        return render_template('show_ticket.html',
                           title='YOU MUST FIRST REGISTER')
    fetch_posts()
    return render_template('pm.html',
                           title='FOLLOWER',
                           send = send,
                           receive = receive)


            


#------------------------------------------------------------------------



app.run(port=port)



