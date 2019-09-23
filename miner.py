from hashlib import sha256
import json
import time
from flask import Flask, request
import requests
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
import json


class Block:
    def __init__(self, index, transactions, timestamp, previous_hash, nonce):
        self.index = index
        self.transactions = transactions
        self.timestamp = timestamp
        self.previous_hash = previous_hash
        self.nonce = nonce

    def compute_hash(self):
        """
        A function that return the hash of the block contents.
        """
        block_string = json.dumps(self.__dict__, sort_keys=True)
        return sha256(block_string.encode()).hexdigest()

class Blockchain:


    # difficulty of our PoW algorithm
    difficulty = 2

    def __init__(self):
        self.unconfirmed_transactions = []
        self.chain = []

    def create_genesis_block(self):
        """
        A function to generate genesis block and appends it to
        the chain. The block has index 0, previous_hash as 0, and
        a valid hash.
        """
        genesis_block = Block(0, [], time.time(), "0",0)
        #genesis_block.hash = genesis_block.compute_hash()
        genesis_block.hash = self.proof_of_work(genesis_block)
        self.chain.append(genesis_block)

    @property
    def last_block(self):
        return self.chain[-1]

    def add_block(self, block, proof):
        """
        A function that adds the block to the chain after verification.
        Verification includes:
        * Checking if the proof is valid.
        * The previous_hash referred in the block and the hash of latest block
          in the chain match.
        """

        previous_hash = self.last_block.hash
        if previous_hash != block.previous_hash:
            print("in add block false because previous_hash")
            return False

        #delattr(block, "hash")
        if not Blockchain.is_valid_proof(block, proof):
            print("in add block not valid proof ")
            return False
        

        block.hash = proof
        self.chain.append(block)
        return True

    # @classmethod
    def proof_of_work(self, block):
        """
        Function that tries different values of nonce to get a hash
        that satisfies our difficulty criteria.
        """
        block.nonce = 0

        computed_hash = block.compute_hash()
        while not computed_hash.startswith('0' * Blockchain.difficulty):
            block.nonce += 1
            computed_hash = block.compute_hash()

        return computed_hash

    def add_new_transaction(self, transaction):
        #print("new transaction   " + str(transaction) )
        self.unconfirmed_transactions.append(transaction)

    @classmethod
    def is_valid_proof(cls, block, block_hash):
        """
        Check if block_hash is valid hash of block and satisfies
        the difficulty criteria.
        """
        #print("block hash in is valid proof   " + str(block_hash))
        f1 = block_hash.startswith('0' * Blockchain.difficulty)
        
        f2 = block_hash == block.compute_hash()
        #print(str(f1) + "  f " + str(f2) )
        return (f1 and f2)

    @classmethod
    def check_chain_validity(cls, chain):
        result = True
        previous_hash = "0"
        print("in check chain validity ")

        for block in chain:
            block2 = Block(block["index"],
                  block["transactions"],
                  block["timestamp"],
                  block["previous_hash"],
                  block["nonce"])
            block_hash = block['hash']
            # remove the hash field to recompute the hash again
            # using `compute_hash` method. 
            #delattr(block, "hash")
            #del block["hash"]
            c1 =not cls.is_valid_proof(block2, block_hash)
            c2 = previous_hash != block2.previous_hash
            #print(str(c1) + "  c " + str(c2) )
            if  c1 or c2:
                print("condition in check_chain_validity is false ")
                result = False
                break
            #agha 1 tir tagir
            #block2.hash = block_hash
            previous_hash = block_hash
            #print("block.hash " + block2.hash)

        return result
	
    
    def check_contract(self, tr):
        #agr category master bood 
	#nabayad esm group tekrari bashad 
	#name khodesh tekrari nabashad
        # ye nafar nabayad do naghsh begirad 
        #----------------------------mine master-----------------------------
        if tr[0]['type'] == "register" and tr[0]['category'] == "master":
            for block in self.chain:
                for t in block.transactions:
                    if t['type'] == "register"  and (t['name'] == tr[0]['name'] or t['group'] == tr[0]['group']) :
                        print("in check_contract this was repetetive")
                        return False
            return True
        #----------------------------mine follower-----------------------------
        elif tr[0]['type'] == "register" and tr[0]['category'] == "follower":
            #agr category follower bood 
            #nabayad dar group digari bashad 
            # on group vojud dashte bashad 
            #ticket dorost bashad

            exist = False
            ip = ''
            port = ''
            for block in self.chain:
                for t in block.transactions:
                    if t['type'] == "register"  and t['category']=="master"    and t['group'] == tr[0]['group'] :
                        exist = True 
                        ip = t['ip']
                        port = t['port']
                        break
            if not exist:
                print("in check_contract group not exist")
                return False
            else:
                #cheak konim ke esm tekrari nabashe
                for block in self.chain:
                    for t in block.transactions:
                        if t['type'] == "register" and t['name'] == tr[0]['name'] :
                            print("in check_contract  this was repetetive")
                            return False 
                #bayad ticket cheak beshe sign ha dorost bashe.
                #aval bayad follower sign ro barresi konim 
                #yani bayad ba public khode follower validate beshe 
                #agar ok bood hala ba public key e master verify konim 
                # agar ok bood  return true store konim dar block chain 
                ticket_string = tr[0]['ticket']
                ticket = json.loads(ticket_string)

                follower_sign = ticket['follower_sign']
                del ticket['follower_sign']

                dump_ticket = json.dumps(ticket,sort_keys=True)
                h = SHA256.new(dump_ticket.encode())
                follower_publickey = ticket['Pubaddress'].encode()
                Fpubkey = RSA.importKey(follower_publickey)
                v = Fpubkey.verify(h.digest(),follower_sign)
                print("in check_contract verify is   "+ str(v))
                if v :
                    #bayad master_sign ra check konim
                    #bayad be ip:port of master be path /verify request bedahim
                    #sepas on true or false midahad 
                    # nn

                    master_address = str(ip)+":"+str(port)
                    #print(master_address)
                    headers = {'Content-Type': "application/json"}

                    response = requests.post(master_address + "/verify",
                             data=dump_ticket, headers=headers)
                    #print(response.json())
                    if response.json() == "True":
                        return True
                    else :
                        print("this key is not verified with master public key")
                        return False
                else :
                    print("this key is not verified with follower public key")
                    return False
        #----------------------------mine pm-----------------------------
        if tr[0]['type'] == "pm" :
            #bayad berama az bc pubkey ro biaram sign ro verify konam 
            #va yeki bodan mabda va maghsad
            #agar ok bood pm ro bezaram to bc
            flag = False
            for block in self.chain:
                for t in block.transactions:
                    if t['type'] == "register"  and t['name'] == tr[0]['receiver'] and t['group'] == tr[0]['group'] :
                        flag = True

            if not flag :
                print("in check_contract you are not in the same group")
                return False


            ticket_string = ''
            for block in self.chain:
                for t in block.transactions:
                    if t['type'] == "register"  and t['group'] == tr[0]['group'] and t['name'] == tr[0]['sender'] :
                        ticket_string = t['ticket']
            #print("tr[0] "+json.dumps(tr[0]))
            sign = tr[0]["sign"]
            del tr[0]["sign"]
            dump_post_obj = json.dumps(tr[0],sort_keys=True)
            #print("post object  "+dump_post_obj)
            h = SHA256.new(dump_post_obj.encode()) 
            #print("hash   " + str(h.digest())) 
            ticket = json.loads(ticket_string)
            pubkey_str = ticket["Pubaddress"]
            pubkey = RSA.importKey(pubkey_str.encode())
            v = pubkey.verify(h.digest(),sign)
            if not v :
                print("your sign is incorrect so didnt mine")
            return v
        
	
	
    def mine(self):
        """
        This function serves as an interface to add the pending
        transactions to the blockchain by adding them to the block
        and figuring out Proof Of Work.
        """
        if not self.unconfirmed_transactions:
            return False
		
        #cheak it is ok to add smart contract
        if not self.check_contract(self.unconfirmed_transactions):
            return False
		
        last_block = self.last_block

        new_block = Block(index=last_block.index + 1,
                          transactions=self.unconfirmed_transactions,
                          timestamp=time.time(),
                          previous_hash=last_block.hash , nonce=0)

        proof = self.proof_of_work(new_block)#nonce avaz shod 
        res = self.add_block(new_block, proof)
        print("in mone func res for mine block " +str(res))
        self.unconfirmed_transactions = []
        # announce it to the network
        announce_new_block(new_block, proof)
        return True

app = Flask(__name__)

# the node's copy of blockchain
blockchain = Blockchain()
blockchain.create_genesis_block()

# the address to other participating members of the network
#creat a list
peers = set()


# endpoint to submit a new transaction. This will be used by
# our application to add new data (posts) to the blockchain

                

@app.route('/new_transaction', methods=['POST'])
def new_transaction():
    tx_data = request.get_json()
    #required_fields = ["IP", "port","content"]

    #for field in required_fields:
    #    if not tx_data.get(field):
    #        return "Invlaid transaction data", 404
    #print ("in new transaction func")
    #tx_data["timestamp"] = time.time()

    blockchain.add_new_transaction(tx_data)

    return "Success", 201


# endpoint to return the node's copy of the chain.
# Our application will be using this endpoint to query
# all the posts to display.
@app.route('/chain', methods=['GET'])
def get_chain():
    # make sure we've the longest chain
    consensus()
    chain_data = []
    for block in blockchain.chain:
        chain_data.append(block.__dict__)
    #print("get chain   "+str(len(chain_data)) + " data: " +str(chain_data) )
    return json.dumps({"length": len(chain_data),
                       "chain": chain_data,
                       "peers": list(peers)})

@app.route('/chain2', methods=['GET'])
def get_chain2():
    chain_data = []
    for block in blockchain.chain:
        chain_data.append(block.__dict__)
    #print("chain2 "+ str(len(chain_data)))
    return json.dumps({"length": len(chain_data),
                       "chain": chain_data})



# endpoint to request the node to mine the unconfirmed
# transactions (if any). We'll be using it to initiate
# a command to mine from our application itself.
@app.route('/mine', methods=['GET'])
def mine_unconfirmed_transactions():
    result = blockchain.mine()
    print("in /mine resulf of mine is "+str(result))
    return json.dumps(str(result))


# endpoint to add new peers to the network.
@app.route('/register_node', methods=['POST'])
def register_new_peers():
    node_address = request.get_json()["node_address"]
    if not node_address:
        return "Invalid data", 400

    # Add the node to the peer list
    # bayad chek konim az ghabl nabashe in 
    global peers
    if request.host_url not in peers:
        peers.add(request.host_url)
    if node_address not in peers:
        peers.add(node_address)        
        #peers.add(request.host_url)
        #print("in register new peers "+str(peers))
        # alan bayad be peer hasham bege ino ezafe konid vali loop mishe 
        for p in peers:
            data = {"node_address": node_address}
            headers = {'Content-Type': "application/json"}
            response =requests.post(p + "register_node",
                             data=json.dumps(data), headers=headers)

           
    return get_chain()


@app.route('/register_with', methods=['POST'])
def register_with_existing_node():
    """
    Internally calls the `register_node` endpoint to
    register current node with the node specified in the
    request, and sync the blockchain as well as peer data.
    """
    node_address = request.get_json()["node_address"]#8000
    if not node_address:
        return "Invalid data", 400

    data = {"node_address": request.host_url}#8001
    headers = {'Content-Type': "application/json"}


    # Make a request to register with remote node and obtain information
    response = requests.post(node_address + "/register_node",
                             data=json.dumps(data), headers=headers)

    if response.status_code == 200:
        global blockchain
        global peers
        # update chain and the peers
        chain_dump = response.json()['chain']
        blockchain = create_chain_from_dump(chain_dump)#8001 update herself
        peers.update(response.json()['peers'])#8001
        return "Registration successful", 200
    else:
        #print("it was not 200 ok it can not register node ")
        # if something goes wrong, pass it on to the API response
        return "is was not 200 ok",response.content, response.status_code

def create_chain_from_dump(chain_dump):
    blockchain = Blockchain()
    for idx, block_data in enumerate(chain_dump):
        block = Block(block_data["index"],
                      block_data["transactions"],
                      block_data["timestamp"],
                      block_data["previous_hash"],
                      block_data["nonce"])
        proof = block_data['hash']
        if idx > 0:
            #block.hash = proof
            added = blockchain.add_block(block, proof)
            if not added:
                raise Exception("The chain dump is tampered!!")
        else:  # the block is a genesis block, no verification needed
            block.hash = proof
            blockchain.chain.append(block)
    return blockchain

# endpoint to add a block mined by someone else to
# the node's chain. The block is first verified by the node
# and then added to the chain.
@app.route('/add_block', methods=['POST'])
def verify_and_add_block():
    block_data = request.get_json()
    block = Block(block_data["index"],
                  block_data["transactions"],
                  block_data["timestamp"],
                  block_data["previous_hash"],
                  block_data["nonce"])

    proof = block_data["hash"]#proof bedune hash ast
    added = blockchain.add_block(block, proof)
    print("in verify_and_add_block added is   " + str(added))

    if not added:
        return "The block was discarded by the node", 400
    #response = get_chain2()
    #print("Content "+ str(response.content))
    return "Block added to the chain", 201


# endpoint to query unconfirmed transactions
@app.route('/pending_tx')
def get_pending_tx():
    return json.dumps(blockchain.unconfirmed_transactions)

# endpoint to query peers
@app.route('/peers')
def get_peers():
    return str(peers)


def consensus():
    """
    Our simple consnsus algorithm. If a longer valid chain is
    found, our chain is replaced with it.
    """
    global blockchain

    longest_chain = None
    current_len = len(blockchain.chain)

    for node in peers:
        print("in consensus function "+'{}chain'.format(node))
        response = requests.get('{}chain2'.format(node))
        #print("Content", response.content)
        res = response.json()
        length =res['length']
        chain = res['chain']
        if length > current_len and blockchain.check_chain_validity(chain):
            current_len = length
            longest_chain = chain

    if longest_chain:
        chain2 = []
        for block in longest_chain:
            block2 = Block(block["index"],
                  block["transactions"],
                  block["timestamp"],
                  block["previous_hash"],
                  block["nonce"])
            block2.hash = block['hash']
            chain2.append(block2)
        blockchain.chain = chain2
        return True

    return False


def announce_new_block(block, proof):
    """
    A function to announce to the network once a block has been mined.
    Other blocks can simply verify the proof of work and add it to their
    respective chains.
    """
    print("annonce new block")
    for peer in peers:
        print(str("{}add_block".format(peer)))
        url = "{}add_block".format(peer)
        headers = {'Content-Type': "application/json"}
        block.hash = proof
        requests.post(url, data=json.dumps(block.__dict__), headers=headers)



