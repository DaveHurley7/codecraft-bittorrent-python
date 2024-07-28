import json
import sys
import hashlib
import socket as skt
from random import choice

# import bencodepy - available if you need it!
import requests #- available if you need it!
    
# Examples:
#
# - decode_bencode(b"5:hello") -> b"hello"
# - decode_bencode(b"10:hello12345") -> b"hello12345"
def decode_bencode(bencoded_value):
    if chr(bencoded_value[0]).isdigit():
        first_colon_index = bencoded_value.find(b":")
        if first_colon_index == -1:
            raise ValueError("Invalid encoded value")
        strlen = int(bencoded_value[:first_colon_index])
        return bencoded_value[first_colon_index+1:first_colon_index+1+strlen], bencoded_value[first_colon_index+1+strlen:]
    elif bencoded_value[0:1] == b"i":
        idx_of_e = bencoded_value.find(b"e")
        if idx_of_e == -1:
            raise ValueError("Invalid encoded value")
        return int(bencoded_value[1:idx_of_e]), bencoded_value[idx_of_e+1:]
    elif bencoded_value[0:1] == b"l":
        blist = []
        bencoded_value = bencoded_value[1:]
        while bencoded_value[0:1] != b"e":
            item, bencoded_value = decode_bencode(bencoded_value)
            blist.append(item)
        return blist, bencoded_value[1:]
    elif bencoded_value[0:1] == b"d":
        bdict = {}
        bencoded_value = bencoded_value[1:]
        while bencoded_value[0:1] != b"e":
            key, bencoded_value = decode_bencode(bencoded_value)
            if not isinstance(key,bytes):
                raise ValueError("Key must be of type string")
            value, bencoded_value = decode_bencode(bencoded_value)
            bdict[key.decode()] = value
        return bdict, bencoded_value[1:]
    else:
        raise NotImplementedError("Only strings, integers and lists are supported at the moment")
        
def enc_bencode(value):
    if isinstance(value,bytes):
        strlen = str(len(value)).encode()
        enc_val = strlen + b":" + value
    elif isinstance(value,str):
        strlen = str(len(value)).encode()
        enc_val = strlen + b":" + value.encode()
    elif isinstance(value,int):
        intstr = str(value).encode()
        enc_val = b"i" + intstr + b"e"
    elif isinstance(value,list):
        enc_val = b"l"
        for item in value:
            enc_val += enc_bencode(item)
        enc_val += b"e"
    elif isinstance(value,dict):
        enc_val = b"d"
        for k, v in value.items():
            bkey = enc_bencode(k)
            bval = enc_bencode(v)
            enc_val += bkey + bval
        enc_val += b"e"
    else:
        print("VAL:",type(value),value)
        return b""
    return enc_val

def make_hash(data,as_text=False):
    hasher = hashlib.sha1()
    hasher.update(data)
    return hasher.hexdigest() if as_text else hasher.digest()

def get_piece_hashes(str_hashlist):
    hashes = []
    while len(str_hashlist) >= 20:
        hashes.append(str_hashlist[:20])
        str_hashlist = str_hashlist[20:]
    return hashes

def bytes_to_ip(ip_bytes):
    ip_addr = ""
    for b in ip_bytes:
        ip_addr += str(b) + "."
    return ip_addr[:-1]

def extract_peers(peer_list):
    peers = []
    while peer_list:
        ip_bytes = peer_list[:4]
        port_bytes = peer_list[4:6]
        peer_list = peer_list[6:]
        ip_addr = bytes_to_ip(ip_bytes)
        port = int.from_bytes(port_bytes)
        peers.append((ip_addr,port))
    return peers

def get_peer_list(tracker_url,info_hash,file_len):
    q_params = {
        "info_hash": info_hash,
        "peer_id": "00112233445566778899",
        "port": 6881,
        "uploaded": 0,
        "downloaded": 0,
        "left": str(file_len),
        "compact": 1
    }
    resp = requests.get(tracker_url,params=q_params)
    content = decode_bencode(resp.content)
    peer_list = extract_peers(content[0]["peers"])
    return peer_list

def make_socket(csk_info):
    host, port = csk_info.split(":")
    return host, int(port)

def to_hexstr(valstr):
    vals = ["0","1","2","3","4","5","6","7","8","9","a","b","c","d","e","f"]
    hexstr = ""
    for b in valstr:
        fbyte = b >> 4
        lbyte = b & 15
        hexstr += vals[fbyte] + vals[lbyte]
    return hexstr

def load_btfile_content(filename):
    file = open(filename,"rb")
    benc_content = file.read()
    file.close()
    decoded, _ = decode_bencode(benc_content)
    return decoded

def peer_handshake(peer,info_hash):
    sk = skt.socket(skt.AF_INET,skt.SOCK_STREAM)
    sk.connect(peer)
    sk.send(b"\x13BitTorrent protocol\x00\x00\x00\x00\x00\x00\x00\x00"+info_hash+b"00112233445566778899")
    resp = sk.recv(80)
    peer_id = resp[48:]
    return sk

def read_msg(peer):
    msglen = peer.recv(4)
    payload = peer.recv(int.from_bytes(msglen))
    return payload

MAX_BLOCK_SIZE = 0x4000
MAX_REQUESTS = 5

class MsgId:
    Choke = b"\x00"
    Unchoke = b"\x01"
    Interested = b"\0x02"
    Not_Interested = b"\x03"
    Have = b"\x04"
    Bitfield = b"\x05"
    Request = b"\x06"
    Piece = b"\x07"
    Cancel = b"\x08"
    
def last_block(block_num,n_blocks,last_size):
    if block_num + 1 != n_blocks:
        return False
    if not last_size:
        return False
    return True

def handle_peer_msgs(peer_sk, piece_id, piecelen):
    while msg := read_msg(peer_sk):
        if msg[0] == MsgId.Bitfield:
            break
    peer_sk.send(b"\x00\x00\x00\x01"+MsgId.Interested)
    while msg := read_msg(peer_sk):
        if msg[0] == MsgId.Unchoke:
            break
    last_block_size = piecelen % MAX_BLOCK_SIZE
    n_blocks = piecelen // MAX_BLOCK_SIZE
    if last_block_size:
        n_blocks += 1
    blocks_received = [None]*n_blocks
    pending = []
    block_num = 0
    while block_num < 5:
        msg = (b"\x00\x00\x00\x0d"+MsgId.Request+b""
              b""+piece_id.to_bytes(4)+b""
              b""+(block_num*MAX_BLOCK_SIZE).to_bytes(4)+b""
              b""+(last_block_size if last_block(block_num,n_blocks,last_block_size) else MAX_BLOCK_SIZE)+b"")
        peer_sk.send(msg)
        pending.append(block_num)
        block_num += 1
        if block_num == n_blocks and block_num < 5:
            break
    while True:
        if len(pending) < MAX_REQUESTS and block_num < n_blocks:
            msg = (b"\x00\x00\x00\x0d"+MsgId.Request+b""
                    b""+piece_id.to_bytes(4)+b""
                    b""+(block_num*MAX_BLOCK_SIZE).to_bytes(4)+b""
                    b""+(last_block_size if last_block(block_num,n_blocks,last_block_size) else MAX_BLOCK_SIZE)+b"")
            peer_sk.send(msg)
            pending.append(block_num)
            block_num += 1    
        if not pending:
            break
        msg = read_msg(peer_sk)
        if msg[0] == MsgId.Piece:
            resp_piece = int.from_bytes(msg[1:5])
            offset = int.from_bytes(msg[5:9])
            data = int.from_bytes(msg[9:13])
            block_id = offset // MAX_BLOCK_SIZE
            blocks_received[block_id] == data
            pending.remove(block_id)
    
def download_piece(peer_sk,piece_id,piecelen,piece_hash,outfile):
    blocks = handle_peer_msgs(peer_sk,piece_id,piecelen)
    hasher = hashlib.sha1()
    for block in blocks:
        hasher.update(block)
    if piece_hash != hasher.digest():
        print("Received piece doesn't match any piece hashes")
    btfile = open(outfile,"wb")
    for block in blocks:
        btfile.write(block)
    btfile.close()
    
def main():
    command = sys.argv[1]

    # You can use print statements as follows for debugging, they'll be visible when running tests.
    #print("Logs from your program will appear here!")

    if command == "decode":
        bencoded_value = sys.argv[2].encode()

        # json.dumps() can't handle bytes, but bencoded "strings" need to be
        # bytestrings since they might contain non utf-8 characters.
        #
        # Let's convert them to strings for printing to the console.
        def bytes_to_str(data):
            if isinstance(data, bytes):
                return data.decode()

            raise TypeError(f"Type not serializable: {type(data)}")

        # Uncomment this block to pass the first stage
        decoded, _ = decode_bencode(bencoded_value)
        print(json.dumps(decoded, default=bytes_to_str))
    elif command == "info":
        decoded = load_btfile_content(sys.argv[2])
        tracker = decoded["announce"].decode()
        file_len = decoded["info"]["length"]
        info_hash = make_hash(enc_bencode(decoded["info"]),True)
        piece_hashes = get_piece_hashes(decoded["info"]["pieces"])
        print("Tracker URL:",tracker)
        print("Length:",file_len)
        print("Info Hash:",info_hash)
        print("Piece Length:",decoded["info"]["piece length"])
        for phash in piece_hashes:
            print(phash.hex())
    elif command == "peers":
        decoded = load_btfile_content(sys.argv[2])
        tracker = decoded["announce"]
        info_hash = make_hash(enc_bencode(decoded["info"]))
        file_len = decoded["info"]["length"]
        peers = get_peer_list(tracker,info_hash,file_len)
        for peer in peers:
            print(*peer,sep=":")
    elif command == "handshake":
        decoded = load_btfile_content(sys.argv[2])
        info_hash = make_hash(enc_bencode(decoded["info"]))
        sk = skt.socket(skt.AF_INET,skt.SOCK_STREAM)
        sk.connect(make_socket(sys.argv[3]))
        sk.send(b"\x13BitTorrent protocol\x00\x00\x00\x00\x00\x00\x00\x00"+info_hash+b"00112233445566778899")
        resp = sk.recv(80)
        peer_id = resp[48:]
        sk.close()
        print("Peer ID:",to_hexstr(peer_id))
    elif command == "download_piece":
        btfile = None
        piece_id = None
        outfile = None
        argc = 2
        argmax = len(sys.argv)
        print("ARGS",sys.argv)
        while argc < argmax:
            if sys.argv[argc].endswith(".torrent"):
                btfile = sys.argv[argc]
            elif sys.argv[argc] == "-o":
                argc += 1
                outfile = sys.argv[argc]
            elif sys.argv[argc].isdigit():
                piece_id = int(sys.argv[argc])
            else:
                print("invalid argument: ", sys.argv[argc])
            argc += 1
        if not btfile:
            print("No .torrent file provided")
            quit(1)
        if not isinstance(piece_id,int):
            print("A piece must be specified")
            quit(1)
        #quit(1)
        decoded = load_btfile_content(btfile)
        tracker = decoded["announce"].decode()
        info_hash = make_hash(enc_bencode(decoded["info"]))
        file_len = decoded["info"]["length"]
        print("NUM PIECES:",len(decoded["info"]["pieces"])/20)
        print("PIECE LEN:",decoded["info"]["piece length"])
        peers = get_peer_list(tracker,info_hash,file_len)
        peer_sk = peer_handshake(choice(peers),info_hash)
        piece_start = piece_id*20
        download_piece(peer_sk,piece_id,decoded["info"]["piece length"],decoded["info"]["pieces"][piece_start:piece_start+20],outfile) 
        peer_sk.close()
    else:
        raise NotImplementedError(f"Unknown command {command}")


if __name__ == "__main__":
    main()
