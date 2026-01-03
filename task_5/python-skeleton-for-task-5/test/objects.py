from typing import Optional
import constants as const
import hashlib
from jcs import canonicalize
from abc import ABC, abstractmethod

class Object(ABC):
    #def get_objid(self, obj_dict):
    #    return hashlib.blake2s(canonicalize(obj_dict)).hexdigest()

    def get_objid(self):
        return hashlib.blake2s(canonicalize(self.make_dict())).hexdigest()
    
    @abstractmethod
    def make_dict(self):
        pass


class Block(Object):
    def __init__(self, 
                 T: Optional[str], 
                 created: Optional[int], 
                 miner: Optional[str], 
                 nonce: Optional[str], 
                 note: Optional[str], 
                 previd: Optional[str], 
                 txids: Optional[list[str]]):
        self.T = T
        self.created = created
        self.miner = miner
        self.nonce = nonce
        self.note = note
        self.previd = previd
        self.txids = txids
        self.type = "block"

    def make_dict(self) -> str:
        return {
            "T": self.T,
            "created": self.created,
            "miner": self.miner,
            "nonce": self.nonce,
            "note": self.note,
            "previd": self.previd,
            "txids": self.txids,
            "type": self.type
        }

    # mines the block and returns the object id
    def mine_block(self) -> str:
        nonce_len = 64
        nonce_int = 0

        target_int = int(self.T, 16)

        while True:
            self.nonce = format(nonce_int, f'0{nonce_len}x')

            #block_id = self.get_objid(self.make_dict())
            block_id = self.get_objid()
            block_int = int(block_id, 16)

            if block_int < target_int:
                return block_id

            nonce_int += 1


class TransactionInputOutpoint:
    def __init__(self, txid: Optional[str], index: Optional[int]):
        self.txid = txid
        self.index = index

    def make_dict(self):
        return {
            "txid": self.txid,
            "index": self.index
        }


class TransactionInput:
    def __init__(self, outpoint: Optional[TransactionInputOutpoint], sig: Optional[str]):
        self.outpoint = outpoint
        self.sig = sig
    
    def make_dict(self):
        return {
            "outpoint": self.outpoint.make_dict(),
            "sig": self.sig
        }


class TransactionOutput:
    def __init__(self, pubkey: Optional[str], value: Optional[int]):
        self.pubkey = pubkey
        self.value = value

    def make_dict(self):
        return {
            "pubkey": self.pubkey,
            "value": self.value
        }


class Transaction(Object):
    def __init__(self, inputs: Optional[list[TransactionInput]], outputs: Optional[list[TransactionOutput]]):
        self.inputs = inputs
        self.outputs = outputs
        self.type = "transaction"

    def make_dict(self):
        return {
            "type": self.type,
            "inputs": [i.make_dict() for i in self.inputs],
            "outputs": [o.make_dict() for o in self.outputs]
        }

class CoinbaseTransaction(Object):
    def __init__(self, height: Optional[int], outputs: Optional[list[TransactionOutput]]):
        self.height = height
        self.outputs = outputs
        self.type = "transaction"

    def make_dict(self):
        return {
            "type": self.type,
            "height": self.height,
            "outputs": [o.make_dict() for o in self.outputs]
        }