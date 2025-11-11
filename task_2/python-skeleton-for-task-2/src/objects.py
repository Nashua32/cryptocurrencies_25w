from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from datetime import datetime
from jcs import canonicalize

import copy
import hashlib
import json
import re
import binascii

import constants as const

import object_db as db

from message.msgexceptions import NonfaultyNodeException

# perform syntactic checks. returns true iff check succeeded
OBJECTID_REGEX = re.compile("^[0-9a-f]{64}$")
def validate_objectid(objid_str):
    return isinstance(objid_str, str) and bool(OBJECTID_REGEX.fullmatch(objid_str))


PUBKEY_REGEX = re.compile("^[0-9a-f]{64}$")
def validate_pubkey(pubkey_str):
    return isinstance(pubkey_str, str) and bool(PUBKEY_REGEX.fullmatch(pubkey_str))


SIGNATURE_REGEX = re.compile("^[0-9a-f]{128}$")
def validate_signature(sig_str):
    return isinstance(sig_str, str) and bool(SIGNATURE_REGEX.fullmatch(sig_str))

NONCE_REGEX = re.compile("^[0-9a-f]{64}$")
def validate_nonce(nonce_str):
    return isinstance(nonce_str, str) and bool(NONCE_REGEX.fullmatch(nonce_str))


TARGET_REGEX = re.compile("^[0-9a-f]{64}$")
def validate_target(target_str):
    return isinstance(target_str, str) and bool(TARGET_REGEX.fullmatch(target_str))


#validates one input of the transaction
def validate_transaction_input(in_dict):

    #syntactic checks

    if not isinstance(in_dict, dict):
        return False
    
    if "outpoint" not in in_dict or "sig" not in in_dict:
        return False
    outpoint = in_dict["outpoint"]
    sig = in_dict["sig"]

    if not isinstance(outpoint, dict):
        return False
    
    if "txid" not in outpoint or "index" not in outpoint:
        return False
    txid = outpoint["txid"]
    index = outpoint["index"]

    #check if the referenced transaction exists and has given index

    tr = db.get_object(txid)

    if tr is None:
        return "unkonwn_object" #does not necessarily indicate an error

    if "outputs" not in tr: #tr is not a transaction
        return False
    
    if not isinstance(index, int) or index < 0 or index >= len(tr["outputs"]):
        return False
    

    return True



def validate_transaction_output(out_dict):
    
    #syntactic checks

    if not isinstance(out_dict, dict):
        return False
    
    if "pubkey" not in out_dict or "value" not in out_dict:
        return False

    pubkey = out_dict["pubkey"]
    value = out_dict["value"]

    if not validate_pubkey(pubkey):
        return False
    
    if not isinstance(value, int) or value < 0:
        return False

    return True

def validate_transaction(trans_dict):
    
    #syntactic checks
    if not isinstance(trans_dict, dict):
        return False
    
    #check if there are no additional keys in the dictionary that are not type, height, inputs and outputs
    allowed_keys = {"type", "height", "inputs", "outputs"}
    if not set(trans_dict.keys()).issubset(allowed_keys):
        return False
    

     #validate outputs and sum their values (has to be done for both coinbase and normal transactions)

    if not "outputs" in trans_dict:
        return False

    output_sum = 0

    for outp in trans_dict["outputs"]:
        if not validate_transaction_output(outp):
            return False
        
        output_sum = output_sum + outp["value"]
    


    #check if it is a coinbase transaction
    if "height" in trans_dict:
        if not isinstance(trans_dict["height"], int):
            return False

        if "inputs" in trans_dict: #coinbase transaction has no inputs
            return False
        
        return True #no semantic checks in this exercise yet
    

    #it is not a coinbase transaction -> validate the inputs, too

    if "inputs" not in trans_dict or "outputs" not in trans_dict:
        return False

    #validate inputs, check their signatures and sum their values

    input_sum = 0

    for inp in trans_dict["inputs"]:

        res = validate_transaction_input(inp)
        if res is False:
            return False
        elif res == "unknown_object":
            raise NonfaultyNodeException("UNKNOWN_OBJECT")

        referenced_tx = db.get_object(inp["outpoint"]["txid"])
        index = inp["outpoint"]["index"]
        referenced_output = referenced_tx["outputs"][index]

        if not isinstance (referenced_output, dict) or "pubkey" not in referenced_output or "value" not in referenced_output:
            return False

        #increase the input sum
        input_sum = input_sum + referenced_output["value"]

        #check the signature of the input
        referenced_pubkey = referenced_output["pubkey"]
        signature = inp["sig"]

        if not validate_pubkey(referenced_pubkey) or not validate_signature(signature):
            return False

        if not verify_tx_signature(trans_dict, signature, referenced_pubkey):
            return False


    #check weak law of conversation

    if output_sum > input_sum:
        return False
    

    return True



def validate_block(block_dict):
    # todo
    return True

def validate_object(obj_dict):
    if obj_dict['type'] == "block":
        return validate_block(obj_dict)
    else:
        return validate_transaction(obj_dict)

def get_objid(obj_dict):
    h = hashlib.blake2s()
    h.update(canonicalize(obj_dict))
    return h.hexdigest()

# perform semantic checks

# verify the signature sig in tx_dict using pubkey
def verify_tx_signature(tx_dict, sig, pubkey):

    try: 
        tx_no_sigs = copy.deepcopy(tx_dict)

        #replace all sig values in tx_dict with null
        if "inputs" in tx_no_sigs:
            for inp in tx_no_sigs["inputs"]:
                if "sig" in inp:
                    inp["sig"] = None
        
        plaintext_bytes = canonicalize(tx_no_sigs)
        pubkey_bytes = binascii.unhexlify(pubkey)
        sig_bytes = binascii.unhexlify(sig)

        Ed25519PublicKey.from_public_bytes(pubkey_bytes).verify(sig_bytes, plaintext_bytes)

        return True

    except (InvalidSignature, ValueError, binascii.Error, TypeError):
        return False

class TXVerifyException(Exception):
    pass


def verify_transaction(tx_dict, input_txs):

    pass # todo 

class BlockVerifyException(Exception):
    pass

# apply tx to utxo
# returns mining fee
def update_utxo_and_calculate_fee(tx, utxo):
    # todo
    return 0

# verify that a block is valid in the current chain state, using known transactions txs
def verify_block(block, prev_block, prev_utxo, prev_height, txs):
    # todo
    return 0
