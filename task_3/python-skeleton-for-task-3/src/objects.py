from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from datetime import datetime
from jcs import canonicalize
import sqlite3
import time

from message.msgexceptions import *

import copy
import hashlib
import json
import re
from main import broadcast_getobject, gather_previous_txs

import constants as const

# perform syntactic checks. returns true iff check succeeded
OBJECTID_REGEX = re.compile("^[0-9a-f]{64}$")
def validate_objectid(objid_str):
    if not isinstance(objid_str, str):
        return False
    return OBJECTID_REGEX.match(objid_str)

PUBKEY_REGEX = re.compile("^[0-9a-f]{64}$")
def validate_pubkey(pubkey_str):
    if not isinstance(pubkey_str, str):
        return False
    return PUBKEY_REGEX.match(pubkey_str)

SIGNATURE_REGEX = re.compile("^[0-9a-f]{128}$")
def validate_signature(sig_str):
    if not isinstance(sig_str, str):
        return False
    return SIGNATURE_REGEX.match(sig_str)

NONCE_REGEX = re.compile("^[0-9a-f]{64}$")
def validate_nonce(nonce_str):
    if not isinstance(nonce_str, str):
        return False
    return NONCE_REGEX.match(nonce_str)


TARGET_REGEX = re.compile("^[0-9a-f]{64}$")
def validate_target(target_str):
    if not isinstance(target_str, str):
        return False
    return TARGET_REGEX.match(target_str)

def is_ascii_printable(s: str):
    try:
        s.encode("ascii")
    except UnicodeEncodeError:
        return False
    return s.isprintable()

# syntactic checks
def validate_transaction_input(in_dict):
    if not isinstance(in_dict, dict):
        raise ErrorInvalidFormat("Not a dictionary!")

    if 'sig' not in in_dict:
        raise ErrorInvalidFormat("sig not set!")
    if not isinstance(in_dict['sig'], str):
        raise ErrorInvalidFormat("sig not a string!")
    if not validate_signature(in_dict['sig']):
        raise ErrorInvalidFormat("sig not syntactically valid!")

    if 'outpoint' not in in_dict:
        raise ErrorInvalidFormat("outpoint not set!")
    if not isinstance(in_dict['outpoint'], dict):
        raise ErrorInvalidFormat("outpoint not a dictionary!")

    outpoint = in_dict['outpoint']
    if 'txid' not in outpoint:
        raise ErrorInvalidFormat("txid not set!")
    if not isinstance(outpoint['txid'], str):
        raise ErrorInvalidFormat("txid not a string!")
    if not validate_objectid(outpoint['txid']):
        raise ErrorInvalidFormat("txid not a valid objectid!")
    if 'index' not in outpoint:
        raise ErrorInvalidFormat("index not set!")
    if not isinstance(outpoint['index'], int):
        raise ErrorInvalidFormat("index not an integer!")
    if outpoint['index'] < 0:
        raise ErrorInvalidFormat("negative index!")
    if len(set(outpoint.keys()) - set(['txid', 'index'])) != 0:
        raise ErrorInvalidFormat("Additional keys present in outpoint!")

    if len(set(in_dict.keys()) - set(['sig', 'outpoint'])) != 0:
        raise ErrorInvalidFormat("Additional keys present!")

    return True # syntax check done

# syntactic checks
def validate_transaction_output(out_dict):
    if not isinstance(out_dict, dict):
        raise ErrorInvalidFormat("Not a dictionary!")

    if 'pubkey' not in out_dict:
        raise ErrorInvalidFormat("pubkey not set!")
    if not isinstance(out_dict['pubkey'], str):
        raise ErrorInvalidFormat("pubkey not a string!")
    if not validate_pubkey(out_dict['pubkey']):
        raise ErrorInvalidFormat("pubkey not syntactically valid!")

    if 'value' not in out_dict:
        raise ErrorInvalidFormat("value not set!")
    if not isinstance(out_dict['value'], int):
        raise ErrorInvalidFormat("value not an integer!")
    if out_dict['value'] < 0:
        raise ErrorInvalidFormat("negative value!")

    if len(set(out_dict.keys()) - set(['pubkey', 'value'])) != 0:
        raise ErrorInvalidFormat("Additional keys present!")

    return True # syntax check done

# syntactic checks
def validate_transaction(trans_dict):
    if not isinstance(trans_dict, dict):
        raise ErrorInvalidFormat("Transaction object invalid: Not a dictionary!") # assert: false

    if 'type' not in trans_dict:
        raise ErrorInvalidFormat("Transaction object invalid: Type not set") # assert: false
    if not isinstance(trans_dict['type'], str):
        raise ErrorInvalidFormat("Transaction object invalid: Type not a string") # assert: false
    if not trans_dict['type'] == 'transaction':
        raise ErrorInvalidFormat("Transaction object invalid: Type not 'transaction'") # assert: false

    if 'outputs' not in trans_dict:
        raise ErrorInvalidFormat("Transaction object invalid: No outputs key set")
    if not isinstance(trans_dict['outputs'], list):
        raise ErrorInvalidFormat("Transaction object invalid: Outputs key not a list")

    index = 0
    for output in trans_dict['outputs']:
        try:
            validate_transaction_output(output)
        except ErrorInvalidFormat as e:
            raise ErrorInvalidFormat(f"Transaction object invalid: Output at index {index} invalid: {e.message}")
        index += 1

    # check for coinbase transaction
    if 'height' in trans_dict:
        # this is a coinbase transaction
        if not isinstance(trans_dict['height'], int):
            raise ErrorInvalidFormat("Coinbase transaction object invalid: Height not an integer")
        if trans_dict['height'] < 0:
            raise ErrorInvalidFormat("Coinbase transaction object invalid: Negative height")

        if len(trans_dict['outputs']) > 1:
            raise ErrorInvalidFormat("Coinbase transaction object invalid: More than one output set")

        if len(set(trans_dict.keys()) - set(['type', 'height', 'outputs'])) != 0:
            raise ErrorInvalidFormat("Coinbase transaction object invalid: Additional keys present")
        return

    # this is a normal transaction
    if not 'inputs' in trans_dict:
        raise ErrorInvalidFormat("Normal transaction object invalid: Inputs not set")

    if not isinstance(trans_dict['inputs'], list):
        raise ErrorInvalidFormat("Normal transaction object invalid: Inputs not a list")
    for input in trans_dict['inputs']:
        try:
            validate_transaction_input(input)
        except ErrorInvalidFormat as e:
            raise ErrorInvalidFormat(f"Normal transaction object invalid: Input at index {index} invalid: {e.message}")
        index += 1
    if len(trans_dict['inputs']) == 0:
        raise ErrorInvalidFormat(f"Normal transaction object invalid: No input set")

    if len(set(trans_dict.keys()) - set(['type', 'inputs', 'outputs'])) != 0:
        raise ErrorInvalidFormat(f"Normal transaction object invalid: Additional key present")

    return True # syntax check done


# syntactic checks
def validate_block(block_dict):
    if not isinstance(block_dict, dict):
        raise ErrorInvalidFormat("Block object invalid: Not a dictionary!")
    
    # Validating 'type'
    if 'type' not in block_dict:
        raise ErrorInvalidFormat("Block object invalid: Type not set")
    if not isinstance(block_dict['type'], str):
        raise ErrorInvalidFormat("Block object invalid: Type not a string")
    if not block_dict['type'] == 'block':
        raise ErrorInvalidFormat("Block object invalid: Type not 'block'")
    
    # Validating 'txids'
    index = 0
    for txid in block_dict['txids']:
        if not isinstance(txid, str):
            raise ErrorInvalidFormat(f"Block object invalid: txid at index {index} not a string")
        index += 1



    # Validating 'nonce'
    if 'nonce' not in block_dict:
        raise ErrorInvalidFormat("Block object invalid: nonce not set")
    if not isinstance(block_dict['nonce'], str):
        raise ErrorInvalidFormat("Block object invalid: nonce not a string")
    if not validate_nonce(block_dict['nonce']):
        raise ErrorInvalidFormat("Block object invalid: nonce not of valid format")

    # Validating 'previd'
    if 'previd' not in block_dict:
        raise ErrorInvalidFormat("Block object invalid: previd not set")
    if block_dict['previd'] is None and get_objid(block_dict) != const.GENESIS_BLOCK_ID:
        raise ErrorInvalidGenesis("Block object invalid: Block is not Genesis block, but has a null previd")
    if not isinstance(block_dict['previd'], str):
        raise ErrorInvalidFormat("Block object invalid: previd not a string")


    # Validating 'created'
    if 'created' not in block_dict:
        raise ErrorInvalidFormat("Block object invalid: created not set")
    if not isinstance(block_dict['created'], int):
        raise ErrorInvalidFormat("Block object invalid: created not an int")

    # Validating 'T' (target)
    if 'T' not in block_dict:
        raise ErrorInvalidFormat('Block object invalid: T not set')
    if not isinstance(block_dict['T'], str):
        raise ErrorInvalidFormat("Block object invalid: T not a string")
    if not validate_target(block_dict['T']):
        raise ErrorInvalidFormat("Block object invalid: T not of valid format")

    # Validating 'note'
    if 'note' in block_dict:
        if not is_ascii_printable(block_dict['note']):
            raise ErrorInvalidFormat("Block object invalid: note not ASCII-printable")
        if len(block_dict['note'] > 128):
            raise ErrorInvalidFormat("Block object invalid: note too long")

    # Validating 'miner'
    if 'miner' in block_dict:
        if not is_ascii_printable(block_dict['miner']):
            raise ErrorInvalidFormat("Block object invalid: miner not ASCII-printable")
        if len(block_dict['miner'] > 128):
            raise ErrorInvalidFormat("Block object invalid: miner too long")

# syntactic checks
def validate_object(obj_dict):
    if not isinstance(obj_dict, dict):
        raise ErrorInvalidFormat("Object invalid: Not a dictionary!")

    if 'type' not in obj_dict:
        raise ErrorInvalidFormat("Object invalid: Type not set!")
    if not isinstance(obj_dict['type'], str):
        raise ErrorInvalidFormat("Object invalid: Type not a string")

    obj_type = obj_dict['type']
    if obj_type == 'transaction':
        return validate_transaction(obj_dict)
    elif obj_type == 'block':
        return validate_block(obj_dict)

    raise ErrorInvalidFormat("Object invalid: Unknown object type")

def expand_object(obj_str):
    return json.loads(obj_str)

def get_objid(obj_dict):
    return hashlib.blake2s(canonicalize(obj_dict)).hexdigest()

# perform semantic checks

# verify the signature sig in tx_dict using pubkey
def verify_tx_signature(tx_dict, sig, pubkey):
    tx_local = copy.deepcopy(tx_dict)

    for i in tx_local['inputs']:
        i['sig'] = None

    pubkey_obj = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pubkey))
    sig_bytes = bytes.fromhex(sig)

    try:
        pubkey_obj.verify(sig_bytes, canonicalize(tx_local))
    except InvalidSignature:
        return False

    return True

class TXVerifyException(Exception):
    pass

# semantic checks
# assert: tx_dict is syntactically valid
def verify_transaction(tx_dict, input_txs):
    # coinbase transaction
    if 'height' in tx_dict:
        return # assume all syntactically valid coinbase transactions are valid

    # regular transaction
    insum = 0 # sum of input values
    in_dict = dict()
    for i in tx_dict['inputs']:
        ptxid = i['outpoint']['txid']
        ptxidx = i['outpoint']['index']

        if ptxid in in_dict:
            if ptxidx in in_dict[ptxid]:
                raise ErrorInvalidTxConservation(f"The same input ({ptxid}, {ptxidx}) was used multiple times in this transaction")
            else:
                in_dict[ptxid].add(ptxidx)
        else:
            in_dict[ptxid] = {ptxidx}

        if ptxid not in input_txs:
            raise ErrorUnknownObject(f"Transaction {ptxid} not known")

        ptx_dict = input_txs[ptxid]

        # just to be sure
        if ptx_dict['type'] != 'transaction':
            raise ErrorInvalidFormat("Previous TX '{}' is not a transaction!".format(ptxid))

        if ptxidx >= len(ptx_dict['outputs']):
            raise ErrorInvalidTxOutpoint("Invalid output index in previous TX '{}'!".format(ptxid))

        output = ptx_dict['outputs'][ptxidx]
        if not verify_tx_signature(tx_dict, i['sig'], output['pubkey']):
            raise ErrorInvalidTxSignature("Invalid signature from previous TX '{}'!".format(ptxid))

        insum = insum + output['value']

    if insum < sum([o['value'] for o in tx_dict['outputs']]):
        raise ErrorInvalidTxConservation("Sum of inputs < sum of outputs!")

# ---- UTXO helper functions (Task 1+2) ----

def _utxo_to_json(utxo):
    """
    utxo: set[(txid, index)]
    -> JSON-String für DB: Liste von [txid, index]
    """
    # sortieren für deterministische Darstellung
    as_list = sorted([[txid, idx] for (txid, idx) in utxo])
    return json.dumps(as_list, separators=(',', ':'))


def _utxo_from_json(s):
    """
    JSON-String -> utxo: set[(txid, index)]
    """
    data = json.loads(s)
    return {(txid, idx) for txid, idx in data}


def load_block_utxo(blockid):
    """
    UTXO-Set nach diesem Block aus der DB laden.
    Wenn wir noch keins gespeichert haben, leeres Set.
    """
    con = sqlite3.connect(const.DB_NAME)
    try:
        cur = con.cursor()
        res = cur.execute("SELECT utxo FROM utxos WHERE blockid = ?", (blockid,))
        row = res.fetchone()
        if row is None:
            return set()
        return _utxo_from_json(row[0])
    finally:
        con.close()


def store_block_utxo(blockid, utxo):
    """
    UTXO-Set nach diesem Block in die DB schreiben.
    """
    con = sqlite3.connect(const.DB_NAME)
    try:
        cur = con.cursor()
        utxo_json = _utxo_to_json(utxo)
        cur.execute(
            "INSERT OR REPLACE INTO utxos(blockid, utxo) VALUES(?, ?)",
            (blockid, utxo_json)
        )
        con.commit()
    except Exception as e:
        con.rollback()
        raise e
    finally:
        con.close()

# apply tx to utxo
# returns mining fee
def update_utxo_and_calculate_fee(tx, utxo):
    txid = get_objid(tx)

    # Coinbase-Transaktion: hat keine Inputs, erzeugt nur Outputs
    if 'height' in tx:
        for idx, _out in enumerate(tx['outputs']):
            utxo.add((txid, idx))
        return 0

    # Normale Transaktion
    # 1) Inputs müssen alle im aktuellen UTXO-Set sein
    for txin in tx['inputs']:
        prev_txid = txin['outpoint']['txid']
        prev_idx  = txin['outpoint']['index']
        key = (prev_txid, prev_idx)

        if key not in utxo:
            # -> entweder Output existiert nicht oder wurde bereits ausgegeben
            raise ErrorInvalidTxOutpoint(
                f"Transaction tries to spend non-existing or already spent output {key}"
            )

    # 2) Jetzt Inputs entfernen
    for txin in tx['inputs']:
        prev_txid = txin['outpoint']['txid']
        prev_idx  = txin['outpoint']['index']
        utxo.remove((prev_txid, prev_idx))

    # 3) Neue Outputs hinzufügen
    for idx, _out in enumerate(tx['outputs']):
        utxo.add((txid, idx))

    # Fee wird (noch) nicht hier berechnet, sondern in verify_coinbase,
    # daher 0 zurückgeben.
    return 0

# verify that a block is valid in the current chain state, using known transactions txs
def verify_block(block, prev_block, prev_utxo, prev_height, txs):
    
    # Checking if T is the required target
    if not block['T'] == const.BLOCK_TARGET:
        raise ErrorInvalidFormat("Block invalid: Block T is not required target")
    
    # Checking if the timestamp is before the current time and after the timestamp of the previous block
    if not block['created'] <= time.time() or block['created'] <= prev_block['created']:
        raise ErrorInvalidBlockTimestamp("Block invalid: Block creation timestamp is in the future of before timestamp of previous block")

    # Checking proof-of-work
    block_id = get_objid(block)
    if not int(block_id, 16) < int(block['T'], 16):
        raise ErrorInvalidBlockPOW("Block invalid: Block does not satisfy Proof-Of-Work equation")

    # Checking if we have all tx correspondings to the txids in the database
    tx_ids = block['txids']
    txs = []
    for tx_id in tx_ids:

        # If not, we send a getobject msg to the peers and leave validation pending ...
        tx = get_db_object(tx_id)
        if not tx:
            broadcast_getobject(tx_id)

            # ... and send a UnfindableObject error back (see description of UNFINDABLE_OBJECT in Kerma project description)
            raise ErrorUnfindableObject("Block Verification put on hold: Referenced transaction not in local database") 
        
        txs.append(tx)
        

    # ---- Task 2: UTXO-Set über alle TXs des Blocks fortschreiben ----

    con = sqlite3.connect(const.DB_NAME)
    cur = con.cursor()

    # UTXO-Set nach dem Parent-Block als Startpunkt
    # prev_utxo kommt als Argument rein; fallback: leeres Set
    current_utxo = set(prev_utxo) if prev_utxo is not None else set()

    total_fees = 0

    for tx in txs:
        # (a) TX wie in Task 2 validieren
        validate_transaction(tx)
        prev_txs = gather_previous_txs(cur, tx)
        verify_transaction(tx, prev_txs)

        # Zusätzlich: sicherstellen, dass alle Inputs im UTXO-Set sind
        # -> passiert in update_utxo_and_calculate_fee
        fee = update_utxo_and_calculate_fee(tx, current_utxo)
        total_fees += fee

    con.close()


    # Checking for coinbase transactions
    # And validating if there is at most one coinbase transaction
    for tx in txs[1:]:
        if 'height' in tx:
            raise ErrorInvalidBlockCoinbase("Block invalid: Block contains multiple coinbase txs or there is a coinbase tx after the first txid index")
        
    potential_coinbase = txs[0]
    # And validating it if there is one
    if 'height' in potential_coinbase:
        verify_coinbase(potential_coinbase, txs[1:], get_block_height(block))
    block_id = get_objid(block)
    store_block_utxo(block_id, current_utxo)


# INPUT: 
# coinbase_tx ... the coinbase tx in the block, 
# block_txs ... the non-coinbase transactions in the block, 
# height ... the height of the block the coinbase transaction belongs to
def verify_coinbase(coinbase_tx, block_txs, height):
    # Validate public key
    outputs = coinbase_tx['outputs']
    if not 'pubkey' in outputs or not validate_pubkey(outputs['pubkey']):
        raise ErrorInvalidBlockCoinbase("Coinbase tx in block invalid: Coinbase tx contains invalid public key")
    
    # Validate that a transaction output value exists
    if not 'value' in outputs or not isinstance(outputs['value'], int):
        raise ErrorInvalidBlockCoinbase("Coinbase tx in block invalid: Coinbase tx contains invalid value")
    
    # Validate height
    if not coinbase_tx['height'] == height:
        raise ErrorInvalidBlockCoinbase("Coinbase tx in block invalid: Coinbase height doesn't match block height")
    
    # calculate transaction fees
    transaction_fees = 0

    con = sqlite3.connect(const.DB_NAME)
    for block_tx in block_txs:
        # the fee of a transaction is the sum of its input values minus the sum of its output values
        prev_txs = gather_previous_txs(con, block_tx)
        input_values = 0
        for block_tx_input in block_tx['inputs']:
            prev_txid = block_tx_input['outpoint']['txid']
            prev_tx_index = block_tx_input['outpoint']['index']

            input_values += prev_txs[prev_txid]['outputs'][prev_tx_index]['value']
        
        output_values = 0
        for block_tx_output in block_tx['outputs']:
            output_values += block_tx_output['value']
        
        transaction_fees += input_values - output_values

    con.close()

    # Verify weak law of conservatism
    if outputs['value'] > transaction_fees + const.BLOCK_REWARD:
        raise ErrorInvalidBlockCoinbase("Coinbase tx in block invalid: Coinbase tx output higher than transaction fees + block reward")


def get_block_height(block_dict):
    height = 1

    previd = block_dict['previd']

    while previd != const.GENESIS_BLOCK_ID:
        height += 1
        prev_block = get_db_object(previd)
        previd = prev_block['previd']
    
    return height

def get_db_object(objid):
    con = sqlite3.connect(const.DB_NAME)
    try:
        cur = con.cursor()
        res = cur.execute("SELECT obj FROM objects WHERE oid = ?", (objid,))

        return res.fetchone()
    
    except Exception as e:
        con.rollback()
        raise e
    finally:
        con.close()