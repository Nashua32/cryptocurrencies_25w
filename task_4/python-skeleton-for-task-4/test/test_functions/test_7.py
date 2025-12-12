import constants as const
from objects import Block, CoinbaseTransaction, Transaction, TransactionInput, TransactionOutput, TransactionInputOutpoint
from message_sender import MessageSender

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
import copy
from jcs import canonicalize

def generate_keypair():
    privkey_obj = Ed25519PrivateKey.generate()

    pubkey_obj = privkey_obj.public_key()

    priv_bytes = privkey_obj.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )

    pub_bytes = pubkey_obj.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    priv_hex = priv_bytes.hex()
    pub_hex = pub_bytes.hex()

    return priv_hex, pub_hex

def sign_tx(tx_dict, priv_hex):
    tx_local = copy.deepcopy(tx_dict)
    for i in tx_local['inputs']:
        i['sig'] = None

    priv_bytes = bytes.fromhex(priv_hex)
    privkey_obj = Ed25519PrivateKey.from_private_bytes(priv_bytes)

    msg_bytes = canonicalize(tx_local)
    sig_bytes = privkey_obj.sign(msg_bytes)

    return sig_bytes.hex()

async def test7_send_blockchain_with_double_spend_transaction():
    print(f"\nTEST 7: SEND BLOCKCHAIN WITH DOUBLE SPEND TRANSACTION")
    privkey, pubkey = generate_keypair()

    genesis_block = const.GENESIS_BLOCK
    genesis_block_id = const.GENESIS_BLOCK_ID

    coinbase_output = TransactionOutput(
        pubkey=pubkey,
        value=const.BLOCK_REWARD
    )
    block_1_coinbase = CoinbaseTransaction(
        height=1,
        outputs=[coinbase_output]
    )
    block_1_coinbase_id = block_1_coinbase.get_objid(block_1_coinbase.make_dict())

    block_1 = Block(
        T=const.BLOCK_TARGET,
        created=genesis_block["created"]+1,
        miner="Me",
        nonce=None,
        note="Hey7",
        previd=genesis_block_id,
        txids=[block_1_coinbase_id]
    )
    block_1_id = block_1.mine_block()

    block_2_transaction_input_outpoint = TransactionInputOutpoint(
        txid=block_1_coinbase_id,
        index=0
    )

    block_2_transaction_input = TransactionInput(
        outpoint=block_2_transaction_input_outpoint,
        sig=None
    )

    block_2_transaction_output = TransactionOutput(
        pubkey=pubkey,
        value=const.BLOCK_REWARD
    )

    block_2_transaction = Transaction(
        inputs=[block_2_transaction_input],
        outputs=[block_2_transaction_output]
    )

    block_2_transaction_sig = sign_tx(block_2_transaction.make_dict(), privkey)
    block_2_transaction.inputs[0].sig = block_2_transaction_sig

    block_2_transaction_id = block_2_transaction.get_objid(block_2_transaction.make_dict())

    block_2 = Block(
        T=const.BLOCK_TARGET,
        created=genesis_block["created"]+2,
        miner="Me",
        nonce=None,
        note="Hey7",
        previd=block_1_id,
        txids=[block_2_transaction_id]
    )

    block_2_id = block_2.mine_block()

    # This spends from the same coinbase as the transaction in the block before
    block_3_transaction_input_outpoint = TransactionInputOutpoint(
        txid=block_1_coinbase_id,
        index=0
    )

    block_3_transaction_input = TransactionInput(
        outpoint=block_3_transaction_input_outpoint,
        sig=None
    )

    # I set BLOCK_REWARD - 1 as the value so that the objid isn't the same
    block_3_transaction_output = TransactionOutput(
        pubkey=pubkey,
        value=const.BLOCK_REWARD-1
    )

    block_3_transaction = Transaction(
        inputs=[block_3_transaction_input],
        outputs=[block_3_transaction_output]
    )

    block_3_transaction_sig = sign_tx(block_3_transaction.make_dict(), privkey)
    block_3_transaction.inputs[0].sig = block_3_transaction_sig

    block_3_transaction_id = block_3_transaction.get_objid(block_3_transaction.make_dict())

    block_3 = Block(
        T=const.BLOCK_TARGET,
        created=genesis_block["created"]+3,
        miner="Me",
        nonce=None,
        note="Hey7",
        previd=block_2_id,
        txids=[block_3_transaction_id]
    )

    block_3_id = block_3.mine_block()

    # connecting to node
    sender = MessageSender("SENDER")
    await sender.connect_to_node()

    # we should receive a getchaintip msg
    msg = await sender.read_msg()
    print(f"Node: {msg}")

    assert msg["type"] == "getchaintip"

    # we send the chaintip message
    await sender.send_chaintip(block_3_id)

    # we should receive a getobject message for our chaintip
    msg = await sender.read_msg()
    print(f"Node: {msg}")

    assert msg["type"] == "getobject"
    assert msg["objectid"] == block_3_id

    # we send block 3
    await sender.send_object(block_3)

    # now the node should request all transactions and blocks in some order
    missing_objects = {
        block_3_transaction_id: block_3_transaction,
        block_2_id: block_2,
        block_2_transaction_id: block_2_transaction,
        block_1_id: block_1,
        block_1_coinbase_id: block_1_coinbase
    }
    
    # this loop will run until we receive an error message or the read timeouts
    while True:
        msg = await sender.read_msg()
        print(f"Node: {msg}")
        
        if msg["type"] == "getobject":
            assert msg["objectid"] in missing_objects.keys()

            # we send the object
            await sender.send_object(missing_objects[msg["objectid"]])

        elif msg["type"] == "error":
            print(f"TEST 7 PASSED\n")
            return
