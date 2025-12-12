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

async def test8_send_blockchain_with_non_existing_output():
    print(f"\nTEST 8: SEND BLOCKCHAIN WITH NON EXISTING TRANSACTION OUTPOINT")

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

    # block 1 doesn't actually contain the coinbase transaction defined above
    block_1 = Block(
        T=const.BLOCK_TARGET,
        created=genesis_block["created"]+1,
        miner="Me",
        nonce=None,
        note="Hey8",
        previd=genesis_block_id,
        txids=[]
    )

    block_1_id = block_1.mine_block()

    # this outpoint doesn't exist!
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
        note="Hey8",
        previd=block_1_id,
        txids=[block_2_transaction_id]
    )

    block_2_id = block_2.mine_block()

    # connecting to node
    sender = MessageSender("SENDER")
    await sender.connect_to_node()

    # we should receive a getchaintip msg
    msg = await sender.read_msg()
    print(f"Node: {msg}")

    assert msg["type"] == "getchaintip"

    # we send the chaintip message
    await sender.send_chaintip(block_2_id)

    # we should receive a getobject message for our chaintip
    msg = await sender.read_msg()
    print(f"Node: {msg}")

    assert msg["type"] == "getobject"
    assert msg["objectid"] == block_2_id

    # we send block 2
    await sender.send_object(block_2)

    # now the node will request the previous block or the transaction
    msg = await sender.read_msg()
    print(f"Node: {msg}")

    assert msg["type"] == "getobject"
    assert msg["objectid"] == block_1_id or msg["objectid"] == block_2_transaction_id

    if msg["objectid"] == block_1_id:
        # we send block 1
        await sender.send_object(block_1)
    else:
        await sender.send_object(block_2_transaction)

    # the node requests the transaction in block_2 or block_1
    msg = await sender.read_msg()
    print(f"Node: {msg}")

    assert msg["type"] == "getobject"
    assert msg["objectid"] == block_2_transaction_id or msg["objectid"] == block_1_id

    if msg["objectid"] == block_1_id:
        # we send block 1
        await sender.send_object(block_1)
    else:
        await sender.send_object(block_2_transaction)

    # the node sends ihaveobject msgs for block_1 and getobject msgs for the outpoint in block_2_transaction
    while True:
        msg = await sender.read_msg()
        print(f"Node: {msg}")

        if msg["type"] == "ihaveobject":
            assert msg["objectid"] != block_2_transaction_id # should never be accepted
        elif msg["type"] == "getobject":
            assert msg["objectid"] == block_1_coinbase_id
            await sender.send_object(block_1_coinbase)
        elif msg["type"] == "error":
            print(f"\nTEST 8 PASSED")
            return

    