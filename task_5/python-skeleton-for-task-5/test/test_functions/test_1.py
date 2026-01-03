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

async def test1_send_transaction_should_appear_in_mempool():
    print(f"\nTEST 1: SEND TRANSACTION. SHOULD APPEAR IN MEMPOOL")

    genesis_block = const.GENESIS_BLOCK
    genesis_block_id = const.GENESIS_BLOCK_ID

    privkey, pubkey = generate_keypair()

    # this coinbase will be the outpoint of our tx
    coinbase_output = TransactionOutput(pubkey, const.BLOCK_REWARD)
    coinbase_transaction = CoinbaseTransaction(1, [coinbase_output])
    coinbase_transaction_id = coinbase_transaction.get_objid()

    transaction_input_outpoint = TransactionInputOutpoint(coinbase_transaction_id, 0)
    transaction_input = TransactionInput(outpoint=transaction_input_outpoint, sig=None)

    transaction_output = TransactionOutput(pubkey, const.BLOCK_REWARD)

    transaction = Transaction([transaction_input], [transaction_output])

    transaction_sig = sign_tx(transaction.make_dict(), privkey)
    transaction.inputs[0].sig = transaction_sig

    transaction_id = transaction.get_objid()

    # this is the block containing the coinbase
    block_1 = Block(
        const.BLOCK_TARGET,
        genesis_block["created"]+1,
        miner="Me",
        nonce=None,
        note="Hey from Test 1",
        previd=genesis_block_id,
        txids=[coinbase_transaction_id]
    )

    block_1_id = block_1.mine_block()

    # this is the block containing the transaction
    block_2 = Block(
        const.BLOCK_TARGET,
        genesis_block["created"]+2,
        miner="Me",
        nonce=None,
        note="Hey from Test 1",
        previd=block_1_id,
        txids=[transaction_id]
    )

    block_2_id = block_2.mine_block()

    # we connect to the node
    sender = MessageSender("SENDER")
    await sender.connect_to_node()

    # we should receive a getchaintip msg
    msg = await sender.read_msg()
    print(f"Node: {msg}")

    assert msg["type"] == "getchaintip"

    # we send a getmempool msg -> the mempool should be empty
    await sender.send_getmempool()
    msg = await sender.read_msg()
    print(f"Node: {msg}")

    assert msg["type"] == "mempool"
    assert len(msg["txids"]) == 0

    # we send the coinbase tx -> it should not appear in the mempool
    await sender.send_object(coinbase_transaction)

    msg = await sender.read_msg()
    print(f"Node: {msg}") # should be ihaveobject for coinbase

    assert msg["type"] == "ihaveobject"
    assert msg["objectid"] == coinbase_transaction_id

    # we send the block with the coinbase -> that way the coinbase appears in the UTXO and can be used by our tx
    await sender.send_object(block_1)

    msg = await sender.read_msg()
    print(f"Node: {msg}")

    assert msg["type"] == "ihaveobject"
    assert msg["objectid"] == block_1_id

    # check that the coinbase is not in the mempool
    await sender.send_getmempool()

    msg = await sender.read_msg()
    print(f"Node: {msg}")

    assert msg["type"] == "mempool"
    assert len(msg["txids"]) == 0

    # we send the transaction -> it should now be in the mempool
    await sender.send_object(transaction)

    msg = await sender.read_msg()
    print(f"Node: {msg}")

    assert msg["type"] == "ihaveobject"
    assert msg["objectid"] == transaction_id

    # check that transaction is now in the mempool
    await sender.send_getmempool()

    msg = await sender.read_msg()
    print(f"Node: {msg}")

    assert msg["type"] == "mempool"
    assert len(msg["txids"]) == 1
    assert msg["txids"][0] == transaction_id

    # we send a block containing the transaction -> the mempool should now be empty
    await sender.send_object(block_2)

    msg = await sender.read_msg()
    print(f"Node: {msg}")

    assert msg["type"] == "ihaveobject"
    assert msg["objectid"] == block_2_id

    # check that the mempool is now empty
    await sender.send_getmempool()

    msg = await sender.read_msg()
    print(f"Node: {msg}")

    assert msg["type"] == "mempool"
    assert len(msg["txids"]) == 0

    transaction_input_outpoint_new = TransactionInputOutpoint(coinbase_transaction_id, 0)
    transaction_input_new = TransactionInput(transaction_input_outpoint_new, None)
    transaction_output_new = TransactionOutput(pubkey, value=const.BLOCK_REWARD-1)
    transaction_new = Transaction([transaction_input_new], [transaction_output_new])
    transaction_sig_new = sign_tx(transaction_new.make_dict(), privkey)
    transaction_new.inputs[0].sig = transaction_sig_new
    transaction_id_new = transaction_new.get_objid()

    # this block contains no transactions
    block_2_new = Block(
        const.BLOCK_TARGET,
        genesis_block["created"]+2,
        miner="Me",
        nonce=None,
        note="HEllo from test 1",
        previd=block_1_id,
        txids=[]
    )

    block_2_new_id = block_2_new.mine_block()

    block_3 = Block(
        const.BLOCK_TARGET,
        genesis_block["created"]+3,
        miner="Me",
        nonce=None,
        note="Hello from test 1",
        previd=block_2_new_id,
        txids=[transaction_id_new]
    )

    block_3_id = block_3.mine_block()

    # we send the new chain. Block 1 is the last common ancestor
    await sender.send_object(block_2_new)

    msg = await sender.read_msg()
    print(f"Node: {msg}")

    assert msg["type"] == "ihaveobject"
    assert msg["objectid"] == block_2_new_id

    # we send block 3. The node will ask for transaction_new
    await sender.send_object(block_3)

    msg = await sender.read_msg()
    print(f"Node: {msg}")

    assert msg["type"] == "getobject"
    assert msg["objectid"] == transaction_id_new

    await sender.send_object(transaction_new)

    msg = await sender.read_msg()
    print(f"Node: {msg}")

    assert msg["type"] == "ihaveobject"
    assert msg["objectid"] == transaction_id_new

    msg = await sender.read_msg()
    print(f"Node: {msg}")

    assert msg["type"] == "ihaveobject"
    assert msg["objectid"] == block_3_id

    # now we send the getmempool message, which should return an empty mempool
    await sender.send_getmempool()

    msg = await sender.read_msg()
    print(f"Node: {msg}")

    assert msg["type"] == "mempool"
    assert len(msg["txids"]) == 0

    print(f"TEST 1 PASSED\n")

