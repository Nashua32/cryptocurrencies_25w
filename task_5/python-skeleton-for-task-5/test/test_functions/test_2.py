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

async def test2_chain_reorganization_should_lead_to_new_mempool():
    print(f"\nTEST 2: CHAIN REORGANIZATION SHOULD LEAD TO NEW MEMPOOL")

    genesis_block = const.GENESIS_BLOCK
    genesis_block_id = const.GENESIS_BLOCK_ID

    privkey, pubkey = generate_keypair()

    # The old chain contains a transaction from a outpoint which isn't used in the new chain.
    # The mempool after sending the new chain should contain this transaction

    ##### COMMON CHAIN BEGIN
    coinbase_output = TransactionOutput(pubkey, const.BLOCK_REWARD)
    coinbase_transaction = CoinbaseTransaction(1, [coinbase_output])
    coinbase_transaction_id = coinbase_transaction.get_objid()

    # this transaction contains two outputs. One is used in chain 1 and the other in chain 2
    transaction_input_outpoint = TransactionInputOutpoint(coinbase_transaction_id, 0)
    transaction_input = TransactionInput(outpoint=transaction_input_outpoint, sig=None)
    transaction_output_1 = TransactionOutput(pubkey, const.BLOCK_REWARD // 2)
    transaction_output_2 = TransactionOutput(pubkey, const.BLOCK_REWARD // 2)
    transaction = Transaction([transaction_input], [transaction_output_1, transaction_output_2])
    transaction_sig = sign_tx(transaction.make_dict(), privkey)
    transaction.inputs[0].sig = transaction_sig
    transaction_id = transaction.get_objid()

    # this is the block containing the coinbase
    block_1 = Block(
        const.BLOCK_TARGET,
        genesis_block["created"]+1,
        miner="Me",
        nonce=None,
        note="Hey from Test 2",
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
        note="Hey from Test 2",
        previd=block_1_id,
        txids=[transaction_id]
    )
    block_2_id = block_2.mine_block()
    ##### COMMON CHAIN END

    ##### OLD CHAIN BEGIN
    # this transaction spends the first transaction output
    transaction_input_outpoint_firstspent = TransactionInputOutpoint(transaction_id, 0)
    transaction_input_firstspent = TransactionInput(outpoint=transaction_input_outpoint_firstspent, sig=None)
    transaction_output_firstspent = TransactionOutput(pubkey, const.BLOCK_REWARD // 2)
    transaction_firstspent = Transaction([transaction_input_firstspent], [transaction_output_firstspent])
    transaction_firstspent_sig = sign_tx(transaction_firstspent.make_dict(), privkey)
    transaction_firstspent.inputs[0].sig = transaction_firstspent_sig
    transaction_firstspent_id = transaction_firstspent.get_objid()

    block_3 = Block(
        const.BLOCK_TARGET,
        genesis_block["created"]+3,
        miner="Me",
        nonce=None,
        note="Hey from Test 2",
        previd=block_2_id,
        txids=[transaction_firstspent_id]
    )
    block_3_id = block_3.mine_block()
    ##### OLD CHAIN END


    ##### NEW CHAIN BEGIN (Block 2 is Last Common Ancestor)
    # this transaction spends from the second output of transaction 
    transaction_input_outpoint_secondspent = TransactionInputOutpoint(transaction_id, 1)
    transaction_input_secondspent = TransactionInput(transaction_input_outpoint_secondspent, sig=None)
    transaction_output_secondspent = TransactionOutput(pubkey, const.BLOCK_REWARD // 2)
    transaction_secondspent = Transaction([transaction_input_secondspent], [transaction_output_secondspent])
    transaction_secondspent_sig = sign_tx(transaction_secondspent.make_dict(), privkey)
    transaction_secondspent.inputs[0].sig = transaction_secondspent_sig
    transaction_secondspent_id = transaction_secondspent.get_objid()

    # this block contains the new transaction
    block_3_new = Block(
        const.BLOCK_TARGET,
        genesis_block["created"]+3,
        miner="Me",
        nonce=None,
        note="Hello from test 2",
        previd=block_2_id,
        txids=[transaction_secondspent_id]
    )
    block_3_new_id = block_3_new.mine_block()

    # this block is the new chaintip
    block_4 = Block(
        const.BLOCK_TARGET,
        genesis_block["created"]+4,
        miner="Me",
        nonce=None,
        note="Hello from test 2",
        previd=block_3_new_id,
        txids=[]
    )
    block_4_id = block_4.mine_block()
    ##### NEW CHAIN END

    ##### MESSAGE SENDING BEGIN
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

    # we send the coinbase
    await sender.send_object(coinbase_transaction)
    msg = await sender.read_msg()
    print(f"Node: {msg}")
    assert msg["type"] == "ihaveobject"
    assert msg["objectid"] == coinbase_transaction_id

    # we send the first block (contains the coinbase)
    await sender.send_object(block_1)
    msg = await sender.read_msg()
    print(f"Node: {msg}")
    assert msg["type"] == "ihaveobject"
    assert msg["objectid"] == block_1_id

    # we send the transaction that creates the two outputs
    await sender.send_object(transaction)
    msg = await sender.read_msg()
    print(f"Node: {msg}")
    assert msg["type"] == "ihaveobject"
    assert msg["objectid"] == transaction_id

    # now the mempool should contain this transaction
    await sender.send_getmempool()
    msg = await sender.read_msg()
    print(f"Node: {msg}")
    assert msg["type"] == "mempool"
    assert len(msg["txids"]) == 1
    assert msg["txids"][0] == transaction_id

    # now we send the transaction that spends from the first output of the transaction
    await sender.send_object(transaction_firstspent)
    msg = await sender.read_msg()
    print(f"Node: {msg}")
    assert msg["type"] == "ihaveobject"
    assert msg["objectid"] == transaction_firstspent_id

    # the mempool should contain both `transaction` and `transaction_firstspent` now (they could both be added to a block right now!)
    await sender.send_getmempool()
    msg = await sender.read_msg()
    print(f"Node: {msg}")
    assert msg["type"] == "mempool"
    assert len(msg["txids"]) == 2
    assert msg["txids"][0] == transaction_id
    assert msg["txids"][1] == transaction_firstspent_id

    # now we send the second block, which contains the transaction that creates the two outputs
    await sender.send_object(block_2)
    msg = await sender.read_msg()
    print(f"Node: {msg}")
    assert msg["type"] == "ihaveobject"
    assert msg["objectid"] == block_2_id

    # the mempool should now contain only `transaction_firstspent`
    await sender.send_getmempool()
    msg = await sender.read_msg()
    print(f"Node: {msg}")
    assert msg["type"] == "mempool"
    assert len(msg["txids"]) == 1
    assert msg["txids"][0] == transaction_firstspent_id

    # now we send the third block, that contains `transaction_firstspent`
    await sender.send_object(block_3)
    msg = await sender.read_msg()
    print(f"Node: {msg}")
    assert msg["type"] == "ihaveobject"
    assert msg["objectid"] == block_3_id

    # now the mempool should be empty
    await sender.send_getmempool()
    msg = await sender.read_msg()
    print(f"Node: {msg}")
    assert msg["type"] == "mempool"
    assert len(msg["txids"]) == 0

    # now we send the new longest chain

    # first we send `transaction_secondspent`
    await sender.send_object(transaction_secondspent)
    msg = await sender.read_msg()
    print(f"Node: {msg}")
    assert msg["type"] == "ihaveobject"
    assert msg["objectid"] == transaction_secondspent_id

    # the mempool should now contain `transaction_secondspent`
    await sender.send_getmempool()
    msg = await sender.read_msg()
    print(f"Node: {msg}")
    assert msg["type"] == "mempool"
    assert len(msg["txids"]) == 1
    assert msg["txids"][0] == transaction_secondspent_id
    
    # we send the new block_3, which contains the transaction that spends from the second output
    await sender.send_object(block_3_new)
    msg = await sender.read_msg()
    print(f"Node: {msg}")
    assert msg["type"] == "ihaveobject"
    assert msg["objectid"] == block_3_new_id

    # the mempool should still contain `transaction_secondspent`, since block_3_new isn't part of the longest chain
    await sender.send_getmempool()
    msg = await sender.read_msg()
    print(f"Node: {msg}")
    assert msg["type"] == "mempool"
    assert len(msg["txids"]) == 1
    assert msg["txids"][0] == transaction_secondspent_id

    # now we send block_4 --> the new chaintip
    await sender.send_object(block_4)
    msg = await sender.read_msg()
    print(f"Node: {msg}")
    assert msg["type"] == "ihaveobject"
    assert msg["objectid"] == block_4_id

    # the mempool should now contain only `transaction_firstspent` since it isn't part of the longest chain
    await sender.send_getmempool()
    msg = await sender.read_msg()
    print(f"Node: {msg}")
    assert msg["type"] == "mempool"
    assert len(msg["txids"]) == 1
    assert msg["txids"][0] == transaction_firstspent_id

    ##### MESSAGE SENDING END

    print(f"TEST 2 PASSED\n")