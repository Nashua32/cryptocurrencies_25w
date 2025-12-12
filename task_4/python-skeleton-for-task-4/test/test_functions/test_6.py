import constants as const
from objects import Block, CoinbaseTransaction, TransactionOutput
from message_sender import MessageSender

async def test6_send_blockchain_with_incorrect_height_in_a_coinbase():
    print(f"\nTEST 6: SEND BLOCKCHAIN WITH INCORRECT HEIGHT IN A COINBASE")
    genesis_block = const.GENESIS_BLOCK
    genesis_block_id = const.GENESIS_BLOCK_ID

    coinbase_transaction_output = TransactionOutput(
        pubkey="3f0bc71a375b574e4bda3ddf502fe1afd99aa020bf6049adfe525d9ad18ff33f",
        value=const.BLOCK_REWARD
    )

    # should be height 1
    coinbase_invalid_height = CoinbaseTransaction(
        height=2,
        outputs=[coinbase_transaction_output]
    )

    coinbase_invalid_height_id = coinbase_invalid_height.get_objid(coinbase_invalid_height.make_dict())

    block_1_invalid_coinbase = Block(
        T=const.BLOCK_TARGET,
        created=genesis_block["created"]+1,
        miner="Me",
        nonce=None,
        note="Hey6",
        previd=genesis_block_id,
        txids=[coinbase_invalid_height_id]
    )

    block_1_id = block_1_invalid_coinbase.mine_block()

    block_2 = Block(
        T=const.BLOCK_TARGET,
        created=genesis_block["created"]+2,
        miner="Me",
        nonce=None,
        note="Hey6",
        previd=block_1_id,
        txids=[]
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

    # now the node requests block 1
    msg = await sender.read_msg()
    print(f"Node: {msg}")

    assert msg["type"] == "getobject"
    assert msg["objectid"] == block_1_id

    # we send the block which contains the invalid coinbase
    await sender.send_object(block_1_invalid_coinbase)

    # the node should send us a getobject for the unknown coinbase
    msg = await sender.read_msg()
    print(f"Node: {msg}")

    assert msg["type"] == "getobject"
    assert msg["objectid"] == coinbase_invalid_height_id

    # we send the invalid coinbase
    await sender.send_object(coinbase_invalid_height)

    # and we should receive an error message
    msg = await sender.read_msg()
    print(f"Node: {msg}")

    assert msg["type"] == "error"

    print(f"TEST 6 PASSED\n")