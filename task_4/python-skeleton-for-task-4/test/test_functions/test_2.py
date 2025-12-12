import constants as const
from objects import Block
from message_sender import MessageSender

async def test2_send_blockchain_with_non_increasing_timestamps():
    print(f"\nTEST 2: SEND BLOCKCHAIN WITH NON INCREASING TIMESTAMPS")

    # Building blockchain
    genesis_block = const.GENESIS_BLOCK
    genesis_created = genesis_block["created"]

    block_1 = Block(
        T=const.BLOCK_TARGET, 
        created=genesis_created+1, 
        miner="Me", 
        nonce=None, 
        note="Hey2",
        previd=const.GENESIS_BLOCK_ID, 
        txids=[]
    )

    block_1_id = block_1.mine_block()

    block_2_non_increasing = Block(
        T=const.BLOCK_TARGET, 
        created=genesis_created+1, 
        miner="Me", 
        nonce=None, 
        note="Hey2", 
        previd=block_1_id, 
        txids=[]
    )

    block_2_id = block_2_non_increasing.mine_block()

    block_3 = Block(
        T=const.BLOCK_TARGET, 
        created=genesis_created+2, 
        miner="Me", 
        nonce=None, 
        note="Hey2", 
        previd=block_2_id, 
        txids=[]
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

    # we send the object
    await sender.send_object(block_3)

    # we should now receive requests for the other blocks
    msg = await sender.read_msg()
    print(f"Node: {msg}")

    assert msg["type"] == "getobject"
    assert msg["objectid"] == block_2_id

    # we then send the block with the non increasing created timestamp
    await sender.send_object(block_2_non_increasing)

    # we should receive a new request for block 1
    msg = await sender.read_msg()
    print(f"Node: {msg}")
    
    assert msg["type"] == "getobject"
    assert msg["objectid"] == block_1_id

    # we send block 1 --> The node should recognize that the created timestamp isn't increasing
    await sender.send_object(block_1)

    # the node should send an error message
    msg = await sender.read_msg()
    print(f"Node: {msg}")

    assert msg["type"] == "error"

    print(f"TEST 2 PASSED\n")