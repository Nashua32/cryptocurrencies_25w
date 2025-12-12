import constants as const
from objects import Block
from message_sender import MessageSender

async def test1_send_blockchain_with_unavailable_block():
    print(f"TEST 1: SEND BLOCKCHAIN WITH UNAVAILABLE BLOCK")
    # Building blockchain
    genesis_block = const.GENESIS_BLOCK
    genesis_created = genesis_block["created"]

    unavailable_block = Block(
        T=const.BLOCK_TARGET, 
        created=genesis_created+1, 
        miner="Me", 
        nonce=None, 
        note="Hey1", 
        previd=const.GENESIS_BLOCK_ID, 
        txids=[]
    )

    unavailable_block_id = unavailable_block.mine_block()

    available_block_1 = Block(
        T=const.BLOCK_TARGET, 
        created=genesis_created+2, 
        miner="Me", 
        nonce=None, 
        note="Hey1", 
        previd=unavailable_block_id, 
        txids=[]
    )

    available_block_1_id = available_block_1.mine_block()

    available_block_2 = Block(
        T=const.BLOCK_TARGET, 
        created=genesis_created+3, 
        miner="Me", 
        nonce=None, 
        note="Hey1", 
        previd=available_block_1_id, 
        txids=[]
    )

    available_block_2_id = available_block_2.mine_block()

    # connecting to node
    sender = MessageSender("SENDER")
    await sender.connect_to_node()

    # we should receive a getchaintip msg
    msg = await sender.read_msg()
    print(f"Node: {msg}")

    assert msg["type"] == "getchaintip"

    # we send the chaintip message
    await sender.send_chaintip(available_block_2_id)

    # we should receive a getobject message for our chaintip
    msg = await sender.read_msg()
    print(f"Node: {msg}")

    assert msg["type"] == "getobject"
    assert msg["objectid"] == available_block_2_id

    # we send the object
    await sender.send_object(available_block_2)

    # we should now receive requests for the other blocks
    msg = await sender.read_msg()
    print(f"Node: {msg}")

    assert msg["type"] == "getobject"
    assert msg["objectid"] == available_block_1_id

    # we then send the available_block_1
    await sender.send_object(available_block_1)

    # we should receive a new request for unavailable_block
    msg = await sender.read_msg()
    print(f"Node: {msg}")
    
    assert msg["type"] == "getobject"
    assert msg["objectid"] == unavailable_block_id

    # unavailable_block is unavailable so the validation should timeout
    msg = await sender.read_msg()
    print(f"Node: {msg}")

    assert msg["type"] == "error"

    print(f"TEST 1 PASSED\n")