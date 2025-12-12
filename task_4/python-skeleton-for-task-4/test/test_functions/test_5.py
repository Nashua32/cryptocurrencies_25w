import constants as const
from objects import Block
from message_sender import MessageSender

# different genesis block has valid POW, but null previd
async def test5_send_blockchain_that_stops_at_different_genesis():
    print("\nTEST 5: SEND BLOCKCHAIN THAT STOPS AT DIFFERENT GENESIS")
    genesis = const.GENESIS_BLOCK

    block_new_genesis = Block(
        T=const.BLOCK_TARGET,
        created=genesis["created"],
        miner="Me",
        nonce=None,
        note="Hey5",
        previd=None,
        txids=[]
    )

    block_new_genesis_id = block_new_genesis.mine_block()

    block_1 = Block(
        T=const.BLOCK_TARGET,
        created=genesis["created"]+1,
        miner="Me",
        nonce=None,
        note="Hey5",
        previd=block_new_genesis_id,
        txids=[]
    )

    block_1_id = block_1.mine_block()

    block_2 = Block(
        T=const.BLOCK_TARGET,
        created=genesis["created"]+2,
        miner="Me",
        nonce=None,
        note="Hey5",
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

    # we send the invalid object
    await sender.send_object(block_1)

    # after which it requests our new genesis block
    msg = await sender.read_msg()
    print(f"Node: {msg}")
    
    assert msg["type"] == "getobject"
    assert msg["objectid"] == block_new_genesis_id

    # we send the new genesis block
    await sender.send_object(block_new_genesis)

    # and should receive an error msg
    msg = await sender.read_msg()
    print(f"Node: {msg}")

    assert msg["type"] == "error"

    print(f"TEST 5 PASSED\n")