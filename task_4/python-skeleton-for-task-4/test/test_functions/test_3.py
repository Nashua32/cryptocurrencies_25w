import constants as const
from objects import Block
from message_sender import MessageSender
import datetime

async def test3_send_blockchain_with_block_in_year_2077():
    print(f"\nTEST 3: SEND BLOCKCHAIN WITH BLOCK IN YEAR 2077")
    genesis_block = const.GENESIS_BLOCK
    genesis_created = genesis_block["created"]

    block_1 = Block(
        T=const.BLOCK_TARGET,
        created=genesis_created+1,
        miner="Me",
        nonce=None,
        note="Hey3",
        previd=const.GENESIS_BLOCK_ID,
        txids=[]
    )

    block_1_id = block_1.mine_block()

    block_created = 3398928000
    print(f"Creating block with created: {datetime.datetime.fromtimestamp(block_created)}")
    block_2_2077 = Block(
        T=const.BLOCK_TARGET,
        created=3398928000,
        miner="Me",
        nonce=None,
        note="Hey3",
        previd=block_1_id,
        txids=[]
    )

    block_2_id = block_2_2077.mine_block()

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

    # we send the object
    await sender.send_object(block_2_2077)

    # we should receive an error message
    msg = await sender.read_msg()
    print(f"Node: {msg}")

    assert msg["type"] == "error"

    print(f"TEST 3 PASSED\n")