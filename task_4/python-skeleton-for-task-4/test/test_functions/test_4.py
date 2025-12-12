import constants as const
from objects import Block
from message_sender import MessageSender

async def test4_send_blockchain_with_invalid_proof_of_work():
    print(f"\nTEST 4: SEND BLOCKCHAIN WITH INVALID PROOF OF WORK")
    genesis_block = const.GENESIS_BLOCK
    genesis_block_id = const.GENESIS_BLOCK_ID

    block_1_invalid_pow = Block(
        T=const.BLOCK_TARGET,
        created=genesis_block["created"]+1,
        miner="Me",
        nonce="00000000000000000000000000000000000000000000000000000000005bb0f2",
        note="Hey4",
        previd=genesis_block_id,
        txids=[]
    )

    block_1_id = block_1_invalid_pow.get_objid(block_1_invalid_pow.make_dict())

    block_2 = Block(
        T=const.BLOCK_TARGET,
        created=genesis_block["created"]+2,
        miner="Me",
        nonce=None,
        note="Hey4",
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

    # now the node requests block 1 with the invalid POW
    msg = await sender.read_msg()
    print(f"Node: {msg}")

    assert msg["type"] == "getobject"
    assert msg["objectid"] == block_1_id

    # we send the invalid object
    await sender.send_object(block_1_invalid_pow)

    # and should receive an error msg
    msg = await sender.read_msg()
    print(f"Node: {msg}")

    assert msg["type"] == "error"

    print(f"TEST 4 PASSED\n")