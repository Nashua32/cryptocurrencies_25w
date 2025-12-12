import constants as const
from objects import Block
from message_sender import MessageSender

async def test9_multiple_valid_and_invalid_chaintips():
    print(f"\nTEST 9: MULTIPLE VALID AND INVALID CHAINTIPS")

    sender_valid_1 = MessageSender("SENDER_VALID_1") # sends a valid chain
    sender_valid_2 = MessageSender("SENDER_VALID_2") # sends another valid chain that builds on the chain of sender_valid_1
    sender_invalid_longest = MessageSender("SENDER_INVALID_LONGEST") # sends the longest chain out of all nodes, but it is invalid
    sender_valid_longest = MessageSender("SENDER_VALID_LONGEST") # sends the longest valid chain. This should be the chain returned by getchaintip at the end

    genesis_block = const.GENESIS_BLOCK
    genesis_block_id = const.GENESIS_BLOCK_ID

    ############ SENDER VALID 1
    print(f"\nSENDER VALID 1 (Chain Height: 1)")
    block_1_sv1 = Block(
        T=const.BLOCK_TARGET,
        created=genesis_block["created"]+1,
        miner="Me",
        nonce=None,
        note="Hey9 from SV1",
        previd=genesis_block_id,
        txids=[]
    )

    block_1_sv1_id = block_1_sv1.mine_block()

    await sender_valid_1.connect_to_node()

    # we should receive a getchaintip msg
    msg = await sender_valid_1.read_msg()
    print(f"Node: {msg}")

    assert msg["type"] == "getchaintip"

    # we send the chaintip
    await sender_valid_1.send_chaintip(block_1_sv1_id)

    # we receive a getobject for block_1
    msg = await sender_valid_1.read_msg()
    print(f"Node: {msg}")

    assert msg["type"] == "getobject"
    assert msg["objectid"] == block_1_sv1_id

    await sender_valid_1.send_object(block_1_sv1)

    # we should receive an ihaveobject
    msg = await sender_valid_1.read_msg()
    print(f"Node: {msg}")
    
    assert msg["type"] == "ihaveobject"
    print(f"SENDER VALID 1 PASSED\n")


    ############ SENDER VALID 2
    print(f"\nSENDER VALID 2 (Chain Height: 2)")
    block_2_sv2 = Block(
        T=const.BLOCK_TARGET,
        created=genesis_block["created"]+2,
        miner="Me",
        nonce=None,
        note="Hey9 from Sender Valid 2",
        previd=block_1_sv1_id,
        txids=[]
    )

    block_2_sv2_id = block_2_sv2.mine_block()

    await sender_valid_2.connect_to_node()

    # we should receive a getchaintip msg
    msg = await sender_valid_2.read_msg()
    print(f"Node: {msg}")

    assert msg["type"] == "getchaintip"

    # we send the chaintip
    await sender_valid_2.send_chaintip(block_2_sv2_id)

    # we receive a getobject for block_2
    msg = await sender_valid_2.read_msg()
    print(f"Node: {msg}")

    assert msg["type"] == "getobject"
    assert msg["objectid"] == block_2_sv2_id

    await sender_valid_2.send_object(block_2_sv2)

    # we should receive an ihaveobject
    msg = await sender_valid_2.read_msg()
    print(f"Node: {msg}")
    
    assert msg["type"] == "ihaveobject"
    print(f"SENDER VALID 2 PASSED\n")

    ############ SENDER INVALID LONGEST
    print(f"\nSENDER INVALID LONGEST (Chain Height: 4)")

    # This block is invalid! It is created at the same time as the genesis block
    block_1_sil = Block(
        T=const.BLOCK_TARGET,
        created=genesis_block["created"],
        miner="Me",
        nonce=None,
        note="Hey9 from Sender Invalid Longest",
        previd=genesis_block_id,
        txids=[]
    )

    block_1_sil_id = block_1_sil.mine_block()

    block_2_sil = Block(
        T=const.BLOCK_TARGET,
        created=genesis_block["created"]+2,
        miner="Me",
        nonce=None,
        note="Hey9 from Sender Invalid Longest",
        previd=block_1_sil_id,
        txids=[]
    )

    block_2_sil_id = block_2_sil.mine_block()

    block_3_sil = Block(
        T=const.BLOCK_TARGET,
        created=genesis_block["created"]+3,
        miner="Me",
        nonce=None,
        note="Hey9 from Sender Invalid Longest",
        previd=block_2_sil_id,
        txids=[]
    )

    block_3_sil_id = block_3_sil.mine_block()

    block_4_sil = Block(
        T=const.BLOCK_TARGET,
        created=genesis_block["created"]+4,
        miner="Me",
        nonce=None,
        note="Hey9 from Sender Invalid Longest",
        previd=block_3_sil_id,
        txids=[]
    )

    block_4_sil_id = block_4_sil.mine_block()

    await sender_invalid_longest.connect_to_node()

    # we should receive a getchaintip msg
    msg = await sender_invalid_longest.read_msg()
    print(f"Node: {msg}")

    assert msg["type"] == "getchaintip"

    # we send the chaintip
    await sender_invalid_longest.send_chaintip(block_4_sil_id)

    # we receive a getobject for block_4
    msg = await sender_invalid_longest.read_msg()
    print(f"Node: {msg}")

    assert msg["type"] == "getobject"
    assert msg["objectid"] == block_4_sil_id

    await sender_invalid_longest.send_object(block_4_sil)

    # we receive a getobject for block_3 and send it
    msg = await sender_invalid_longest.read_msg()
    print(f"Node: {msg}")

    assert msg["type"] == "getobject"
    assert msg["objectid"] == block_3_sil_id

    await sender_invalid_longest.send_object(block_3_sil)

    # we receive a getobject for block_2 and send it
    msg = await sender_invalid_longest.read_msg()
    print(f"Node: {msg}")

    assert msg["type"] == "getobject"
    assert msg["objectid"] == block_2_sil_id

    await sender_invalid_longest.send_object(block_2_sil)

    # we receive a getobject for the invalid block_1 and send it
    msg = await sender_invalid_longest.read_msg()
    print(f"Node: {msg}")

    assert msg["type"] == "getobject"
    assert msg["objectid"] == block_1_sil_id

    await sender_invalid_longest.send_object(block_1_sil)

    # we should receive an error msg
    msg = await sender_invalid_longest.read_msg()
    print(f"Node: {msg}")

    assert msg["type"] == "error"

    print(f"SENDER INVALID LONGEST PASSED\n")


    ############ SENDER VALID LONGEST
    print(f"\nSENDER VALID LONGEST (Chain Height: 3)")

    block_1_svl = Block(
        T=const.BLOCK_TARGET,
        created=genesis_block["created"]+1,
        miner="Me",
        nonce=None,
        note="Hey9 from Sender Valid Longest",
        previd=genesis_block_id,
        txids=[]
    )

    block_1_svl_id = block_1_svl.mine_block()

    block_2_svl = Block(
        T=const.BLOCK_TARGET,
        created=genesis_block["created"]+2,
        miner="Me",
        nonce=None,
        note="Hey9 from Sender Valid Longest",
        previd=block_1_svl_id,
        txids=[]     
    )

    block_2_svl_id = block_2_svl.mine_block()

    block_3_svl = Block(
        T=const.BLOCK_TARGET,
        created=genesis_block["created"]+3,
        miner="Me",
        nonce=None,
        note="Hey9 from Sender Valid Longest",
        previd=block_2_svl_id,
        txids=[]            
    )

    block_3_svl_id = block_3_svl.mine_block()

    await sender_valid_longest.connect_to_node()

    # we should receive a getchaintip msg
    msg = await sender_valid_longest.read_msg()
    print(f"Node: {msg}")

    assert msg["type"] == "getchaintip"

    # we send the chaintip
    await sender_valid_longest.send_chaintip(block_3_svl_id)

    # we receive a getobject for block_3 and send it
    msg = await sender_valid_longest.read_msg()
    print(f"Node: {msg}")

    assert msg["type"] == "getobject"
    assert msg["objectid"] == block_3_svl_id

    await sender_valid_longest.send_object(block_3_svl)

    # we receive a getobject for block_2 and send it
    msg = await sender_valid_longest.read_msg()
    print(f"Node: {msg}")

    assert msg["type"] == "getobject"
    assert msg["objectid"] == block_2_svl_id

    await sender_valid_longest.send_object(block_2_svl)

    # we receive a getobject for block_1 and send it
    msg = await sender_valid_longest.read_msg()
    print(f"Node: {msg}")

    assert msg["type"] == "getobject"
    assert msg["objectid"] == block_1_svl_id

    await sender_valid_longest.send_object(block_1_svl)

    # the node should now send 3 ihaveobject messages for all these blocks
    ihaveobject_ids = [block_1_svl_id, block_2_svl_id, block_3_svl_id]

    while len(ihaveobject_ids) > 0:
        msg = await sender_valid_longest.read_msg()
        print(f"Node: {msg}")

        assert msg["type"] == "ihaveobject"
        assert msg["objectid"] in ihaveobject_ids
        ihaveobject_ids.remove(msg["objectid"])

    # now when we call getchaintip, we should receive block_3_svl_id
    await sender_valid_longest.send_getchaintip()
    msg = await sender_valid_longest.read_msg()
    print(f"Node: {msg}")

    assert msg["type"] == "chaintip"
    assert msg["blockid"] == block_3_svl_id

    # and the block from the invalid message sender should not have been saved
    await sender_valid_longest.send_getobject(block_1_sil_id)
    msg = await sender_valid_longest.read_msg()
    print(f"Node: {msg}")
    assert msg["type"] == "error"

    await sender_valid_longest.send_getobject(block_2_sil_id)
    msg = await sender_valid_longest.read_msg()
    print(f"Node: {msg}")
    assert msg["type"] == "error"

    await sender_valid_longest.send_getobject(block_3_sil_id)
    msg = await sender_valid_longest.read_msg()
    print(f"Node: {msg}")
    assert msg["type"] == "error"

    print(f"TEST 9 PASSED\n")