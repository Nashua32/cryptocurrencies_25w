from objects import *
from message_sender import MessageSender
import asyncio
from test_functions.test_1 import test1_send_blockchain_with_unavailable_block
from test_functions.test_2 import test2_send_blockchain_with_non_increasing_timestamps
from test_functions.test_3 import test3_send_blockchain_with_block_in_year_2077
from test_functions.test_4 import test4_send_blockchain_with_invalid_proof_of_work
from test_functions.test_5 import test5_send_blockchain_that_stops_at_different_genesis
from test_functions.test_6 import test6_send_blockchain_with_incorrect_height_in_a_coinbase
from test_functions.test_7 import test7_send_blockchain_with_double_spend_transaction
from test_functions.test_8 import test8_send_blockchain_with_non_existing_output
from test_functions.test_9 import test9_multiple_valid_and_invalid_chaintips

"""
IMPORTANT!

These tests only work, in an offline environment i.e. where only the test MessageSenders communicate with the node,
since the assertions also test the order of operations.
To successfully run these tests you need to comment out this part in src/constants.py:

PRELOADED_PEERS = {
    #Peer("128.130.122.73", 18018), TODO: COMMENT THIS
}


Then run the following commands:
docker compose down -v # this "resets" the tests, since it deletes the database with the test blocks
docker compose up --build # starts the application

Then you can run test.py and the tests should pass
"""

if __name__ == "__main__":
    asyncio.run(test1_send_blockchain_with_unavailable_block())

    asyncio.run(test2_send_blockchain_with_non_increasing_timestamps())

    asyncio.run(test3_send_blockchain_with_block_in_year_2077())

    asyncio.run(test4_send_blockchain_with_invalid_proof_of_work())

    asyncio.run(test5_send_blockchain_that_stops_at_different_genesis())

    asyncio.run(test6_send_blockchain_with_incorrect_height_in_a_coinbase())

    asyncio.run(test7_send_blockchain_with_double_spend_transaction())

    asyncio.run(test8_send_blockchain_with_non_existing_output())

    asyncio.run(test9_multiple_valid_and_invalid_chaintips())