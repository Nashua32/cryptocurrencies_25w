from objects import *
from message_sender import MessageSender
import asyncio
from test_functions.test_1 import test1_send_transaction_should_appear_in_mempool
from test_functions.test_2 import test2_chain_reorganization_should_lead_to_new_mempool


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

Then you can run test.py from the `test` directory and the test should pass

IMPORTANT!!!!!
Since the database needs to be reset after every test, you can only run one of the below tests at a time.
You need to `docker compose down -v` and `docker compose up --build` after every test and comment out all tests
that you don't want to run (I know this is stupid af, but I really wasn't motivated to find smart solutions for this lecture)
"""

if __name__ == "__main__":
    asyncio.run(test1_send_transaction_should_appear_in_mempool())
    #asyncio.run(test2_chain_reorganization_should_lead_to_new_mempool())