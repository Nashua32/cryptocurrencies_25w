import constants as const
import asyncio
from message_builder import *
from jcs import canonicalize
import json
from objects import Object

class MessageSender:
    def __init__(self, name):
        self.reader = None
        self.writer = None
        self.name = name

    # writes the msg
    async def write_msg(self, msg_dict):
        msg_bytes = canonicalize(msg_dict)
        self.writer.write(msg_bytes)
        self.writer.write(b'\n')
        await self.writer.drain()

    # reads a new msg
    async def read_msg(self):
        msg_str = await asyncio.wait_for(self.reader.readline(), timeout=const.HELLO_MSG_TIMEOUT)
        try:
            msg = json.loads(msg_str)
        except Exception as e:
            raise Exception("JSON parse error: {}".format(str(e)))

        return msg

    # connects to our node and sends a hello msg
    async def connect_to_node(self):
        try:
            self.reader, self.writer = await asyncio.open_connection("localhost", 18018)
        except Exception as e:
            print(f"failed to connect to localhost 18018: {str(e)}")
            self.reader = None
            self.writer = None
            return

        # wait for hello by the node
        hellomsg = await self.read_msg()
        print(f"Node: {hellomsg}")

        # send hello to the node
        hello = mk_hello_msg()
        await self.write_msg(hello)
        print(f"{self.name}: {hello}")

        # wait for getmempool msg
        getmempool_str = await self.read_msg()
        print(f"Node: {getmempool_str}")

        # wait for the getpeers message
        getpeersmsg_str = await self.read_msg()
        print(f"Node: {getpeersmsg_str}")

        print(f"{self.name} connected successfully to localhost")

    # sends the given object as a object message
    async def send_object(self, object: Object):
        object_dict = object.make_dict()
        object_msg = mk_object_msg(object_dict)
        await self.write_msg(object_msg)
        print(f"{self.name}: {object_msg}")

    # sends a getobject message for the given object_id
    async def send_getobject(self, object_id: str):
        getobject_msg = mk_getobject_msg(object_id)
        await self.write_msg(getobject_msg)
        print(f"{self.name}: {getobject_msg}")

    # sends a chaintip message, where blockid is the tip of the longest chain
    async def send_chaintip(self, blockid: str):
        chaintip_msg = mk_chaintip_msg(blockid)
        await self.write_msg(chaintip_msg)
        print(f"{self.name}: {chaintip_msg}")

    # send a getchaintip message
    async def send_getchaintip(self):
        getchaintip_msg = mk_getchaintip_msg()
        await self.write_msg(getchaintip_msg)
        print(f"{self.name}: {getchaintip_msg}")

    async def send_getmempool(self):
        getmempool_msg = mk_getmempool_msg()
        await self.write_msg(getmempool_msg)
        print(f"{self.name}: {getmempool_msg}")

    async def send_mempool(self, txids: list[str]):
        mempool_msg = mk_mempool_msg(txids)
        await self.write_msg(mempool_msg)
        print(f"{self.name}: {mempool_msg}")