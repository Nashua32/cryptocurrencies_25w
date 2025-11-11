import asyncio
import argparse
import json
import time
import os
import hashlib
from typing import Optional, Callable
from pathlib import Path
from copy import deepcopy

# robust import for jcs canonicalize
try:
    from jcs import canonicalize  # jcs==0.2.1
except ImportError:
    try:
        from python_jcs import canonicalize  # alternative package name
    except ImportError as e:
        raise SystemExit("ERROR: jcs/python-jcs not installed. Try: pip install jcs==0.2.1 or python-jcs") from e

HELLO_VERSION = "0.10.0"  # must match regex 0\.10\.\d on the server
HELLO_AGENT = "tester/1.3"

def canon_bytes(obj: dict) -> bytes:
    # canonical JSON per jcs
    return canonicalize(obj)

def object_id(obj: dict) -> str:
    # blake2s over canonical JSON
    h = hashlib.blake2s()
    h.update(canon_bytes(obj))
    return h.hexdigest()

def line(msg: dict) -> bytes:
    # newline-delimited canonical JSON
    return canon_bytes(msg) + b"\n"

class PeerClient:
    def __init__(self, host: str, port: int, name: str, debug: bool = False):
        self.host = host
        self.port = port
        self.name = name
        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None
        self.debug = debug

    async def connect_and_handshake(self, timeout: float = 5.0):
        self.reader, self.writer = await asyncio.open_connection(self.host, self.port, limit=1_000_000)
        # Server will send hello + getpeers first
        for _ in range(2):
            line_in = await asyncio.wait_for(self.reader.readline(), timeout=timeout)
            if self.debug:
                print(f"[{self.name}] <= {line_in.decode(errors='ignore').strip()}")
        # Send our hello (first message must be hello)
        await self.send({"type": "hello", "version": HELLO_VERSION, "agent": HELLO_AGENT})

    async def send(self, msg: dict):
        data = line(msg)
        if self.debug:
            try:
                print(f"[{self.name}] => {data.decode().strip()}")
            except Exception:
                pass
        self.writer.write(data)
        await self.writer.drain()

    async def recv_json(self, timeout: float = 5.0) -> Optional[dict]:
        try:
            line_in = await asyncio.wait_for(self.reader.readline(), timeout=timeout)
        except asyncio.TimeoutError:
            return None
        if not line_in:
            return None
        if self.debug:
            print(f"[{self.name}] <= {line_in.decode(errors='ignore').strip()}")
        try:
            return json.loads(line_in.decode())
        except Exception:
            return None

    async def expect(self, predicate: Callable[[dict], bool], timeout: float = 5.0) -> Optional[dict]:
        end = time.time() + timeout
        while time.time() < end:
            msg = await self.recv_json(timeout=max(0.05, end - time.time()))
            if msg is None:
                continue
            if predicate(msg):
                return msg
        return None

    async def close(self):
        try:
            if self.writer:
                self.writer.close()
                await self.writer.wait_closed()
        except Exception:
            pass

def ok(label: str):
    print(f"✅ {label}")

def fail(label: str, extra: str = ""):
    print(f"❌ {label}{(': ' + extra) if extra else ''}")

def info(msg: str):
    print(f"ℹ️  {msg}")

def freshen_coinbase(obj: dict) -> dict:
    """
    Return a new, still-valid coinbase with a slightly tweaked pubkey to force a new objectid.
    (Coinbase has no input signatures, so changing pubkey is okay.)
    """
    new_obj = deepcopy(obj)
    if not isinstance(new_obj, dict):
        return obj
    if new_obj.get("type") != "transaction" or "height" not in new_obj:
        return obj
    outs = new_obj.get("outputs")
    if not isinstance(outs, list) or not outs:
        return obj
    out0 = outs[0]
    pk = out0.get("pubkey")
    if not (isinstance(pk, str) and len(pk) == 64):
        return obj
    hexdigits = "0123456789abcdef"
    last = pk[-1].lower()
    try:
        idx = hexdigits.index(last)
        out0["pubkey"] = pk[:-1] + hexdigits[(idx + 1) % 16]
    except ValueError:
        pass
    return new_obj

async def preload_coinbase(host: str, port: int, coinbase_obj: dict, debug: bool) -> bool:
    """
    Send a coinbase object via G1 and ensure G2 observes ihaveobject.
    Returns True if preload succeeded.
    """
    label = "0) Preload coinbase (send OBJECT and expect IHAVEOBJECT on second peer)"
    g1 = PeerClient(host, port, "G1", debug)
    g2 = PeerClient(host, port, "G2", debug)
    try:
        await asyncio.gather(g1.connect_and_handshake(), g2.connect_and_handshake())
        await g1.send({"type": "object", "object": coinbase_obj})
        ihave = await g2.expect(lambda m: m.get("type") == "ihaveobject" and "objectid" in m, timeout=5.0)
        if ihave:
            ok(label)
            return True
        else:
            fail(label, "second peer did not receive ihaveobject")
            return False
    finally:
        await asyncio.gather(g1.close(), g2.close())

async def test_object_exchange_same_peer(host: str, port: int, obj_body: Optional[dict], debug: bool) -> bool:
    label = "1a) Object Exchange: same peer can GET after sending OBJECT"
    if obj_body is None:
        print(f"⏭️  {label} (skipped: no object provided)")
        return True
    c1 = PeerClient(host, port, "G1", debug)
    try:
        await c1.connect_and_handshake()
        await c1.send({"type":"object","object":obj_body})
        oid = object_id(obj_body)
        await c1.send({"type":"getobject","objectid":oid})
        got = await c1.expect(lambda m: m.get("type")=="object" and m.get("object") is not None, timeout=5.0)
        if got:
            ok(label)
            return True
        fail(label, "did not receive object after getobject")
        return False
    finally:
        await c1.close()

async def test_object_exchange_cross_peer(host: str, port: int, obj_body: Optional[dict], debug: bool) -> bool:
    label1 = "1b) Object Exchange: second peer can GET an object first peer sent"
    label2 = "1c) Object Exchange: second peer receives IHAVEOBJECT for new object"
    if obj_body is None:
        print(f"⏭️  {label1} / {label2} (skipped: no object provided)")
        return True
    c1 = PeerClient(host, port, "G1", debug)
    c2 = PeerClient(host, port, "G2", debug)
    try:
        await asyncio.gather(c1.connect_and_handshake(), c2.connect_and_handshake())
        send_obj = obj_body
        # If it's a coinbase, mutate slightly so it becomes "new" and triggers gossip again
        if isinstance(obj_body, dict) and obj_body.get("type") == "transaction" and "height" in obj_body:
            send_obj = freshen_coinbase(obj_body)
        await c1.send({"type":"object","object":send_obj})
        ihave = await c2.expect(lambda m: m.get("type")=="ihaveobject" and "objectid" in m, timeout=5.0)
        ihave_ok = ihave is not None
        if ihave_ok:
            ok(label2)
            oid = ihave["objectid"]
            await c2.send({"type":"getobject","objectid":oid})
            got = await c2.expect(lambda m: m.get("type")=="object" and m.get("object") is not None, timeout=5.0)
            if got:
                ok(label1)
                return True
            else:
                fail(label1, "did not receive object after getobject")
                return False
        else:
            fail(label2, "did not receive ihaveobject")
            return False
    finally:
        await asyncio.gather(c1.close(), c2.close())

async def test_ihave_triggers_getobject(host: str, port: int, debug: bool) -> bool:
    label = "1d) Object Exchange: IHAVEOBJECT triggers GETOBJECT"
    c1 = PeerClient(host, port, "G1", debug)
    try:
        await c1.connect_and_handshake()
        fake_id = os.urandom(16).hex()
        await c1.send({"type":"ihaveobject","objectid":fake_id})
        got = await c1.expect(lambda m: m.get("type")=="getobject" and m.get("objectid")==fake_id, timeout=5.0)
        if got:
            ok(label)
            return True
        fail(label, "no getobject in response to ihaveobject")
        return False
    finally:
        await c1.close()

async def test_tx_validation(host: str, port: int, invalid_obj: Optional[dict], valid_obj: Optional[dict], debug: bool) -> bool:
    label_invalid = "2a) Tx Validation: invalid transaction yields ERROR and no gossip"
    label_valid = "2b) Tx Validation: valid transaction is gossiped"
    res_a = True
    if invalid_obj is None:
        print(f"⏭️  {label_invalid} (skipped: no invalid_tx.json provided)")
    else:
        g1 = PeerClient(host, port, "G1", debug)
        g2 = PeerClient(host, port, "G2", debug)
        try:
            await asyncio.gather(g1.connect_and_handshake(), g2.connect_and_handshake())
            await g1.send({"type":"object","object":invalid_obj})
            err = await g1.expect(lambda m: m.get("type")=="error" and "name" in m and "msg" in m, timeout=5.0)
            ihave = await g2.expect(lambda m: m.get("type")=="ihaveobject", timeout=2.5)
            if err and ihave is None:
                ok(label_invalid)
            else:
                res_a = False
                if not err:
                    fail(label_invalid, "sender did not receive error")
                if ihave is not None:
                    fail(label_invalid, "invalid tx was still gossiped (ihaveobject seen)")
        finally:
            await asyncio.gather(g1.close(), g2.close())

    res_b = True
    if valid_obj is None:
        print(f"⏭️  {label_valid} (skipped: no valid_tx.json provided)")
    else:
        g1 = PeerClient(host, port, "G1", debug)
        g2 = PeerClient(host, port, "G2", debug)
        try:
            await asyncio.gather(g1.connect_and_handshake(), g2.connect_and_handshake())
            await g1.send({"type":"object","object":valid_obj})
            ihave = await g2.expect(lambda m: m.get("type")=="ihaveobject", timeout=5.0)
            if ihave:
                ok(label_valid)
            else:
                res_b = False
                fail(label_valid, "no ihaveobject for valid tx")
        finally:
            await asyncio.gather(g1.close(), g2.close())

    return res_a and res_b

def load_json_or_none(path: Optional[str]) -> Optional[dict]:
    if not path:
        return None
    p = Path(path)
    if not p.exists():
        return None
    try:
        with p.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"⚠️  Could not load {path}: {e}")
        return None

async def main():
    parser = argparse.ArgumentParser(description="Local grader for P2P node (object exchange + tx validation)")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=18018)
    parser.add_argument("--valid", default="valid_tx.json", help="Path to a valid transaction JSON (object body)")
    parser.add_argument("--invalid", default="invalid_tx.json", help="Path to an invalid transaction JSON (object body)")
    parser.add_argument("--coinbase", default=None, help="Optional path to a coinbase transaction JSON (object body) to preload")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    valid_obj = load_json_or_none(args.valid)
    invalid_obj = load_json_or_none(args.invalid)
    coinbase_obj = load_json_or_none(args.coinbase)

    print(f"🔎 Testing node at {args.host}:{args.port}")
    print(f"   Using valid: {args.valid} ({'found' if valid_obj else 'missing'})")
    print(f"   Using invalid: {args.invalid} ({'found' if invalid_obj else 'missing'})")
    if coinbase_obj:
        print(f"   Preloading coinbase: {args.coinbase} (found)")
    else:
        print(f"   Preloading coinbase: (none)")

    print("")

    if coinbase_obj is not None:
        pre_ok = await preload_coinbase(args.host, args.port, coinbase_obj, args.debug)
        if not pre_ok:
            print("❗ Preload failed; subsequent tests may also fail due to UNKNOWN_OBJECT.")

    obj_for_1x = coinbase_obj if coinbase_obj is not None else valid_obj

    passed = True
    passed &= await test_object_exchange_same_peer(args.host, args.port, obj_for_1x, args.debug)
    passed &= await test_object_exchange_cross_peer(args.host, args.port, obj_for_1x, args.debug)
    passed &= await test_ihave_triggers_getobject(args.host, args.port, args.debug)
    passed &= await test_tx_validation(args.host, args.port, invalid_obj, valid_obj, args.debug)

    print("\n" + ("🎉 ALL REQUESTED TESTS PASSED" if passed else "❗Some tests failed"))

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass