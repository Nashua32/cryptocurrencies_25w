import json
from hashlib import blake2s

def canonical_json(obj) -> str:
    """
    Produce RFC-8785–compatible canonical JSON:
      - UTF-8
      - Sorted keys
      - No whitespace
      - No trailing zeros in numbers
    """
    return json.dumps(
        obj,
        separators=(",", ":"),
        sort_keys=True,
        ensure_ascii=False
    )

def objectid_for(obj) -> str:
    """
    Compute blake2s of the canonical JSON representation.
    """
    cj = canonical_json(obj).encode("utf-8")
    return blake2s(cj).hexdigest()

if __name__ == "__main__":
    # Example object — replace this with your transaction/block/message
    message = {"type":"transaction","height":1,"outputs":		[{"pubkey":"712651f450ba05b63898b99ef5f7ba45632e8e2527f7f715cd671ec4024cc51e","value":50000000000000}]}


    cj = canonical_json(message)
    oid = objectid_for(message)

    print("Canonical JSON:")
    print(cj)
    print("\nObjectID (blake2s):")
    print(oid)

