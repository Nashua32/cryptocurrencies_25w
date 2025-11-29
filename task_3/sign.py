from nacl.signing import SigningKey

# ----------------------------
# Fixed keypair (32-byte seed)
# ----------------------------
# Example private key (replace with your own if needed):
fixed_sk_hex = "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100"
sk = SigningKey(bytes.fromhex(fixed_sk_hex))
vk = sk.verify_key

# ---- Canonicalized transactions to sign ----
msg_t0 = b'{"type":"transaction","inputs":[{"outpoint":{"txid":"6ebfb4c8e8e9b19dcf54c6ce3e1e143da1f473ea986e70c5cb8899a4671c933a","index":0},"sig":null}],"outputs":[{"pubkey":"a7cbde2778e80e132712e8147e668a8f95c1f86b8bcbd366d5eb492d63ea6c99","value":50000000000000}]}'

msg_t1 = b'{"type":"object","object":{"type":"transaction","inputs":[{"outpoint":{"txid":"6ebfb4c8e8e9b19dcf54c6ce3e1e143da1f473ea986e70c5cb8899a4671c933a","index":0},"sig":"b1f62648c67093c6b8dad15012bf5b7256ac0f0eb95f21aa21c8f5f3a9d6e1d20e8412b75fdec9f83969d136052b04cbd03345cad7212abfea498207"}],"outputs":[{"pubkey":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","value":50000000000000}]}}'

msg_t2 = b''  # (you can fill this later)

# ---- Sign messages using fixed key ----
sig = sk.sign(msg_t0).signature
sig_t1 = sk.sign(msg_t1).signature

print("PRIVATE KEY:", sk.encode().hex())
print("PUBLIC KEY: ", vk.encode().hex())
print("SIGNATURE of t0:", sig.hex())
print("SIG of t1_wrapped:", sig_t1.hex())

