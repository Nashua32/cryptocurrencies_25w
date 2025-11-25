# NC Test – Block & Coinbase

## 1. Verbinden

```bash
nc 127.0.0.1 18018
```
Warte auf die hello-Nachricht vom Node.

## 2. Hello senden
```bash
{"type":"hello","version":"0.10.2","agent":"netcat"}
```

## 3. Coinbase-Transaktion senden
```bash
{"type":"object","object":{"type":"transaction","height":1,"outputs":[{"pubkey":"3f0bc71a375b574e4bda3ddf502fe1afd99aa020bf6049adfe525d9ad18ff33f","value":50000000000000}]}}
```

## 4. Block senden
```bash
{"type":"object","object":{"T":"0000abc000000000000000000000000000000000000000000000000000000000","created":1671148800,"miner":"student","nonce":"0000000000000000000000000000000000000000000000000000000000002bc9","note":"Test block on assignment genesis with 1 coinbase tx","previd":"00002fa163c7dab0991544424b9fd302bb1782b185e5a3bbdf12afb758e57dee","txids":["6ebfb4c8e8e9b19dcf54c6ce3e1e143da1f473ea986e70c5cb8899a4671c933a"],"type":"block"}}
```

## 5. UTXO-Set im Docker-Container prüfen

```bash
sqlite3 db.db
.headers on
.mode column
SELECT blockid, utxo FROM utxos;
.quit
```
Falls sqlite3 nicht da ist:

```bash
apk add --no-cache sqlite
```
