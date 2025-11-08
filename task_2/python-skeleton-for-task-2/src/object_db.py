import sqlite3
import json
import os


import constants as const

def main():
    con = sqlite3.connect(const.DB_NAME)
    try:
        cur = con.cursor()
        # Build database

        # Build "blocks" table
        cur.execute(
        """
        CREATE TABLE IF NOT EXISTS blocks (
            blockid TEXT PRIMARY KEY,
            T TEXT NOT NULL,
            created INTEGER NOT NULL,
            miner TEXT,
            nonce TEXT NOT NULL,
            note TEXT,
            previd TEXT,
            txids TEXT NOT NULL,
            type TEXT
        )
        """)

        # Build "txs" table - contains normal txs and coinbase txs
        cur.execute(
        """
        CREATE TABLE IF NOT EXISTS txs (
            txid TEXT PRIMARY KEY,
            type TEXT,
            height TEXT,
            inputs TEXT,
            outputs TEXT
        )
        """
        )

        # Preload genesis block
        cur.execute(
        """
        INSERT OR IGNORE INTO blocks (blockid, T, created, miner, nonce, note, previd, txids, type)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            const.GENESIS_BLOCK_ID,
            const.GENESIS_BLOCK["T"],
            const.GENESIS_BLOCK["created"],
            const.GENESIS_BLOCK["miner"],
            const.GENESIS_BLOCK["nonce"],
            const.GENESIS_BLOCK["note"],
            const.GENESIS_BLOCK["previd"],
            json.dumps(const.GENESIS_BLOCK["txids"]),
            const.GENESIS_BLOCK["type"]
        ))

        con.commit()

    except Exception as e:
        con.rollback()
        print(str(e))
    finally:
        con.close()


# checks if the database contains a block, tx, or coinbase tx with the specific objectid
def exists_object(objectid):
    con = sqlite3.connect(const.DB_NAME)
    try:
        cur = con.cursor()
        cur.execute("SELECT 1 FROM blocks WHERE blockid = ?", (objectid,))
        row = cur.fetchone()
        if row:
            return True
        
        cur.execute("SELECT 1 FROM txs WHERE txid = ?", (objectid,))
        row = cur.fetchone()
        if row:
            return True
        
        return False
        
    except Exception as e:
        print(f"Exception occured during DB call: {str(e)}")
    finally:
        con.close()

# returns the object corresponding to the given objectid if it exists
def get_object(objectid):
    con = sqlite3.connect(const.DB_NAME)
    try:
        cur = con.cursor()
        cur.execute("SELECT * FROM blocks WHERE blockid = ?", (objectid,))
        row = cur.fetchone()
        if row:
            return {
                "T": row[1],
                "created": row[2],
                "miner": row[3],
                "nonce": row[4],
                "note": row[5],
                "previd": row[6],
                "txids": json.loads(row[7]) if row[7] else [],
                "type": row[8]
            }
        
        print("NO BLOCK FOUND???")

        
        cur.execute("SELECT * FROM txs WHERE txid = ?", (objectid,))
        row = cur.fetchone()
        if row:
            # this corresponds to "height" --> if yes, it is a coinbase transaction
            if row[2]:
                return {
                    "type": row[1],
                    "height": row[2],
                    "outputs": json.loads(row[4])
                }
            else:
                return {
                    "type": row[1],
                    "inputs": json.loads(row[3]),
                    "outputs": json.loads(row[4])
                }
        
        return None
        
    except Exception as e:
        print(f"Exception occured during object fetching: {str(e)}")
    finally:
        con.close()

# stores the object in its respective table
def store_object(object_dict, object_id):
    con = sqlite3.connect(const.DB_NAME)
    cur = con.cursor()

    try:
        if object_dict["type"] == "block":
            cur.execute("""
                INSERT OR IGNORE INTO blocks (blockid, T, created, miner, nonce, note, previd, txids, type)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                object_id,
                object_dict.get("T"),
                object_dict.get("created"),
                object_dict.get("miner"),
                object_dict.get("nonce"),
                object_dict.get("note"),
                object_dict.get("previd"),
                json.dumps(object_dict.get("txids", [])),
                object_dict.get("type")
            ))

        elif object_dict["type"] == "transaction":
            cur.execute("""
                INSERT OR IGNORE INTO txs (txid, type, height, inputs, outputs)
                VALUES (?, ?, ?, ?, ?)
            """, (
                object_id,
                object_dict.get("type"),
                object_dict.get("height"),
                json.dumps(object_dict.get("inputs", [])),
                json.dumps(object_dict.get("outputs", [])),
            ))

        con.commit()

    except Exception as e:
        print(f"Exception occured during DB insertion: {str(e)}")
    finally:
        con.close()

if __name__ == "__main__":
    main()
