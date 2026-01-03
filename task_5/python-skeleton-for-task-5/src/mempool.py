import copy
import sqlite3

import constants as const
import objects

#### I didn't use any of these functions for the mempool BEGIN
# get expanded object for 
def fetch_object(oid, cur): ### stupid fucking function, this already exists in objects.py
    pass # TODO

# get utxo for block
def fetch_utxo(bid, cur): ### also kind of stupid. this shit belongs in objects.py. I wrote a get_utxo() function in objects.py
    pass # TODO

# returns (blockid, intermediate_blocks)
def find_lca_and_intermediate_blocks(tip, blockids):
    pass # TODO

# return a list of transactions by index
def find_all_txs(txids):
    pass # TODO
#### I didn't use any of these functions for the mempool END

# return a list of transactions in blocks
def get_all_txids_in_blocks(blocks):
    txids = []
    for block in blocks:
        for txid in block["txids"]:
            txids.append(txid)
    return txids

# returns a list of all transactions in the blocks
# e.g. blocks = [B0, B1], B0.txids = [tx0id, tx1id], B1.txids = [tx2id, tx3id] --> returns [tx0, tx1, tx2, tx3]
def get_all_txs_in_blocks(blocks: list[dict]) -> list[dict]:
    txids = get_all_txids_in_blocks(blocks)
    txs = []
    for txid in txids:
        txs.append(objects.get_object(txid))
    return txs

# get (id of lca, list of old blocks from lca, list of new blocks from lca) 
# old_tip... the id of the old tip, new_tip... the id of the new tip
# e.g. old chain = (B0, B1, B2), new chain = (B0, B1, B2', B3') -> returns (B1_id, [B2], [B2', B3'])
def get_lca_and_intermediate_blocks(old_tip: str, new_tip: str):
    
    old_tip_ancestors: list[str] = [old_tip] # list of previds until genesis block from old tip
    curr_block: dict = objects.get_object(old_tip)

    while curr_block["previd"] != None:
        old_tip_ancestors.insert(0, curr_block["previd"])
        curr_block = objects.get_object(curr_block["previd"])

    new_tip_ancestors: list[str] = [new_tip] # list of previds until gensis block from new tip
    curr_block = objects.get_object(new_tip)
    if curr_block == None:
        print(f"WHAT THE FUCK! {new_tip} is not in database!!!")

    while curr_block["previd"] != None:
        new_tip_ancestors.insert(0, curr_block["previd"])
        curr_block = objects.get_object(curr_block["previd"])
    
    # we get the id of the Last Common Ancestor
    lca_id = None
    for old_block_id, new_block_id in zip(old_tip_ancestors, new_tip_ancestors):
        if old_block_id == new_block_id:
            lca_id = old_block_id
    
    # we get the blocks from the LCA in the old chain
    old_tip_intermediate_blocks: list[dict] = []
    curr_block = objects.get_object(old_tip)
    while objects.get_objid(curr_block) != lca_id:
        old_tip_intermediate_blocks.insert(0, curr_block)
        curr_block = objects.get_object(curr_block["previd"])

    # we get the blocks from the LCA in the new chain
    new_tip_intermediate_blocks: list[dict] = []
    curr_block = objects.get_object(new_tip)
    while objects.get_objid(curr_block) != lca_id:
        new_tip_intermediate_blocks.insert(0, curr_block)
        curr_block = objects.get_object(curr_block["previd"])

    return (lca_id, old_tip_intermediate_blocks, new_tip_intermediate_blocks)

# old/new_tip... id of the old/new chaintip, mptxids... tx ids in the current mempool
def rebase_mempool(old_tip, new_tip, mptxids):
    pass # TODO

class Mempool:

    """
    butxo is the set of unspent outputs of a transaction with id txid
    butxo: dict[str, dict[str, int]] == utxo[txid] = {outpoint_ind: outpoint_val, ...}
    """
    def __init__(self, bbid: str, butxo: dict):
        self.base_block_id = bbid
        self.utxo = butxo
        self.txs = [] # description says this should be a list of txids

    """
    We can add a new tx, if it only spends from unspent outputs that are also not spent by any txs currently in the
    mempool
    I guess this shit should return true, if it was added
    """
    def try_add_tx(self, tx: dict) -> bool:
        print(f"Trying to add transaction with id {objects.get_objid(tx)} to mempool")

        # we update the utxo with the function in objects.py. If this yields an exception, we can't add the new tx
        try:
            new_utxo = copy.deepcopy(self.utxo)
            objects.update_mempool_utxo(tx, new_utxo)
            self.utxo = new_utxo
            self.txs.append(objects.get_objid(tx)) # we only add the id
            print(f"Added tx to mempool. New Mempool UTXO: {new_utxo}")
            return True
        except Exception as e:
            print(f"Adding tx to mempool failed: {str(e)}")
            return False
        
    # old/new_tip... id of the old/new chaintip
    def rebase_mempool(self, old_tip, new_tip):
        lca_id, old_tip_intermediate_blocks, new_tip_intermediate_blocks = get_lca_and_intermediate_blocks(old_tip, new_tip)

        lca_block = objects.get_object(lca_id)
        lca_block_utxo = objects.get_utxo(lca_id) # this is the new state of the chain

        # all transactions in the new chain are applied against the LCA state (equivalent to just getting the utxo set of new_tip)
        new_tip_utxo = copy.deepcopy(objects.get_utxo(new_tip))
        print(f"NEW TIP UTXO: {new_tip_utxo}")

        # now we apply the txs in the old chain to the new chain
        new_mempool_txs = []
        old_chain_txs = get_all_txs_in_blocks(old_tip_intermediate_blocks)
        for old_chain_tx in old_chain_txs:
            try:
                objects.update_mempool_utxo(old_chain_tx, new_tip_utxo)
                new_mempool_txs.append(objects.get_objid(old_chain_tx))
            except Exception as e:
                continue # if the utxo update fails, we just ignore the tx in the old chain
        
        # now we apply the txs in the old mempool to the new utxo
        for old_mempool_tx_id in self.txs:
            try:
                old_mempool_tx = objects.get_object(old_mempool_tx_id)
                objects.update_mempool_utxo(old_mempool_tx, new_tip_utxo)
                new_mempool_txs.append(old_mempool_tx_id)
            except Exception as e:
                continue
        
        self.utxo = new_tip_utxo
        self.txs = new_mempool_txs
        self.base_block_id = new_tip


    def rebase_to_block(self, bid: str):
        pass # TODO