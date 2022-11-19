#!/usr/bin/env python3
# Copyright (c) 2021-2022 DeckerSU, https://github.com/DeckerSU
# Copyright (c) 2015-2016 The Bitcoin Core developers
# Copyright (c) 2017-2022 The Zcash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

# partially based on p2p-acceptblock.py test from ZCash QA rpc-tests

from io import BytesIO
from test_framework.comptool import wait_until
from test_framework.mininode import(
    CBlock,
    NetworkThread,
    NodeConn,
    NodeConnCB,
    msg_block,
    msg_ping,
    msg_pong,
    mininode_lock
)

import time
import logging

from test_framework.util import get_rpc_proxy, hex_str_to_bytes, rpc_url, start_node

class TestNode(NodeConnCB):
    def __init__(self):
        NodeConnCB.__init__(self)
        self.create_callback_map()
        self.connection = None
        self.ping_counter = 1
        self.last_pong = msg_pong()
        self.conn_closed = False

    def add_connection(self, conn):
        self.connection = conn

    # Spin until verack message is received from the node.
    # We use this to signal that our test can begin. This
    # is called from the testing thread, so it needs to acquire
    # the global lock.
    def wait_for_verack(self):
        while True:
            with mininode_lock:
                if self.verack_received:
                    return
            time.sleep(0.05)

    # Wrapper for the NodeConn's send_message function
    def send_message(self, message):
        self.connection.send_message(message)

    def on_close(self, conn):
        self.conn_closed = True

    def on_reject(self, conn, message):
        conn.rejectMessage = message

    def on_getdata(self, conn, message):
        self.last_getdata = message

    def on_tx(self, conn, message):
        self.last_tx = message

    def on_inv(self, conn, message):
        self.last_inv = message

    def on_notfound(self, conn, message):
        self.last_notfound = message

    def on_pong(self, conn, message):
        self.last_pong = message
    
        # Sync up with the node after delivery of a block
    def sync_with_ping(self, timeout=30):
        def received_pong():
            return (self.last_pong.nonce == self.ping_counter)
        self.connection.send_message(msg_ping(nonce=self.ping_counter))
        success = wait_until(received_pong, timeout)
        self.ping_counter += 1
        return success


def main():
    # logging.basicConfig(level=logging.DEBUG)

    NodeConn.MAGIC_BYTES = {
        "testnet3": b"\x5a\x1f\x7e\x62",  # testnet3
    }

    # create rpc connection to existing node, normally this is done by start_node(...)
    nodes = []
    url = "http://%s:%s@%s:%d" % ('1', '1', '127.0.0.1', int(17771))
    # url = "http://%s:%s@%s:%d" % ('2', '2', '127.0.0.1', int(17772))
    nodes.append(get_rpc_proxy(url, 0, timeout=None))

    test_node = TestNode()
    connections = []
    connections.append(NodeConn('127.0.0.1', 17770, nodes[0], test_node, "testnet3", 170011))
    # connections.append(NodeConn('127.0.0.2', 17770, nodes[0], test_node, "testnet3", 170011))
    test_node.add_connection(connections[0])
    NetworkThread().start()
    test_node.wait_for_verack()
    
    blocks_file = open('blocks.hex', 'r')
    ht = 0
    for hex_block in blocks_file:
        ht += 1
        block = CBlock()
        f = BytesIO(hex_str_to_bytes(hex_block.strip()))
        block.deserialize(f)
        block.calc_sha256()
        test_node.send_message(msg_block(block))
        time.sleep(0.05)
        test_node.sync_with_ping()
        time.sleep(0.05)
        print("Block #{} / {}: {}".format(ht, nodes[0].getblockcount(), block.hash))
    blocks_file.close
    
    [ c.disconnect_node() for c in connections ]

if __name__ == '__main__':
    main()
