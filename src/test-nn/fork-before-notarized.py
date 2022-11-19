#!/usr/bin/env python3
# Copyright (c) 2021-2022 DeckerSU, https://github.com/DeckerSU
# Copyright (c) 2015-2016 The Bitcoin Core developers
# Copyright (c) 2017-2022 The Zcash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

# partially based on p2p-acceptblock.py test from ZCash QA rpc-tests

from io import BytesIO
import os
import shutil
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

from test_framework.util import PortSeed, connect_nodes, get_rpc_proxy, hex_str_to_bytes, initialize_datadir, p2p_port, rpc_url, start_node

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

    # setup
    binary='/home/decker/KomodoOcean/src/komodod'
    os.environ["ZCASHD"] = binary
    PortSeed.n = 777 # must be initialized

    # clear datadir
    shutil.rmtree("/tmp/node0/testnet3", True)
    shutil.rmtree("/tmp/node1/testnet3", True)

    for i in range(0, 2):
        initialize_datadir('/tmp', i)

    # nodes[0] - will be Node #1 from the description and nodes[1] will be Node #2
    nodes = []
    
    # -testnet arg needed via daemon start time, otherwise it somehow will try to
    # sync with mainnet, regardless of komodo.conf ... nodes list contains rpc 
    # connections

    for i in range(0, 2):
        nodes.append(start_node(i, '/tmp', ["-testnet"]))

    test_node = TestNode()
    NetworkThread().start()

    connections = []
    # list of classed provided p2p connections to a node
    # add p2p connection to Node #1 and pass it via p2p its set of blocks
    connections.append(NodeConn('127.0.0.1', p2p_port(0), nodes[0], test_node, "testnet3", 170011))
    test_node.add_connection(connections[0])
    test_node.wait_for_verack()
    time.sleep(1) # here we should wait for genesis import, otherwise node will reject block with ht.1
    blocks_file = open('node-1.hex', 'r')
    ht = 0
    for hex_block in blocks_file:
        ht += 1
        block = CBlock()
        f = BytesIO(hex_str_to_bytes(hex_block.strip()))
        block.deserialize(f)
        block.calc_sha256()
        test_node.send_message(msg_block(block))
        test_node.sync_with_ping()
        print("Block #{} / {}: {}".format(ht, nodes[0].getblockcount(), block.hash))
    blocks_file.close
    connections[0].disconnect_node()
    connections.pop(0) # close p2p connection with first node

    # add p2p connection to Node #2
    connections.append(NodeConn('127.0.0.1', p2p_port(1), nodes[1], test_node, "testnet3", 170011))
    test_node.add_connection(connections[0])
    test_node.wait_for_verack()
    time.sleep(1) # here we should wait for genesis import, otherwise node will reject block with ht.1
    blocks_file = open('node-2.hex', 'r')
    ht = 0
    for hex_block in blocks_file:
        ht += 1
        block = CBlock()
        f = BytesIO(hex_str_to_bytes(hex_block.strip()))
        block.deserialize(f)
        block.calc_sha256()
        test_node.send_message(msg_block(block))
        test_node.sync_with_ping()
        print("Block #{} / {}: {}".format(ht, nodes[1].getblockcount(), block.hash))
    blocks_file.close
    connections[0].disconnect_node()
    connections.pop(0) # close p2p connection with first node

    # time to interconnect nodes, let Node #2 know about #1
    connect_nodes(nodes[0], 1)
    # let's give them some time
    time.sleep(1)

    node0_getinfo = nodes[0].getinfo()
    node1_getinfo = nodes[1].getinfo()

    print("Node #{}: ht.{} notarized.{}".format(0, node0_getinfo['blocks'], node0_getinfo['notarized']))
    print("Node #{}: ht.{} notarized.{}".format(1, node1_getinfo['blocks'], node1_getinfo['notarized']))

    assert(nodes[0].getblockcount() == 132)
    assert(nodes[0].getbestblockhash() == "0197e7e118cd26d2146f9fed5dee89133187a3c3e9d2e68ccafe93a1d5c85e2a")

    # stopping spinned daemons 
    for i in range(0, 2):
        nodes[i].stop()

if __name__ == '__main__':
    main()
