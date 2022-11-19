### Try to fork before notarized ###

#### Node #1

`komodod` node, synced with 132 blocks (`node-1.hex`) and have a notarization
transaction made with `./komodo-cli -testnet nn_notarize_test` at the time of 128
block synced:
```
{
  "split_tx_txid": "75e55661e2acedca0e0fe18a97e231a19d57ecbedc3054a31bde72981a533cca",
  "split_tx_sent": "true",
  "nota_tx_txid": "c5e11b79566fb6d2e303b089c21e5d73770c0656053fc5096611aa155c60d602",
  "nota_tx_sent": "true",
  "notarizedhash": "0059fe4fd3639370ab410c43ca35d691b26cc9eea3c0ff5bae8597f0cebf4ca7",
  "notarizedtxid": "4445434b45520000000000000000000000000000000000000000000000000001",
  "notarizedheight": 128
}
```
This nota tx `c5e11b79566fb6d2e303b089c21e5d73770c0656053fc5096611aa155c60d602` is included in block `#129` (`005bfe85a4fcb35f2294e2a5482cdc8a94d21857bd7d7fba91eb4e7bdb4749f1`), and this nota tx is successfully recognized by daemon as a notarization:
```
2022-11-19 00:45:35 [] ht.129 NOTARIZED.128 KMD.0059fe4fd3639370ab410c43ca35d691b26cc9eea3c0ff5bae8597f0cebf4ca7 BTCTXID.4445434b45520000000000000000000000000000000000000000000000000001 lens.(72 74) MoM.0000000000000000000000000000000000000000000000000000000000000000 0
```
So, `getinfo` will show the following:
```
  "notarized": 128,
  "prevMoMheight": 0,
  "notarizedhash": "0059fe4fd3639370ab410c43ca35d691b26cc9eea3c0ff5bae8597f0cebf4ca7",
  "notarizedtxid": "4445434b45520000000000000000000000000000000000000000000000000001",
  ```
Then node synced to the block `#132` and this set of blocks (state of blockchain) is saved as `node-1.hex`, the sequence of the last blocks is following:

```
#127 - 0120bfeb272efa2a12c51a567ac844a7ca32a3da8ed564ed6731313234b9a9a8
#128 - 0059fe4fd3639370ab410c43ca35d691b26cc9eea3c0ff5bae8597f0cebf4ca7 (notarized)
#129 - 005bfe85a4fcb35f2294e2a5482cdc8a94d21857bd7d7fba91eb4e7bdb4749f1 (contains notatx)
#130 - 00123d3ca38984c27a0021d0e19bd36fd1e816ba6b4d5d3acb5a5422d92b9382
#131 - 008534d2e488f13028775545d9f453fac93a6e03eacda8e40b0444fb08fb4ca8
#132 - 0197e7e118cd26d2146f9fed5dee89133187a3c3e9d2e68ccafe93a1d5c85e2a
```

#### Node #2

`komodod` node, which have same #127 blocks as node #1, but next blocks forms different and longer chain, such as:
```
#127 - 0120bfeb272efa2a12c51a567ac844a7ca32a3da8ed564ed6731313234b9a9a8
#128 - 002b330554b62d6f2f1700d98bf88bf895dc68e64085dede8760eadaead661db (fork point, different from Node #1 block)
#129 - 00b224eeb9d87d2233f9a224e63f5274156cf873c5a6712eeb61716463ccd109
#130 - 005c1e700bf7a2237c70df3d9b38e2078ac68dde776873947ae2a29c0d2e4376
#131 - 011aa8b7b0a38c8ae3583e8034cd6761a0322e123116f30f0bce854fe0663b38
#132 - 00d0f218547ec5b41a42b1a8937013cfb76f37cd94f2535a1203f45e94c7fce7
#133 - 00e029275df205895c999cfc082a9d5c58545edbe9d13d34d27dd5b31c54572f
#134 - 013a6882c7e9aa6ee6187e6f9bec7a53395ebe2f14b4ef4183fe63d5e5bdf8ca
#135 - 009d581da88026151419f76d000a19e551bce66b44f39770a1933ab258e19334
#136 - 00f32437f1bfb01446ab833ae1023b7cf9dce723bcaa6ef98d79268ecd4ec62f
#137 - 00f0ba4dccfd841aa75fdac2da554a3ec88e49c1b4d78d28a06997760325c5ca
```
This chain is saved as `node-2.hex`.

Create empty `komodo.conf` files inside there 2 directories `/tmp/node1` and `/tmp/node2`, otherwise daemon will exit on start.

Now we should spin up 2 nodes:
```
/home/decker/KomodoOcean/src/komodod -testnet -bind=127.0.0.1 -listen=1 -txindex=1 -server=1 -rpcuser=1 -rpcpassword=1 -rpcport=17771 -datadir=/tmp/node1
/home/decker/KomodoOcean/src/komodod -testnet -bind=127.0.0.2 -listen=1 -txindex=1 -server=1 -rpcuser=2 -rpcpassword=2 -rpcport=17772 -datadir=/tmp/node2
```
To control 1st or 2nd node use the following commands:
```
/home/decker/KomodoOcean/src/komodo-cli -rpcuser=1 -rpcpassword=1 -rpcport=17771 getinfo
/home/decker/KomodoOcean/src/komodo-cli -rpcuser=2 -rpcpassword=2 -rpcport=17772 getinfo
```
Let the *first node* sync using `node-1.hex` blocks data and `p2p-send-block.py` script. Then, sync the *second node*
using  `node-2.hex`. 

And finally let's interconnect them, estabilishing connection from `#2` -> `#1`:
```
/home/decker/KomodoOcean/src/komodo-cli -rpcuser=2 -rpcpassword=2 -rpcport=17772 addnode 127.0.0.1:17770 onetry
``` 
In the log of `#1` we should see:
```
2022-11-19 04:07:27 receive version message: /MagicBean:0.7.2beta3/: version 170011, blocks=137, us=0.0.0.0:0, peer=31
2022-11-19 04:07:27 pindexOldTip->nHeight.132 > notarizedht 128 && pindexFork->nHeight.127 is < notarizedht 128, so ignore it
2022-11-19 04:07:27 [ Debug ]
- Current tip : 0197e7e118cd26d2146f9fed5dee89133187a3c3e9d2e68ccafe93a1d5c85e2a, height 132, work 0000000000000000000000000000000000000000000000000000000000001eb6
- New tip     : 00e029275df205895c999cfc082a9d5c58545edbe9d13d34d27dd5b31c54572f, height 133, work 0000000000000000000000000000000000000000000000000000000000001f48
- Fork point  : 0120bfeb272efa2a12c51a567ac844a7ca32a3da8ed564ed6731313234b9a9a8, height 127
- Last ntrzd  : 0059fe4fd3639370ab410c43ca35d691b26cc9eea3c0ff5bae8597f0cebf4ca7, height 128
2022-11-19 04:07:27 [ Debug ] nHeight = 127, nTargetHeight = 133
2022-11-19 04:07:27 [ Debug -> New blocks list ] 00e029275df205895c999cfc082a9d5c58545edbe9d13d34d27dd5b31c54572f, height 133
2022-11-19 04:07:27 [ Debug -> New blocks list ] 00d0f218547ec5b41a42b1a8937013cfb76f37cd94f2535a1203f45e94c7fce7, height 132
2022-11-19 04:07:27 [ Debug -> New blocks list ] 011aa8b7b0a38c8ae3583e8034cd6761a0322e123116f30f0bce854fe0663b38, height 131
2022-11-19 04:07:27 [ Debug -> New blocks list ] 005c1e700bf7a2237c70df3d9b38e2078ac68dde776873947ae2a29c0d2e4376, height 130
2022-11-19 04:07:27 [ Debug -> New blocks list ] 00b224eeb9d87d2233f9a224e63f5274156cf873c5a6712eeb61716463ccd109, height 129
2022-11-19 04:07:27 [ Debug -> New blocks list ] 002b330554b62d6f2f1700d98bf88bf895dc68e64085dede8760eadaead661db, height 128
2022-11-19 04:07:27 InvalidChainFound: invalid block=00e029275df205895c999cfc082a9d5c58545edbe9d13d34d27dd5b31c54572f  height=133  log2_work=12.967226  date=2022-11-19 01:07:01
2022-11-19 04:07:27 InvalidChainFound:  current best=0197e7e118cd26d2146f9fed5dee89133187a3c3e9d2e68ccafe93a1d5c85e2a  height=132  log2_work=12.940681  date=2022-11-19 00:49:44
2022-11-19 04:07:27 ERROR: ActivateBestChainStep(): pindexOldTip->nHeight.132 > notarizedht 128 && pindexFork->nHeight.127 is < notarizedht 128, so ignore it
2022-11-19 04:07:27 ERROR: ProcessNewBlock: ActivateBestChain failed
2022-11-19 04:07:27 Misbehaving: 127.0.0.1:55542 (0 -> 100)
```

Let's automate this test as `fork-before-notarized.py`.

