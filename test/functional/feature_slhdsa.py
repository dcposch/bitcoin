#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test OP_CHECKSIGPQADD (SLH-DSA tapscript BIP draft) in P2MR outputs.

- Create a P2MR output whose script tree has a 2-of-3 OP_CHECKSIGPQADD leaf
  and a second leaf.
- Spend it with two SLH-DSA-SHA2-128s signatures. Check mempool acceptance
  and block inclusion.
- Check that a bad signature is rejected by policy, and by consensus on a node
  where the deployment is active. A node without the deployment accepts the
  block, so the change is a soft fork.
- Check that opcode 0xca stays OP_SUCCESS202 in P2TR.
"""

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.key import compute_xonly_pubkey, generate_privkey
from test_framework.messages import (
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
    sha256,
)
from test_framework.script import (
    CScript,
    LEAF_VERSION_TAPSCRIPT,
    OP_0,
    OP_2,
    OP_CHECKSIGPQADD,
    OP_NUMEQUAL,
    OP_TRUE,
    TaggedHash,
    TaprootSignatureMsg,
    taproot_construct,
)
from test_framework import slhdsa
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet

KEY_TYPE_SLHDSA_SHA2_128S = 0x01
CHUNK_SIZE = 520
AMOUNT = 1_000_000
FEE = 50_000

SLH_ACTIVE_ARGS = ["-testactivationheight=p2mr@1", "-testactivationheight=pqsig@1"]


def tapbranch(a, b):
    return TaggedHash("TapBranch", a + b if a < b else b + a)


def encode_signature(sig):
    """Split a 7,856-byte signature into 15 chunks of 520 bytes, one of 56 bytes, and the count 0x10."""
    assert_equal(len(sig), slhdsa.SIG_BYTES)
    chunks = [sig[i:i + CHUNK_SIZE] for i in range(0, len(sig), CHUNK_SIZE)]
    assert_equal(len(chunks), 16)
    assert_equal(len(chunks[-1]), 56)
    return chunks + [bytes([len(chunks)])]


def slh_message(tx, spent_utxos, input_index, leaf_script):
    """M = ser_tag("SLHSighash") || 0x00 || SigMsg(0x00, 1) || tapleaf_hash || 0x01 || codesep_pos."""
    msg = TaprootSignatureMsg(tx, spent_utxos, 0, input_index, scriptpath=True, leaf_script=leaf_script, codeseparator_pos=0xffffffff)
    # TaprootSignatureMsg writes key_version 0x00 (BIP 342). Use the key type instead.
    assert_equal(msg[-5], 0)
    msg = msg[:-5] + bytes([KEY_TYPE_SLHDSA_SHA2_128S]) + msg[-4:]
    return sha256(b"SLHSighash") * 2 + msg


class SLHDSATest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        # Node 0 enforces the P2MR and SLH-DSA rules in blocks. Node 1 does not.
        # Both nodes apply them as policy.
        self.extra_args = [SLH_ACTIVE_ARGS, []]

    def make_key(self, seed_byte):
        sk, pk = slhdsa.slh_keygen(bytes([seed_byte]) * 16, bytes([seed_byte ^ 0x5a]) * 16, bytes([seed_byte ^ 0xa5]) * 16)
        return sk, bytes([KEY_TYPE_SLHDSA_SHA2_128S]) + pk

    def spend_tx(self, funding, spk, witness_stack):
        tx = CTransaction()
        tx.version = 2
        tx.vin = [CTxIn(COutPoint(int(funding["txid"], 16), funding["sent_vout"]))]
        tx.vout = [CTxOut(AMOUNT - FEE, self.wallet.get_output_script())]
        tx.wit.vtxinwit = [CTxInWitness()]
        tx.wit.vtxinwit[0].scriptWitness.stack = witness_stack
        return tx

    def run_test(self):
        node = self.nodes[0]
        self.wallet = MiniWallet(node)
        self.generate(node, COINBASE_MATURITY)  # mature coins for the MiniWallet

        self.log.info("Generate three SLH-DSA-SHA2-128s keys")
        (sk_a, pk_a), (sk_b, pk_b), (sk_c, pk_c) = [self.make_key(b) for b in (0x0a, 0x0b, 0x0c)]

        self.log.info("Build a P2MR output with a 2-of-3 OP_CHECKSIGPQADD leaf")
        leaf = bytes(CScript([OP_0, pk_a, OP_CHECKSIGPQADD, pk_b, OP_CHECKSIGPQADD, pk_c, OP_CHECKSIGPQADD, OP_2, OP_NUMEQUAL]))
        other_leaf = bytes(CScript([OP_TRUE]))
        leaf_hash = TaggedHash("TapLeaf", bytes([LEAF_VERSION_TAPSCRIPT, len(leaf)]) + leaf)
        other_hash = TaggedHash("TapLeaf", bytes([LEAF_VERSION_TAPSCRIPT, len(other_leaf)]) + other_leaf)
        p2mr_spk = CScript([OP_2, tapbranch(leaf_hash, other_hash)])
        control = bytes([LEAF_VERSION_TAPSCRIPT | 1]) + other_hash

        funding = self.wallet.send_to(from_node=node, scriptPubKey=p2mr_spk, amount=AMOUNT, fee=1000)
        funding2 = self.wallet.send_to(from_node=node, scriptPubKey=p2mr_spk, amount=AMOUNT, fee=1000)
        self.generate(node, 1)
        spent_utxo = [CTxOut(AMOUNT, p2mr_spk)]

        self.log.info("Sign with keys A and C")
        tx = self.spend_tx(funding, p2mr_spk, [])
        msg = slh_message(tx, spent_utxo, 0, leaf)
        assert_equal(len(msg), 276)
        sig_a = slhdsa.slh_sign(msg, b"", sk_a)
        sig_c = slhdsa.slh_sign(msg, b"", sk_c)
        assert slhdsa.slh_verify(msg, sig_a, b"", pk_a[1:])
        # Witness: <sig_C> <0> <sig_A> <leaf> <control>
        stack = encode_signature(sig_c) + [b""] + encode_signature(sig_a) + [leaf, control]
        tx.wit.vtxinwit[0].scriptWitness.stack = stack
        self.log.info(f"Spend size: {len(tx.serialize())} bytes, {tx.get_vsize()} vB, witness {len(tx.wit.vtxinwit[0].serialize())} bytes")

        self.log.info("A bad signature is rejected by policy")
        bad_tx = self.spend_tx(funding, p2mr_spk, list(stack))
        bad_chunk = bytearray(bad_tx.wit.vtxinwit[0].scriptWitness.stack[3])
        bad_chunk[0] ^= 1
        bad_tx.wit.vtxinwit[0].scriptWitness.stack[3] = bytes(bad_chunk)
        res = node.testmempoolaccept([bad_tx.serialize().hex()])[0]
        assert_equal(res["allowed"], False)
        assert_equal(res["reject-reason"], "mempool-script-verify-flag-failed (Invalid SLH-DSA signature)")

        self.log.info("Only one signature does not satisfy the 2-of-3 leaf")
        one_sig_tx = self.spend_tx(funding, p2mr_spk, [b"", b""] + encode_signature(sig_a) + [leaf, control])
        res = node.testmempoolaccept([one_sig_tx.serialize().hex()])[0]
        assert_equal(res["allowed"], False)
        assert "Script evaluated without error but finished with a false/empty top stack element" in res["reject-reason"]

        self.log.info("The valid spend is accepted to the mempool and mined")
        res = node.testmempoolaccept([tx.serialize().hex()])[0]
        assert_equal(res["allowed"], True)
        txid = node.sendrawtransaction(tx.serialize().hex())
        assert_equal(txid, tx.txid_hex)
        block_hash = self.generate(node, 1)[0]
        assert txid in node.getblock(block_hash)["tx"]
        assert_equal(node.getrawmempool(), [])
        assert_equal(self.nodes[1].getbestblockhash(), block_hash)

        self.log.info("Opcode 0xca stays OP_SUCCESS202 in P2TR")
        internal_key = compute_xonly_pubkey(generate_privkey())[0]
        tap = taproot_construct(internal_key, [("slh", leaf), ("other", other_leaf)])
        p2tr_funding = self.wallet.send_to(from_node=node, scriptPubKey=tap.scriptPubKey, amount=AMOUNT, fee=1000)
        self.generate(node, 1)
        p2tr_control = bytes([LEAF_VERSION_TAPSCRIPT | tap.negflag]) + tap.internal_pubkey + tap.leaves["slh"].merklebranch
        p2tr_tx = self.spend_tx(p2tr_funding, tap.scriptPubKey, [b"\x01\x02\x03", leaf, p2tr_control])
        res = node.testmempoolaccept([p2tr_tx.serialize().hex()])[0]
        assert_equal(res["allowed"], False)
        assert "OP_SUCCESSx reserved for soft-fork upgrades" in res["reject-reason"]
        # By consensus, the garbage witness is valid: OP_SUCCESS202 makes the script succeed.
        block = self.generateblock(node, output=self.wallet.get_address(), transactions=[p2tr_tx.serialize().hex()])
        assert p2tr_tx.txid_hex in node.getblock(block["hash"])["tx"]

        self.log.info("A block with a bad signature is invalid on the node with the deployment, and valid without it")
        self.disconnect_nodes(0, 1)
        bad_tx2 = self.spend_tx(funding2, p2mr_spk, list(stack))  # the signatures sign the message of the first spend
        block = self.generateblock(self.nodes[1], output=self.wallet.get_address(), transactions=[bad_tx2.serialize().hex()], submit=False, sync_fun=self.no_op)
        assert_equal(node.submitblock(block["hex"]), "block-script-verify-flag-failed (Invalid SLH-DSA signature)")
        assert_equal(self.nodes[1].submitblock(block["hex"]), None)
        assert_equal(self.nodes[1].getbestblockhash(), block["hash"])
        assert node.getbestblockhash() != block["hash"]


if __name__ == '__main__':
    SLHDSATest(__file__).main()
