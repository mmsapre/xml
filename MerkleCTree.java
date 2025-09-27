import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;

/**
 * RFC 6962-compatible Merkle tree with:
 *  - Leaf hash  : H(0x00 || leaf)
 *  - Node hash  : H(0x01 || left || right)
 *  - Inclusion proof (audit path)
 *  - Consistency proof (append-only)
 *
 * See RFC 6962 §2.1 (Merkle Hash Trees), §2.1.1 (Audit Paths), §2.1.2 (Consistency Proofs).
 */
public final class MerkleCTree {

    public static final String HASH_ALGO = "SHA-256";

    /** A compact sibling node in a proof; side=true means sibling is on the RIGHT of current node. */
    public static final class ProofNode {
        public final byte[] hash;
        public final boolean siblingOnRight;
        public ProofNode(byte[] hash, boolean siblingOnRight) { this.hash = hash; this.siblingOnRight = siblingOnRight; }
    }

    /** Inclusion proof (audit path) bundle. */
    public static final class InclusionProof {
        public final int leafIndex;        // 0-based
        public final int leafCount;        // total leaves
        public final List<ProofNode> path; // bottom -> top
        public InclusionProof(int idx, int n, List<ProofNode> path) {
            this.leafIndex = idx; this.leafCount = n; this.path = path;
        }
    }

    /** Consistency proof: shows oldSize tree is a prefix of newSize tree. */
    public static final class ConsistencyProof {
        public final int oldSize;
        public final int newSize;
        public final List<byte[]> nodes; // ordered nodes per RFC 6962
        public ConsistencyProof(int oldSize, int newSize, List<byte[]> nodes) {
            this.oldSize = oldSize; this.newSize = newSize; this.nodes = nodes;
        }
    }

    private final List<byte[]> leaves; // raw leaf payloads d(i)
    // memoization cache for sub-tree hashes keyed by (start,size)
    private final Map<Long, byte[]> subtreeCache = new HashMap<>();

    public MerkleCTree(List<byte[]> leaves) {
        this.leaves = Collections.unmodifiableList(new ArrayList<>(leaves));
    }

    public int size() { return leaves.size(); }

    /** Root = MTH(D[0:n]) */
    public byte[] root() {
        return mth(0, size());
    }

    /** Inclusion proof for leaf at index m. */
    public InclusionProof inclusionProof(int m) {
        if (m < 0 || m >= size()) throw new IllegalArgumentException("index out of range");
        List<ProofNode> path = new ArrayList<>();
        buildInclusionPath(0, size(), m, path);
        return new InclusionProof(m, size(), path);
    }

    /** Consistency proof that oldSize (m) tree is a prefix of current tree (n). */
    public ConsistencyProof consistencyProof(int oldSize) {
        int n = size(), m = oldSize;
        if (m <= 0 || m > n) throw new IllegalArgumentException("oldSize must be 1..n");
        List<byte[]> nodes = new ArrayList<>();
        buildConsistencyProof(0, n, m, true, nodes);
        return new ConsistencyProof(m, n, nodes);
    }

    // -------- Verification helpers --------

    public static byte[] hashLeaf(byte[] leaf) {
        return sha256(concat(new byte[]{0x00}, leaf));
    }
    public static byte[] hashNode(byte[] left, byte[] right) {
        return sha256(concat(new byte[]{0x01}, left, right));
    }

    /** Verify inclusion proof against expectedRoot. */
    public static boolean verifyInclusion(byte[] leaf, InclusionProof proof, byte[] expectedRoot) {
        byte[] h = hashLeaf(leaf);
        int idx = proof.leafIndex;
        for (ProofNode sib : proof.path) {
            if (sib.siblingOnRight) {
                h = hashNode(h, sib.hash);
            } else {
                h = hashNode(sib.hash, h);
            }
            idx >>= 1;
        }
        return Arrays.equals(h, expectedRoot);
    }

    /**
     * Verify consistency proof that oldRoot (size m) is a prefix of newRoot (size n).
     * Implements RFC 6962 §2.1.2 logic.
     */
    public static boolean verifyConsistency(byte[] oldRoot, int m,
                                            byte[] newRoot, int n,
                                            List<byte[]> proofNodes) {
        if (m == n) return Arrays.equals(oldRoot, newRoot);
        if (m <= 0 || m > n) return false;
        // Reconstruct two hashes per RFC: one should reach oldRoot, the other reaches newRoot.
        int fn = m - 1;
        int sn = n - 1;

        // Find the largest power of two less than or equal to m
        int k = largestPowerOfTwoLE(m);
        byte[] fr = null, sr = null;
        int i = 0;

        // If m is a power of two, start fr with first proof node; else start with oldRoot
        if (k == m) {
            fr = proofNodes.get(i++);
            sr = fr.clone();
        } else {
            fr = oldRoot.clone();
            sr = proofNodes.get(i++).clone();
        }

        while (i < proofNodes.size()) {
            byte[] c = proofNodes.get(i++);
            if ((fn & 1) == 1) {
                fr = hashNode(c, fr);
                sr = hashNode(c, sr);
            } else if (fn < sn) {
                sr = hashNode(sr, c);
            }
            fn >>= 1;
            sn >>= 1;
        }
        return Arrays.equals(fr, oldRoot) && Arrays.equals(sr, newRoot);
    }

    // -------- Tree construction & proofs (RFC 6962) --------

    private static int largestPowerOfTwoLessThan(int n) {
        int k = Integer.highestOneBit(n - 1);
        return k;
    }
    private static int largestPowerOfTwoLE(int n) {
        return Integer.highestOneBit(n);
    }

    /** MTH(D[start : start+size]) */
    private byte[] mth(int start, int size) {
        if (size == 0) return sha256(new byte[0]); // hash of empty string
        long key = (((long) start) << 32) ^ (long) size;
        byte[] cached = subtreeCache.get(key);
        if (cached != null) return cached;

        final byte[] result;
        if (size == 1) {
            result = hashLeaf(leaves.get(start));
        } else {
            int k = largestPowerOfTwoLessThan(size);
            byte[] left = mth(start, k);
            byte[] right = mth(start + k, size - k);
            result = hashNode(left, right);
        }
        subtreeCache.put(key, result);
        return result;
    }

    /** RFC §2.1.1 audit path. */
    private void buildInclusionPath(int start, int size, int m, List<ProofNode> out) {
        if (size == 1) return;
        int k = largestPowerOfTwoLessThan(size);
        if (m < k) {
            // go left; sibling is right subtree
            out.add(new ProofNode(mth(start + k, size - k), true)); // sibling on right
            buildInclusionPath(start, k, m, out);
        } else {
            // go right; sibling is left subtree
            out.add(new ProofNode(mth(start, k), false)); // sibling on left
            buildInclusionPath(start + k, size - k, m - k, out);
        }
    }

    /** RFC §2.1.2 consistency proof. */
    private void buildConsistencyProof(int start, int n, int m, boolean isTop, List<byte[]> out) {
        if (m == n) {
            if (!isTop) out.add(mth(start, n));
            return;
        }
        int k = largestPowerOfTwoLessThan(n);
        if (m <= k) {
            // left subtree shares prefix; prove left then add right commitment
            buildConsistencyProof(start, k, m, false, out);
            out.add(mth(start + k, n - k));
        } else {
            // left subtree identical; prove right and add left commitment
            buildConsistencyProof(start + k, n - k, m - k, false, out);
            out.add(mth(start, k));
        }
    }

    // -------- Utilities --------

    public static byte[] sha256(byte[]... chunks) {
        try {
            MessageDigest md = MessageDigest.getInstance(HASH_ALGO);
            for (byte[] c : chunks) md.update(c);
            return md.digest();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
    public static byte[] concat(byte[]... parts) {
        int len = 0; for (byte[] p : parts) len += p.length;
        ByteBuffer buf = ByteBuffer.allocate(len);
        for (byte[] p : parts) buf.put(p);
        return buf.array();
    }

    /** Helper to encode (path, valueHash) into a single RFC leaf payload. */
    public static byte[] encodeLeaf(String path, byte[] valueHash) {
        byte[] p = path.getBytes(StandardCharsets.UTF_8);
        ByteBuffer b = ByteBuffer.allocate(4 + p.length + valueHash.length);
        b.putInt(p.length).put(p).put(valueHash);
        return b.array();
    }

    public static String hex(byte[] x) {
        StringBuilder sb = new StringBuilder(x.length * 2);
        for (byte b : x) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}
