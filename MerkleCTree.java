import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;

public final class MerkleCTree {

    public static final String HASH_ALGO = "SHA-256";

    public static final class ProofNode {
        public final byte[] hash;
        public final boolean siblingOnRight;
        public ProofNode(byte[] hash, boolean siblingOnRight) {
            this.hash = hash; this.siblingOnRight = siblingOnRight;
        }
    }

    public static final class InclusionProof {
        public final int leafIndex;
        public final int leafCount;
        public final List<ProofNode> path;
        public InclusionProof(int idx, int n, List<ProofNode> path) {
            this.leafIndex = idx; this.leafCount = n; this.path = path;
        }
    }

    private final List<byte[]> leaves;
    private final Map<Long, byte[]> cache = new HashMap<>();

    public MerkleCTree(List<byte[]> leaves) {
        this.leaves = Collections.unmodifiableList(new ArrayList<>(leaves));
    }

    public int size() { return leaves.size(); }
    public byte[] root() { return mth(0, size()); }

    public InclusionProof inclusionProof(int m) {
        List<ProofNode> path = new ArrayList<>();
        buildInclusionPath(0, size(), m, path);
        return new InclusionProof(m, size(), path);
    }

    public static byte[] hashLeaf(byte[] leaf) { return sha256(concat(new byte[]{0x00}, leaf)); }
    public static byte[] hashNode(byte[] left, byte[] right) { return sha256(concat(new byte[]{0x01}, left, right)); }

    public static boolean verifyInclusion(byte[] leaf, InclusionProof proof, byte[] expectedRoot) {
        byte[] h = hashLeaf(leaf);
        for (ProofNode sib : proof.path) {
            h = sib.siblingOnRight ? hashNode(h, sib.hash) : hashNode(sib.hash, h);
        }
        return Arrays.equals(h, expectedRoot);
    }

    private byte[] mth(int start, int size) {
        if (size == 0) return sha256(new byte[0]);
        long key = (((long) start) << 32) ^ size;
        if (cache.containsKey(key)) return cache.get(key);
        byte[] result;
        if (size == 1) {
            result = hashLeaf(leaves.get(start));
        } else {
            int k = largestPowerOfTwoLessThan(size);
            byte[] left = mth(start, k);
            byte[] right = mth(start + k, size - k);
            result = hashNode(left, right);
        }
        cache.put(key, result);
        return result;
    }

    private void buildInclusionPath(int start, int size, int m, List<ProofNode> out) {
        if (size == 1) return;
        int k = largestPowerOfTwoLessThan(size);
        if (m < k) {
            out.add(new ProofNode(mth(start + k, size - k), true));
            buildInclusionPath(start, k, m, out);
        } else {
            out.add(new ProofNode(mth(start, k), false));
            buildInclusionPath(start + k, size - k, m - k, out);
        }
    }

    private static int largestPowerOfTwoLessThan(int n) { return Integer.highestOneBit(n - 1); }

    public static byte[] encodeLeaf(String path, byte[] valueHash) {
        byte[] p = path.getBytes(StandardCharsets.UTF_8);
        ByteBuffer b = ByteBuffer.allocate(4 + p.length + valueHash.length);
        b.putInt(p.length).put(p).put(valueHash);
        return b.array();
    }

    public static byte[] sha256(byte[]... parts) {
        try {
            MessageDigest md = MessageDigest.getInstance(HASH_ALGO);
            for (byte[] p : parts) md.update(p);
            return md.digest();
        } catch (Exception e) { throw new RuntimeException(e); }
    }

    public static byte[] concat(byte[]... parts) {
        int len = 0; for (byte[] p : parts) len += p.length;
        ByteBuffer buf = ByteBuffer.allocate(len);
        for (byte[] p : parts) buf.put(p);
        return buf.array();
    }

    public static String hex(byte[] x) {
        StringBuilder sb = new StringBuilder(x.length * 2);
        for (byte b : x) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}
