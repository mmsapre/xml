import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Path-aware canonicalizer for JSON that:
 *  - Sorts object fields by name
 *  - Sorts array elements by structural hash (order-insensitive)
 *  - Produces canonical paths like $.field, $.array[#0], ...
 *  - Computes SHA-256 value-hashes for leaves
 *  - Builds RFC-6962 Merkle tree over (path,valueHash) pairs
 */
public final class JsonPathMerkle {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** Result bundle containing Merkle root, tree, and path→hash mapping. */
    public static final class Result {
        public final byte[] root;
        public final MerkleCTree tree;
        public final Map<String, byte[]> pathValueHashes;
        public Result(byte[] root, MerkleCTree tree, Map<String, byte[]> pathValueHashes) {
            this.root = root; this.tree = tree; this.pathValueHashes = pathValueHashes;
        }
    }

    /** Build Merkle root + path map from a JSON string. */
    public static Result build(String json) throws Exception {
        JsonNode rootNode = MAPPER.readTree(json);
        Map<String, byte[]> leaves = new LinkedHashMap<>();
        walkJson(rootNode, "$", leaves);

        // Sort paths to get deterministic leaf order
        List<String> paths = new ArrayList<>(leaves.keySet());
        Collections.sort(paths);

        List<byte[]> encodedLeaves = new ArrayList<>(paths.size());
        for (String p : paths) {
            encodedLeaves.add(MerkleCTree.encodeLeaf(p, leaves.get(p)));
        }
        MerkleCTree tree = new MerkleCTree(encodedLeaves);
        return new Result(tree.root(), tree, leaves);
    }

    /** Build an inclusion proof for a canonical path. */
    public static MerkleCTree.InclusionProof prove(String json, String canonicalPath) throws Exception {
        Result r = build(json);
        List<String> sorted = new ArrayList<>(r.pathValueHashes.keySet());
        Collections.sort(sorted);
        int idx = Collections.binarySearch(sorted, canonicalPath);
        if (idx < 0) throw new IllegalArgumentException("path not found: " + canonicalPath);
        return r.tree.inclusionProof(idx);
    }

    /** Verify a leaf path/value against the root using its proof. */
    public static boolean verify(String path, String normalizedValue, MerkleCTree.InclusionProof proof, byte[] expectedRoot) {
        byte[] vhash = MerkleCTree.sha256(("V|" + normalizedValue).getBytes(StandardCharsets.UTF_8));
        byte[] leaf = MerkleCTree.encodeLeaf(path, vhash);
        return MerkleCTree.verifyInclusion(leaf, proof, expectedRoot);
    }

    // ----------------- Canonical traversal -----------------

    private static void walkJson(JsonNode node, String path, Map<String, byte[]> out) {
        if (node == null || node.isNull()) {
            out.put(path, MerkleCTree.sha256("V|null".getBytes(StandardCharsets.UTF_8)));
            return;
        }
        if (node.isValueNode()) {
            String norm;
            if (node.isNumber()) norm = node.numberValue().toString();
            else if (node.isBoolean()) norm = Boolean.toString(node.booleanValue());
            else norm = node.asText();
            out.put(path, MerkleCTree.sha256(("V|" + norm).getBytes(StandardCharsets.UTF_8)));
            return;
        }
        if (node.isObject()) {
            List<String> fields = new ArrayList<>();
            node.fieldNames().forEachRemaining(fields::add);
            Collections.sort(fields);
            if (fields.isEmpty()) {
                out.put(path + ".__emptyObject", MerkleCTree.sha256("V|{}".getBytes(StandardCharsets.UTF_8)));
            } else {
                for (String f : fields) {
                    walkJson(node.get(f), path.equals("$") ? "$." + f : path + "." + f, out);
                }
            }
            return;
        }
        if (node.isArray()) {
            List<JsonNode> elems = new ArrayList<>();
            node.forEach(elems::add);
            if (elems.isEmpty()) {
                out.put(path + ".__emptyArray", MerkleCTree.sha256("V|[]".getBytes(StandardCharsets.UTF_8)));
                return;
            }
            // Canonicalize array by structural hash
            List<Child> ranked = new ArrayList<>(elems.size());
            for (JsonNode e : elems) ranked.add(new Child(e, hashStructure(e)));
            ranked.sort(Comparator.comparing(c -> MerkleCTree.hex(c.structHash)));
            for (int i = 0; i < ranked.size(); i++) {
                walkJson(ranked.get(i).node, path + "[#" + i + "]", out);
            }
            return;
        }
        // Fallback (should not happen)
        out.put(path, MerkleCTree.sha256(("V|" + node.asText()).getBytes(StandardCharsets.UTF_8)));
    }

    /** Structural hash used to canonicalize arrays (not part of Merkle leaf). */
    private static byte[] hashStructure(JsonNode n) {
        if (n == null || n.isNull()) return MerkleCTree.sha256("N|null".getBytes(StandardCharsets.UTF_8));
        if (n.isValueNode()) {
            String v = n.isNumber() ? n.numberValue().toString()
                    : n.isBoolean() ? Boolean.toString(n.booleanValue())
                    : n.asText();
            return MerkleCTree.sha256(("N|V|" + v).getBytes(StandardCharsets.UTF_8));
        }
        if (n.isObject()) {
            List<String> fields = new ArrayList<>();
            n.fieldNames().forEachRemaining(fields::add);
            Collections.sort(fields);
            List<byte[]> parts = new ArrayList<>();
            parts.add("N|O|".getBytes(StandardCharsets.UTF_8));
            for (String f : fields) {
                parts.add(f.getBytes(StandardCharsets.UTF_8));
                parts.add(hashStructure(n.get(f)));
            }
            return MerkleCTree.sha256(parts.toArray(new byte[0][]));
        }
        if (n.isArray()) {
            List<byte[]> childHashes = new ArrayList<>();
            for (JsonNode e : n) childHashes.add(hashStructure(e));
            childHashes.sort(Comparator.comparing(MerkleCTree::hex));
            List<byte[]> parts = new ArrayList<>();
            parts.add("N|A|".getBytes(StandardCharsets.UTF_8));
            parts.addAll(childHashes);
            return MerkleCTree.sha256(parts.toArray(new byte[0][]));
        }
        return MerkleCTree.sha256(("N|UNK|" + n.asText()).getBytes(StandardCharsets.UTF_8));
    }

    private static final class Child {
        final JsonNode node; final byte[] structHash;
        Child(JsonNode n, byte[] h) { this.node = n; this.structHash = h; }
    }
}
