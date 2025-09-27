import java.util.*;

public class JsonMerkleMain {
    public static void main(String[] args) throws Exception {
        String json1 = "{ \"id\": 1, \"tags\": [\"x\", \"y\"], \"addr\": {\"pin\": 411045} }";
        String json2 = "{ \"tags\": [\"y\", \"x\"], \"id\": 1, \"addr\": {\"pin\": 411046}, \"extra\": 42 }";

        // Build Merkle trees
        JsonPathMerkle.Result r1 = JsonPathMerkle.build(json1);
        JsonPathMerkle.Result r2 = JsonPathMerkle.build(json2);

        System.out.println("=== MERKLE ROOTS ===");
        System.out.println("Root v1 = " + MerkleCTree.hex(r1.root));
        System.out.println("Root v2 = " + MerkleCTree.hex(r2.root));

        // Show canonical paths
        System.out.println("\n=== CANONICAL PATHS (v2) ===");
        r2.pathValueHashes.keySet().forEach(System.out::println);

        // Create & verify inclusion proof for $.addr.pin
        String path = "$.addr.pin";
        MerkleCTree.InclusionProof proof = JsonPathMerkle.prove(json2, path);
        boolean ok = JsonPathMerkle.verify(path, "411046", proof, r2.root);

        System.out.println("\n=== INCLUSION PROOF ===");
        System.out.println("Path: " + path);
        System.out.println("Proof length: " + proof.path.size());
        for (int i = 0; i < proof.path.size(); i++) {
            MerkleCTree.ProofNode node = proof.path.get(i);
            System.out.printf(" step%d: siblingOnRight=%s hash=%s%n",
                    i, node.siblingOnRight, MerkleCTree.hex(node.hash));
        }
        System.out.println("Verification result: " + ok);

        // Show diff between v1 and v2
        System.out.println("\n=== DIFF (v1 -> v2) ===");
        diff(r1, r2);
    }

    static void diff(JsonPathMerkle.Result r1, JsonPathMerkle.Result r2) {
        Set<String> allPaths = new TreeSet<>();
        allPaths.addAll(r1.pathValueHashes.keySet());
        allPaths.addAll(r2.pathValueHashes.keySet());

        List<String> added = new ArrayList<>();
        List<String> removed = new ArrayList<>();
        List<String> changed = new ArrayList<>();

        for (String p : allPaths) {
            byte[] h1 = r1.pathValueHashes.get(p);
            byte[] h2 = r2.pathValueHashes.get(p);

            if (h1 == null && h2 != null) added.add(p);
            else if (h1 != null && h2 == null) removed.add(p);
            else if (h1 != null && h2 != null && !Arrays.equals(h1, h2)) changed.add(p);
        }

        System.out.println("Added:");
        added.forEach(p -> System.out.println("  " + p));
        System.out.println("Removed:");
        removed.forEach(p -> System.out.println("  " + p));
        System.out.println("Changed:");
        changed.forEach(p -> System.out.println("  " + p));
    }
}
