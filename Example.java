// Example.java
public class Example {
  public static void main(String[] args) throws Exception {
    String json1 = "{ \"id\":1, \"tags\":[\"x\",\"y\"], \"addr\":{\"pin\":411045} }";
    String json2 = "{ \"tags\":[\"y\",\"x\"], \"id\":1, \"addr\":{\"pin\":411046} }";

    JsonPathMerkle.Result j1 = JsonPathMerkle.build(json1);
    JsonPathMerkle.Result j2 = JsonPathMerkle.build(json2);

    System.out.println("JSON root v1 = " + MerkleCTree.hex(j1.root));
    System.out.println("JSON root v2 = " + MerkleCTree.hex(j2.root));

    // Inclusion proof for changed field
    MerkleCTree.InclusionProof proof = JsonPathMerkle.prove(json2, "$.addr.pin");
    boolean ok = JsonPathMerkle.verify("$.addr.pin", "411046", proof, j2.root);
    System.out.println("Proof verifies? " + ok);

    // Consistency proof (append-only scenario): if v2 had the same leaves as v1 plus more
    // MerkleCTree.ConsistencyProof cp = j2.tree.consistencyProof(j1.tree.size());
    // boolean cOK = MerkleCTree.verifyConsistency(j1.root, j1.tree.size(), j2.root, j2.tree.size(), cp.nodes);
  }
}
