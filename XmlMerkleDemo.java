// XmlMerkleDemo.java
import java.util.*;
import java.nio.charset.StandardCharsets;

public class XmlMerkleDemo {
  public static void main(String[] args) throws Exception {
    // v1
    String xml1 =
        "<Order xmlns=\"urn:ex\">" +
          "<Item sku=\"A\"><Qty>2</Qty></Item>" +
          "<Item sku=\"B\"><Qty>1</Qty></Item>" +
        "</Order>";

    // v2 (reordered siblings + change Qty for sku=B)
    String xml2 =
        "<ex:Order xmlns:ex=\"urn:ex\">" +
          "<ex:Item sku=\"B\"><ex:Qty>3</ex:Qty></ex:Item>" +   // value changed (1 -> 3)
          "<ex:Item sku=\"A\"><ex:Qty>2</ex:Qty></ex:Item>" +
        "</ex:Order>";

    // Build Merkle trees
    XmlPathMerkle.Result r1 = XmlPathMerkle.build(xml1);
    XmlPathMerkle.Result r2 = XmlPathMerkle.build(xml2);

    System.out.println("XML root v1 = " + MerkleCTree.hex(r1.root));
    System.out.println("XML root v2 = " + MerkleCTree.hex(r2.root));

    // Canonical path for sku=B quantity text node (after order-insensitive canonicalization)
    // NOTE: Because siblings are canonicalized by content, the path index is stable:
    // /urn:ex|Order/urn:ex|Item[#0]/urn:ex|Qty[#0].#text[#0]  or  [#1] depending on content ranks.
    // Let's list all paths so you can see what to prove:
    System.out.println("\n--- Canonical leaf paths in v2 (abbrev) ---");
    r2.pathValueHashes.keySet().stream().limit(10).forEach(System.out::println);

    // Find the path for the B/Qty text. A quick way: filter by attribute and #text
    String targetPath = r2.pathValueHashes.keySet().stream()
        .filter(p -> p.contains("/urn:ex|Item[#") && p.endsWith(".#text[#0]"))
        .filter(p -> {
          // ensure this is under the Item whose @sku == "B"
          // Item attribute path looks like: /.../urn:ex|Item[#k].@null|sku
          String prefix = p.substring(0, p.indexOf("/urn:ex|Qty"));
          String skuPath = prefix + ".@null|sku";
          byte[] skuHash = r2.pathValueHashes.get(skuPath);
          if (skuHash == null) return false;
          String valHashHex = MerkleCTree.hex(skuHash);
          // Compute expected value-hash for "B"
          byte[] expected = MerkleCTree.sha256(("V|" + "B").getBytes(StandardCharsets.UTF_8));
          return valHashHex.equals(MerkleCTree.hex(expected));
        })
        .findFirst()
        .orElseThrow(() -> new RuntimeException("Could not find B/Qty text path"));

    System.out.println("\nTarget path (B Qty text) = " + targetPath);

    // Make an inclusion proof for that path in v2
    MerkleCTree.InclusionProof proof = XmlPathMerkle.prove(xml2, targetPath);
    System.out.println("\nInclusion proof for v2:");
    System.out.println("  leafIndex=" + proof.leafIndex + ", leafCount=" + proof.leafCount);
    for (int i = 0; i < proof.path.size(); i++) {
      MerkleCTree.ProofNode node = proof.path.get(i);
      System.out.println("  step" + i + ": siblingOnRight=" + node.siblingOnRight +
          " hash=" + MerkleCTree.hex(node.hash));
    }

    // Verify the proof against v2 root (value is "3" for the Qty text)
    boolean ok = XmlPathMerkle.verify(targetPath, "3", proof, r2.root);
    System.out.println("\nProof verifies? " + ok);

    // Optional: show that a wrong value fails verification
    boolean bad = XmlPathMerkle.verify(targetPath, "1", proof, r2.root);
    System.out.println("Proof verifies with wrong value (should be false)? " + bad);
  }
}
