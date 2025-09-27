// XmlMerkleDiffDemo.java
import java.util.*;
import java.nio.charset.StandardCharsets;

public class XmlMerkleDiffDemo {

  static class ChangeSet {
    final List<String> added = new ArrayList<>();
    final List<String> removed = new ArrayList<>();
    final List<Changed> changed = new ArrayList<>();
  }
  static class Changed {
    final String path; final String oldHashHex; final String newHashHex;
    Changed(String p, byte[] oldH, byte[] newH) {
      this.path = p; this.oldHashHex = MerkleCTree.hex(oldH); this.newHashHex = MerkleCTree.hex(newH);
    }
  }

  static ChangeSet diff(XmlPathMerkle.Result oldR, XmlPathMerkle.Result newR) {
    ChangeSet cs = new ChangeSet();
    Set<String> all = new TreeSet<>();
    all.addAll(oldR.pathValueHashes.keySet());
    all.addAll(newR.pathValueHashes.keySet());

    for (String p : all) {
      byte[] oh = oldR.pathValueHashes.get(p);
      byte[] nh = newR.pathValueHashes.get(p);
      if (oh == null && nh != null) cs.added.add(p);
      else if (oh != null && nh == null) cs.removed.add(p);
      else if (oh != null && nh != null && !Arrays.equals(oh, nh)) cs.changed.add(new Changed(p, oh, nh));
    }
    return cs;
  }

  public static void main(String[] args) throws Exception {
    // v1
    String xml1 = "<Order xmlns=\"urn:ex\">"
        + "<Item sku=\"A\"><Qty>2</Qty></Item>"
        + "<Item sku=\"B\"><Qty>1</Qty></Item>"
        + "</Order>";

    // v2 (siblings reordered, B's Qty changed 1 -> 3)
    String xml2 = "<Order xmlns=\"urn:ex\">"
        + "<Item sku=\"B\"><Qty>3</Qty></Item>"
        + "<Item sku=\"A\"><Qty>2</Qty></Item>"
        + "</Order>";

    XmlPathMerkle.Result r1 = XmlPathMerkle.build(xml1);
    XmlPathMerkle.Result r2 = XmlPathMerkle.build(xml2);

    System.out.println("Root v1 = " + MerkleCTree.hex(r1.root));
    System.out.println("Root v2 = " + MerkleCTree.hex(r2.root));

    ChangeSet cs = diff(r1, r2);

    System.out.println("\n=== ADDED (" + cs.added.size() + ") ===");
    cs.added.forEach(System.out::println);

    System.out.println("\n=== REMOVED (" + cs.removed.size() + ") ===");
    cs.removed.forEach(System.out::println);

    System.out.println("\n=== CHANGED (" + cs.changed.size() + ") ===");
    for (Changed c : cs.changed) {
      System.out.println(c.path);
      System.out.println("  oldHash=" + c.oldHashHex);
      System.out.println("  newHash=" + c.newHashHex);
    }

    // (Optional) Prove one change
    // Pick the changed Qty text path (the one ending with .#text[#0])
    String changedQtyPath = cs.changed.stream()
        .map(ch -> ch.path)
        .filter(p -> p.contains("/urn:ex|Qty") && p.endsWith(".#text[#0]"))
        .findFirst().orElse(null);

    if (changedQtyPath != null) {
      var proof = XmlPathMerkle.prove(xml2, changedQtyPath);
      boolean ok = XmlPathMerkle.verify(changedQtyPath, "3", proof, r2.root);
      System.out.println("\nProof for " + changedQtyPath + " verifies? " + ok);
    }
  }
}
