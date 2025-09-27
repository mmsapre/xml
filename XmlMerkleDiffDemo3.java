import java.util.*;

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

  public static void main(String[] args) throws Exception {
    String xml1 = ""; // baseline is empty
    String xml2 = "<Order xmlns=\"urn:ex\">"
        + "<Item sku=\"B\"><Qty>3</Qty></Item>"
        + "<Item sku=\"A\"><Qty>2</Qty></Item>"
        + "</Order>";

    XmlPathMerkle.Result r1 = (xml1 == null || xml1.isBlank()) ? null : XmlPathMerkle.build(xml1);
    XmlPathMerkle.Result r2 = XmlPathMerkle.build(xml2);

    if (r1 != null) {
      System.out.println("Root v1 = " + MerkleCTree.hex(r1.root));
    } else {
      System.out.println("Root v1 = <empty>");
    }
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

    // Collapsed paths
    printCollapsedChangedPathsWithAncestors(cs.changed);

    // Tag summary
    TagSummary ts = summarizeTagChanges(cs);
    printTagSummary(ts);
  }

  /** Diff now handles null/empty baseline: all paths from r2 -> added. */
  static ChangeSet diff(XmlPathMerkle.Result r1, XmlPathMerkle.Result r2) {
    ChangeSet cs = new ChangeSet();

    if (r1 == null) {
      // Baseline empty: everything is added
      for (Map.Entry<String, byte[]> e : r2.pathValueHashes.entrySet()) {
        cs.added.add(e.getKey());
      }
      return cs;
    }

    Set<String> all = new TreeSet<>();
    all.addAll(r1.pathValueHashes.keySet());
    all.addAll(r2.pathValueHashes.keySet());

    for (String p : all) {
      byte[] oh = r1.pathValueHashes.get(p);
      byte[] nh = r2.pathValueHashes.get(p);
      if (oh == null && nh != null) cs.added.add(p);
      else if (oh != null && nh == null) cs.removed.add(p);
      else if (oh != null && nh != null && !Arrays.equals(oh, nh))
        cs.changed.add(new Changed(p, oh, nh));
    }
    return cs;
  }

  // ----------- Collapsed path printer (unchanged from previous version) -----------

  static void printCollapsedChangedPathsWithAncestors(List<Changed> changed) {
    System.out.println("\n--- Collapsed changed paths (no indices, no #text) & ancestors ---");
    Set<String> collapsed = new LinkedHashSet<>();
    for (Changed c : changed) {
      String norm = normalizePathWithoutText(c.path);
      addWithAncestors(norm, collapsed);
    }
    for (String p : collapsed) System.out.println(p);
  }

  static String normalizePathWithoutText(String canonical) {
    String s = canonical;
    s = s.replaceAll("\\[#\\d+\\]", "");
    s = s.replaceAll("\\.#text(?:\\[#\\d+\\])?", "");
    s = s.replaceAll("\\.@", "/@");
    s = s.replaceAll("\\.__empty(Element|Array|Object)", "");
    s = s.replaceAll("/{2,}", "/");
    return s;
  }

  static void addWithAncestors(String path, Set<String> out) {
    if (path == null || path.isEmpty()) return;
    if (!path.startsWith("/")) { out.add(path); return; }
    String[] parts = path.substring(1).split("/");
    StringBuilder cur = new StringBuilder("/");
    for (String part : parts) {
      if (part.isEmpty()) continue;
      if (cur.length() > 1) cur.append("/");
      cur.append(part);
      out.add(cur.toString());
    }
  }

  // ----------- Tag summary (unchanged from previous version) -----------

  enum ChangeType { ADDED, REMOVED, CHANGED }
  static final class TagSummary {
    final Map<String, Set<String>> elements = new TreeMap<>();
    final Map<String, Set<String>> attributes = new TreeMap<>();
    void markElement(String tag, ChangeType t) {
      elements.computeIfAbsent(tag, k -> new TreeSet<>()).add(t.name());
    }
    void markAttribute(String attr, ChangeType t) {
      attributes.computeIfAbsent(attr, k -> new TreeSet<>()).add(t.name());
    }
  }

  static TagSummary summarizeTagChanges(ChangeSet cs) {
    TagSummary ts = new TagSummary();
    for (String p : cs.added) emitTag(ts, normalizePathWithoutText(p), ChangeType.ADDED);
    for (String p : cs.removed) emitTag(ts, normalizePathWithoutText(p), ChangeType.REMOVED);
    for (Changed c : cs.changed) emitTag(ts, normalizePathWithoutText(c.path), ChangeType.CHANGED);
    return ts;
  }

  static void emitTag(TagSummary ts, String normalizedPath, ChangeType ct) {
    if (normalizedPath == null || normalizedPath.isEmpty()) return;
    String[] parts = normalizedPath.split("/");
    if (parts.length == 0) return;
    String last = parts[parts.length - 1];
    if (last.startsWith("@")) {
      ts.markAttribute(last, ct);
      if (parts.length >= 2) {
        String parent = parts[parts.length - 2];
        if (!parent.startsWith("@")) ts.markElement(parent, ChangeType.CHANGED);
      }
    } else {
      ts.markElement(last, ct);
    }
  }

  static void printTagSummary(TagSummary ts) {
    System.out.println("\n--- Tag change summary ---");
    if (ts.elements.isEmpty() && ts.attributes.isEmpty()) {
      System.out.println("(no tag-level changes)");
      return;
    }
    if (!ts.elements.isEmpty()) {
      System.out.println("Elements:");
      ts.elements.forEach((tag, ops) ->
          System.out.println("  " + tag + " : " + String.join(",", ops)));
    }
    if (!ts.attributes.isEmpty()) {
      System.out.println("Attributes:");
      ts.attributes.forEach((attr, ops) ->
          System.out.println("  " + attr + " : " + String.join(",", ops)));
    }
  }
}
