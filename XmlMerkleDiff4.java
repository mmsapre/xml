import java.util.*;

/** Utility: compute XML Merkle diffs and return structured results + payload Map. */
public final class XmlMerkleDiff {

  private XmlMerkleDiff() {}

  // ---------------- Models ----------------

  public static final class ChangeSet {
    public final List<String> added = new ArrayList<>();
    public final List<String> removed = new ArrayList<>();
    public final List<Changed> changed = new ArrayList<>();
  }
  public static final class Changed {
    public final String path;
    public final String oldHashHex;
    public final String newHashHex;
    Changed(String p, byte[] oldH, byte[] newH) {
      this.path = p;
      this.oldHashHex = MerkleCTree.hex(oldH);
      this.newHashHex = MerkleCTree.hex(newH);
    }
  }

  public enum ChangeType { ADDED, REMOVED, CHANGED }

  public static final class TagSummary {
    public final Map<String, Set<String>> elements = new TreeMap<>();   // tagName -> ops
    public final Map<String, Set<String>> attributes = new TreeMap<>(); // @attr -> ops
    void markElement(String tag, ChangeType t) {
      elements.computeIfAbsent(tag, k -> new TreeSet<>()).add(t.name());
    }
    void markAttribute(String attr, ChangeType t) {
      attributes.computeIfAbsent(attr, k -> new TreeSet<>()).add(t.name());
    }
  }

  // ---------------- Core API ----------------

  /** Build the structured diff between two XML strings (xmlOld can be null/blank). */
  public static ChangeSet diff(String xmlOld, String xmlNew) throws Exception {
    XmlPathMerkle.Result oldR = (xmlOld == null || xmlOld.isBlank()) ? null : XmlPathMerkle.build(xmlOld);
    XmlPathMerkle.Result newR = XmlPathMerkle.build(xmlNew);
    return diff(oldR, newR);
  }

  /** Variant if you already computed Merkle results. */
  public static ChangeSet diff(XmlPathMerkle.Result oldR, XmlPathMerkle.Result newR) {
    ChangeSet cs = new ChangeSet();

    if (oldR == null) { // empty baseline → everything is added
      cs.added.addAll(newR.pathValueHashes.keySet());
      return cs;
    }

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

  /** Return de-noised, index-free changed paths + all their ancestor subpaths (no #text). */
  public static Set<String> collapsedChangedPaths(ChangeSet cs) {
    Set<String> collapsed = new LinkedHashSet<>();
    for (Changed c : cs.changed) {
      String norm = normalizePathWithoutText(c.path);
      addWithAncestors(norm, collapsed);
    }
    // include ancestors for added/removed too (useful when old is empty)
    for (String p : cs.added)  { addWithAncestors(normalizePathWithoutText(p), collapsed); }
    for (String p : cs.removed){ addWithAncestors(normalizePathWithoutText(p), collapsed); }
    return collapsed;
  }

  /** Build tag-level summary (elements + attributes) with ADDED/REMOVED/CHANGED. */
  public static TagSummary summarizeTagChanges(ChangeSet cs) {
    TagSummary ts = new TagSummary();
    for (String p : cs.added)  emitTag(ts, normalizePathWithoutText(p), ChangeType.ADDED);
    for (String p : cs.removed)emitTag(ts, normalizePathWithoutText(p), ChangeType.REMOVED);
    for (Changed c : cs.changed) emitTag(ts, normalizePathWithoutText(c.path), ChangeType.CHANGED);
    return ts;
  }

  /**
   * Build a single payload map you can log/ship.
   * Keys:
   *  - "rootOld","rootNew" (hex or "<empty>")
   *  - "added","removed" (List<String>)
   *  - "changed" (List<Map<String,String>> with path/oldHash/newHash)
   *  - "collapsedPaths" (List<String>)
   *  - "tagSummaryElements","tagSummaryAttributes" (Map<String,List<String>>)
   */
  public static Map<String,Object> buildPayload(XmlPathMerkle.Result oldR, XmlPathMerkle.Result newR, ChangeSet cs) {
    Map<String,Object> m = new LinkedHashMap<>();
    m.put("rootOld", oldR == null ? "<empty>" : MerkleCTree.hex(oldR.root));
    m.put("rootNew", MerkleCTree.hex(newR.root));

    m.put("added", new ArrayList<>(cs.added));
    m.put("removed", new ArrayList<>(cs.removed));

    List<Map<String,String>> changed = new ArrayList<>();
    for (Changed c : cs.changed) {
      Map<String,String> row = new LinkedHashMap<>();
      row.put("path", c.path);
      row.put("oldHash", c.oldHashHex);
      row.put("newHash", c.newHashHex);
      changed.add(row);
    }
    m.put("changed", changed);

    Set<String> collapsed = collapsedChangedPaths(cs);
    m.put("collapsedPaths", new ArrayList<>(collapsed));

    TagSummary ts = summarizeTagChanges(cs);
    m.put("tagSummaryElements", toSortedLists(ts.elements));
    m.put("tagSummaryAttributes", toSortedLists(ts.attributes));

    return m;
  }

  // ---------------- Helpers ----------------

  /** Remove [#k], drop #text, render attributes as /@attr, and tidy slashes. */
  public static String normalizePathWithoutText(String canonical) {
    String s = canonical;
    s = s.replaceAll("\\[#\\d+\\]", "");              // remove canonical indices
    s = s.replaceAll("\\.#text(?:\\[#\\d+\\])?", ""); // drop text segments entirely
    s = s.replaceAll("\\.@", "/@");                   // attributes
    s = s.replaceAll("\\.__empty(Element|Array|Object)", "");
    s = s.replaceAll("/{2,}", "/");                   // collapse double slashes
    return s;
  }

  private static void addWithAncestors(String path, Set<String> out) {
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

  private static void emitTag(TagSummary ts, String normalizedPath, ChangeType ct) {
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

  private static Map<String,List<String>> toSortedLists(Map<String,Set<String>> in) {
    Map<String,List<String>> out = new TreeMap<>();
    for (Map.Entry<String,Set<String>> e : in.entrySet()) {
      out.put(e.getKey(), new ArrayList<>(e.getValue()));
    }
    return out;
  }
}
