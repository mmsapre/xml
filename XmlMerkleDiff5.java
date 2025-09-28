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
    public final Map<String, Set<String>> elements = new TreeMap<>();
    public final Map<String, Set<String>> attributes = new TreeMap<>();
    void markElement(String tag, ChangeType t) {
      elements.computeIfAbsent(tag, new java.util.function.Function<String, Set<String>>() {
        public Set<String> apply(String k) { return new TreeSet<String>(); }
      }).add(t.name());
    }
    void markAttribute(String attr, ChangeType t) {
      attributes.computeIfAbsent(attr, new java.util.function.Function<String, Set<String>>() {
        public Set<String> apply(String k) { return new TreeSet<String>(); }
      }).add(t.name());
    }
  }

  // ---------------- Core API ----------------

  /** Build the structured diff between two XML strings (xmlOld can be null/blank). */
  public static ChangeSet diff(String xmlOld, String xmlNew) throws Exception {
    XmlPathMerkle.Result oldR = (xmlOld == null || xmlOld.trim().isEmpty()) ? null : XmlPathMerkle.build(xmlOld);
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

    Set<String> all = new TreeSet<String>();
    all.addAll(oldR.pathValueHashes.keySet());
    all.addAll(newR.pathValueHashes.keySet());

    for (String p : all) {
      byte[] oh = oldR.pathValueHashes.get(p);
      byte[] nh = newR.pathValueHashes.get(p);

      if (oh == null && nh != null) {
        cs.added.add(p);
      } else if (oh != null && nh == null) {
        cs.removed.add(p);
      } else if (oh != null && nh != null && !Arrays.equals(oh, nh)) {
        // keep ONLY leaf value changes: text nodes or attributes
        if (isValueLeafPath(p)) cs.changed.add(new Changed(p, oh, nh));
      }
    }
    return cs;
  }

  // ---------------- Collapsed paths ----------------

  /** Back-compat default: collapsed paths WITH ancestors and guaranteed root. */
  public static Set<String> collapsedChangedPaths(ChangeSet cs) {
    return collapsedChangedPaths(cs, true);
  }

  /**
   * Collapsed paths; if includeAncestors=true, also add all ancestor prefixes and ensure root is present.
   * If includeAncestors=false, returns only direct, normalized paths (no indices, no #text).
   */
  public static Set<String> collapsedChangedPaths(ChangeSet cs, boolean includeAncestors) {
    if (!includeAncestors) return collapsedChangedPathsDirect(cs);

    Set<String> collapsed = new LinkedHashSet<String>();
    for (String p : cs.added)   addWithAncestors(normalizePathWithoutText(p), collapsed);
    for (String p : cs.removed) addWithAncestors(normalizePathWithoutText(p), collapsed);
    for (Changed c : cs.changed) addWithAncestors(normalizePathWithoutText(c.path), collapsed);

    // ensure root present
    if (!collapsed.isEmpty()) {
      String any = collapsed.iterator().next();
      String root = extractRoot(any);
      if (root != null) collapsed.add(root);
    }
    // remove empties
    collapsed.remove(""); collapsed.remove("/");
    return collapsed;
  }

  /** Return ONLY the direct, normalized paths that changed/added/removed (no ancestors, no #text, no indices). */
  public static Set<String> collapsedChangedPathsDirect(ChangeSet cs) {
    Set<String> out = new LinkedHashSet<String>();
    for (Changed c : cs.changed) out.add(normalizePathWithoutText(c.path));
    for (String p : cs.added)    out.add(normalizePathWithoutText(p));
    for (String p : cs.removed)  out.add(normalizePathWithoutText(p));
    out.remove(""); out.remove("/");
    return out;
  }

  // ---------------- Tag summary ----------------

  /** Build tag-level summary (elements + attributes) with ADDED/REMOVED/CHANGED. */
  public static TagSummary summarizeTagChanges(ChangeSet cs) {
    TagSummary ts = new TagSummary();
    for (String p : cs.added)    emitTag(ts, normalizePathWithoutText(p), ChangeType.ADDED);
    for (String p : cs.removed)  emitTag(ts, normalizePathWithoutText(p), ChangeType.REMOVED);
    for (Changed c : cs.changed) emitTag(ts, normalizePathWithoutText(c.path), ChangeType.CHANGED);
    return ts;
  }

  /**
   * Build a single payload map you can log/ship.
   * Keys:
   *  - "rootOld","rootNew" (hex or "<empty>")
   *  - "added","removed" (List<String>)
   *  - "changed" (List<Map<String,String>> with path/oldHash/newHash)
   *  - "collapsedPaths" (List<String>)  // NOTE: uses *direct* collapsed paths now
   *  - "tagSummaryElements","tagSummaryAttributes" (Map<String,List<String>>)
   */
  public static Map<String,Object> buildPayload(XmlPathMerkle.Result oldR, XmlPathMerkle.Result newR, ChangeSet cs) {
    Map<String,Object> m = new LinkedHashMap<String,Object>();
    m.put("rootOld", oldR == null ? "<empty>" : MerkleCTree.hex(oldR.root));
    m.put("rootNew", MerkleCTree.hex(newR.root));

    m.put("added", new ArrayList<String>(cs.added));
    m.put("removed", new ArrayList<String>(cs.removed));

    List<Map<String,String>> changed = new ArrayList<Map<String,String>>();
    for (Changed c : cs.changed) {
      Map<String,String> row = new LinkedHashMap<String,String>();
      row.put("path", c.path);
      row.put("oldHash", c.oldHashHex);
      row.put("newHash", c.newHashHex);
      changed.add(row);
    }
    m.put("changed", changed);

    // Use direct collapsed paths (only the direct changed/added/removed paths)
    Set<String> collapsed = collapsedChangedPathsDirect(cs);
    m.put("collapsedPaths", new ArrayList<String>(collapsed));

    TagSummary ts = summarizeTagChanges(cs);
    m.put("tagSummaryElements", toSortedLists(ts.elements));
    m.put("tagSummaryAttributes", toSortedLists(ts.attributes));

    return m;
  }

  // ---------------- Helpers ----------------

  /** Keep only value leaves: attributes (.@...) and text nodes (.#text[#k]). */
  private static boolean isValueLeafPath(String canonicalPath) {
    return canonicalPath != null && (canonicalPath.contains(".@") || canonicalPath.contains(".#text["));
  }

  /** Remove [#k], drop #text, render attributes as /@attr, and tidy slashes. */
  public static String normalizePathWithoutText(String canonical) {
    String s = canonical == null ? "" : canonical;
    s = s.replaceAll("\\[#\\d+\\]", "");              // remove canonical indices
    s = s.replaceAll("\\.#text(?:\\[#\\d+\\])?", ""); // drop text segments entirely
    s = s.replaceAll("\\.@", "/@");                   // attributes => segment
    s = s.replaceAll("\\.__empty(Element|Array|Object)", "");
    s = s.replaceAll("/{2,}", "/");                   // collapse double slashes
    return s;
  }

  private static void addWithAncestors(String path, Set<String> out) {
    if (path == null || path.isEmpty()) return;
    if (!path.startsWith("/")) { out.add(path); return; }
    String[] parts = path.substring(1).split("/");
    StringBuilder cur = new StringBuilder("/");
    for (int i = 0; i < parts.length; i++) {
      String part = parts[i];
      if (part == null || part.isEmpty()) continue;
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
    Map<String,List<String>> out = new TreeMap<String,List<String>>();
    for (Map.Entry<String,Set<String>> e : in.entrySet()) {
      out.put(e.getKey(), new ArrayList<String>(e.getValue()));
    }
    return out;
  }

  /** Extract "/root" from a path like "/root/...". */
  private static String extractRoot(String anyPath) {
    if (anyPath == null || !anyPath.startsWith("/")) return null;
    int secondSlash = anyPath.indexOf('/', 1);
    if (secondSlash == -1) return anyPath;            // it was just "/root"
    return anyPath.substring(0, secondSlash);         // "/root"
  }
}
