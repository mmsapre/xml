import java.util.*;

/** Utility: compute JSON Merkle diffs and return structured results + payload Map. */
public final class JsonMerkleDiff {

  private JsonMerkleDiff() {}

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

  /** Key-level summary: key -> set(ADDED/REMOVED/CHANGED) */
  public static final class KeySummary {
    public final Map<String, Set<String>> keys = new TreeMap<>();
    void markKey(String key, ChangeType t) {
      keys.computeIfAbsent(key, new java.util.function.Function<String, Set<String>>() {
        public Set<String> apply(String k) { return new TreeSet<String>(); }
      }).add(t.name());
    }
  }

  // ---------------- Core API ----------------

  /** Build the structured diff between two JSON strings (jsonOld can be null/blank). */
  public static ChangeSet diff(String jsonOld, String jsonNew) throws Exception {
    JsonPathMerkle.Result oldR = (jsonOld == null || jsonOld.trim().isEmpty()) ? null : JsonPathMerkle.build(jsonOld);
    JsonPathMerkle.Result newR = JsonPathMerkle.build(jsonNew);
    return diff(oldR, newR);
  }

  /** Variant if you already computed Merkle results. */
  public static ChangeSet diff(JsonPathMerkle.Result oldR, JsonPathMerkle.Result newR) {
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
        // Keep ONLY value leaves (exclude empty-object/array markers)
        if (isValueLeafPath(p)) cs.changed.add(new Changed(p, oh, nh));
      }
    }
    return cs;
  }

  // ---------------- Collapsed paths ----------------

  /** Back-compat default: collapsed paths WITH ancestors. */
  public static Set<String> collapsedChangedPaths(ChangeSet cs) {
    return collapsedChangedPaths(cs, true);
  }

  /**
   * Collapsed paths; if includeAncestors=true, also add all ancestor prefixes.
   * If includeAncestors=false, returns only direct, normalized paths (no indices).
   */
  public static Set<String> collapsedChangedPaths(ChangeSet cs, boolean includeAncestors) {
    if (!includeAncestors) return collapsedChangedPathsDirect(cs);

    Set<String> out = new LinkedHashSet<String>();
    for (Changed c : cs.changed) addWithAncestors(normalizeJsonPath(c.path), out);
    for (String p : cs.added)   addWithAncestors(normalizeJsonPath(p), out);
    for (String p : cs.removed) addWithAncestors(normalizeJsonPath(p), out);
    out.remove("$"); // tidy
    return out;
  }

  /** ONLY the direct, normalized paths that changed/added/removed (no ancestors). */
  public static Set<String> collapsedChangedPathsDirect(ChangeSet cs) {
    Set<String> out = new LinkedHashSet<String>();
    for (Changed c : cs.changed) out.add(normalizeJsonPath(c.path));
    for (String p : cs.added)    out.add(normalizeJsonPath(p));
    for (String p : cs.removed)  out.add(normalizeJsonPath(p));
    out.remove("$");
    return out;
  }

  // ---------------- Key summary ----------------

  /** Build key-level summary (JSON keys) with ADDED/REMOVED/CHANGED. */
  public static KeySummary summarizeKeyChanges(ChangeSet cs) {
    KeySummary ks = new KeySummary();
    for (String p : cs.added)    emitKey(ks, normalizeJsonPath(p), ChangeType.ADDED);
    for (String p : cs.removed)  emitKey(ks, normalizeJsonPath(p), ChangeType.REMOVED);
    for (Changed c : cs.changed) emitKey(ks, normalizeJsonPath(c.path), ChangeType.CHANGED);
    return ks;
  }

  /**
   * Build a single payload map you can log/ship.
   * Keys:
   *  - "rootOld","rootNew" (hex or "<empty>")
   *  - "added","removed" (List<String>)
   *  - "changed" (List<Map<String,String>> with path/oldHash/newHash)
   *  - "collapsedPaths" (List<String>)  // NOTE: uses *direct* collapsed paths
   *  - "keySummary" (Map<String,List<String>>)
   */
  public static Map<String,Object> buildPayload(JsonPathMerkle.Result oldR, JsonPathMerkle.Result newR, ChangeSet cs) {
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

    Set<String> collapsed = collapsedChangedPathsDirect(cs);
    m.put("collapsedPaths", new ArrayList<String>(collapsed));

    KeySummary ks = summarizeKeyChanges(cs);
    m.put("keySummary", toSortedLists(ks.keys));

    return m;
  }

  // ---------------- Helpers ----------------

  /** JSON value leaves are any non-container leaves; exclude empty-object/array markers. */
  private static boolean isValueLeafPath(String canonicalPath) {
    if (canonicalPath == null) return false;
    // We add markers like ".__emptyObject" / ".__emptyArray" for empty containers — exclude those.
    if (canonicalPath.endsWith(".__emptyObject")) return false;
    if (canonicalPath.endsWith(".__emptyArray"))  return false;
    // Everything else in JsonPathMerkle is a value (number/string/bool/null) at some path.
    return true;
  }

  /** Remove canonical array indices [#k]. */
  public static String normalizeJsonPath(String path) {
    String s = path == null ? "" : path;
    s = s.replaceAll("\\[#\\d+\\]", ""); // drop canonical indices
    return s;
  }

  private static void addWithAncestors(String path, Set<String> out) {
    if (path == null || path.isEmpty()) return;
    if (!path.startsWith("$")) { out.add(path); return; }
    String[] parts = path.substring(1).split("\\."); // remove '$'
    StringBuilder cur = new StringBuilder("$");
    for (int i = 0; i < parts.length; i++) {
      String part = parts[i];
      if (part == null || part.isEmpty()) continue;
      if (cur.length() > 1) cur.append(".");
      cur.append(part);
      out.add(cur.toString());
    }
  }

  /** For payload JSON: Map<String,Set<String>> -> Map<String,List<String>> */
  private static Map<String,List<String>> toSortedLists(Map<String,Set<String>> in) {
    Map<String,List<String>> out = new TreeMap<String,List<String>>();
    for (Map.Entry<String,Set<String>> e : in.entrySet()) {
      out.put(e.getKey(), new ArrayList<String>(e.getValue()));
    }
    return out;
  }

  private static void emitKey(KeySummary ks, String normalizedPath, ChangeType ct) {
    if (normalizedPath == null || normalizedPath.isEmpty()) return;
    // pick the LAST path token as the "key"
    // e.g., $.addr.pin -> "pin"; $.tags[#0] -> "tags" (indices are already stripped)
    String[] parts = normalizedPath.split("\\.");
    if (parts.length == 0) return;
    String last = parts[parts.length - 1];
    if (!"$".equals(last)) ks.markKey(last, ct);
  }
}
