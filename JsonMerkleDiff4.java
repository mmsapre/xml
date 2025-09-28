import java.util.*;
import com.fasterxml.jackson.databind.*;

/** Utility: compute JSON Merkle diffs and return structured results + payload/summary Maps. */
public final class JsonMerkleDiff {

  private JsonMerkleDiff() {}

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

  public static final class KeySummary {
    public final Map<String, Set<String>> keys = new TreeMap<>();
    void markKey(String key, ChangeType t) {
      keys.computeIfAbsent(key, new java.util.function.Function<String, Set<String>>() {
        public Set<String> apply(String k) { return new TreeSet<String>(); }
      }).add(t.name());
    }
  }

  // ---------------- Core API ----------------

  public static ChangeSet diff(String jsonOld, String jsonNew) throws Exception {
    JsonPathMerkle.Result oldR = (jsonOld == null || jsonOld.trim().isEmpty()) ? null : JsonPathMerkle.build(jsonOld);
    JsonPathMerkle.Result newR = JsonPathMerkle.build(jsonNew);
    return diff(oldR, newR);
  }

  public static ChangeSet diff(JsonPathMerkle.Result oldR, JsonPathMerkle.Result newR) {
    ChangeSet cs = new ChangeSet();
    if (oldR == null) {
      cs.added.addAll(newR.pathValueHashes.keySet());
      return cs;
    }
    Set<String> all = new TreeSet<String>();
    all.addAll(oldR.pathValueHashes.keySet());
    all.addAll(newR.pathValueHashes.keySet());
    for (String p : all) {
      byte[] oh = oldR.pathValueHashes.get(p);
      byte[] nh = newR.pathValueHashes.get(p);
      if (oh == null && nh != null) cs.added.add(p);
      else if (oh != null && nh == null) cs.removed.add(p);
      else if (oh != null && nh != null && !Arrays.equals(oh, nh)) {
        if (isValueLeafPath(p)) cs.changed.add(new Changed(p, oh, nh));
      }
    }
    return cs;
  }

  // ---------------- Collapsed paths ----------------

  public static Set<String> collapsedChangedPaths(ChangeSet cs) {
    return collapsedChangedPaths(cs, true);
  }

  public static Set<String> collapsedChangedPaths(ChangeSet cs, boolean includeAncestors) {
    if (!includeAncestors) return collapsedChangedPathsDirect(cs);
    Set<String> out = new LinkedHashSet<String>();
    for (Changed c : cs.changed) addWithAncestors(normalizeJsonPath(c.path), out);
    for (String p : cs.added) addWithAncestors(normalizeJsonPath(p), out);
    for (String p : cs.removed) addWithAncestors(normalizeJsonPath(p), out);
    out.remove("$");
    return out;
  }

  public static Set<String> collapsedChangedPathsDirect(ChangeSet cs) {
    Set<String> out = new LinkedHashSet<String>();
    for (Changed c : cs.changed) out.add(normalizeJsonPath(c.path));
    for (String p : cs.added) out.add(normalizeJsonPath(p));
    for (String p : cs.removed) out.add(normalizeJsonPath(p));
    out.remove("$");
    return out;
  }

  // ---------------- Key summary ----------------

  public static KeySummary summarizeKeyChanges(ChangeSet cs) {
    KeySummary ks = new KeySummary();
    for (String p : cs.added) ks.markKey(extractKey(normalizeJsonPath(p)), ChangeType.ADDED);
    for (String p : cs.removed) ks.markKey(extractKey(normalizeJsonPath(p)), ChangeType.REMOVED);
    for (Changed c : cs.changed) ks.markKey(extractKey(normalizeJsonPath(c.path)), ChangeType.CHANGED);
    return ks;
  }

  // ---------------- Change Summary (JSON-structured) ----------------

  /** Build { paths:{added/removed/changed}, keySummary:{added/removed/changed} } */
  public static Map<String,Object> buildChangeSummary(ChangeSet cs, boolean directPaths) {
    Map<String,Object> root = new LinkedHashMap<String,Object>();
    Map<String,Object> paths = new LinkedHashMap<String,Object>();
    Set<String> added   = directPaths ? normalizeSetDirect(cs.added)   : normalizeSetWithAncestors(cs.added);
    Set<String> removed = directPaths ? normalizeSetDirect(cs.removed) : normalizeSetWithAncestors(cs.removed);
    Set<String> changed = new LinkedHashSet<String>();
    if (directPaths) for (Changed c : cs.changed) changed.add(normalizeJsonPath(c.path));
    else for (Changed c : cs.changed) addWithAncestors(normalizeJsonPath(c.path), changed);

    paths.put("added", new ArrayList<String>(added));
    paths.put("removed", new ArrayList<String>(removed));
    paths.put("changed", new ArrayList<String>(changed));
    root.put("paths", paths);

    KeySummary ks = summarizeKeyChanges(cs);
    List<String> changedKeys = new ArrayList<String>();
    List<String> addedKeys = new ArrayList<String>();
    List<String> removedKeys = new ArrayList<String>();
    for (Map.Entry<String,Set<String>> e : ks.keys.entrySet()) {
      if (e.getValue().contains(ChangeType.CHANGED.name())) changedKeys.add(e.getKey());
      if (e.getValue().contains(ChangeType.ADDED.name())) addedKeys.add(e.getKey());
      if (e.getValue().contains(ChangeType.REMOVED.name())) removedKeys.add(e.getKey());
    }
    Map<String,Object> keySummary = new LinkedHashMap<String,Object>();
    keySummary.put("changed", changedKeys);
    keySummary.put("added", addedKeys);
    keySummary.put("removed", removedKeys);
    root.put("keySummary", keySummary);

    return root;
  }

  // ---------------- Change Summary with JSON extraction ----------------

  /** Config for extracting Id, types, and key map from NEW JSON via SIMPLE dot paths (no wildcards). */
  public static final class JsonExtractConfig {
    /** Dot path for Id, e.g., "$.order.id" or "order.id" */
    public String idPath;
    /** Dot path to an array for types, e.g., "$.items[*].type" -> since no wildcards,
     *  use either "$.items" (array) and let valueField pick "type", or "$.types" (array of strings). */
    public String typesArrayPath; // points to array
    public String typesValueField; // if array elements are objects, which field to read (nullable)
    /** Map extraction from an array: entry array path, and key/value field names on each element. */
    public KeyMapConfig keyMap;
    public static final class KeyMapConfig {
      public String entryArrayPath;   // e.g., "$.items"
      public String keyField;         // e.g., "sku"
      public String valueField;       // e.g., "qty"
    }
  }

  /**
   * Build summary AND attach "extracted" (Id, types, key) from NEW JSON.
   * root = { paths:{...}, keySummary:{...}, extracted:{ Id, types[], key{} } }
   */
  public static Map<String,Object> buildChangeSummary(ChangeSet cs, boolean directPaths,
                                                      String newJson, JsonExtractConfig jcfg) throws Exception {
    Map<String,Object> base = buildChangeSummary(cs, directPaths);

    Map<String,Object> extracted = new LinkedHashMap<String,Object>();
    if (newJson == null || newJson.trim().isEmpty() || jcfg == null) {
      extracted.put("Id", null);
      extracted.put("types", new ArrayList<String>());
      extracted.put("key", new LinkedHashMap<String,String>());
      base.put("extracted", extracted);
      return base;
    }

    ObjectMapper om = new ObjectMapper();
    JsonNode root = om.readTree(newJson);

    // Id
    String id = readStringAt(root, jcfg.idPath);
    extracted.put("Id", (id != null && id.isEmpty()) ? null : id);

    // types
    List<String> types = new ArrayList<String>();
    if (jcfg.typesArrayPath != null && !jcfg.typesArrayPath.trim().isEmpty()) {
      JsonNode arr = readAt(root, jcfg.typesArrayPath);
      if (arr != null && arr.isArray()) {
        for (JsonNode e : arr) {
          if (jcfg.typesValueField != null && e.isObject()) {
            JsonNode v = e.get(jcfg.typesValueField);
            if (v != null && !v.isNull()) types.add(v.asText());
          } else {
            if (!e.isNull()) types.add(e.asText());
          }
        }
      }
    }
    extracted.put("types", types);

    // key map
    Map<String,String> keyMap = new LinkedHashMap<String,String>();
    if (jcfg.keyMap != null && jcfg.keyMap.entryArrayPath != null) {
      JsonNode arr = readAt(root, jcfg.keyMap.entryArrayPath);
      if (arr != null && arr.isArray()) {
        for (JsonNode e : arr) {
          if (!e.isObject()) continue;
          JsonNode k = jcfg.keyMap.keyField == null ? null : e.get(jcfg.keyMap.keyField);
          JsonNode v = jcfg.keyMap.valueField == null ? null : e.get(jcfg.keyMap.valueField);
          String ks = k == null || k.isNull() ? null : k.asText();
          String vs = v == null || v.isNull() ? null : v.asText();
          if (ks != null && ks.length() > 0) keyMap.put(ks, vs);
        }
      }
    }
    extracted.put("key", keyMap);

    base.put("extracted", extracted);
    return base;
  }

  // ---------------- Payload ----------------

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

  private static boolean isValueLeafPath(String path) {
    return !(path.endsWith(".__emptyObject") || path.endsWith(".__emptyArray"));
  }

  public static String normalizeJsonPath(String path) {
    return path == null ? "" : path.replaceAll("\\[#\\d+\\]", "");
  }

  private static void addWithAncestors(String path, Set<String> out) {
    if (path == null || path.isEmpty()) return;
    if (!path.startsWith("$")) { out.add(path); return; }
    String[] parts = path.substring(1).split("\\.");
    StringBuilder cur = new StringBuilder("$");
    for (String part : parts) {
      if (part == null || part.isEmpty()) continue;
      if (cur.length() > 1) cur.append(".");
      cur.append(part);
      out.add(cur.toString());
    }
  }

  private static String extractKey(String path) {
    if (path == null || path.isEmpty()) return "";
    String[] parts = path.split("\\.");
    return parts.length == 0 ? "" : parts[parts.length - 1];
  }

  private static Set<String> normalizeSetDirect(List<String> raw) {
    Set<String> out = new LinkedHashSet<String>();
    for (String p : raw) out.add(normalizeJsonPath(p));
    return out;
  }

  private static Set<String> normalizeSetWithAncestors(List<String> raw) {
    Set<String> out = new LinkedHashSet<String>();
    for (String p : raw) addWithAncestors(normalizeJsonPath(p), out);
    return out;
  }

  // ---- simple dot-path evaluator for extraction ----

  private static final ObjectMapper __om = new ObjectMapper();

  /** Read node at dot path like "$.order.items" or "order.items"; returns node or null. */
  private static JsonNode readAt(JsonNode root, String path) {
    if (root == null || path == null || path.trim().isEmpty()) return null;
    String p = path.trim();
    if (p.startsWith("$.")) p = p.substring(2);
    else if (p.startsWith("$")) p = p.substring(1);
    String[] parts = p.split("\\.");
    JsonNode cur = root;
    for (int i = 0; i < parts.length; i++) {
      String key = parts[i];
      if (key.length() == 0) continue;
      if (!cur.isObject()) return null;
      cur = cur.get(key);
      if (cur == null) return null;
    }
    return cur;
  }

  /** Read string value at dot path; if node is array/object, returns null. */
  private static String readStringAt(JsonNode root, String path) {
    if (path == null || path.trim().isEmpty()) return null;
    JsonNode n = readAt(root, path);
    if (n == null || n.isNull() || n.isContainerNode()) return null;
    return n.asText();
  }

  private static Map<String,List<String>> toSortedLists(Map<String,Set<String>> in) {
    Map<String,List<String>> out = new TreeMap<String,List<String>>();
    for (Map.Entry<String,Set<String>> e : in.entrySet()) {
      out.put(e.getKey(), new ArrayList<String>(e.getValue()));
    }
    return out;
  }
}
