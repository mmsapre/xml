import java.util.*;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.xpath.*;
import org.w3c.dom.*;

/** Utility: compute XML Merkle diffs and return structured results + payload/summary Maps. */
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

  public static ChangeSet diff(String xmlOld, String xmlNew) throws Exception {
    XmlPathMerkle.Result oldR = (xmlOld == null || xmlOld.trim().isEmpty()) ? null : XmlPathMerkle.build(xmlOld);
    XmlPathMerkle.Result newR = XmlPathMerkle.build(xmlNew);
    return diff(oldR, newR);
  }

  public static ChangeSet diff(XmlPathMerkle.Result oldR, XmlPathMerkle.Result newR) {
    ChangeSet cs = new ChangeSet();

    if (oldR == null) { // empty baseline → everything added
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
        // value leaves only
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
    Set<String> collapsed = new LinkedHashSet<String>();
    for (String p : cs.added)   addWithAncestors(normalizePathWithoutText(p), collapsed);
    for (String p : cs.removed) addWithAncestors(normalizePathWithoutText(p), collapsed);
    for (Changed c : cs.changed) addWithAncestors(normalizePathWithoutText(c.path), collapsed);
    if (!collapsed.isEmpty()) {
      String any = collapsed.iterator().next();
      String root = extractRoot(any);
      if (root != null) collapsed.add(root);
    }
    collapsed.remove(""); collapsed.remove("/");
    return collapsed;
  }

  public static Set<String> collapsedChangedPathsDirect(ChangeSet cs) {
    Set<String> out = new LinkedHashSet<String>();
    for (Changed c : cs.changed) out.add(normalizePathWithoutText(c.path));
    for (String p : cs.added)    out.add(normalizePathWithoutText(p));
    for (String p : cs.removed)  out.add(normalizePathWithoutText(p));
    out.remove(""); out.remove("/");
    return out;
  }

  // ---------------- Tag summary ----------------

  public static TagSummary summarizeTagChanges(ChangeSet cs) {
    TagSummary ts = new TagSummary();
    for (String p : cs.added)    emitTag(ts, normalizePathWithoutText(p), ChangeType.ADDED);
    for (String p : cs.removed)  emitTag(ts, normalizePathWithoutText(p), ChangeType.REMOVED);
    for (Changed c : cs.changed) emitTag(ts, normalizePathWithoutText(c.path), ChangeType.CHANGED);
    return ts;
  }

  // ---------------- Change Summary (JSON-structured) ----------------

  /** Build { paths:{added/removed/changed}, tagSummary:{added/removed/changed} } */
  public static Map<String,Object> buildChangeSummary(ChangeSet cs, boolean directPaths) {
    Map<String,Object> root = new LinkedHashMap<String,Object>();

    Map<String,Object> paths = new LinkedHashMap<String,Object>();
    Set<String> added   = directPaths ? normalizeSetDirect(cs.added)   : normalizeSetWithAncestors(cs.added);
    Set<String> removed = directPaths ? normalizeSetDirect(cs.removed) : normalizeSetWithAncestors(cs.removed);
    Set<String> changed = new LinkedHashSet<String>();
    if (directPaths) {
      for (Changed c : cs.changed) changed.add(normalizePathWithoutText(c.path));
    } else {
      for (Changed c : cs.changed) addWithAncestors(normalizePathWithoutText(c.path), changed);
    }
    added.remove(""); removed.remove(""); changed.remove("");
    paths.put("added",   new ArrayList<String>(added));
    paths.put("removed", new ArrayList<String>(removed));
    paths.put("changed", new ArrayList<String>(changed));
    root.put("paths", paths);

    TagSummary ts = summarizeTagChanges(cs);
    List<String> changedTags = new ArrayList<String>();
    List<String> addedTags = new ArrayList<String>();
    List<String> removedTags = new ArrayList<String>();
    for (Map.Entry<String,Set<String>> e : ts.elements.entrySet()) {
      if (e.getValue().contains(ChangeType.CHANGED.name())) changedTags.add(e.getKey());
      if (e.getValue().contains(ChangeType.ADDED.name())) addedTags.add(e.getKey());
      if (e.getValue().contains(ChangeType.REMOVED.name())) removedTags.add(e.getKey());
    }
    for (Map.Entry<String,Set<String>> e : ts.attributes.entrySet()) {
      if (e.getValue().contains(ChangeType.CHANGED.name())) changedTags.add(e.getKey());
      if (e.getValue().contains(ChangeType.ADDED.name())) addedTags.add(e.getKey());
      if (e.getValue().contains(ChangeType.REMOVED.name())) removedTags.add(e.getKey());
    }
    Map<String,Object> tagSummary = new LinkedHashMap<String,Object>();
    tagSummary.put("changed", changedTags);
    tagSummary.put("added", addedTags);
    tagSummary.put("removed", removedTags);
    root.put("tagSummary", tagSummary);

    return root;
  }

  // ---------------- Change Summary with XPath extraction ----------------

  /** Config for extracting Id, types, and key map from NEW XML via XPath. */
  public static final class XPathExtractConfig {
    /** XPath (string result) for Id, e.g., "string(/ex:Order/@id)" */
    public String idXPath;
    /** XPath (nodeset) for types list; each node’s string-value appended. e.g., "//ex:Item/@type" */
    public String typesXPath;
    /** Map extraction: iterate entry nodes and compute key/value via relative XPath expressions. */
    public KeyMapConfig keyMap;
    public static final class KeyMapConfig {
      /** Nodeset of entries, e.g., "//ex:Item" */
      public String entryXPath;
      /** Relative expr from entry node for map key, e.g., "string(@sku)" */
      public String keyExpr;
      /** Relative expr from entry node for map value, e.g., "string(ex:Qty)" */
      public String valueExpr;
    }
    /** Optional namespace resolver; set if your xpaths use prefixes (ex, etc). */
    public NamespaceContext nsContext;
  }

  /**
   * Build summary AND attach "extracted" (Id, types, key) from NEW XML.
   * root = { paths:{...}, tagSummary:{...}, extracted:{ Id, types[], key{} } }
   */
  public static Map<String,Object> buildChangeSummary(ChangeSet cs, boolean directPaths,
                                                      String newXml, XPathExtractConfig xcfg) throws Exception {
    Map<String,Object> base = buildChangeSummary(cs, directPaths);

    Map<String,Object> extracted = new LinkedHashMap<String,Object>();
    if (newXml == null || newXml.trim().isEmpty() || xcfg == null) {
      extracted.put("Id", null);
      extracted.put("types", new ArrayList<String>());
      extracted.put("key", new LinkedHashMap<String,String>());
      base.put("extracted", extracted);
      return base;
    }

    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    dbf.setNamespaceAware(true);
    DocumentBuilder db = dbf.newDocumentBuilder();
    Document doc = db.parse(new java.io.ByteArrayInputStream(newXml.getBytes("UTF-8")));

    XPathFactory xpf = XPathFactory.newInstance();
    XPath xp = xpf.newXPath();
    if (xcfg.nsContext != null) xp.setNamespaceContext(xcfg.nsContext);

    // Id
    String id = null;
    if (xcfg.idXPath != null && !xcfg.idXPath.trim().isEmpty()) {
      id = xp.compile(xcfg.idXPath).evaluate(doc);
      if (id != null && id.isEmpty()) id = null;
    }
    extracted.put("Id", id);

    // types
    List<String> types = new ArrayList<String>();
    if (xcfg.typesXPath != null && !xcfg.typesXPath.trim().isEmpty()) {
      NodeList nodes = (NodeList) xp.compile(xcfg.typesXPath).evaluate(doc, XPathConstants.NODESET);
      if (nodes != null) {
        for (int i = 0; i < nodes.getLength(); i++) {
          String v = stringValue(nodes.item(i));
          if (v != null && !v.isEmpty()) types.add(v);
        }
      }
    }
    extracted.put("types", types);

    // key map
    Map<String,String> keyMap = new LinkedHashMap<String,String>();
    if (xcfg.keyMap != null && xcfg.keyMap.entryXPath != null && !xcfg.keyMap.entryXPath.trim().isEmpty()) {
      NodeList entries = (NodeList) xp.compile(xcfg.keyMap.entryXPath).evaluate(doc, XPathConstants.NODESET);
      XPathExpression keyExpr = xcfg.keyMap.keyExpr == null ? null : xp.compile(xcfg.keyMap.keyExpr);
      XPathExpression valExpr = xcfg.keyMap.valueExpr == null ? null : xp.compile(xcfg.keyMap.valueExpr);
      if (entries != null) {
        for (int i = 0; i < entries.getLength(); i++) {
          Node entry = entries.item(i);
          String k = keyExpr == null ? null : keyExpr.evaluate(entry);
          String v = valExpr == null ? null : valExpr.evaluate(entry);
          if (k != null && !k.isEmpty()) keyMap.put(k, v);
        }
      }
    }
    extracted.put("key", keyMap);

    base.put("extracted", extracted);
    return base;
  }

  // ---- Missing helpers for path normalization (XML) ----
private static Set<String> normalizeSetDirect(List<String> raw) {
  Set<String> out = new LinkedHashSet<String>();
  if (raw == null) return out;
  for (String p : raw) {
    String n = normalizePathWithoutText(p);
    if (n != null && n.length() > 0 && !"/".equals(n)) out.add(n);
  }
  return out;
}

private static Set<String> normalizeSetWithAncestors(List<String> raw) {
  Set<String> out = new LinkedHashSet<String>();
  if (raw == null) return out;
  for (String p : raw) {
    String n = normalizePathWithoutText(p);
    if (n != null && n.length() > 0) addWithAncestors(n, out);
  }
  // prune accidental root-only empties
  out.remove(""); out.remove("/");
  return out;
}

  // ---------------- Payload (unchanged, uses direct collapsed paths) ----------------

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

    Set<String> collapsed = collapsedChangedPathsDirect(cs);
    m.put("collapsedPaths", new ArrayList<String>(collapsed));

    TagSummary ts = summarizeTagChanges(cs);
    m.put("tagSummaryElements", toSortedLists(ts.elements));
    m.put("tagSummaryAttributes", toSortedLists(ts.attributes));
    return m;
  }

  // ---------------- Helpers ----------------

  private static boolean isValueLeafPath(String canonicalPath) {
    return canonicalPath != null && (canonicalPath.contains(".@") || canonicalPath.contains(".#text["));
  }

  public static String normalizePathWithoutText(String canonical) {
    String s = canonical == null ? "" : canonical;
    s = s.replaceAll("\\[#\\d+\\]", "");
    s = s.replaceAll("\\.#text(?:\\[#\\d+\\])?", "");
    s = s.replaceAll("\\.@", "/@");
    s = s.replaceAll("\\.__empty(Element|Array|Object)", "");
    s = s.replaceAll("/{2,}", "/");
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
    } else ts.markElement(last, ct);
  }

  private static Map<String,List<String>> toSortedLists(Map<String,Set<String>> in) {
    Map<String,List<String>> out = new TreeMap<String,List<String>>();
    for (Map.Entry<String,Set<String>> e : in.entrySet()) {
      out.put(e.getKey(), new ArrayList<String>(e.getValue()));
    }
    return out;
  }

  private static String extractRoot(String anyPath) {
    if (anyPath == null || !anyPath.startsWith("/")) return null;
    int idx = anyPath.indexOf('/', 1);
    return idx == -1 ? anyPath : anyPath.substring(0, idx);
  }

  private static String stringValue(Node n) {
    if (n == null) return null;
    short t = n.getNodeType();
    if (t == Node.ATTRIBUTE_NODE) return n.getNodeValue();
    return n.getTextContent();
  }
}
