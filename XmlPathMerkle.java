// XmlPathMerkle.java
import org.w3c.dom.*;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Path-aware canonicalizer for XML:
 *  - Namespace-stable names: "namespaceURI|localName"
 *  - Sibling elements order-insensitive via structural hashing and canonical indices [#k]
 *  - Attributes included at ".@{ns|name}" (sorted)
 *  - Text nodes at ".#text[#k]" (trimmed; empty text ignored)
 * Builds RFC 6962 Merkle tree over (canonicalPath, valueHash) leaves.
 */
public final class XmlPathMerkle {

    public static final class Result {
        public final byte[] root;
        public final MerkleCTree tree;
        public final Map<String, byte[]> pathValueHashes;
        public Result(byte[] root, MerkleCTree tree, Map<String, byte[]> pathValueHashes) {
            this.root = root; this.tree = tree; this.pathValueHashes = pathValueHashes;
        }
    }

    public static Result build(String xml) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true); dbf.setIgnoringComments(true); dbf.setCoalescing(true);
        DocumentBuilder db = dbf.newDocumentBuilder();
        Document doc = db.parse(new java.io.ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
        Element root = doc.getDocumentElement();

        Map<String, byte[]> leaves = new LinkedHashMap<>();
        walkElem(root, "/" + qName(root), leaves);

        List<String> paths = new ArrayList<>(leaves.keySet());
        Collections.sort(paths);
        List<byte[]> rfcLeaves = new ArrayList<>(paths.size());
        for (String p : paths) rfcLeaves.add(MerkleCTree.encodeLeaf(p, leaves.get(p)));

        MerkleCTree tree = new MerkleCTree(rfcLeaves);
        return new Result(tree.root(), tree, leaves);
    }

    public static MerkleCTree.InclusionProof prove(String xml, String canonicalPath) throws Exception {
        Result r = build(xml);
        List<String> sorted = new ArrayList<>(r.pathValueHashes.keySet());
        Collections.sort(sorted);
        int idx = Collections.binarySearch(sorted, canonicalPath);
        if (idx < 0) throw new IllegalArgumentException("path not found: " + canonicalPath);
        return r.tree.inclusionProof(idx);
    }

    public static boolean verify(String path, String normalizedValue, MerkleCTree.InclusionProof proof, byte[] expectedRoot) {
        byte[] vhash = MerkleCTree.sha256(("V|" + normalizedValue).getBytes(StandardCharsets.UTF_8));
        byte[] leaf = MerkleCTree.encodeLeaf(path, vhash);
        return MerkleCTree.verifyInclusion(leaf, proof, expectedRoot);
    }

    // ---- Canonical traversal (order-insensitive siblings) ----

    private static void walkElem(Element el, String path, Map<String, byte[]> out) {
        // attributes (sorted by qName)
        NamedNodeMap attrs = el.getAttributes();
        List<String> an = new ArrayList<>();
        for (int i = 0; i < attrs.getLength(); i++) an.add(qName(attrs.item(i)));
        Collections.sort(an);
        for (String name : an) {
            String val = el.getAttributeNS(ns(name), local(name));
            out.put(path + ".@" + name, MerkleCTree.sha256(("V|" + val).getBytes(StandardCharsets.UTF_8)));
        }

        // collect children (text+elements) first
        NodeList kids = el.getChildNodes();
        List<Child> units = new ArrayList<>();
        for (int i = 0; i < kids.getLength(); i++) {
            Node k = kids.item(i);
            if (k.getNodeType() == Node.TEXT_NODE) {
                String txt = k.getTextContent() == null ? "" : k.getTextContent().trim();
                if (!txt.isEmpty()) {
                    units.add(Child.text(txt, path + ".#text[*]"));
                }
            } else if (k.getNodeType() == Node.ELEMENT_NODE) {
                Element c = (Element) k;
                String name = qName(c);
                byte[] sh = hashElemStructure(c);
                units.add(Child.elem(name, sh, path + "/" + name + "[*]", c));
            }
        }

        if (an.isEmpty() && units.isEmpty()) {
            // explicit empty marker so structure-only changes are detectable
            out.put(path + ".__emptyElement", MerkleCTree.sha256("V|<empty>".getBytes(StandardCharsets.UTF_8)));
            return;
        }

        // order-insensitive: sort units by (type, name, structHash)
        units.sort(Comparator
                .comparingInt((Child u) -> u.typeOrder())
                .thenComparing(u -> u.nameOrEmpty())
                .thenComparing(u -> MerkleCTree.hex(u.structHash)));

        // assign canonical indices and traverse
        int textCounter = 0;
        Map<String, Integer> elemCounter = new HashMap<>();
        for (Child u : units) {
            if (u.isText) {
                String tpath = path + ".#text[#"+(textCounter++)+"]";
                out.put(tpath, MerkleCTree.sha256(("V|" + u.text).getBytes(StandardCharsets.UTF_8)));
            } else {
                int idx = elemCounter.merge(u.name, 1, Integer::sum) - 1;
                walkElem(u.elem, path + "/" + u.name + "[#" + idx + "]", out);
            }
        }
    }

    /** Structural hash to canonicalize element order (not used as a Merkle leaf). */
    private static byte[] hashElemStructure(Element el) {
        List<byte[]> parts = new ArrayList<>();
        parts.add(("N|EL|" + qName(el) + "|").getBytes(StandardCharsets.UTF_8));

        // attributes
        NamedNodeMap attrs = el.getAttributes();
        List<String> an = new ArrayList<>();
        for (int i = 0; i < attrs.getLength(); i++) an.add(qName(attrs.item(i)));
        Collections.sort(an);
        for (String name : an) {
            String val = el.getAttributeNS(ns(name), local(name));
            parts.add(("@" + name + "=" + val + "|").getBytes(StandardCharsets.UTF_8));
        }

        // children
        NodeList kids = el.getChildNodes();
        List<byte[]> childHashes = new ArrayList<>();
        for (int i = 0; i < kids.getLength(); i++) {
            Node k = kids.item(i);
            if (k.getNodeType() == Node.TEXT_NODE) {
                String t = k.getTextContent() == null ? "" : k.getTextContent().trim();
                if (!t.isEmpty()) childHashes.add(MerkleCTree.sha256(("N|TEXT|" + t).getBytes(StandardCharsets.UTF_8)));
            } else if (k.getNodeType() == Node.ELEMENT_NODE) {
                childHashes.add(hashElemStructure((Element) k));
            }
        }
        childHashes.sort(Comparator.comparing(MerkleCTree::hex));
        for (byte[] ch : childHashes) parts.add(ch);

        return MerkleCTree.sha256(parts.toArray(new byte[0][]));
    }

    private static String qName(Node n) {
        String ln = n.getLocalName();
        String ns = n.getNamespaceURI();
        if (ln == null) ln = n.getNodeName();
        if (ns == null) return ln;
        return ns + "|" + ln;
    }
    private static String ns(String nsPipeLocal) {
        int i = nsPipeLocal.indexOf('|');
        return i < 0 ? null : nsPipeLocal.substring(0, i);
    }
    private static String local(String nsPipeLocal) {
        int i = nsPipeLocal.indexOf('|');
        return i < 0 ? nsPipeLocal : nsPipeLocal.substring(i + 1);
    }

    private static final class Child {
        final boolean isText; final String text;
        final String name; final byte[] structHash; final Element elem;
        Child(boolean isText, String text, String name, byte[] structHash, Element elem) {
            this.isText=isText; this.text=text; this.name=name; this.structHash=structHash; this.elem=elem;
        }
        static Child text(String t, String path){ return new Child(true, t, null, null, null); }
        static Child elem(String name, byte[] sh, String provisional, Element e){ return new Child(false, null, name, sh, e); }
        int typeOrder(){ return isText?0:1; }
        String nameOrEmpty(){ return name==null?"":name; }
    }
}
