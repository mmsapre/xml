public class XmlMerkleDemo {
    public static void main(String[] args) throws Exception {
        String xml1 = "<Order xmlns=\"urn:ex\"><Item sku=\"A\"><Qty>2</Qty></Item><Item sku=\"B\"><Qty>1</Qty></Item></Order>";
        String xml2 = "<Order xmlns=\"urn:ex\"><Item sku=\"B\"><Qty>3</Qty></Item><Item sku=\"A\"><Qty>2</Qty></Item></Order>";

        XmlPathMerkle.Result r1 = XmlPathMerkle.build(xml1);
        XmlPathMerkle.Result r2 = XmlPathMerkle.build(xml2);

        System.out.println("Root v1 = " + MerkleCTree.hex(r1.root));
        System.out.println("Root v2 = " + MerkleCTree.hex(r2.root));

        System.out.println("\nCanonical paths in v2:");
        r2.pathValueHashes.keySet().forEach(System.out::println);

        // Choose one path to prove (the Qty text of sku=B)
        String path = r2.pathValueHashes.keySet().stream()
                .filter(p -> p.contains("@sku") && p.endsWith("B")) // find Item[#i] with B
                .findFirst()
                .map(p -> p.substring(0, p.lastIndexOf(".@sku")) + "/urn:ex|Qty[#0].#text[#0]")
                .orElseThrow();

        System.out.println("\nProving inclusion for path: " + path);
        MerkleCTree.InclusionProof proof = XmlPathMerkle.prove(xml2, path);
        boolean ok = XmlPathMerkle.verify(path, "3", proof, r2.root);
        System.out.println("Proof verifies? " + ok);
    }
}
