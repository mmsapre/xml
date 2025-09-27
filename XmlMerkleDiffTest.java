import org.junit.Test;
import java.util.*;
import static org.junit.Assert.*;

public class XmlMerkleDiffTest {

  @Test
  public void diff_detects_change_and_summaries() throws Exception {
    String xml1 = "<Order xmlns=\"urn:ex\">"
        + "<Item sku=\"A\"><Qty>2</Qty></Item>"
        + "<Item sku=\"B\"><Qty>1</Qty></Item>"
        + "</Order>";

    String xml2 = "<Order xmlns=\"urn:ex\">"
        + "<Item sku=\"B\"><Qty>3</Qty></Item>"  // changed value
        + "<Item sku=\"A\"><Qty>2</Qty></Item>"  // sibling reorder ignored
        + "</Order>";

    XmlPathMerkle.Result r1 = XmlPathMerkle.build(xml1);
    XmlPathMerkle.Result r2 = XmlPathMerkle.build(xml2);

    XmlMerkleDiff.ChangeSet cs = XmlMerkleDiff.diff(r1, r2);

    // Assertions
    assertTrue(cs.added.isEmpty());
    assertTrue(cs.removed.isEmpty());
    assertEquals(1, cs.changed.size());
    assertTrue(cs.changed.get(0).path.contains("urn:ex|Qty"));

    // Collapsed changed paths
    Set<String> collapsed = XmlMerkleDiff.collapsedChangedPaths(cs);
    assertTrue(collapsed.contains("/urn:ex|Order"));
    assertTrue(collapsed.contains("/urn:ex|Order/urn:ex|Item"));
    assertTrue(collapsed.contains("/urn:ex|Order/urn:ex|Item/urn:ex|Qty"));
    for (String p : collapsed) {
      assertFalse(p.contains("#text"));
      assertFalse(p.matches(".*\\[#\\d+\\].*"));
    }

    // Tag summary
    XmlMerkleDiff.TagSummary ts = XmlMerkleDiff.summarizeTagChanges(cs);
    assertTrue(ts.elements.containsKey("urn:ex|Qty"));
    assertTrue(ts.elements.get("urn:ex|Qty").contains("CHANGED"));
    assertTrue(ts.elements.get("urn:ex|Item").contains("CHANGED"));
    assertTrue(ts.elements.get("urn:ex|Order").contains("CHANGED"));

    // Payload Map
    Map<String,Object> payload = XmlMerkleDiff.buildPayload(r1, r2, cs);
    assertEquals(MerkleCTree.hex(r1.root), payload.get("rootOld"));
    assertEquals(MerkleCTree.hex(r2.root), payload.get("rootNew"));
    assertTrue(((List<?>)payload.get("added")).isEmpty());
    assertTrue(((List<?>)payload.get("removed")).isEmpty());
    assertEquals(1, ((List<?>)payload.get("changed")).size());
    assertTrue(((List<?>)payload.get("collapsedPaths"))
        .contains("/urn:ex|Order/urn:ex|Item/urn:ex|Qty"));
  }

  @Test
  public void diff_empty_baseline_marks_all_added() throws Exception {
    String xml1 = ""; // empty baseline
    String xml2 = "<Order xmlns=\"urn:ex\">"
        + "<Item sku=\"B\"><Qty>3</Qty></Item>"
        + "<Item sku=\"A\"><Qty>2</Qty></Item>"
        + "</Order>";

    XmlMerkleDiff.ChangeSet cs = XmlMerkleDiff.diff(xml1, xml2);

    assertTrue(cs.changed.isEmpty());
    assertTrue(cs.removed.isEmpty());
    assertFalse(cs.added.isEmpty());

    Set<String> collapsed = XmlMerkleDiff.collapsedChangedPaths(cs);
    assertTrue(collapsed.contains("/urn:ex|Order"));
    assertTrue(collapsed.contains("/urn:ex|Order/urn:ex|Item"));
    assertTrue(collapsed.contains("/urn:ex|Order/urn:ex|Item/urn:ex|Qty"));

    XmlMerkleDiff.TagSummary ts = XmlMerkleDiff.summarizeTagChanges(cs);
    assertTrue(ts.elements.containsKey("urn:ex|Order"));
    assertTrue(ts.elements.get("urn:ex|Order").contains("ADDED"));
    assertTrue(ts.elements.containsKey("urn:ex|Item"));
    assertTrue(ts.elements.get("urn:ex|Item").contains("ADDED"));
    assertTrue(ts.elements.containsKey("urn:ex|Qty"));
    assertTrue(ts.elements.get("urn:ex|Qty").contains("ADDED"));
    assertTrue(ts.attributes.containsKey("@sku"));
    assertTrue(ts.attributes.get("@sku").contains("ADDED"));
  }
}
