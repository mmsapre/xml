import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import java.util.*;

public class XmlMerkleDiffTest {

  @Test
  void diff_detects_change_and_summaries() throws Exception {
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

    // No adds/removes, only one change (the Qty text)
    assertTrue(cs.added.isEmpty());
    assertTrue(cs.removed.isEmpty());
    assertEquals(1, cs.changed.size());
    assertTrue(cs.changed.get(0).path.contains("urn:ex|Qty"));

    // Collapsed paths should include Order/Item/Qty (no indices, no #text)
    Set<String> collapsed = XmlMerkleDiff.collapsedChangedPaths(cs);
    assertTrue(collapsed.contains("/urn:ex|Order"));
    assertTrue(collapsed.contains("/urn:ex|Order/urn:ex|Item"));
    assertTrue(collapsed.contains("/urn:ex|Order/urn:ex|Item/urn:ex|Qty"));
    assertFalse(collapsed.stream().anyMatch(p -> p.contains("#text")));
    assertFalse(collapsed.stream().anyMatch(p -> p.matches(".*\\[#\\d+\\].*")));

    // Tag summary should say Qty changed; Item and Order changed via ancestry
    XmlMerkleDiff.TagSummary ts = XmlMerkleDiff.summarizeTagChanges(cs);
    assertTrue(ts.elements.containsKey("urn:ex|Qty"));
    assertTrue(ts.elements.get("urn:ex|Qty").contains("CHANGED"));
    assertTrue(ts.elements.get("urn:ex|Item").contains("CHANGED"));
    assertTrue(ts.elements.get("urn:ex|Order").contains("CHANGED"));

    // Build payload map and check key pieces exist
    Map<String,Object> payload = XmlMerkleDiff.buildPayload(r1, r2, cs);
    assertEquals(MerkleCTree.hex(r1.root), payload.get("rootOld"));
    assertEquals(MerkleCTree.hex(r2.root), payload.get("rootNew"));
    assertTrue(((List<?>)payload.get("added")).isEmpty());
    assertTrue(((List<?>)payload.get("removed")).isEmpty());
    assertEquals(1, ((List<?>)payload.get("changed")).size());
    assertTrue(((List<?>)payload.get("collapsedPaths")).contains("/urn:ex|Order/urn:ex|Item/urn:ex|Qty"));

    Map<?,?> elemSummary = (Map<?,?>) payload.get("tagSummaryElements");
    assertTrue(elemSummary.containsKey("urn:ex|Qty"));
  }

  @Test
  void diff_empty_baseline_marks_all_added() throws Exception {
    String xml1 = ""; // empty baseline
    String xml2 = "<Order xmlns=\"urn:ex\">"
        + "<Item sku=\"B\"><Qty>3</Qty></Item>"
        + "<Item sku=\"A\"><Qty>2</Qty></Item>"
        + "</Order>";

    XmlMerkleDiff.ChangeSet cs = XmlMerkleDiff.diff(xml1, xml2);

    assertTrue(cs.changed.isEmpty());
    assertTrue(cs.removed.isEmpty());
    assertFalse(cs.added.isEmpty()); // everything added

    // Collapsed should include structural ancestors
    Set<String> collapsed = XmlMerkleDiff.collapsedChangedPaths(cs);
    assertTrue(collapsed.contains("/urn:ex|Order"));
    assertTrue(collapsed.contains("/urn:ex|Order/urn:ex|Item"));
    assertTrue(collapsed.contains("/urn:ex|Order/urn:ex|Item/urn:ex|Qty"));

    // Tag summary should show ADDED for Order/Item/Qty and @sku
    XmlMerkleDiff.TagSummary ts = XmlMerkleDiff.summarizeTagChanges(cs);
    assertTrue(ts.elements.getOrDefault("urn:ex|Order", Set.of()).contains("ADDED"));
    assertTrue(ts.elements.getOrDefault("urn:ex|Item", Set.of()).contains("ADDED"));
    assertTrue(ts.elements.getOrDefault("urn:ex|Qty", Set.of()).contains("ADDED"));
    assertTrue(ts.attributes.getOrDefault("@sku", Set.of()).contains("ADDED"));
  }
}
