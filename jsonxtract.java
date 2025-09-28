String j1 = "{ \"order\": {\"id\":\"ORD-8\"}, \"items\":[{\"sku\":\"A\",\"type\":\"retail\",\"qty\":2},{\"sku\":\"B\",\"type\":\"wholesale\",\"qty\":1}] }";
String j2 = "{ \"order\": {\"id\":\"ORD-9\"}, \"items\":[{\"sku\":\"B\",\"type\":\"wholesale\",\"qty\":3},{\"sku\":\"A\",\"type\":\"retail\",\"qty\":2}], \"extra\":42 }";

JsonMerkleDiff.ChangeSet jcs = JsonMerkleDiff.diff(j1, j2);

// configure extraction (simple dot paths)
JsonMerkleDiff.JsonExtractConfig jcfg = new JsonMerkleDiff.JsonExtractConfig();
jcfg.idPath = "$.order.id";
jcfg.typesArrayPath = "$.items";    // array of objects
jcfg.typesValueField = "type";      // extract this field from each
JsonMerkleDiff.JsonExtractConfig.KeyMapConfig jkm = new JsonMerkleDiff.JsonExtractConfig.KeyMapConfig();
jkm.entryArrayPath = "$.items";
jkm.keyField = "sku";
jkm.valueField = "qty";
jcfg.keyMap = jkm;

Map<String,Object> jSummary = JsonMerkleDiff.buildChangeSummary(jcs, true, j2, jcfg);
System.out.println(new com.fasterxml.jackson.databind.ObjectMapper()
  .writerWithDefaultPrettyPrinter().writeValueAsString(jSummary));
