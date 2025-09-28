String xmlOld = "<Order xmlns=\"urn:ex\"><Item sku=\"A\" type=\"retail\"><Qty>2</Qty></Item><Item sku=\"B\" type=\"wholesale\"><Qty>1</Qty></Item></Order>";
String xmlNew = "<ex:Order xmlns:ex=\"urn:ex\" id=\"ORD-9\"><ex:Item sku=\"B\" type=\"wholesale\"><ex:Qty>3</ex:Qty></ex:Item><ex:Item sku=\"A\" type=\"retail\"><ex:Qty>2</ex:Qty></ex:Item></ex:Order>";

XmlMerkleDiff.ChangeSet xcs = XmlMerkleDiff.diff(xmlOld, xmlNew);

XmlMerkleDiff.XPathExtractConfig xcfg = new XmlMerkleDiff.XPathExtractConfig();
xcfg.idXPath = "string(/ex:Order/@id)";
xcfg.typesXPath = "//ex:Item/@type";
XmlMerkleDiff.XPathExtractConfig.KeyMapConfig km = new XmlMerkleDiff.XPathExtractConfig.KeyMapConfig();
km.entryXPath = "//ex:Item";
km.keyExpr = "string(@sku)";
km.valueExpr = "string(ex:Qty)";
xcfg.keyMap = km;
xcfg.nsContext = new javax.xml.namespace.NamespaceContext() {
  public String getNamespaceURI(String p){ return "ex".equals(p) ? "urn:ex" : null; }
  public String getPrefix(String u){ return "urn:ex".equals(u) ? "ex" : null; }
  public java.util.Iterator getPrefixes(String u){ return java.util.Collections.singleton("ex").iterator(); }
};

Map<String,Object> xSummary = XmlMerkleDiff.buildChangeSummary(xcs, true, xmlNew, xcfg);
System.out.println(new com.fasterxml.jackson.databind.ObjectMapper()
  .writerWithDefaultPrettyPrinter().writeValueAsString(xSummary));
