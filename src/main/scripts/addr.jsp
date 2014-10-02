<%@ page import="java.util.Map,java.util.concurrent.ConcurrentSkipListMap" %>
<%
  ConcurrentSkipListMap remoteMap = (ConcurrentSkipListMap) application.getAttribute("REMOTE_MAP");
  if (remoteMap == null) {
    remoteMap = new ConcurrentSkipListMap();
    application.setAttribute("REMOTE_MAP", remoteMap);
  }
  String host = request.getParameter("host");
  if (host != null) {
    host = host.replaceAll("[^0-9A-Za-z_\\-]", "");
    if (!host.isEmpty()) {
      remoteMap.put(host, request.getRemoteAddr());
    }
    return;
  }
  StringBuilder sb = new StringBuilder();
  for (Object o : remoteMap.entrySet()) {
    Map.Entry entry = (Map.Entry) o;
    sb.append(entry.getKey() + ":\"" + entry.getValue() + "\",");
  }
  int len = sb.length();
  out.print("{" + (len == 0 ? sb : sb.substring(0, len - 1)) + "}");
%>