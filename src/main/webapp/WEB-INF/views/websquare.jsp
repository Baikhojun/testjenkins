<%@ page contentType="text/html;charset=UTF-8" language="java" isELIgnored="true" %>
<%@ page language="java" import="java.net.InetAddress" %>
<%
InetAddress inet= InetAddress.getLocalHost();
%>
<%
	String w2xPath = request.getParameter("w2xPath");
	if(w2xPath == null) response.sendRedirect("/?w2xPath=/ui/sample_crud.xml");
%>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns='http://www.w3.org/1999/xhtml' xmlns:ev='http://www.w3.org/2001/xml-events' xmlns:w2='http://www.inswave.com/websquare' xmlns:xf='http://www.w3.org/2002/xforms'>
	<head>
		<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
		<meta http-equiv="X-UA-Compatible" content="IE=Edge" />
		<link rel="shortcut icon" type="image⁄x-icon" href="/assets/images/contents/Demo_campus.ico">
		<title>YERP (<%=inet.getHostAddress().substring(inet.getHostAddress().lastIndexOf(".")+1) %>)</title>
		<script type="text/javascript" src="/websquare/javascript.wq?q=/bootloader"></script>
		<script type="text/javascript">
			window.onload = init;
			function init() {
				try{
					WebSquare.startApplication();
				} catch(e) {
					alert(e.message);
				}
			}
		</script>
	</head>
<body></body>
</html>