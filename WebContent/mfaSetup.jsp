<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
    pageEncoding="ISO-8859-1"
    import="com.ibm.security.appscan.altoromutual.util.ServletUtil"
    import="com.ibm.security.appscan.altoromutual.util.TotpUtil"%>

<%
/**
 This application is for demonstration use only. It contains known application security
vulnerabilities that were created expressly for demonstrating the functionality of
application security testing tools. These vulnerabilities may present risks to the
technical environment in which the application is installed. You must delete and
uninstall this demonstration application upon completion of the demonstration for
which it is intended.

IBM DISCLAIMS ALL LIABILITY OF ANY KIND RESULTING FROM YOUR USE OF THE APPLICATION
OR YOUR FAILURE TO DELETE THE APPLICATION FROM YOUR ENVIRONMENT UPON COMPLETION OF
A DEMONSTRATION. IT IS YOUR RESPONSIBILITY TO DETERMINE IF THE PROGRAM IS APPROPRIATE
OR SAFE FOR YOUR TECHNICAL ENVIRONMENT. NEVER INSTALL THE APPLICATION IN A PRODUCTION
ENVIRONMENT. YOU ACKNOWLEDGE AND ACCEPT ALL RISKS ASSOCIATED WITH THE USE OF THE APPLICATION.

IBM AltoroJ
(c) Copyright IBM Corp. 2008, 2013 All Rights Reserved.
*/
%>

<%
	String enrollUser = (String) session.getAttribute(ServletUtil.SESSION_ATTR_MFA_ENROLL_USER);
	String enrollSecret = (String) session.getAttribute(ServletUtil.SESSION_ATTR_MFA_ENROLL_SECRET);

	// Self-guard: this page is meaningless without a pending enrollment.
	if (enrollUser == null || enrollSecret == null){
		response.sendRedirect(request.getContextPath()+"/login.jsp");
		return;
	}

	String otpAuthUri = TotpUtil.buildOtpAuthUri(enrollUser, enrollSecret);
%>

<jsp:include page="header.jspf"/>

<div id="wrapper" style="width: 99%;">
	<jsp:include page="/toc.jspf"/>
   <td valign="top" colspan="3" class="bb">
		<div class="fl" style="width: 99%;">

		<h1>Set Up Two-Factor Authentication</h1>

		<p><span id="_ctl0__ctl0_Content_Main_message" style="color:#FF0066;font-size:12pt;font-weight:bold;">
		<%
		String error = (String)session.getAttribute(ServletUtil.SESSION_ATTR_MFA_ERROR);
		if (error != null && error.trim().length() > 0){
			session.removeAttribute(ServletUtil.SESSION_ATTR_MFA_ERROR);
			out.print(error);
		}
		%>
		</span></p>

		<p>To protect your account, scan the QR code below with Google Authenticator
		(or any compatible TOTP app), then enter the current 6-digit code to finish.</p>

		<div id="qrcode" style="margin: 10px 0;"></div>
		<input type="hidden" id="otpauth" value="<%= otpAuthUri %>"/>

		<p>Can't scan? Enter this key manually:<br/>
		<code style="font-size:14pt;"><%= enrollSecret %></code></p>

		<form action="doMfaSetup" method="post" name="mfaSetup" id="mfaSetup">
		  <table>
		    <tr>
		      <td>Verification code:</td>
		      <td>
		        <input type="text" id="code" name="code" value="" maxlength="6" autocomplete="off" style="width: 150px;">
		      </td>
		    </tr>
		    <tr>
		        <td></td>
		        <td>
		          <input type="submit" name="btnSubmit" value="Verify &amp; Enable">
		        </td>
		      </tr>
		  </table>
		</form>

		</div>

		<script type="text/javascript" src="js/qrcode.min.js"></script>
		<script type="text/javascript">
			(function(){
				var uri = document.getElementById("otpauth").value;
				new QRCode(document.getElementById("qrcode"), {
					text: uri,
					width: 200,
					height: 200
				});
				document.getElementById("code").focus();
			})();
		</script>
    </td>
</div>

<jsp:include page="footer.jspf"/>
