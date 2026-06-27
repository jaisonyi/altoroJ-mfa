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
package com.ibm.security.appscan.altoromutual.servlet;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import com.ibm.security.appscan.Log4AltoroJ;
import com.ibm.security.appscan.altoromutual.util.DBUtil;
import com.ibm.security.appscan.altoromutual.util.ServletUtil;
import com.ibm.security.appscan.altoromutual.util.TotpUtil;

/**
 * Completes first-login MFA enrollment. The candidate secret is generated at
 * login time and held in the session; it is only persisted once the user proves
 * they scanned it by entering a valid code. On success the authenticated session
 * is established.
 * @author AltoroJ
 */
public class MfaSetupServlet extends HttpServlet {
	private static final long serialVersionUID = 1L;

	public MfaSetupServlet() {
		super();
	}

	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		response.sendRedirect(request.getContextPath()+"/mfaSetup.jsp");
	}

	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		HttpSession session = request.getSession(false);

		String enrollUser = (session == null) ? null : (String) session.getAttribute(ServletUtil.SESSION_ATTR_MFA_ENROLL_USER);
		String secret = (session == null) ? null : (String) session.getAttribute(ServletUtil.SESSION_ATTR_MFA_ENROLL_SECRET);

		// No pending enrollment - the user must authenticate with a password first.
		if (enrollUser == null || secret == null){
			response.sendRedirect(request.getContextPath()+"/login.jsp");
			return;
		}

		String code = request.getParameter("code");

		try {
			if (TotpUtil.verifyCode(secret, code)){
				// Confirmed: persist the secret and mark the account MFA-enabled.
				DBUtil.setTotpSecret(enrollUser, secret);
				DBUtil.setMfaEnabled(enrollUser, true);

				session.removeAttribute(ServletUtil.SESSION_ATTR_MFA_ENROLL_USER);
				session.removeAttribute(ServletUtil.SESSION_ATTR_MFA_ENROLL_SECRET);
				session.removeAttribute(ServletUtil.SESSION_ATTR_MFA_ERROR);

				Log4AltoroJ.getInstance().logInfo("MFA enrollment completed >>> User: " + enrollUser);

				Cookie accountCookie = ServletUtil.establishSession(enrollUser, session);
				response.addCookie(accountCookie);
				response.sendRedirect(request.getContextPath()+"/bank/main.jsp");
				return;
			}

			session.setAttribute(ServletUtil.SESSION_ATTR_MFA_ERROR, "Invalid verification code. Scan the QR code and enter the current 6-digit code.");
			response.sendRedirect(request.getContextPath()+"/mfaSetup.jsp");
		} catch (Exception ex) {
			ex.printStackTrace();
			response.sendError(500);
		}
	}
}
