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
 * Second factor of the login flow for users who have already enrolled in MFA.
 * Verifies the TOTP code against the user's stored secret and, only on success,
 * establishes the authenticated session.
 * @author AltoroJ
 */
public class MfaVerifyServlet extends HttpServlet {
	private static final long serialVersionUID = 1L;

	public MfaVerifyServlet() {
		super();
	}

	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		response.sendRedirect(request.getContextPath()+"/mfa.jsp");
	}

	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		HttpSession session = request.getSession(false);

		String pendingUser = (session == null) ? null : (String) session.getAttribute(ServletUtil.SESSION_ATTR_MFA_PENDING_USER);

		// No pending verification - the user must authenticate with a password first.
		if (pendingUser == null){
			response.sendRedirect(request.getContextPath()+"/login.jsp");
			return;
		}

		// Enforce a per-session attempt limit to slow down code guessing.
		Integer attempts = (Integer) session.getAttribute(ServletUtil.SESSION_ATTR_MFA_ATTEMPTS);
		if (attempts == null)
			attempts = Integer.valueOf(0);

		if (attempts.intValue() >= ServletUtil.MFA_MAX_ATTEMPTS){
			Log4AltoroJ.getInstance().logError("MFA verification locked out >>> User: " + pendingUser);
			session.removeAttribute(ServletUtil.SESSION_ATTR_MFA_PENDING_USER);
			session.removeAttribute(ServletUtil.SESSION_ATTR_MFA_ATTEMPTS);
			session.setAttribute("loginError", "Too many incorrect verification codes. Please log in again.");
			response.sendRedirect(request.getContextPath()+"/login.jsp");
			return;
		}

		String code = request.getParameter("code");

		try {
			String secret = DBUtil.getTotpSecret(pendingUser);

			if (secret != null && TotpUtil.verifyCode(secret, code)){
				// Second factor satisfied - now establish the authenticated session.
				session.removeAttribute(ServletUtil.SESSION_ATTR_MFA_PENDING_USER);
				session.removeAttribute(ServletUtil.SESSION_ATTR_MFA_ATTEMPTS);
				session.removeAttribute(ServletUtil.SESSION_ATTR_MFA_ERROR);

				Cookie accountCookie = ServletUtil.establishSession(pendingUser, session);
				response.addCookie(accountCookie);
				response.sendRedirect(request.getContextPath()+"/bank/main.jsp");
				return;
			}

			session.setAttribute(ServletUtil.SESSION_ATTR_MFA_ATTEMPTS, Integer.valueOf(attempts.intValue() + 1));
			session.setAttribute(ServletUtil.SESSION_ATTR_MFA_ERROR, "Invalid verification code. Please try again.");
			Log4AltoroJ.getInstance().logError("MFA verification failed >>> User: " + pendingUser);
			response.sendRedirect(request.getContextPath()+"/mfa.jsp");
		} catch (Exception ex) {
			ex.printStackTrace();
			response.sendError(500);
		}
	}
}
