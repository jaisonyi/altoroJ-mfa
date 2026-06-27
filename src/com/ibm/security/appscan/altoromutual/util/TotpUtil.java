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

package com.ibm.security.appscan.altoromutual.util;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;

import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorConfig;
import com.warrenstrange.googleauth.GoogleAuthenticatorConfig.GoogleAuthenticatorConfigBuilder;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;

/**
 * Utility class for TOTP (Time-based One-Time Password, RFC 6238) multi-factor
 * authentication compatible with Google Authenticator and similar apps.
 */
public class TotpUtil {

	/** Label shown for the account inside the authenticator app. */
	private static final String ISSUER = "AltoroJ";

	private static final GoogleAuthenticator AUTHENTICATOR;
	static {
		// A window size of 3 accepts the current 30-second code plus the
		// immediately preceding and following one, tolerating modest clock skew
		// between the server and the user's device.
		GoogleAuthenticatorConfig config = new GoogleAuthenticatorConfigBuilder()
				.setWindowSize(3)
				.build();
		AUTHENTICATOR = new GoogleAuthenticator(config);
	}

	private TotpUtil(){
	}

	/**
	 * Generate a new random shared secret to be enrolled in an authenticator app.
	 * @return a Base32-encoded secret
	 */
	public static String generateSecret(){
		GoogleAuthenticatorKey key = AUTHENTICATOR.createCredentials();
		return key.getKey();
	}

	/**
	 * Verify a user-supplied 6-digit code against the stored secret.
	 * @param secret the Base32-encoded shared secret
	 * @param code the code entered by the user (whitespace is ignored)
	 * @return true if the code is valid for the current time window
	 */
	public static boolean verifyCode(String secret, String code){
		if (secret == null || code == null)
			return false;

		code = code.replaceAll("\\s", "");
		if (!code.matches("\\d{6}"))
			return false;

		try {
			return AUTHENTICATOR.authorize(secret, Integer.parseInt(code));
		} catch (NumberFormatException e) {
			return false;
		}
	}

	/**
	 * Build the {@code otpauth://totp/...} URI that an authenticator app reads
	 * (typically rendered as a QR code) to enroll the secret. Constructed
	 * directly to avoid pulling in the QR generator's HTTP-client dependency;
	 * the defaults assumed by authenticator apps (SHA1, 6 digits, 30s period)
	 * match this server's verification settings.
	 * @param username the account name shown in the authenticator app
	 * @param secret the Base32-encoded shared secret
	 * @return the otpauth provisioning URI
	 */
	public static String buildOtpAuthUri(String username, String secret){
		String label = ISSUER + ":" + username;
		return "otpauth://totp/" + encode(label) + "?secret=" + secret + "&issuer=" + encode(ISSUER);
	}

	private static String encode(String value){
		try {
			// otpauth path/query components use percent-encoding with %20 for spaces.
			return URLEncoder.encode(value, "UTF-8").replace("+", "%20");
		} catch (UnsupportedEncodingException e) {
			return value;
		}
	}
}
