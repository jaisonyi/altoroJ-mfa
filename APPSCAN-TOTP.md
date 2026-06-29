# Scanning AltoroJ (with MFA/TOTP) using HCL AppScan

This AltoroJ build adds **TOTP multi‑factor authentication** (Google Authenticator
compatible) to the login. That extra step breaks AppScan's normal *recorded*
login on playback — but AppScan can handle it with its built‑in **TOTP / OTP
generation** feature. This document explains why, and exactly how to configure it.

---

## 1. Why a recorded login fails after MFA was added

| | Original AltoroJ | AltoroJ with MFA (this build) |
|---|---|---|
| Login steps | 1 (username + password) | 2 (username + password **+ 6‑digit code**) |
| Are the values static? | Yes | The code **changes every 30 s** |
| Request‑based replay | Resends same creds → **works** | Resends the **old** code → **rejected** |
| AppScan result | Reaches `bank/main.jsp`, sees "Sign Off" | *"No In‑session pattern identified after login playback"* |

The login **records** fine (you can complete it manually, including the code).
It's the **playback** that fails: request‑based playback re‑sends the recorded
one‑time code, which has already expired. This is by design — MFA exists to stop
replayed/automated logins.

### Login flow (the requests AppScan replays)
```
GET  /altoromutual/login.jsp                      200   (sets JSESSIONID)
POST /altoromutual/doLogin     uid=&passw=         302 → /mfa.jsp   (password OK, 2FA pending)
GET  /altoromutual/mfa.jsp                         200   ("Two-Factor Authentication")
POST /altoromutual/doMfaVerify code=<6 digits>     302 → /bank/main.jsp
GET  /altoromutual/bank/main.jsp                   200   ("Hello John Smith" / "Sign Off")
```

Captured proof (run live against this app):

| Scenario | `POST /doMfaVerify` | `/bank/main.jsp` | "Sign Off"? | Result |
|---|---|---|---|---|
| Fresh code (TOTP generated) | `302 → /bank/main.jsp` | `200` | Yes | ✅ logged in |
| Stale code (recorded/replayed) | `302 → /mfa.jsp` | `302 → /login.jsp` | No | ❌ login fails |

The stale‑code row is exactly the AppScan error. The fix is to make AppScan
**generate a fresh code at playback**.

---

## 2. AppScan login configuration

Record the login normally, then enable TOTP generation.

### 2a. Record the login sequence
1. Click **Sign In**
2. Set **`uid`** = username (e.g. `jsmith`)
3. Set **`passw`** = password (e.g. `demo1234`)
4. Submit → page becomes **`mfa.jsp`**
5. Set the **`code`** field (AppScan will fill this with the generated code)
6. Click **Verify** → lands on `bank/main.jsp`
7. In‑session detection pattern: **`Sign Off`**

### 2b. TOTP / OTP settings (Login management → Advanced options)

| Field | Value |
|---|---|
| **Secret Key** | the user's **Base32** secret (see §3) |
| **OTP length** | `6` |
| **Hash algorithm** | `SHA1` |
| **Time step** | `30` (seconds) |
| **HTTP parameter** | `code` |
| Applies to request | `POST /altoromutual/doMfaVerify` |

Keep **Request‑based** playback. AppScan now computes the current code,
substitutes it into `code`, completes `/doMfaVerify`, reaches `bank/main.jsp`,
and detects "Sign Off" → login passes.

> The defaults above (6 digits, SHA1, 30 s) are the standard Google Authenticator
> parameters this app uses.

---

## 3. Where to get the "Secret Key"

The secret is **per user** and is **overwritten whenever the user re‑enrolls**.
There are two ways to obtain the current value.

### Method A — Read it from the database (authoritative)
The secret is stored in **`PEOPLE.TOTP_SECRET`** in the embedded Derby DB at
`~/altoro/altoro`.

```sql
SELECT USER_ID, TOTP_SECRET, MFA_ENABLED FROM PEOPLE;
```

Derby is embedded, so Tomcat holds an exclusive lock. Either:
- **Snapshot (no downtime):** copy `~/altoro/altoro` aside, delete `db.lck` and
  `dbex.lck` in the copy, and query the copy; or
- **Stop Tomcat → query `~/altoro/altoro` → start Tomcat.**

Example using the bundled Derby jar:
```bash
# point classpath at derby-10.8.2.2.jar (from WEB-INF/lib or the Gradle cache)
java -cp derby-10.8.2.2.jar:. ij
# then in ij:
CONNECT 'jdbc:derby:/Users/<you>/altoro/altoro';
SELECT USER_ID, TOTP_SECRET FROM PEOPLE;
```

### Method B — Re‑enroll and copy from the setup page (no DB access)
1. Reset the user's MFA (or use a fresh user).
2. Log in → the **`mfaSetup.jsp`** page shows the QR + the **Base32 "manual entry
   key"**.
3. Copy that key into **both** Google Authenticator **and** AppScan's *Secret Key*.

> ⚠️ Security note: secrets are readable from the DB only because this is a
> deliberately‑vulnerable demo app that stores TOTP secrets in **plaintext**. A
> real app would encrypt them at rest, so Method B (capture at enrollment) would
> be the only option.

---

## 4. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| "No In‑session pattern identified after login playback" | Replaying an expired code (TOTP not configured) | Enable TOTP settings (§2b) |
| Login still fails with TOTP enabled | Secret Key ≠ the user's enrolled secret | Re‑read `PEOPLE.TOTP_SECRET` (§3A) or re‑enroll (§3B) and update Secret Key |
| Worked before, fails now | User was re‑enrolled / DB reinitialized → new secret | Update the Secret Key to the new value |
| Session lost mid‑scan | `/doMfaVerify` needs the `JSESSIONID` from `/doLogin` | Don't strip cookies; keep request‑based playback's cookie handling |

---

## 5. Quick reference
- **Endpoint with the code:** `POST /altoromutual/doMfaVerify`, parameter **`code`**
- **TOTP params:** length **6**, hash **SHA1**, step **30 s**
- **In‑session pattern:** `Sign Off`
- **Secret source:** `PEOPLE.TOTP_SECRET` (DB) or `mfaSetup.jsp` (enrollment)
