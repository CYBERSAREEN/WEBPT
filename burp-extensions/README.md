# Burp extensions: when to use what

| Extension | Use when | Practise on |
|---|---|---|
| Logger++ | evidence, filter by status/length/regex across all tools | meridian (500 vs 401 differential) |
| Active Scan++ | extra passive/active checks on narrowed scope | parcelpoint, meridian |
| JS Miner | secrets/endpoints/interesting strings inside JS in proxy history | harbor (post-login bundles), orbit (hidden internal endpoint string), clouddocs (hidden root param reference) |
| Link Finder | endpoints from JS | harbor, orbit, clouddocs |
| Param Miner | hidden params/headers (feed with arsenal `wordlist.txt`) | clouddocs (`root` param), orbit (rate-limit/debug header guessing) |
| Autorize | access control, role-vs-role replay - log in as officer, browse normally as resident, Autorize replays every request under the officer session and flags where resident already succeeded unaided, or vice versa | northfield (3 endpoints: case detail, user directory, role change - manual one-by-one testing is slow, this is the actual point of the tool) |
| Turbo Intruder | race conditions via single-packet attack (fires a burst of requests with minimal network jitter so they land on the server near-simultaneously) | brewline (concurrent top-ups against the same bonus check) |
| Pentest Coverage Tracker | what you have not tested yet across a multi-endpoint target | northfield, orbit |
| Burp wordlists / SecLists | content discovery, param guessing, OTP/JWT secret wordlists | orbit (debug header name), harbor (HS256 secret) |
| SAML Raider | SAML response/assertion tampering, signature wrapping | not yet built in BreachLab - needs a real SSO flow, ask if you want this added |

## Turbo Intruder quick-start (Brewline)
1. Send the `/api/labs/brewline/topup` request to Turbo Intruder (right-click -> Extensions -> Turbo Intruder -> Send to Turbo Intruder).
2. Use the built-in `race-single-packet-attack.py` template (ships with the extension).
3. Set the request count to ~20-30, leave the body as a fixed valid top-up amount - no payload markers needed, every request is identical.
4. Run, then check the wallet endpoint for `bonusGrants > 1`.

## Autorize quick-start (Northfield)
1. Log in as the **officer** account in one browser tab, grab that session cookie.
2. Extensions -> Autorize -> paste the officer cookie as the "high-privilege" value, enable the extension.
3. Log in as the **resident** account as your normal browsing session.
4. Browse Northfield normally as resident. Autorize silently replays each of your requests using the officer cookie AND reports where the resident's own (unmodified) request already returned data it shouldn't have.
5. Read the Autorize results table for anything marked "Bypassed" - that is: resident got a response as good as officer's, unaided.
