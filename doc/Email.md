---
Date: 2017-06-21
Understanding: Intermediate
---

How is Email Delivered?
=======================

## Modern Email Security

Email security has evolved over time to detect spam and spoofed email
addresses. There are several technologies involved in modern email security,
in chronological order:

1. [SPF](http://www.openspf.org/Introduction)
-- Sender Policy Framework

This framework allows a domain owner to specify a list of domains that are
allowed to send mail as the domain name.

This list is specified in the DNS of the domain (TXT or SPF record) along with
the recommended result for domains that are not in the list. The recipient's
mail server will query the mailer domain's SPF record and compare it to the IP
address that the email was mailed from. If the IP is not in the SPF record, the
email is more likely to be spam or a phishing attempt.

SPF example using Gmail:
```
$ dig -t TXT gmail.com
;; ANSWER SECTION:
gmail.com.              299     IN      TXT     "v=spf1 redirect=_spf.google.com" # Check SPF of redirect.
$ dig -t TXT _spf.google.com
;; ANSWER SECTION:
_spf.google.com.        299     IN      TXT     "v=spf1 include:_netblocks.google.com include:_netblocks2.google.com include:_netblocks3.google.com ~all"
```

At the end, `~all` specifies that emails sent as gmail.com but not originating
from one of Google's netblocks IP addresses should SOFTFAIL (spam).

Criticisms of SPF include breakage of email forwarding services. For example,
if charlie@example.com sent mail to a forwarding service, it gets forwarded to
the destination mailbox. Unfortunately, the destination domain will now check
the SPF record of the return path (example.com) and see that this email fails
the SPF check because the email came from the forwarding service!

To mitigate this problem, the mail forwarding service can, instead of
forwarding, *remail* the email instead. [Sender Rewriting Scheme
(SRS)](http://www.openspf.org/SRS) allows a mail forwarding service to rewrite
the return path on an email to indicate that the mailer is now the mail
forwarding domain. This rewrite allows the destination domain to check the SPF
record for the mail forwarding service instead of the original domain that the
email was sent from. Because the SPF checking point has now changed, the mail
forwarding service may perform its own SPF check and write the result into the
message headers.

As a consequence of SRS, mail received may indicate that it was forwarded. For
example, Gmail will show *via forwarder.tld* on incoming mail from a forwarding
service with SRS.

Without SRS, forwarding services risk having their senders' emails labeled as
spam or rejected, especially if the receiver's mail service checks SPF of
incoming mail *and* does not whitelist forwarding services that do not
implement SRS.

2. [DKIM](http://www.dkim.org/#introduction)
-- DomainKeys Identifed Mail

DKIM is used to sign an email that is sent from a domain.

The domain owner generates a public/private key pair and attaches the public
key to the domain's DNS. Email originating from that domain has parts of its
headers (and/or body, but only headers for simplicity) hashed and attached as a
digital signature in the message. The DKIM check at a destination domain will
check the sender's DNS for the public key and validate the digitial signature,
showing that the email was sent from that domain and was not changed during
transit. Note that mail forwarding services no longer are affected as the
sender's public key is checked, not the originating IP of the email.

DKIM example using Gmail:
```
$# Message header snippet of mail received from a Gmail user:
$# X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
$#         d=1e100.net; s=20161025;
$#           ^^^^^^^^^    ^^^^^^^^
$
$ dig -t TXT 20161025._domainkey.1e100.net # Get DKIM public key from this DNS record.
;; ANSWER SECTION:
20161025._domainkey.1e100.net. 86399 IN TXT     "k=rsa\; p=MIIBIjAN<...>uQIDAQAB"
```

DKIM provides authentication, but does not necessarily prevent abuse. The [DKIM
RFC lists numerous security
considerations](https://tools.ietf.org/html/rfc6376#section-8) including replay
attacks whereby a malicious user reuses/spams a maliciously crafted message
with a valid signature.

DKIM is also harder to implement, therefore many mail providers may not offer
DKIM signing yet or may transmit signed messages incorrectly.

>  Survivability of signatures after transit is not guaranteed, and
>  signatures can fail to verify through no fault of the Signer.
>  Therefore, a Verifier SHOULD NOT treat a message that has one or more
>  bad signatures and no good signatures differently from a message with
>  no signature at all.

The weaknesses of SPF and DKIM are somewhat alleviated with DMARC policies.

3. [DMARC](https://dmarc.org/overview/)
-- Domain-based Message Authentication, Reporting & Conformance

DMARC allows domain owners to specify policies for emails that fail both SPF
and DKIM checks. Emails that fail both checks may be acted upon if DMARC policy
specifies quarantine or reject.

DMARC example for Google (Gmail may have a different DMARC policy):
```
$ dig -t TXT _dmarc.google.com
;; ANSWER SECTION:
_dmarc.google.com.      299     IN      TXT     "v=DMARC1\; p=reject\; rua=mailto:mailauth-reports@google.com"
```

Google (@google.com) specifies emails not originating from domains allowed by
the SPF records *and* not signed or fail the DKIM key check should be rejected
per its DMARC policy. If either SPF or DKIM checks pass, DMARC can still fail
due to sender-validation alignment whereby the domain or subdomain of the
sender address must match the checked SPF and/or DKIM domain. This alignment
adds stricter validation for sender addresses and was missing in SPF and DKIM.
Reject policies force strict routing for emails from that domain.

DMARC also includes feedback to the sender domain for reports and monitoring.

4. [ARC](http://arc-spec.org/)
-- Authenticated Received Chain

Currently in draft standardization and preliminary testing by the IETF DMARC
working group, ARC adds additional headers for email authentication. As email
is routed, the previous authentication methods (SPF and DKIM) may fail as
headers or body text are modified. ARC offers an opportunity at the destination
to validate a message should that message be otherwise labeled as spam or
rejected.

At each delivery point during routing, the security features on a message (SPF,
DKIM, DMARC) are checked and attached to an authentication-results header on
the message. The server then takes a signed snapshot of some of the header
fields and creates a message-signature header with it. The authentication
results and message signature are signed with a DKIM-like signature into an ARC
"seal" that certifies these ARC results for that point in the route. The intent
is to allow multiple monotonically-increasing-indexed ARC headers in a message,
and as long as one or more seals can be validated, the destination has an
educated guess as to the origin and route of a message and can decide whether
the origin is authentic.


## Routing Email

The following scenarios show how email is routed, with specificity to Gmail.

Mailboxes (mail storage)
- alice@gmail.com
- bob@gmail.com

SMTP servers (outgoing mail)
- smtp.gmail.com
- smtp.example.com

Mail Forwarding Services
- forwarder.tld (implements SRS)


### Disclaimer

Some of this analysis is possibly flawed due to implementation-defined behavior.
Scenarios were tested when possible. Scenarios focus on Gmail because, while
testing, its message sources were subjectively easier to read. Corrections are
welcomed!


### Receiver gets mail directly from a mailbox.

1. Baseline: alice@gmail.com through smtp.gmail.com to bob@gmail.com
```
Route: sender as gmail.com --> smtp.gmail.com
                                 --> server specified in MX record for gmail.com
                                       --> receiver

Result: OK (SPF PASS, DKIM PASS, DMARC PASS)
        Gmail receiver observes "From: alice@gmail.com"
```


2. alice@gmail.com through smtp.example.com to bob@gmail.com
```
Route: sender as gmail.com --> smtp.example.com --> MX:gmail.com --> receiver
                                                    ^^^^^^^^^^^^
                                                    SPF and DKIM results
                                                    depend on configuration
                                                    of example.com
                                                    DMARC FAIL for gmail.com

Result: Delivery depends on configuration and reputation of example.com
        Gmail receiver observes "From: alice@gmail.com via example.com"
        (if not rejected).
```
If the sender domain is not of the same domain as the outgoing SMTP server, the
outgoing SMTP server will use a `Return-Path` email address of your account on
the SMTP server so the SPF check at the destination does not fail. The SMTP
server may also decide to sign the message with DKIM keys, which will also be
checked at the receiver.

In this scenario, sending as alice@gmail.com from Microsoft outlook.com will
yield these results:
```
SPF:    PASS with IP 40.92.5.12
DKIM:   PASS with domain outlook.com
DMARC:  FAIL

Authentication-Results: mx.google.com;
       dkim=pass header.i=@outlook.com header.b=<message signature's signed hash>;
       spf=pass (google.com: domain of alice@outlook.com designates 40.92.5.12 as permitted sender) smtp.mailfrom=alice@outlook.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=gmail.com
Return-Path: alice@outlook.com
From: alice@gmail.com
```


3. alice@gmail.com (as alice@example.com) through smtp.gmail.com to bob@gmail.com
```
Route: sender as example.com --> smtp.gmail.com --> MX:gmail.com --> receiver
                                                    ^^^^^^^^^^^^
                                                    SPF PASS for gmail.com,
                                                    DKIM not added?

Result: OK
        Gmail receiver observes "From: alice@example.com via gmail.com".
```
This scenario is representative of sending mail as a non-Gmail domain through
Gmail's SMTP server. Note: G Suite users have a mailbox with a custom domain
instead of gmail.com; scenario #1 applies for G Suite users.

In order for emails originating from gmail.com to pass SPF checks at the
destination, outgoing SMTP servers (including gmail.com) will use an account on
that domain (alice@gmail.com) for the `Return-Path` email address. The sender's
desired email address is represented in the `From` header.

Interesting, Gmail SMTP does not DKIM sign outgoing messages if the sender is
not of gmail.com. Microsoft outlook.com SMTP, however, does sign (scenario #2).
Multiple DKIM signatures can be added to the same email (i.e., remailed
via multiple forwarding services), so this behavior for Gmail is perplexing.


4. alice@gmail.com (as alice@example.com) through smtp.example.com to bob@gmail.com
```
Route: sender as example.com --> smtp.example.com --> MX:gmail.com --> receiver
                                                      ^^^^^^^^^^^^
                                                      SPF, DKIM, DMARC results
                                                      depend on configuration
                                                      of example.com

Result: OK
        Gmail receiver observes "From: alice@example.com"
```


### Receiver gets mail from a forwarding address.

Email from a remailer (forwarding service using SRS) will appear in Gmail with
*via forwarder.tld*.

**Hypothesis**: The *via forwarder.tld* label is omitted if the email was DKIM
signed at the sender and sender address is a whitelisted domain (scenario #5,
sender as gmail.com). This behavior may also be related to ARC. This hypothesis
affects scenarios #6 and #8.


5. alice@gmail.com through smtp.gmail.com
    to bob@forwarder.tld forwarded to bob@gmail.com
```
Route: sender as gmail.com
       --> smtp.gmail.com --> MX:forwarder.tld --> MX:gmail.com --> receiver
                              ^^^^^^^^^^^^^^^^     ^^^^^^^^^^^^
                              Return-Path:              |
                                alice@gmail.com         |
                              /                    Return-Path:
  SPF PASS for gmail.com ----+                       SRS0+<hash>=<timestamp>=gmail.com=alice@forwarder.tld
  DKIM PASS for gmail.com
  DMARC PASS for gmail.com                         SPF check depends on
                                                   configuration of forwarder.tld

                                                   DKIM PASS for gmail.com
                                                   DMARC PASS for gmail.com

Result: OK
        Gmail receiver observes "From: alice@gmail.com"
```


6. alice@gmail.com through smtp.example.com
    to bob@forwarder.tld forwarded to bob@gmail.com
```
Route: sender as gmail.com
       --> smtp.example.com --> MX:forwarder.tld --> MX:gmail.com --> receiver
                                ^^^^^^^^^^^^^^^^     ^^^^^^^^^^^^
                                Return-Path:              |
                                  alice@example.com       |
                                /                    Return-Path:
                 SPF check ----+                       SRS0+<hash>=<timestamp>=example.com=alice@forwarder.tld
                 depends on example.com
                                                     SPF check depends on forwarder.tld
                                                     DKIM check depends on example.com
                                                     DMARC FAIL for gmail.com

Result: Delivery depends on configuration and reputation of example.com and forwarder.tld
        Gmail receiver observes one of two cases (if not rejected):
        - "From: alice@gmail.com via example.com" if example.com has DKIM and DKIM check passes
        - "From: alice@gmail.com via forwarder.tld" otherwise
```


7. alice@gmail.com (as alice@example.com) through smtp.gmail.com
    to bob@forwarder.tld forwarded to bob@gmail.com
```
Route: sender as example.com
       --> smtp.gmail.com --> MX:forwarder.tld --> MX:gmail.com --> receiver
                              ^^^^^^^^^^^^^^^^     ^^^^^^^^^^^^
                              Return-Path:               |
                                alice@gmail.com          |
                              /                    Return-Path:
  SPF PASS for gmail.com ----+                       SRS0+<hash>=<timestamp>=gmail.com=alice@forwarder.tld

                                                   SPF check depends on forwarder.tld

Result: OK
        Gmail receiver observes "From: alice@example.com via forwarder.tld"
```
Currently, Gmail does not DKIM sign outgoing messages for a `From` address that
is not @gmail.com.


8. alice@gmail.com (as alice@example.com) through smtp.example.com
    to bob@forwarder.tld forwarded to bob@gmail.com
```
Route: sender as example.com
       --> smtp.example.com --> MX:forwarder.tld --> MX:gmail.com --> receiver
                                ^^^^^^^^^^^^^^^^     ^^^^^^^^^^^^
                                Return-Path:               |
                                  alice@example.com        |
                                /                    Return-Path:
    SPF, DKIM, DMARC check ----+                       SRS0+<hash>=<timestamp>=example.com=alice@forwarder.tld
    depends on example.com
                                                     SPF depends on forwarder.tld

                                                     DKIM, DMARC check
                                                     depends on example.com

Result: OK
        Gmail receiver observes one of two cases (if not rejected):
        - "From: alice@example.com" if example.com has DKIM and DKIM check passes
        - "From: alice@example.com via forwarder.tld" otherwise
```


Conclusions
===========
The email security frameworks outlined--SPF, DKIM, and DMARC--are
deterministically evaluated at the destination mail server; however, what that
mail service chooses to do with those results depend on the DMARC policy of the
sender's domain and, importantly, on the *reputation* of the sender's domain
and the route it took to get to the receiver. Reputation heuristics make these
scenarios' routing analysis murky; this analysis may be too strict since the
reputation of a domain may allow mail to pass through despite failed results
for some of these checks.

Domains that are frequently targeted for spoofing/phishing attempts will
typically specify all three frameworks and use a DMARC reject policy.
Check the message source on emails from your financial providers.
