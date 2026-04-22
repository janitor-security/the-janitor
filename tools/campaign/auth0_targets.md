Auth0 targets:
```Tier 1 Targets
In scope
Payment reward chart
P1
$10000 – $50000
P2
$4000 – $10000
P3
$1000 – $4000
P4
$100 – $1000
Name / Location	Tags	Known issues
config.cic-bug-bounty.auth0app.com	
Website Testing
manage.cic-bug-bounty.auth0app.com (Management Dashboard)
https://manage.cic-bug-bounty.auth0app.com/
ReactJS
Website Testing
*.cic-bug-bounty.auth0app.com	
Website Testing
Auth0 Guardian Android
https://play.google.com/store/apps/details?id=com.auth0.guardian&hl=en_US&gl=US
Java
Mobile Application Testing
Kotlin
+1
Auth0 Guardian IoS
https://apps.apple.com/us/app/auth0-guardian/id1093447833
Objective-C
SwiftUI
Swift
+2
marketplace.auth0.com (Auth0 Marketplace)
https://marketplace.auth0.com
Website Testing
HTTP
MFA Integrations	
https://dashboard.fga.dev/
https://dashboard.fga.dev/
.NET
Go
Website Testing
+2
https://api.us1.fga.dev/
https://api.us1.fga.dev/
API Testing
.NET
HTTP
+1
https://customers.us1.fga.dev/
https://customers.us1.fga.dev/
API Testing
.NET
Go
+2
https://play.fga.dev/
https://play.fga.dev/
.NET
Go
Website Testing
+2
```

```SDK Targets
In scope
Payment reward chart
P1
$5000 – $15000
P2
$2000 – $5000
P3
$500 – $2000
P4
$100 – $500
Name / Location	Tags	Known issues
Auth0 SDK for Web (Auth0.js)
https://github.com/auth0/auth0.js
Lock for Web (lock)
https://github.com/auth0/lock
Auth0 Single Page App SDK (auth0-spa-js)
https://github.com/auth0/auth0-spa-js
.NET SDK (Auth0.Net)
https://github.com/auth0/Auth0.Net
Auth0 Next.js SDK (nextjs-auth0)
https://github.com/auth0/nextjs-auth0
Auth0 Java SDK (auth0-java)
https://github.com/auth0/auth0-java
Auth0 React Native SDK (react-native-auth0)
https://github.com/auth0/react-native-auth0
Auth0 PHP SDK (auth0-php)
https://github.com/auth0/auth0-php
```

```Tier 2 Targets
In scope
Payment reward chart
P1
$5000 – $15000
P2
$2000 – $5000
P3
$500 – $2000
P4
$100 – $500
Name / Location	Tags	Known issues
auth0.com	
ReactJS
Website Testing
NodeJS
samltool.io	
Handlebars
jQuery
YUI
+1
webauthn.me	
jQuery
Website Testing
ExpressJS
+1
openidconnect.net	
ReactJS
jQuery
Lodash
+1
jwt.io	
jQuery
Lodash
Website Testing
+2
auth0.net	
Website Testing
```

The following should NOT be investigated:
```Out of scope targets
Out of scope
Name / Location	Tags	Known issues
auth0.auth0.com	
Website Testing
manage.auth0.com	
Website Testing
accounts.auth0.com	
Website Testing
webtask.io	
Website Testing
phenix.rocks	
Website Testing
Auth0 Docs (including quickstarts)	
Website Testing
sharelock.io	
Website Testing
goextend.io	
Website Testing
https://support.auth0.com/tickets/new	
support.auth0.com	
community.auth0.com	
Auth0 passport-ws-fed
https://github.com/auth0/passport-wsfed-saml2
```

The context of the specific Autho0 page:
```
Auth0 Bonus
Date: April 9th 12:00 AM PST - May 9th 11:59 PM PST

Scope:

Auth0 Brand Customization- Emails
Valid submissions include, but are not limited to, cross-tenant access of email templates, reading or modifying sensitive server-side files via email template customizations, any privilege escalation in viewing and editing email templates, and bypassing the escaping functions of the template language (Liquid) to execute code either on the Auth0 server or against another user. Please note that any file access or code execution exclusively within a testing sandbox would not qualify.
Please reference the documentation for setting up email customization https://auth0.com/docs/customize/email and https://auth0.com/docs/api/management/v2/email-templates/post-email-templates. Email testing can be done via https://auth0.com/docs/customize/email/email-templates/customize-email-templates#test-updated-templates. An external SMTP server should be configured to access the email template customization.
Auth0 Enteprise Connections
Auth0 provides Enterprise connections to authenticate users in an external, federated identity provider (IdP). For the enterprise connections authentication bypass, valid submissions must involve one of the Enterprise connector identity providers (see https://auth0.com/docs/authenticate/identity-providers/enterprise-identity-providers for more details).
Bonus Multiplier

P1: 3x
P2: 2x
P3: 1.5x
P4: 1x (no multiplier)
Note
Note that submissions that rely on intentionally insecure implementations that do not follow Auth0 documented instructions and best practices will not be accepted.

Only submissions submitted after April 9th, 2026, at 12:00 AM PST, will be eligible for the bonus and multiplier. NO EXCEPTIONS!

Please note: All eligible reports will be awarded based on triaged severity and impact. Each submission will be reviewed individually to determine its eligibility for a bonus. Per our standard terms of agreement, all eligibility and bonus determinations are made at the sole discretion of Okta and are not subject to negotiation.

AI-generated content
We do not accept reports that contain low-effort or AI-generated content. Submissions must demonstrate original analysis, clear understanding of the issue, and actionable detail. Reports lacking meaningful human input will be rejected. Repeat offenders will be removed from the program.

Researcher Environment
https://manage.cic-bug-bounty.auth0app.com was created solely for researcher testing. Testing any other Auth0 environment is strictly out of scope.

How to Access Researcher Environment
At the bottom of the program page click on "Get Credentials". You will be provided the email address & password to your account.
Access your tenant by navigating to: https://manage.cic-bug-bounty.auth0app.com/

Tenant Members
You will be assigned 3 sets of credentials giving you access to 3 users and 3 tenants.
If you are utilizing Tenant 1, you can invite User 2 & User 3 to Tenant 1 as Tenant Members and set their permissions. You will use the credentials for User 2 & User 3 to access their own tenants, as well as, Tenant 1.

Out-of-scope Submissions
We have created a researcher environment and are providing all researchers a tenant and user which you can retrieve at the bottom of the program page by clicking "Get Credentials.

Any submissions on auth0.auth0.com & manage.auth0.com will be immediately marked out of scope.

Automated Scanning Tools, DoS Attempts, etc.
Any use of automated scanning tools, DoS attempts, etc. will result in an immediate ban from the program. If you are using Burp Intruder, do not exceed more than 5 requests per second.

Researcher Personal Data & Researcher Tenant Deprovisioning
Do not use tenants created through the bug bounty program for personal use. Do not populate fields with your personal information. Researcher tenants may be deleted at any time. We reserve all rights to delete inactive tenants, data, or malicious behavior that is deemed disruptive to our infrastructure and/or products in this space.

Rewards
Eligible reports will be awarded based on severity, to be determined by Okta/Auth0 in its sole discretion.

For payout ranges, refer to the In-Scope targets above.

Keep in mind that no two bugs are created equal. These payouts define general guidelines. The Okta/Auth0 Product Security team will determine the nature and impact of the bugs to identify the appropriate payouts around these guidelines. Awards are granted entirely at the discretion of Okta/Auth0.

Duplicate Submissions
Auth0 has maintained a private bug bounty program since 2019 and any submission that were previously discovered will be labeled as duplicates.

Security Risk & Impact
Submissions will only be eligible for a bounty if there is a security risk and/or impact.

Focus Areas
Identity protocol vulnerabilities
OAuth 2.0
OpenID Connect
SAML
Authentication or authorization bypass
PII exfiltration
Cross-tenant escalation of privilege
Target Information:
The main targets are the mobile apps, Authentication and Management APIs, the Management
dashboard, the MFA offering, SDKs and some websites under the Auth0 brand.

Here's an index of our current documentation data:

Target	Documentation
Authentication API	https://auth0.com/docs/api/authentication
Management API	https://auth0.com/docs/api/management/v2
Management Dashboard	https://auth0.com/docs/dashboard
Lock for Web	https://auth0.com/docs/libraries/lock/v11
Auth0 SDK for Web	https://auth0.com/docs/libraries/auth0js/v9
Auth0 Single Page App SDK	https://auth0.com/docs/libraries/auth0-spa-js
Express Open Connect SDK	https://github.com/auth0/express-openid-connect
Auth0 SDK for React Single Page Applications	https://github.com/auth0/auth0-react
Multifactor Authentication Overview	https://auth0.com/multifactor-authentication
Multifactor Authentication Docs	https://auth0.com/docs/multifactor-authentication
Multifactor Authentication Video	https://auth0.com/resources/videos/learn-about-guardian-mfa
FGA Documentation	https://docs.fga.dev/
FGA Swagger Documentation	https://docs.fga.dev/api/service/
Here are download links for our Auth0 Guardian application:

Auth0 Guardian MFA Android: Google Play Store
Auth0 Guardian MFA IoS: Apple App Store

Reporting Criteria
All submissions must be in the following format:

Description


Business Impact (how does this affect Auth0?)


Working proof of concept


Discoverability (how likely is this to be discovered)


Exploitability (how likely is this to be exploited)
Rules of Engagement
Employees and relatives are NOT eligible for a bounty
No DoS - Amazon prohibits this activity and testing cluster not scaled for these attacks
Do NOT contact support or helpdesk for bugbounty related concerns - please contact bugcrowd support
Publicly-known zero-day vulnerabilities will not be considered for eligibility until more than 30 days have passed since patch availability
You are testing on production systems. As such, please refrain from the use of scanning engines or anything that can affect load on our production servers. In addition, use common sense judgement to not do anything to affect our systems in general.
Customer data must not be affected in any way as a result of your testing.
Customer instances must not be accessed in any way.
The use of any automated tools or scanners is prohibited.
Do NOT perform any type of burp scans or scanners.
Do not conduct non-technical attacks such as social engineering, phishing or unauthorized access to infrastructure.
Do not test the physical security of Auth0 offices, employees, equipment, etc.
If you gain access to servers, do not attempt to pivot. Stop all testing and report.
Out Of Scope
The following finding types are specifically excluded from the bounty:

GitHub Actions Vulnerabilities - refer to section below
Double-dipping submissions (refer to double-dipping section below)
Abandoned/unclaimed domains, domain squatting, link rot, social media hijacking etc
Customize Login Page XSS
Race conditions that allow bypassing limits
Invalidating session on password change, reset, etc.
Incomplete proof of concepts
Theoretical vulnerabilities or issues (refer to theoretical issues section below)
Host Header Redirect without user impact
HTTP 404 codes/pages or other HTTP non-200 codes/pages.
Fingerprinting / banner disclosure on common/public services.
Disclosure of known public files or directories, (e.g. robots.txt).
Clickjacking and issues only exploitable through clickjacking.
CSRF on forms that are available to anonymous users (e.g. login or contact form).
Logout / Login Cross-Site Request Forgery (logout CSRF).
Presence of application or web browser ‘autocomplete’ or ‘save password’ functionality.
Lack of Security Speedbump when leaving the site.
No Captcha / Weak Captcha / Captcha Bypass
Login or Forgot Password page brute force and account lockout not enforced
HTTP method enabled
OPTIONS, PUT,GET,DELETE,INFO
WebServer Type disclosures
Social engineering of our service desk, employees or contractors
Physical attacks against Auth0's offices and data centers
Requiring a user's physical device
Error messages with non-sensitive data
Non-application layer Denial of Service or DDoS
Lack of HTTP Only / SECURE flag for cookies
Username / email enumeration
via Login Page error message
via Forgot Password error message
Missing HTTP security headers, specifically (https://www.owasp.org/index.php/List_of_useful_HTTP_headers), e.g.
Strict-Transport-Security
X-Frame-Options
X-XSS-Protection
X-Content-Type-Options
Content-Security-Policy, X-Content-Security-Policy, X-WebKit-CSP
Content-Security-Policy-Report-Only
SPF / DMARC / DKIM Mail and Domain findings
Email Rate Limiting or Spamming
DNSSEC Findings
CSV Issues
AV Scanning
SSL Issues, e.g.
SSL Attacks such as BEAST, BREACH, Renegotiation attack
SSL Forward secrecy not enabled
SSL weak / insecure cipher suites
Cookie Issues
HTTPONLY
SECURE
multiple cookie setting
Anything to do with JSESSIONID
Service Rate Limiting
User or Org enumeration
Security Image Issues
Business Logic Issues
SDKs
Any submissions pertaining to SDKs must not rely on incorrect or unintended implementations of the SDKs. We will accept submissions that can demonstrate exploitation directly from an application build from our SDKs, but not based on individual function calls that are not directly accessible from an application built with the SDK.

In the SDKs, we specify that customers should always validate user input and consider to be untrusted, so we will not accept submissions that rely on improperly validated user input. Researchers should be able to demonstrate security impact when applications and endpoints are built according to documentation.

Theoretical Issues
Any submissions suggesting that an issue could lead to or has the potential to cause impact will be considered OUT OF SCOPE. You MUST provide a complete proof of concept demonstrating the attack detailed in the submission.

Double-dipping
Researchers are strictly prohibited from double-dipping by reporting issues they've already submitted in the Auth0 private program. Any intentional attempts to do so will result in a permanent ban from the program.

GitHub Actions Vulnerabilities
You may submit issues regarding Github Actions token exfiltration, but it will be marked as a duplicate without a bounty.

Chaining Bugs
Chaining of bugs is not frowned upon in any way, we love to see clever exploit chains! However, if you have managed to compromise an Auth0 owned server we do not allow for escalations such as port scanning internal networks, privilege escalation attempts, attempting to pivot to other systems, etc. If you get access this level of access to a server please report it us and we will reward you with an appropriate bounty taking into full consideration the severity of what could be done. Chaining a CSRF vulnerability with a self XSS? Nice! Using AWS access key to dump sensitive info? Not cool.

Unsure of a vuln?
We base all payouts on risk AND impact - when in doubt the question always comes down to risk and impact (aka what can actually be done with the vulnerability and what is the consequence to Auth0). If you can demonstrate why a finding has significant impact, then please submit.
As an example: Let's say you can, as a limited admin, see logs that are not in your user role - What is the impact? If this allows you to compromise something else then please detail the full exploit chain and report. However if the only impact is reading logs.. then there is no need to report it as it would fall under - Business Logic READ issues.
Another example: Let's say you can, as a limited admin, see a list of applications but you cannot access them - What is the impact? Are you able to utilize the appID and access contents (such as the secret, jwt, etc) of the application with another endpoint? Report it. However, if you're only able to see the list of applications and the names, there is no need to report it.

Similar Bugs
Bugs of similar nature or root cause reported by the same person may be combined into one item, thus constituting only a single award.

Safe Harbor:
When conducting vulnerability research according to this policy, we consider this research to be:

Authorized in accordance with the Computer Fraud and Abuse Act (CFAA) (and/or similar state laws), and we will not initiate or support legal action against you for accidental, good faith violations of this policy;
Exempt from the Digital Millennium Copyright Act (DMCA), and we will not bring a claim against you for circumvention of technology controls;
Exempt from restrictions in our Terms & Conditions that would interfere with conducting security research, and we waive those restrictions on a limited basis for work done under this policy; and
Lawful, helpful to the overall security of the Internet, and conducted in good faith.
You are expected, as always, to comply with all applicable laws.
If at any time you have concerns or are uncertain whether your security research is consistent with this policy, please inquire via support@bugcrowd.com before going any further.
```