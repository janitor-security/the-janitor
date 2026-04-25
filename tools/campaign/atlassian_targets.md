Auth0 targets:

```

Tools for teams, from startup to enterprise. Atlassian provides the tools to help every team unleash their full potential.

Get Started (tl;dr version)

Do not access, impact, destroy or otherwise negatively impact Atlassian customers, or customer data in anyway.

Ensure that you use your @bugcrowdninja.com email address.

Bounties are awarded differently per product (see below for more details on payouts).

Ensure you understand the targets, scopes, exclusions, and rules in Scope \& Rewards.

Focus Areas

Due to the collaborative nature of Atlassian products, we are not interested in vulnerabilities surrounding enumeration and information gathering (being able to work effectively as a team is the purpose of our products). Instead, we're more interested in traditional web application vulnerabilities, as well as other vulnerabilities that can have a direct impact to our products. Below is a list of some of the vulnerability classes that we are seeking reports for:



Cross Instance Data Leakage/Access\*\*

Server-side Remote Code Execution (RCE)

Server-Side Request Forgery (SSRF)

Stored/Reflected Cross-site Scripting (XSS)

Cross-site Request Forgery (CSRF)

SQL Injection (SQLi)

XML External Entity Attacks (XXE)

Access Control Vulnerabilities (Insecure Direct Object Reference issues, etc)

Path/Directory Traversal Issues

Ensure you review the out of scope and exclusions list for further details.



\*\* Cross Instance Data Leakage/Access refers to unauthorized data access between instances.



Product Quick Links

Jira and Confluence Cloud: 

Use the following naming convention for your cloud instance: bugbounty-test-<bugcrowd-name>.atlassian.net

Once your cloud instance is set up, you can add additional cloud products at Atlassian Administration

Bitbucket Cloud

Data Center Products

Jira Software Data Center

Confluence Data Center

Bitbucket Data Center

Crowd Data Center

Bamboo Data Center

Other Products

Crucible

Fisheye

Sourcetree

We only accept vulnerabilities affecting the latest version of the product you are testing

Mobile Products:

Jira Cloud (iOS, Android)

Confluence Cloud (iOS, Android)

Jira Data Center (iOS, Android)

Confluence Data Center (iOS, Android)

Creating Your Instance

Jira + Confluence Cloud

To access the instance and start your testing (after you've read and understood the scope and exclusions listed below, of course) you can follow the below steps:



Navigate to this page here

Complete the verification flow

When it is time to rename your instance, using the following format: bugbounty-test-<bugcrowd-name> Note that <bugcrowd-name> should be replaced with your own bugcrowd username

Click "Agree"

Once your instance has been completed that's it - you can test away!

Additional Cloud Products



Once your cloud instance is set up, you can add additional products via Atlassian Administration

Go to the "Products" tab

Click on "Add product"

Select the cloud products you would like to add (e.g Jira Product Discovery, Jira Service Management, Jira Work Management, Statuspage)

Bitbucket Cloud



Navigate to https://bitbucket.org/ and select "Log In"

Select "Sign Up" and create an account with your @bugcrowdninja.com email address.

Start testing!

All Atlassian Data Center Products

To access the target and start your testing (after you've read and understood the scope and exclusions listed below, of course) you can follow the steps below:



Navigate to Data Center product link above

Download the latest version of the product you want to test

Install the product

(if required) Generate a trial license for the product at my.atlassian.com

Start testing

To spin up a local Docker instance follow the steps located at:



Confluence

Jira Core

Jira Software

Jira Service Management

Bitbucket

Crowd

Fisheye

Bamboo

Note: After the trial period expires you can generate another evaluation license and continue researching. Please remember to check that you are still on the latest version.



Disclosure Request Guidance

Submissions that meet the following requirements will be considered for disclosure upon request:



The submission has been accepted

The reported vulnerability has been fixed and released in production

The submission does not regard a customer instance or a customer’s account

Targets 

4 out of 4

Bugcrowd calculates scope ratings based on the depth and breadth of in-scope targets.

Tier 1Reward increase

In scope

Payment reward chart

P1

$12000

P2

$4000

P3

$325

P4

$250

Name / Location	Tags	Known issues

Atlassian Guard Standard and Premium (https://admin.atlassian.com/atlassian-guard)

https://admin.atlassian.com/atlassian-guard

Website Testing

23

Atlassian Admin (https://admin.atlassian.com/)

https://admin.atlassian.com/

Website Testing

39

Atlassian Identity (https://id.atlassian.com/login)

https://id.atlassian.com/login

API Testing

Website Testing

17

Atlassian Start (https://start.atlassian.com)

https://start.atlassian.com

Website Testing

2

Bitbucket Cloud including Bitbucket Pipelines (https://bitbucket.org)

https://bitbucket.org

Django

Website Testing

56

Confluence Cloud (bugbounty-test-<bugcrowd-name>.atlassian.net/wiki)

https://www.atlassian.com/software/confluence

Website Testing

21

Confluence Cloud Premium (bugbounty-test-<bugcrowd-name>.atlassian.net/wiki)

https://www.atlassian.com/software/confluence/premium

Website Testing

43

Confluence Cloud Mobile App for Android

https://play.google.com/store/apps/details?id=com.atlassian.android.confluence.core\&hl=en\_US\&gl=US

Java

Mobile Application Testing

Kotlin

+1

9

Confluence Cloud Mobile App for iOS

https://apps.apple.com/us/app/confluence-cloud/id1006971684

Objective-C

SwiftUI

Swift

+2

3

Jira Cloud Mobile App for Android

https://play.google.com/store/apps/details?id=com.atlassian.android.jira.core\&hl=en\_US\&gl=US

Java

Mobile Application Testing

Kotlin

+1

6

Jira Cloud Mobile App for iOS

https://apps.apple.com/us/app/jira-cloud-by-atlassian/id1006972087

Objective-C

SwiftUI

Swift

+2

3

Jira Service Management Cloud (bugbounty-test-<bugcrowd-name>.atlassian.net)

https://www.atlassian.com/software/jira/service-management

Website Testing

129

Jira Software Cloud (bugbounty-test-<bugcrowd-name>.atlassian.net)

https://www.atlassian.com/software/jira

Website Testing

90

Jira Work Management Cloud formerly Jira Core (bugbounty-test-<bugcrowd-name>.atlassian.net)

https://www.atlassian.com/software/jira/work-management

Java

Redux

ReactJS

+2

35

Any associated \*.atlassian.com or \*.atl-paas.net domain that can be exploited DIRECTLY from the \*.atlassian.net instance		61

Rovo, Rovo Dev and other AI FeaturesReward increase

In scope

Payment reward chart

P1

$12000

P2

$6000

P3

$325

P4

$250

Introducing Rovo!

Rovo is Atlassian's AI solution integrated into the Atlassian platform to help enable teams make better decisions and reach goals faster. Rovo, in addition to other Atlassian Intelligence features are now formally part of the Atlassian Bug Bounty program! Please review the documentation here



Rovo Features in Scope:

Rovo Chat

Rovo Search including Rovo Connectors

Rovo Studio including Rovo Agents and Rovo Forge Agents

Rovo Browser Extension

Rovo Slack App

Other AI Features in Atlassian Products

Atlassian MCP Server

Rovo Dev Products in Scope:

Rovo Dev Code Reviews

Rovo Dev CLI

Atlassian Extension for VSCode

Other Rovo Dev Features in Atlassian Products

Accepted Vulnerabilities

In addition to traditional web application vulnerabilities, we are also interested in:



Search and 3P data ingestion

Broken connector authentication, leakage of client secrets or tokens during the authorization process, insufficient validation of refresh tokens or token expiration.

Data poisoning via injection of malicious, corrupted or malformed data into the ingested 3P content that leads to system crashes or behavior anomalies or compromise the integrity of the search index.

Mismanagement of CORS policies leading to unauthorized cross-origin data fetching.

Scope overreach while ingesting or persistence of access after 3P connector is deactivated or disconnected.

If rate limits announced - exploitation of improperly enforced rate limits and quota on data ingestion, overloading connectors by exploiting insufficient throttling or queue management

Improper error handling that leaks sensitive information

Abusing legitimate connector functionalities to exfiltrate or manipulate data.

Improper enforcement of source-of-truth permissions after the data was ingested:

seeing document titles, snippets, or summaries of restricted documents

any kinds of authorization failures, examples: permissions being out-of-sync, permissions drifts between source-of-truth systems and Atlassian

AI Agents and Chat

Incorrect information disclosure across projects, products, or workspaces due to improper filtering or misconfigured access controls.

Cross product AI features inadvertently suggest or display restricted content bypassing access controls.

Cross product AI features leak restricted content to LLM(s), sensitive data inadvertently displayed in AI-generated summaries or other features.

Bypass or improper authorization policies enforcement in Agents and Rovo chat, including partial data exposure.

Exploiting Forge integration security weaknesses

If rate limits announced - exploitation of improperly enforced rate limits and quota

Sensitive Information disclosure (PII) via AI features

Out of Scope or Non-eligible Issues

Vulnerabilities related to GraphQL, cyclic hydration \& large payload processing

Things not explicitly mentioned in Acceptable Use Policy | Atlassian

Trivial jailbreak prompt injections, in terms of consequence

Supply Chain Vulnerabilities

Vulnerabilities exposed through multi-turn attacks

All kinds of insecure output handling and sensitive information disclosure not mentioned explicitly above

The following will be awarded points only:

Abuse/Misuse/Ethical bypassing Acceptable Use Policy | Atlassian (AUP) enforcement mechanism

Exploiting explicitly outlined categories in AUP

Flooding or overloading AUP enforcement mechanism

Get Started

Please review the documentation here to get started with a trial of Rovo and test drive its features and functionalities.



Name / Location	Tags	Known issues

Rovo

https://www.atlassian.com/software/rovo

Website Testing

17

Rovo Dev CLI

https://support.atlassian.com/rovo/docs/use-rovo-dev-cli/

Python

4

Other Rovo Dev

https://www.atlassian.com/software/rovo-dev

Website Testing

0

Atlassian MCP Server

https://mcp.atlassian.com

0

Tier 2Reward increase

In scope

Payment reward chart

P1

$7000

P2

$2500

P3

$250

P4

$175

Name / Location	Tags	Known issues

Atlassian Compass

https://www.atlassian.com/software/compass

5

Atlassian Marketplace (https://marketplace.atlassian.com)

https://marketplace.atlassian.com

Website Testing

6

Atlassian Atlas

https://www.atlassian.com/software/atlas

Website Testing

3

Bitbucket Data Center

https://www.atlassian.com/enterprise/data-center/bitbucket

Django

ReactJS

Website Testing

+1

21

Confluence Data Center

https://www.atlassian.com/enterprise/data-center/confluence

Java

jQuery

Website Testing

+2

44

Crowd

https://www.atlassian.com/enterprise/data-center/crowd

Java

API Testing

Website Testing

+1

1

Jira Core Data Center

https://www.atlassian.com/enterprise/data-center/jira

Java

ReactJS

jQuery

+2

7

Jira Service Management Data Center

https://www.atlassian.com/enterprise/data-center/jira/service-management

Java

ReactJS

jQuery

+2

16

Jira Software Data Center

https://www.atlassian.com/enterprise/data-center/jira

Java

ReactJS

jQuery

+2

38

\*.atlastunnel.com

https://\*.atlastunnel.com

Website Testing

1

Any other \*.atlassian.com or \*.atl-paas.net domain that cannot be exploited directly from a \*.atlassian.net instance	

Website Testing

24

Atlassian LoomReward increase

In scope

Payment reward chart

P1

$7000

P2

$2500

P3

$250

P4

$175

You can access our products from the quick links below:



Product Quick Links

Loom website - Sign up for free!

Loom Desktop App (macOS)

Loom Desktop App (Windows)

Loom Chrome Extension

Loom for Android

Loom for iOS

Name / Location	Tags	Known issues

\*.loom.com

https://www.loom.com/

Website Testing

52

Loom Desktop App (Windows)

https://www.loom.com/download

AWS

C++

Windows

+2

0

Loom Desktop App (macOS)

https://www.loom.com/download

AWS

Electron

Objective-C

+3

0

Loom for Android

https://play.google.com/store/apps/details?id=com.loom.android\&hl=en\_US\&pli=1

Mobile Application Testing

Android

3

Loom for iOS

https://apps.apple.com/us/app/loom-screen-recorder/id1474480829

Mobile Application Testing

iOS

2

Loom Chrome Extension

https://chromewebstore.google.com/detail/loom-%E2%80%93-screen-recorder-sc/liecbddmkiiihnedobmlmillhodjkdmb?hl=en-US\&pli=1

Browser Extension

2

Tier 3Reward increase

In scope

Payment reward chart

P1

$4000

P2

$1500

P3

$175

P4

$100

Name / Location	Tags	Known issues

Bamboo

https://www.atlassian.com/software/bamboo

Java

API Testing

ReactJS

+2

31

Confluence Companion App for macOS and Windows

https://confluence.atlassian.com/doc/install-atlassian-companion-992678880.html

0

Confluence Data Center Mobile App for Android

https://play.google.com/store/apps/details?id=com.atlassian.confluence.server

Java

Mobile Application Testing

Kotlin

+1

0

Confluence Data Center Mobile App for iOS

https://apps.apple.com/us/app/confluence-server/id1288365159

Objective-C

SwiftUI

Swift

+2

0

Crucible

https://www.atlassian.com/software/crucible

Java

Website Testing

Spring

0

FishEye

https://www.atlassian.com/software/fisheye

Java

Website Testing

Spring

2

Jira Data Center Mobile App for Android

https://play.google.com/store/apps/details?id=com.atlassian.jira.server\&hl=en\_US\&gl=US

Java

Mobile Application Testing

Kotlin

+1

1

Jira Data Center Mobile App for iOS

https://apps.apple.com/us/app/jira-server/id1405353949

Objective-C

SwiftUI

Swift

+2

0

Sourcetree for macOS and Windows (https://www.sourcetreeapp.com/)

https://www.sourcetreeapp.com/

Windows

macOS

Desktop Application Testing

1

Other - (all other Atlassian targets)		26

Jira Product Discovery

https://www.atlassian.com/software/jira/product-discovery

9

Atlassian ForgeReward increase

In scope

Payment reward chart

P1

$7000

P2

$2500

P3

$250

P4

$175

Atlassian Forge is an app development platform designed to revolutionize how Atlassian cloud products are customized, extended, and integrated.



More information on the platform can be found here: https://developer.atlassian.com/platform/forge/



Due to the collaborative nature of Atlassian products, we are not interested in vulnerabilities surrounding enumeration and information gathering (being able to work effectively as a team is the purpose of our products). Instead, we're more interested in vulnerabilities that can have a direct impact to the Forge Platform. Below is a list of some of the vulnerability classes that we are seeking reports for:



Forge Platform

Execution environment

Sandbox escapes

Supporting GraphQL endpoints

Access Control Vulnerabilities (Insecure Direct Object Reference issues, etc)

Server-Side Request Forgery (SSRF)

Forge CLI - https://www.npmjs.com/package/@forge/cli

Deployments

Forge App Installation/Uninstallation flows

UI Kit Stored/Reflected Cross-site Scripting (XSS) specifically targeting default behaviors of UI Kit elements

Name / Location	Tags	Known issues

Forge Platform	

Website Testing

NodeJS

7

GraphQL API (bugbounty-test-<bugcrowd-name>.atlassian.net/gateway/api/graphql)	

API Testing

GraphQL

4

https://www.npmjs.com/package/@forge/cli

https://www.npmjs.com/package/@forge/cli

Lodash

Website Testing

NodeJS

0

Out of Scope

Out of scope

Name / Location	Tags	Known issues

Any internal or development services.	

Website Testing

0

First and third party apps and plugins from the marketplace are excluded from this bounty but may be in scope for https://bugcrowd.com/atlassianapps

https://bugcrowd.com/atlassianapps

Website Testing

0

shop.atlassian.com

https://shop.atlassian.com

Website Testing

0

bytebucket.org	

Website Testing

0

\*.bitbucket.io	

Recon

Website Testing

DNS

0

https://blog.bitbucket.org	

Website Testing

0

HipChat (inc. HipChat Data Center, HipChat Desktop, HipChat Mobile)		0

Stride (inc. Stride Video, Stride Desktop, Stride Mobile)		0

support.atlassian.com

https://support.atlassian.com

0

Any customer instance. Do not test customer instances or affect customer data. Customer cloud instances may be in the form of <customer>.atlassian.net or <customer>.jira.com. Test only your own instances.		0

Any repository that you are not an owner of - do not impact Atlassian customers in any way.	

Website Testing

0

support.loom.com

https://support.loom.com

0

info.loom.com

https://info.loom.com/

0

Rules, Exclusions, and Scopes

Any domain/property of Atlassian not listed in the targets section is strictly out of scope (for more information please see the out of scope and exclusions sections below). For cloud instances, researchers should use the "bugbounty-test-<bugcrowd-name>.atlassian.net" namespace provided in the instructions below. Please do not create additional instances outside of this namespace for testing.



All resources within your instance is in scope (see below for exclusions), this includes the all of the REST APIs and any \*.atlassian.com or \*.atl-paas.net service that can be exploited from an in scope product.



Out-of-Scope

Anything not declared as a target or in scope above should be considered out of scope for the purposes of this bug bounty. However to help avoid grey areas, below are examples of what is considered out of scope.



Identifying apps which are installed, as long as the user level has access to the instance, is known as part of the Atlassian Connect threat model, and is an accepted risk. Please do not report this.

Enumeration or information disclosure of non-sensitive information (e.g. issue keys, project keys, commit hashes).

Blind XSS must not return any user data that you do not have access to (e.g. Screen shots, cookies that aren't owned by you, etc); when testing for blind XSS, please use the least invasive test possible (e.g. calling 1x1 image or nonexistent page on your webserver, etc).

XSSs on Data Center instances that require administrator privileges will be scored as P5 Informational and awarded points only, as they don't let the attacker compromise Confidentiality, Integrity or Availability any more than they already could as an administrator.

When testing, please exercise caution if injecting on any form that may be publicly visible - such as forums, etc. Before injection, please make sure your payload can be removed from the site. If it cannot be easily removed, please check with support@bugcrowd before performing the testing.

No pivoting or post exploitation attacks (i.e. using a vulnerability to find another vulnerability) are allowed on this program. DO NOT under any circumstance leverage a finding to identify further issues.

Customer cloud and data center/server instances and customer data are explicitly out of scope. Customer cloud instances may be in the form of \*.atlassian.net or \*.jira.com. Please only test your own "bugbounty-test-<bugcrowd-name>.atlassian.net" cloud instance or locally instantiated data center/server instance.

Any repository that you are not an owner of - do not impact Atlassian customers in any way.

Any Atlassian billing system. However, specific endpoints that are used inside of a target are in scope. For example, if a REST endpoint is proven to be called from one of the targets, then that endpoint is considered to be in scope. However, all other endpoints are not considered to be in scope, as they are not called from the instance at any stage.

Only the latest version of a Data Center product is eligible for a reward. All vulnerabilities/exploits must be proven to work in the latest version of the Atlassian Data Center product.

Any internal, development, staging, or testing services with no clear security impact to any production data or infrastructure.

Third party add-ons/integrations others than those listed in the targets from the marketplace are strictly excluded (vulnerabilities that exist within third-party apps in any way) - we will pass on any vulnerabilities found, however, they will not be eligible for a bounty.

Vulnerabilities that have been fixed by the vendor within the last 7 days (i.e. we will not accept reports that we are vulnerable to CVE-XXXX-XXXX within 7 days of the patch by the vendor to give our internal teams a chance to detect and patch the issue)

Denial of Service (DoS) reports on cloud products are specifically out of scope. Do not perform DoS attacks on any cloud instance.

DoS reports on Data Center products related to lack of rate limiting, request flooding, resource exhaustion, or other similar network layer/volume based attacks are not accepted.

The following finding types are specifically excluded from the bounty (no payout)

The use of automated scanners is strictly prohibited (we have these tools too - don't even think about using them)

Descriptive error messages (e.g. stack traces, application or server errors).

Fingerprinting / banner disclosure on common/public services.

Clickjacking and issues only exploitable through clickjacking.

Logout Cross-Site Request Forgery (logout CSRF).

Content Spoofing.

Presence of application or web browser ‘autocomplete’ or ‘save password’ functionality.

Lack of Secure/HTTPOnly flags on non-sensitive Cookies.

Lack of "security speed bump" when leaving the site.

Weak Captcha / Captcha bypass.

Login or Forgot Password page brute force and account lockout not enforced.

Username / email enumeration.

Missing HTTP security headers, specifically (https://owasp.org/www-project-secure-headers/), e.g.

Strict-Transport-Security.

X-Frame-Options.

X-XSS-Protection.

X-Content-Type-Options.

Content-Security-Policy, X-Content-Security-Policy, X-WebKit-CSP.

Content-Security-Policy-Report-Only.

Cache-Control and Pragma

HTTP/DNS cache poisoning.

SSL/TLS Issues, e.g.

SSL Attacks such as BEAST, BREACH, Renegotiation attack.

SSL Forward secrecy not enabled.

SSL weak/insecure cipher suites.

Self-XSS reports will not be accepted.

Similarly, any XSS where local access is required (i.e. User-Agent Header injection) will not be accepted. The only exception will be if you can show a working off-path MiTM attack that will allow for the XSS to trigger.

Vulnerabilities that are limited to unsupported browsers will not be accepted (i.e. "this exploit only works in IE6/IE7"). A list of supported browsers can be found here.

Known vulnerabilities in used libraries, or the reports that an Atlassian product uses an outdated third party library (e.g. jQuery, Apache HttpComponents etc) unless you can prove exploitability.

Missing or incorrect SPF records of any kind.

Missing or incorrect DMARC records of any kind.

Source code disclosure vulnerabilities.

Information disclosure of non-confidential information (e. g. issue id, project id, commit hashes).

The ability to upload/download viruses or malicious files to the platform.

Email bombing

Request Flooding

Lack of rate limiting

CSV Injection

Issues where paid or premium features are accessible on free accounts with no inherent "security" implications (impacts to the Confidentiality, Integrity, Availability of the product) may be considered Informational and rewarded points.

Rules

You must ensure that customer data is not affected in any way as a result of your testing. Please ensure you're being non-destructive whilst testing and are only testing using accounts and instances created via the instructions under “Creating your instance” above.

In addition to above, customer instances are not to be accessed in any way (i.e. no customer data is accessed, customer credentials are not to be used or "verified")

If you believe you have found sensitive customer data (e.g., login credentials, API keys etc) or a way to access customer data (i.e. through a vulnerability) report it, but do not attempt to validate or authenticate with these credentials.

If you come across Atlassian Employee login credentials, API keys, or similar sensitive information, please report it immediately. However, please do not attempt to verify or authenticate with these credentials.

Use of any automated tools/scanners is strictly prohibited and will lead to you being removed from the program (trust us, we have those tools too).

Reports need to be submitted in plain text (associated pictures/videos are fine as long as they're in standard formats). Non-plain text reports (e.g. PDF, DOCX) will be asked to be resubmitted in plain text.

To facilitate timely report acceptance, please utilize the Reporting Guidelines below.

Sufficiently similar access control issues should be grouped in one report. Atlassian defines “sufficiently similar” as issues that use the same permissions/configuration for bypassing a particular control, which may be used on multiple related vulnerable endpoints or actions (User X with Y permissions can Create/Delete/Edit Resource Z).

Grants/awards are at the discretion of Atlassian and we withhold the right to grant, modify or deny grants. But we'll be fair about it.

Tax implications of any payouts are the sole responsibility of the reporter.

Do NOT conduct non-technical attacks such as social engineering or phishing attacks on Atlassian, its staff, or customers. Reports that rely on theoretical social engineering or phishing for a successful attack may be considered albeit with a much lesser severity impact.

Do NOT test the physical security of Atlassian offices, employees, equipment, etc.

This bounty follows Bugcrowd’s standard disclosure terms.

Any vulnerability found in a JIRA or Confluence Data Center product may not be eligible for a reward in Jira/Confluence Cloud, and vice versa (i.e. no double dipping).

Scoring and Exceptions

Atlassian uses CVSS to consistently score security vulnerabilities. There may be internal mitigations or controls that affect the final CVSS score and thus final assessed severity. Where discrepancies between the VRT and CVSS score exist, Atlassian will defer to the CVSS score to determine the priority.

A few issue types are not scored by their CVSS scores. These are typically higher severity, but will be rewarded as P4 issues:



XSS Vulnerabilities where the script is blocked by the product's Content Security Policy, unless a bypass is documented as part of the submission

XSS Vulnerabilities where the session cookie has HTTPOnly and Secure Flag set, unless extraction of the session cookie is documented as part of the submission

Open Redirect bugs, and

Broken Access Control or Privilege Escalation bugs, where an Administrator is able to perform System Administrator actions.

These are typically CVSS High (P2) but will be rewarded as Medium (P3) issues:



XSS in Data Center products

Reporting Credentials

If you believe you have found Atlassian employee or customer credentials please report them but do not attempt to validate them.

Credential Reports will be handled as follows:



Customer credential reports will be marked as P5 (Informational)

Atlassian employee credentials will have severity adjusted based on CVSS, but will only be paid out if they can access Atlassian resources (i.e. credentials not related to their work at Atlassian will receive points but will not be paid out)

Reporting Guidelines

A well-crafted report enables effective communication of the issue to our product teams. It also simplifies the process of replicating and validating the submission. A submission that is clear and comprehensively documented aids in triage, validation, and leads to expedited report acceptance.

Where applicable, the following information should be included:



Brief summary of the submission (including product versions tested for Data Center products)

Prerequisites or initial conditions (including any products, user privileges, tools required, files prepared, web server configurations, or any other initial conditions which need to be set prior to initiating the proof of concept)

Reproduction steps (including any vulnerable endpoints, parameters, payloads used, source code for scripts, or command line inputs)

Inclusion of burp requests (or HTTP request examples), screenshots, and screen recordings are highly encouraged.

Templates and/or scripts for testing, such as a nuclei template or python script, are desirable for a submission.

Expected results / behaviour vs actual results / behaviour. Please include any links to formal documentation or resources which state the expected behaviour.

Assessed security impact (as it relates to the Confidentiality, Integrity, and/or Availability of the product)

Where possible, the following information is could be additionally included:



Possible mitigations, fixes and security controls (The more product specific the better).

Root cause analysis of the vulnerability.

Business impact.

For Data Center and on-premise products, a list of impacted versions beyond current version.

References.

Public Disclosure

At Atlassian, one of our values is Open Company, No Bullshit, we believe that vulnerability disclosure is a part of that value. We hold ourselves to the security bug fix service level objectives, found here, and will accept disclosure requests in the bug bounty program after the issue has been fixed and released in production. However, if the report contains any information regarding a customer instance or data the request will be rejected. If you are planning to disclose outside of the bug bounty, we ask that you give us reasonable notice and wait until the associated SLO has passed.



Safe Harbor

When conducting vulnerability research according to this policy, we consider this research to be:



Authorized in accordance with the Computer Fraud and Abuse Act (CFAA) (and/or similar state laws), and we will not initiate or support legal action against you for accidental, good faith violations of this policy;

Exempt from the Digital Millennium Copyright Act (DMCA), and we will not bring a claim against you for circumvention of technology controls;

Exempt from restrictions in our Terms \& Conditions that would interfere with conducting security research, and we waive those restrictions on a limited basis for work done under this policy; and

Lawful, helpful to the overall security of the Internet, and conducted in good faith.

You are expected, as always, to comply with all applicable laws.

If at any time you have concerns or are uncertain whether your security research is consistent with this policy, please submit a report through one of our Official Channels before going any further.



Known Issues

Counts of P1 – P4 vulnerabilities

Includes imported issues tracked outside of Bugcrowd.

Excludes Out of scope vulnerabilities.

Unique

Includes issues in Triaged, Unresoved, and Informational states

Total

Includes Duplicate of unique known issues

```

