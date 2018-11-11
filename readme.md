SFNode meetup talk (November 2018)

# Intro
Security happens in layers. Node.js is part of an ecosystem. There are many tools that will help you code quickly but still remain secure. Just because you add security doesn't mean vulnerabilities disappear. Good security should give you more time to react and counter active attacks.

# Security happens in Layers, the ecosystem
  ![alt text](https://github.com/Trewaters/SFNode-Nov-2018/blob/master/images/owasplogo.png "OWASP Logo") 
- OWASP is  a public group focused on security
  - The “Open Web Application Security Project” (OWASP)
  - Their official website ( https://www.owasp.org/ )
  - OWASP meetups in San Francisco Bay Area ( https://www.meetup.com/Bay-Area-OWASP/ )
  - OWASP Twitter ( https://twitter.com/owasp )

  ![alt text](https://github.com/Trewaters/SFNode-Nov-2018/blob/master/images/200px-Npm-logo.svg.png "npm logo")
- npm has security features everyone should know about
  - There are automatic security Audits in npm. Act on the audits with `npm audit fix` or `npm audit fix --force`. Read the docs found here ( https://docs.npmjs.com/getting-started/running-a-security-audit )
  - Enable Two Factor Authentication (2fa). Read the docs found here ( https://docs.npmjs.com/getting-started/using-two-factor-authentication ). 
  1. For 2fa you will need to use a One Time Password (OTP) Generators ([Authy](https://authy.com/), [Google Authenticator](https://play.google.com/store/apps/details?id=com.google.android.apps.authenticator2&hl=en_US), not sure if it works with [Microsoft Authenticator](https://www.microsoft.com/en-us/account/authenticator))
  2. It is **important** to research how-to backup/recover your OTP and 2fa. Just in case something happens to the device that you have the application installed on.
  - npm 2fa works with yarn

- Linter security rules
  - Source article for more details ( https://github.com/i0natan/nodebestpractices/blob/master/sections/security/lintrules.md )
  - we have tools let’s use them. These security plugins will help you avoid vulnerable coding patterns.
  - TSLint security plugin found here ( https://www.npmjs.com/package/tslint-config-security )
  - ESLint security plugin found here ( https://github.com/nodesecurity/eslint-plugin-security )

- Node.js Security Patches
  - Please use even number Node.js releases for enterprise applications. Even number realeases are supported under LTS. Which last 3 years from Current release to End of Life (EOL).
  ![alt text](https://github.com/Trewaters/SFNode-Nov-2018/blob/master/images/release%20working%20group%20schedule.png "Node.js release schedule")
  - Long-Term Support (LTS) will support Node.js with patches to security flaws as they are discovered. 
  - Bug fixes, security updates, non-semver-major npm updates
  - Please do not use EOL versions of Node.js because there is no support. Even if there is a known security vulnerability it will not be patched in EOL versions.
  - note odd number releases will be EOL once the next major “SemVer” is realeased.
  - Node Security Roadmap from *Google* ( https://nodesecroadmap.fyi/ )

- Semantic Versioning ( SemVer )
  ![alt text](https://github.com/Trewaters/SFNode-Nov-2018/blob/master/images/semver.png "Semantic Versioning")
  - ( https://semver.org/ )
  - Given a version number MAJOR.MINOR.PATCH, increment the:
   - MAJOR version when you make incompatible API changes,
   - MINOR version when you add functionality in a backwards-compatible manner, and
   - PATCH version when you make backwards-compatible bug fixes.

- Node.js Vulnerability Disclosure
  - *“If you See something Say something”*
  - Report Node.js issues by email ( security@nodejs.org )
  - Or use Hackerone Bug Bounty Progam ( https://hackerone.com/nodejs )
  - Read the main bug page for Node.js security details ( https://nodejs.org/en/security/ )
  - [*"Security.md"*](https://github.com/Trewaters/security-README/blob/master/security.md) security ReadMe file should be added to all open source repos. This ReadMe contains security disclosure policy and responsible disclosure practice. I am recommending this as a **new standard**. Read more here (https://3waters.org/?p=250&preview=true)

  ![alt text](https://github.com/Trewaters/SFNode-Nov-2018/blob/master/images/nodegoat.png "NodeGoat")
- NodeGoat
  - ( https://github.com/OWASP/NodeGoat )
  - NodeGoat is an OWASP initiative
  - This app can be exploited. It also guides for devs about ways to fix the issues/vulnerabilities that are in it.
  - Meant to be deployed to Heroku.

  ![alt text](https://github.com/Trewaters/SFNode-Nov-2018/blob/master/images/snyk-logo.png "Snyk Logo")
- scan your application code constantly and automatically to inspect for vulnerabilities with tools like:
  - [npm audit](https://docs.npmjs.com/getting-started/running-a-security-audit)
  - [snyk](https://github.com/snyk/)
  - [NodeJsScan] ( https://github.com/ajinabraham/NodeJsScan )
  - [`npm-check`](https://www.npmjs.com/package/npm-check) which is different than `npm audit fix`

# Threats by category, [Top 10 Threats 2017](https://www.owasp.org/index.php/Category:OWASP_Top_Ten_Project)
### [A1: Injection](https://www.owasp.org/index.php/Top_10-2017_A1-Injection "click for more info")
  - *"tl;dr" Solution: make sure to validate the data you get from users.* 
  - Prevent query injection vulnerabilities
    - ORM/ODM libraries like Mongoose have this feature
    - “Node.js Applicative DoS Through MongoDB Injection” 
   by Vladimir de Turckheim, 
   on YouTube ( https://youtu.be/xJWZsoYmsIE )
  - Avoid JavaScript `eval` statements and `new Function`
  - Avoid module loading `require(someVariable)` using a variable
### [A2: Broken Authentication](https://www.owasp.org/index.php/Top_10-2017_A2-Broken_Authentication "click for more info")
  - *"tl;dr" Solution: use 2fa whenever possible.*
  - Avoid using the Node.js crypto library for handling passwords, use Bcrypt
    - use bcrypt ( https://www.npmjs.com/package/bcrypt )
    - I am curious what is wrong with the crypto library
    - Thomas Hunter II has written articles about this too ( https://medium.com/intrinsic/common-node-js-attack-vectors-the-dangers-of-malicious-modules-863ae949e7e8 )
  - Support blacklisting JWT tokens
    - JWTs Suck (and are stupid), 
by Randall Degges, 
slides here ( https://speakerdeck.com/rdegges/jwts-suck-and-are-stupid ),
on YouTube ( https://youtu.be/JdGOb7AxUo0 )
  - Limit the allowed login request of each user
    - use express-brute ( https://www.npmjs.com/package/express-brute )
### [A3: Sensitive Data Exposure](https://www.owasp.org/index.php/Top_10-2017_A3-Sensitive_Data_Exposure "click for more info")
  - *"tl;dr" Solution: encrypt sensitive data.*
  - Extract secrets from config files or use packages to encrypt them
    - use environment variables for this
    - use `cryptr` ( https://www.npmjs.com/package/cryptr )
### [A4: External Entities](https://www.owasp.org/index.php/Top_10-2017_A4-XML_External_Entities_(XXE) "click for more info")
  - *"tl;dr" Solution: use JSON and avoid serializing sensitive data.*
  - Run unsafe code in a sandbox
    - use a dedicated child process
    - use a cloud serverless framework
    - use libraries like sandbox or vm2
 -	https://www.npmjs.com/package/sandbox
 -	https://www.npmjs.com/package/vm2 
  - Take extra care when working with child processes
    - use `child_process.execFile` if you are unsure but need to use it
### [A5: Broken Access Control](https://www.owasp.org/index.php/Top_10-2017_A5-Broken_Access_Control "click for more info")
  - *"tl;dr" Solution: deny access by default.*
  - Run Node.js as non-root user
### [A6: Security Misconfiguration](https://www.owasp.org/index.php/Top_10-2017_A6-Security_Misconfiguration "click for more info")
  - *"tl;dr" Solution: review default settings to secure installation.*
  - Adjust the HTTP response headers for enhanced security
    - use helmet for express servers ( https://www.npmjs.com/package/helmet )
  - Hide error details from clients
    - set `NODE_ENV` to `production`
  - Modify session middleware settings
### [A7: Cross-Site Scripting (XSS)](https://www.owasp.org/index.php/Top_10-2017_A7-Cross-Site_Scripting_(XSS) "click for more info")
  - *"tl;dr" Solution: separate untrusted data from browser content.*
  - Escape HTML, JS, and CSS output
    - use escape-html ( https://github.com/component/escape-html )
    - use node-esapi ( https://github.com/ESAPI/node-esapi )
### [A8: Insecure Deserialization](https://www.owasp.org/index.php/Top_10-2017_A8-Insecure_Deserialization "click for more info")
  - *"tl;dr" Solution: no serialized data from untrusted sources.*
  - Validate incoming JSON schemas
    - use jsonschema ( https://www.npmjs.com/package/jsonschema )
    - use joi ( https://www.npmjs.com/package/joi )
   - Limit payload size using a reverse proxy or middleware.
    - configure express body parser to accept only small-size payloads
### [A9: Using Components with Known Vulnerabilities](https://www.owasp.org/index.php/Top_10-2017_A9-Using_Components_with_Known_Vulnerabilities "click for more info")
  - *"tl;dr" Solution: institute patch management process.*
  - [`npm audit fix`](https://docs.npmjs.com/getting-started/running-a-security-audit)
  - [`npm-check`](https://www.npmjs.com/package/npm-check)
### [A10: Insufficient Logging and Monitoring](https://www.owasp.org/index.php/Top_10-2017_A10-Insufficient_Logging%26Monitoring "click for more info")
  - *"tl;dr" Solution: read the logs for unusual activity.*
  - use due diligence. Check logs, write scripts, use things like [linkerd](https://linkerd.io/) or [splunk](https://www.splunk.com/) to monitor possible intrusions.

###	DDOS
  - Limit concurrent requests using a middleware
    - cloud load balancers, firewalls
    - `express-rate-limit` ( https://www.npmjs.com/package/express-rate-limit )
  - Avoid DOS attacks by explicitly setting when a process should crash
  - Prevent RegEx from overloading your single thread execution


![alt text](https://github.com/Trewaters/SFNode-Nov-2018/blob/master/images/Hostile-user-itCrowd.gif "hostile users")
*User input is a major vulnerability, please treat it like hostile code and sanitize it. Filter and validate user input.*

# Threats in the Wild
- Electron exploit
  - see if it is still an issue. Fixed in Electron version 2
  -	https://github.com/electron/electron/blob/master/docs/tutorial/security.md
  - THIS IS WHAT GAVE ME THE IDEA FOR THE TALK
- CVE Details – a website I ran across during my research of Node.Js vulnerabilities
  - ( https://www.cvedetails.com/vulnerability-list/vendor_id-12113/Nodejs.html )
- Reverse Shell
  - patched and specific but interesting article on it here ( https://wiremask.eu/writeups/reverse-shell-on-a-nodejs-application/ )

# Acknowledgements
- “i0natan” - Their GitHub site with a list of security best practices ( https://github.com/i0natan/nodebestpractices ).
- Thomas Hunter II - has written articles about crypto ( https://medium.com/intrinsic/common-node-js-attack-vectors-the-dangers-of-malicious-modules-863ae949e7e8 )
