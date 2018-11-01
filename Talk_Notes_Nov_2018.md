SFNode meetup talk (November 2018)

Intro
Security is a philosophy you follow or you don’t. Security through obfuscation doesn’t count as security. The Node.js community relies on you to keep it safe.

# H1
-	A1: Injection
  -Solution: make sure to validate the data somehow. 
  -Prevent query injection vulnerabilities
   -ORM/ODM libraries like Mongoose have this feature
   -“Node.js Applicative DoS Through MongoDB Injection” 
by Vladimir de Turckheim, 
on YouTube ( https://youtu.be/xJWZsoYmsIE )
  -Avoid JavaScript `eval` statements and `new Function`
  -Avoid module loading `require(someVariable)` using a variable
-	A2: Broken Authentication
  -Avoid using the Node.js crypto library for handling passwords, use Bcrypt
   -use bcrypt ( https://www.npmjs.com/package/bcrypt )
   -I am curious what is wrong with the crypto library
   -Thomas Hunter II has written articles about this too ( https://medium.com/intrinsic/common-node-js-attack-vectors-the-dangers-of-malicious-modules-863ae949e7e8 )
  -Support blacklisting JWT tokens
   -JWTs Suck (and are stupid), 
by Randall Degges, 
slides here ( https://speakerdeck.com/rdegges/jwts-suck-and-are-stupid ),
on YouTube ( https://youtu.be/JdGOb7AxUo0 )
  -Limit the allowed login request of each user
   -use express-brute ( https://www.npmjs.com/package/express-brute )
-	A3: Sensitive Data Exposure
  -Extract secrets from config files or use packages to encrypt them
   -use environment variables for this
   -use `cryptr` ( https://www.npmjs.com/package/cryptr )
-	A4: External Entities
  -Run unsafe code in a sandbox
   -use a dedicated child process
   -use a cloud serverless framework
   -use libraries like sandbox or vm2
-	https://www.npmjs.com/package/sandbox
-	https://www.npmjs.com/package/vm2 
  -Take extra care when working with child processes
   -use `child_process.execFile` if you are unsure but need to use it
-	A5: Broken Access Control
  -Run Node.js as non-root user
-	A6: Security Misconfiguration
  -Adjust the HTTP response headers for enhanced security
   -use helmet for express servers ( https://www.npmjs.com/package/helmet )
  -Hide error details from clients
   -set `NODE_ENV` to production
  -Modify session middleware settings
-	A7: Cross-Site Scripting (XSS)
  -Escape HTML, JS, and CSS output
   -use escape-html ( https://github.com/component/escape-html )
   -use node-esapi ( https://github.com/ESAPI/node-esapi )
-	A8: Insecure Deserialization
  -Validate incoming JSON schemas
   -use jsonschema ( https://www.npmjs.com/package/jsonschema )
   -use joi ( https://www.npmjs.com/package/joi )
  -Limit payload size using a reverse proxy or middleware.
   -configure express body parser to accept only small-size payloads
-	A9: Using Components with Known Vulnerabilities
  -npm audit fix
  -npm-check
-	A10: Insufficient Logging and Monitoring
  -use due diligence
-	DDOS
  -Limit concurrent requests using a middleware
   -cloud load balancers, firewalls
   -`express-rate-limit` ( https://www.npmjs.com/package/express-rate-limit )
  -Avoid DOS attacks by explicitly setting when a process should crash
  -Prevent RegEx from overloading your single thread execution

-	User input is a major vulnerability, please treat it like hostile code and sanitize it. Filter and validate user input.
  -gif from it crowd
-	node-html-entities
  -( https://www.npmjs.com/package/html-entities )
  -not quite sure what this is but it has 2M downloads/week
