// ============================================================
// BCSSL Web Application Security Lab — Course & Exercise data
// Content derived from the official student exercise files.
// NOTE: Instructional content only — no completed student
// answers or findings are included anywhere in this data.
// ============================================================

export const COURSE = {
  platform: 'BCSSL Cyber Lab',
  product: 'BCSSL Web Application Security Scanner Lab',
  company: 'Blue Cloud Softech Solutions Ltd.',
  tagline: 'Think Big | AI-First',
  title: 'BCSSL Web Application Security Scanner Lab',
  subtitle: 'Web Application Security Scanner Lab',
  description:
    'A hands-on web application security testing lab. Operate the Project #08 Web Application Security Scanner against a local OWASP Juice Shop target, manually verify observations with curl and Burp Suite, and learn to distinguish scanner observations from confirmed vulnerabilities.',
  target: 'http://localhost:3001',
  targetName: 'OWASP Juice Shop',
  scope: 'LOCAL LAB ONLY',
  level: 'Beginner',
  duration: '6–8 hours',
  exercisesCount: 7,
};

export const EXERCISES = [
  {
    id: 1,
    number: '01',
    slug: 'web-security-scanner',
    title: 'Web Security Scanner',
    tagline: 'Run the Project #08 scanner against the authorized target for the first time.',
    module: 'Scanning Fundamentals',
    duration: '45 min',
    level: 'Beginner',
    icon: 'scanner',
    objectives: [
      'Start and verify the local Juice Shop target',
      'Execute the scanner from the command line with the correct arguments',
      'Generate both console output and an HTML report',
      'Interpret scanner findings as observations (not confirmed vulnerabilities)',
      'Distinguish between scanner output and verified security issues',
    ],
    background: [
      {
        heading: 'About the scanner',
        paragraphs: [
          'In Project #08, you built a command-line web application security scanner that performs passive, non-destructive assessment of HTTP applications. Your scanner analyzes four areas of weakness:',
        ],
        table: {
          headers: ['Module', 'What It Checks'],
          rows: [
            ['headers', 'HTTP security response headers'],
            ['paths', 'Sensitive or interesting paths that may be accessible'],
            ['injection', 'Indicators of potential injection vulnerabilities'],
            ['config', 'Configuration weaknesses and information disclosure'],
          ],
        },
        after: [
          'The scanner is a detection and triage aid. It reports observations and indicators. It does not prove that any finding is exploitable. Every scanner finding must be manually verified before it can be considered a confirmed vulnerability.',
        ],
      },
      {
        heading: 'Observation vs. confirmed vulnerability',
        paragraphs: [
          'A scanner finding is an observation, not a confirmed vulnerability. The scanner tells you what it saw; it does not tell you whether the issue can actually be exploited.',
        ],
      },
    ],
    tasks: [
      {
        title: 'Start and verify the local Juice Shop target',
        steps: [
          'Open a terminal in the lab target directory and start the container with docker compose up -d',
          'Verify the container is running with docker compose ps — you should see bcssl-juice-shop with status Up and port mapping 127.0.0.1:3001->3000/tcp',
          'Verify the target responds: curl.exe -I --max-time 10 http://localhost:3001 (expect HTTP/1.1 200 OK)',
        ],
        code: [
          { label: 'PowerShell', code: 'cd C:\\Users\\devas\\Documents\\Cybersecurity\\BCSSL-Student-Web-Security-Lab\\target\ndocker compose up -d\ndocker compose ps\ncurl.exe -I --max-time 10 http://localhost:3001' },
        ],
      },
      {
        title: 'Run the full scan',
        steps: [
          'Navigate to your completed scanner project directory',
          'Run the scanner with all four modules against the authorized target',
          'Examine the header block, findings table, summary line, and closing caveat in the console output',
        ],
        code: [
          { label: 'PowerShell', code: 'cd C:\\Users\\devas\\Documents\\Cybersecurity\\Web-Security-Scanner\npython scanner.py --url http://localhost:3001 --modules headers,paths,injection,config' },
        ],
      },
      {
        title: 'Generate an HTML report',
        steps: [
          'Re-run the scan with the --html-output argument to write a self-contained HTML report',
          'Open the report in a browser and review the summary section and finding details',
        ],
        code: [
          { label: 'PowerShell', code: 'python scanner.py --url http://localhost:3001 --modules headers,paths,injection,config --html-output reports/juice-shop-scan-exercise01.html' },
        ],
      },
    ],
    questions: [
      { q: 'How many findings did the scanner report in total?', format: 'number', type: 'number', answers: ['4'] },
      { q: 'How many MEDIUM findings were there?', format: 'number', type: 'number', answers: ['2'] },
      { q: 'How many INFO findings were there?', format: 'number', type: 'number', answers: ['2'] },
      { q: 'Which module(s) produced the most findings?', format: 'module name; module name', type: 'keywords', answers: ['headers', 'paths'] },
      { q: 'Which module(s) produced the fewest (or zero) findings?', format: 'module name; module name', type: 'keywords', answers: ['injection', 'config'] },
      { q: 'Were there any operational errors?', format: 'YES/NO', type: 'yesno', answers: ['NO'] },
      { q: 'Which security header was reported missing by the scanner?', format: 'header name', type: 'keyword', answers: ['Content-Security-Policy'], aliases: ['csp'] },
      { q: 'Which path was discovered by the scanner?', format: 'path', type: 'keyword', answers: ['/ftp'], aliases: ['/robots.txt'] },
      { q: 'Does zero injection findings prove there are no injection vulnerabilities?', format: 'YES/NO', type: 'yesno', answers: ['NO'] },
      { q: 'Does zero config findings prove there are no configuration weaknesses?', format: 'YES/NO', type: 'yesno', answers: ['NO'] },
    ],
    evidence: [
      'Console output screenshot — complete scan output including header block, findings table, and summary line',
      'HTML report file — the generated .html report',
      'HTML report screenshot — summary section and at least one finding detail',
      'Written answers to all 10 questions',
    ],
    checklist: [
      'Started the Juice Shop container using docker compose up -d',
      'Verified the container is running with docker compose ps',
      'Verified the target responds at http://localhost:3001',
      'Ran the full scan command with all four modules',
      'Captured a screenshot of the console output',
      'Generated an HTML report using --html-output',
      'Opened and reviewed the HTML report in a browser',
      'Captured a screenshot of the HTML report',
      'Answered all 10 questions',
      'Saved all evidence files for submission',
    ],
  },
  {
    id: 2,
    number: '02',
    slug: 'http-security-headers',
    title: 'HTTP Security Headers',
    tagline: 'Investigate HTTP security response headers and compare manual checks with scanner output.',
    module: 'Header Analysis',
    duration: '40 min',
    level: 'Beginner',
    icon: 'shield',
    objectives: [
      'Understand the purpose of common HTTP security headers',
      'Manually inspect HTTP response headers using curl',
      'Compare your manual observations with your scanner\'s findings',
      'Distinguish between a missing security header and an exploitable vulnerability',
      'Evaluate the practical impact of missing headers in context',
    ],
    background: [
      {
        heading: 'The role of security headers',
        paragraphs: [
          'HTTP response headers are metadata sent by a server alongside the response body. Some headers instruct the browser on how to handle the response securely — these are called HTTP security headers.',
          'Security headers provide defence-in-depth: they add layers of protection that make it harder for attackers to exploit vulnerabilities. However, a missing security header does not automatically mean the application is vulnerable. It means a protective layer is absent.',
        ],
      },
      {
        heading: 'Missing header vs. exploitable vulnerability',
        paragraphs: [
          'A missing header means a recommended security control is not present. An exploitable vulnerability means an attacker can actively leverage a weakness to cause harm. A missing header may increase risk, but it does not prove that an attack is possible — context matters.',
        ],
      },
      {
        heading: 'Headers to investigate',
        list: [
          'Content-Security-Policy (CSP) — restricts sources for scripts, styles, and other resources; mitigates XSS and data injection',
          'Strict-Transport-Security (HSTS) — instructs the browser to always connect over HTTPS; prevents SSL stripping',
          'X-Frame-Options — controls whether the page may be rendered in a frame or iframe; mitigates clickjacking',
          'X-Content-Type-Options — prevents MIME-sniffing away from the declared content type',
          'Set-Cookie flags — HttpOnly prevents script access to cookies; Secure restricts cookies to HTTPS',
        ],
        after: [
          'Note: HSTS and the Secure cookie flag only meaningfully apply to HTTPS. This local lab target is served over plain HTTP, so their absence is expected and is forward-looking hardening rather than a current vulnerability.',
        ],
      },
    ],
    tasks: [
      {
        title: 'Manual header inspection',
        steps: [
          'Use curl to fetch only the response headers from the target',
          'Record every header you see, then check specifically for each of the five header categories',
        ],
        code: [
          { label: 'PowerShell', code: 'curl.exe -I http://localhost:3001\ncurl.exe -v http://localhost:3001' },
        ],
      },
      {
        title: 'Run the scanner\'s header module',
        steps: ['Run the scanner with only the headers module and record its findings'],
        code: [
          { label: 'PowerShell', code: 'cd C:\\Users\\devas\\Documents\\Cybersecurity\\Web-Security-Scanner\npython scanner.py --url http://localhost:3001 --modules headers' },
        ],
      },
      {
        title: 'Compare your observations',
        steps: [
          'Create a comparison table: Header | Present? (manual) | Scanner reported? | Notes',
          'Fill in the table for each of the five header categories',
        ],
      },
      {
        title: 'Investigate cookie behavior',
        steps: [
          'Use curl -v to inspect any Set-Cookie headers in the response',
          'Check whether the HttpOnly and Secure flags are set',
        ],
      },
      {
        title: 'Generate an HTML report',
        steps: ['Run the header module with --html-output to produce the exercise report'],
        code: [
          { label: 'PowerShell', code: 'python scanner.py --url http://localhost:3001 --modules headers --html-output reports/exercise02-headers.html' },
        ],
      },
    ],
    questions: [
      { q: 'What is the status of Content-Security-Policy?', format: 'PRESENT/MISSING', type: 'keyword', answers: ['MISSING'] },
      { q: 'What is the status of Strict-Transport-Security?', format: 'PRESENT/MISSING', type: 'keyword', answers: ['MISSING'] },
      { q: 'What is the status of X-Frame-Options?', format: 'PRESENT/MISSING', type: 'keyword', answers: ['PRESENT'] },
      { q: 'What is the status of X-Content-Type-Options?', format: 'PRESENT/MISSING', type: 'keyword', answers: ['PRESENT'] },
      { q: 'What is the status of Set-Cookie?', format: 'PRESENT/MISSING', type: 'keyword', answers: ['MISSING'] },
      { q: 'Which header helps prevent clickjacking?', format: 'header name', type: 'keyword', answers: ['X-Frame-Options'] },
      { q: 'Which CSP directive is the modern framing-control alternative?', format: 'directive', type: 'keyword', answers: ['frame-ancestors'] },
      { q: 'What attack is CSP commonly used to help mitigate?', format: 'attack name', type: 'keyword', answers: ['XSS'], aliases: ['cross-site scripting'] },
      { q: 'What does HSTS require for protected connections?', format: 'protocol', type: 'keyword', answers: ['HTTPS'] },
      { q: 'Did the scanner report the same missing headers you found manually?', format: 'YES/NO', type: 'yesno', answers: ['YES'] },
    ],
    evidence: [
      'curl header output — complete response headers from curl.exe -I http://localhost:3001',
      'Scanner header module output — console output from --modules headers',
      'Comparison table — manual observations alongside scanner findings',
      'HTML report — the generated exercise02-headers.html report file',
      'Written answers to all 10 questions',
    ],
    checklist: [
      'Started the Juice Shop container using docker compose up -d',
      'Verified the target responds at http://localhost:3001',
      'Used curl to manually inspect response headers',
      'Checked for all five header categories',
      'Ran the scanner\'s header module with --modules headers',
      'Compared manual observations with scanner output',
      'Completed the comparison table',
      'Investigated Set-Cookie headers and flags',
      'Generated an HTML report',
      'Captured all required evidence',
    ],
  },
  {
    id: 3,
    number: '03',
    slug: 'path-discovery',
    title: 'Path Discovery',
    tagline: 'Discover accessible paths on the target and learn why SPAs create false positives.',
    module: 'Reconnaissance',
    duration: '40 min',
    level: 'Beginner',
    icon: 'radar',
    objectives: [
      'Understand common HTTP status codes and their significance in path discovery',
      'Explain what a wordlist is and how it is used',
      'Describe the scanner\'s path-discovery approach',
      'Understand why single-page applications can create false positives in path discovery',
      'Distinguish between discovered resources and security vulnerabilities',
    ],
    background: [
      {
        heading: 'What is path discovery?',
        paragraphs: [
          'Path discovery (also called directory brute-forcing or directory enumeration) is the process of probing a web application for paths that are not linked from the main page. These paths may reveal administrative interfaces, backup files, configuration files, documentation, debug endpoints, or sensitive data stores.',
          'Path discovery is a passive, non-destructive technique. It only sends GET and HEAD requests — the same types of requests your browser makes when you visit a webpage. It does not modify, delete, or upload anything.',
        ],
      },
      {
        heading: 'HTTP status codes that matter',
        table: {
          headers: ['Status', 'Meaning', 'Significance'],
          rows: [
            ['200', 'OK', 'Path exists and is publicly reachable — but may be a catch-all fallback'],
            ['301', 'Moved Permanently', 'Resource exists but has moved; check the Location header'],
            ['302', 'Found (temporary)', 'Temporary redirect; note the destination'],
            ['403', 'Forbidden', 'Path exists but access is denied — access control is working'],
            ['404', 'Not Found', 'Path does not exist (or the server hides its existence)'],
          ],
        },
      },
      {
        heading: 'Wordlists and the SPA false-positive problem',
        paragraphs: [
          'A wordlist is a plain text file containing a list of paths to probe, one per line — common admin paths, backup files, configuration files, and documentation. The scanner reads the wordlist and probes each entry against the target.',
          'A single-page application (SPA) like Juice Shop loads a single HTML shell and constructs the UI dynamically with JavaScript. When a non-existent path is requested, the SPA may still return the same shell with 200 OK. The scanner can then report false positives — paths that appear accessible but are not distinct resources.',
          'To reduce false positives, the scanner compares each 200 response against a baseline (the root path response). This is a heuristic: it reduces false positives but is not perfect. Always verify interesting paths manually in a browser.',
        ],
      },
    ],
    tasks: [
      {
        title: 'Manual path probing',
        steps: [
          'Use curl to manually probe several paths on the target',
          'Record the status code for each path — which returned 200? Which returned 404?',
        ],
        code: [
          { label: 'PowerShell', code: 'curl.exe -I http://localhost:3001/robots.txt\ncurl.exe -I http://localhost:3001/admin\ncurl.exe -I http://localhost:3001/backup.zip\ncurl.exe -I http://localhost:3001/.env\ncurl.exe -I http://localhost:3001/nonexistent-path-12345' },
        ],
      },
      {
        title: 'Run the scanner\'s path discovery module',
        steps: ['Run the scanner with only the paths module and record its findings'],
        code: [
          { label: 'PowerShell', code: 'cd C:\\Users\\devas\\Documents\\Cybersecurity\\Web-Security-Scanner\npython scanner.py --url http://localhost:3001 --modules paths' },
        ],
      },
      {
        title: 'Compare manual results with the scanner',
        steps: [
          'Create a comparison table: Path | Manual status code | Scanner reported? | Notes',
          'Note any differences between your curl results and the scanner output',
        ],
      },
      {
        title: 'Investigate discovered paths',
        steps: [
          'For each path the scanner reports as accessible, visit it in your browser',
          'Compare the content to the target\'s root page — unique resource or fallback response?',
        ],
      },
      {
        title: 'Generate an HTML report',
        steps: ['Run the paths module with --html-output to produce the exercise report'],
        code: [
          { label: 'PowerShell', code: 'python scanner.py --url http://localhost:3001 --modules paths --html-output reports/exercise03-paths.html' },
        ],
      },
    ],
    questions: [
      { q: 'What HTTP status did /robots.txt return?', format: 'status code', type: 'number', answers: ['200'] },
      { q: 'What HTTP status did /admin return?', format: 'status code', type: 'number', answers: ['200'] },
      { q: 'What HTTP status did /backup.zip return?', format: 'status code', type: 'number', answers: ['200'] },
      { q: 'What HTTP status did /.env return?', format: 'status code', type: 'number', answers: ['200'] },
      { q: 'What HTTP status did /nonexistent-path-12345 return?', format: 'status code', type: 'number', answers: ['200'] },
      { q: 'How many paths did the scanner report as accessible?', format: 'number', type: 'number', answers: ['2'] },
      { q: 'Which paths did the scanner report as accessible?', format: 'path; path', type: 'keywords', answers: ['/ftp', '/robots.txt'] },
      { q: 'Is an accessible path automatically a security vulnerability?', format: 'YES/NO', type: 'yesno', answers: ['NO'] },
      { q: 'What is the difference between a discovered resource and a security vulnerability?', format: 'short phrase', type: 'keywords', answers: ['resource', 'vulnerability'] },
      { q: 'Why can single-page applications create false positives in path discovery?', format: 'short phrase', type: 'keyword', answers: ['shell', 'fallback', 'nonexistent', 'non-existent', '200'] },
    ],
    evidence: [
      'Manual curl output — status codes for each probed path',
      'Scanner path discovery output — console output from --modules paths',
      'Comparison table — manual vs. scanner results',
      'Browser verification — screenshots of at least two discovered paths',
      'HTML report — the generated exercise03-paths.html report file',
      'Written answers to all 10 questions',
    ],
    checklist: [
      'Started the Juice Shop container using docker compose up -d',
      'Verified the target responds at http://localhost:3001',
      'Manually probed several paths using curl and recorded status codes',
      'Ran the scanner\'s path discovery module with --modules paths',
      'Compared manual observations with scanner output',
      'Investigated discovered paths in a browser',
      'Generated an HTML report',
      'Captured all required evidence',
    ],
  },
  {
    id: 4,
    number: '04',
    slug: 'safe-injection-indicators',
    title: 'Safe Injection Indicators',
    tagline: 'Understand safe, non-destructive injection testing and scanner limitations on SPAs.',
    module: 'Injection Testing',
    duration: '45 min',
    level: 'Intermediate',
    icon: 'syringe',
    objectives: [
      'Understand what an injection indicator is and what it is not',
      'Distinguish between an indicator and a confirmed exploitable vulnerability',
      'Explain the scanner\'s limited, non-destructive approach to injection testing',
      'Understand why a single-page application may produce zero injection findings',
      'Recognize that zero findings do not prove the absence of injection vulnerabilities',
    ],
    background: [
      {
        heading: 'Injection vulnerabilities and indicators',
        paragraphs: [
          'Injection vulnerabilities occur when an application sends untrusted data to an interpreter (such as an HTML parser or a SQL database) without proper validation or sanitization. The two most common types are SQL injection (SQLi) and cross-site scripting (XSS).',
          'An injection indicator is a signal observed during testing that suggests an injection vulnerability might exist. It is not proof of exploitability. Examples: a database error message in response to a single quote, or a test string like <script>alert(1)</script> being reflected in the response body.',
        ],
      },
      {
        heading: 'Indicator vs. confirmed exploitability',
        table: {
          headers: ['', 'Indicator', 'Confirmed Exploitability'],
          rows: [
            ['What it is', 'A signal that suggests a vulnerability might exist', 'A demonstrated ability to actively exploit a vulnerability'],
            ['What it proves', 'Something unusual was observed', 'An attacker can cause harm'],
            ['What it does NOT prove', 'That the vulnerability is exploitable', '—'],
            ['Example', 'A single quote causes a database error message', 'An attacker extracts the entire user database'],
          ],
        },
        after: [
          'An indicator may be a false positive, or inconclusive. Only manual verification can confirm whether an indicator represents a real, exploitable vulnerability. Your scanner reports indicators only — it does not claim exploitability.',
        ],
      },
      {
        heading: 'The scanner\'s safe approach',
        paragraphs: [
          'The scanner submits a small, fixed set of benign probes to each form field it discovers: special characters such as a single quote, double quote, and SQL comment syntax for SQLi; strings like <script>alert(1)</script> for XSS reflection checks.',
          'These probes contain no data extraction statements, no destructive commands, and no authentication bypass attempts. The scanner checks responses for known SQL error signatures and reflected probe strings. It uses only GET, HEAD, and POST — never PUT, PATCH, DELETE, or file uploads — and it never executes JavaScript.',
        ],
      },
      {
        heading: 'Why an SPA root page may produce zero findings',
        paragraphs: [
          'The injection module works by fetching the target\'s root page and parsing the HTML for <form> elements and their input fields. A single-page application like Juice Shop constructs its UI dynamically with JavaScript — the raw HTML may contain zero forms. With no forms discovered, the scanner has nowhere to submit probes.',
          'Zero injection findings may simply mean the scanner could not find any forms to test. It does not mean the application is free of injection vulnerabilities. Never present a zero-finding result as a clean bill of health — state what the scanner did and did not test, and recommend additional approaches such as browser-based or API testing.',
        ],
      },
    ],
    tasks: [
      {
        title: 'Run the scanner\'s injection module',
        steps: ['Run the scanner with only the injection module and record how many injection indicators were reported'],
        code: [
          { label: 'PowerShell', code: 'cd C:\\Users\\devas\\Documents\\Cybersecurity\\Web-Security-Scanner\npython scanner.py --url http://localhost:3001 --modules injection' },
        ],
      },
      {
        title: 'Investigate why the scanner may have found zero indicators',
        steps: [
          'Open http://localhost:3001 in your browser and view the page source (Ctrl+U)',
          'Count the <form>, <input>, <textarea>, and <select> elements present in the raw HTML',
        ],
      },
      {
        title: 'Compare your findings with the scanner\'s output',
        steps: [
          'Does the scanner\'s result match your manual observation of the page source?',
          'Explain the relationship between the number of forms on the page and the number of injection findings',
        ],
      },
      {
        title: 'Generate an HTML report',
        steps: ['Run the injection module with --html-output to produce the exercise report'],
        code: [
          { label: 'PowerShell', code: 'python scanner.py --url http://localhost:3001 --modules injection --html-output reports/exercise04-injection.html' },
        ],
      },
    ],
    questions: [
      { q: 'How many forms were found on the scanned page?', format: 'number', type: 'number', answers: ['0'] },
      { q: 'How many inputs were found on the scanned page?', format: 'number', type: 'number', answers: ['0'] },
      { q: 'How many injection indicators did the scanner report?', format: 'number', type: 'number', answers: ['0'] },
      { q: 'Does the scanner execute any JavaScript?', format: 'YES/NO', type: 'yesno', answers: ['NO'] },
      { q: 'Does zero injection findings prove there are no injection vulnerabilities?', format: 'YES/NO', type: 'yesno', answers: ['NO'] },
      { q: 'What is an injection indicator?', format: 'short phrase', type: 'keyword', answers: ['signal'], aliases: ['indicator'] },
      { q: 'What types of safe probes does the scanner use for SQL injection?', format: 'short phrase', type: 'keyword', answers: ['quote', 'comment', 'single quote', 'double quote'] },
      { q: 'What types of safe probes does the scanner use for XSS?', format: 'short phrase', type: 'keyword', answers: ['script', 'alert', 'reflect'] },
      { q: 'What is the difference between a scanner observation and a confirmed vulnerability?', format: 'short phrase', type: 'keyword', answers: ['observation', 'confirmed', 'noticed', 'demonstrated', 'exploited'] },
      { q: 'What additional approaches could you use for injection testing?', format: 'short phrase', type: 'keyword', answers: ['browser', 'api', 'authenticated', 'client-rendered', 'context-aware'] },
    ],
    evidence: [
      'Scanner injection module output — console output from --modules injection',
      'Page source observation — screenshot of the root page HTML source with element counts',
      'HTML report — the generated exercise04-injection.html report file',
      'Written answers to all 10 questions',
    ],
    checklist: [
      'Started the Juice Shop container using docker compose up -d',
      'Verified the target responds at http://localhost:3001',
      'Ran the scanner\'s injection module with --modules injection',
      'Examined the target\'s root page HTML source',
      'Counted the form, input, textarea, and select elements',
      'Compared manual observations with scanner output',
      'Generated an HTML report',
      'Captured all required evidence',
    ],
  },
  {
    id: 5,
    number: '05',
    slug: 'config-weaknesses',
    title: 'Configuration Weaknesses',
    tagline: 'Investigate configuration weaknesses and information disclosure on the target.',
    module: 'Configuration Review',
    duration: '40 min',
    level: 'Intermediate',
    icon: 'sliders',
    objectives: [
      'Understand what configuration weaknesses are and why they matter',
      'Identify common types of information disclosure',
      'Explain how the scanner performs non-destructive configuration checks',
      'Recognize the limitations of automated configuration testing on single-page applications',
      'Distinguish between an observation and a confirmed vulnerability',
    ],
    background: [
      {
        heading: 'Configuration weaknesses and information disclosure',
        paragraphs: [
          'Configuration weaknesses are security issues that arise from how an application is set up, rather than from flaws in the application\'s code: unnecessary features enabled, default settings left unchanged, sensitive information exposed in responses, debug modes left on, or missing security controls.',
          'Information disclosure occurs when an application reveals sensitive or unnecessary information — server software names and versions, framework versions, directory structures, debug messages, stack traces, or internal file paths. It is rarely critical on its own, but it gives attackers valuable reconnaissance: they can search for known CVEs in disclosed versions and plan more targeted attacks.',
        ],
      },
      {
        heading: 'What the scanner checks',
        list: [
          'Technology and version disclosure — examines response headers such as Server and X-Powered-By',
          'Directory listings — looks for indicators that a directory listing is being served',
          'Verbose errors and debug output — checks response bodies for error messages, stack traces, or debug information',
        ],
        after: [
          'The scanner does not exploit anything it finds, send write requests, or modify the target. It reports observations only — a disclosed technology or version is an observation, not proof of a vulnerability.',
        ],
      },
      {
        heading: 'The SPA limitation',
        paragraphs: [
          'An SPA returns the same HTML shell for all paths, including non-existent ones, so a malformed request will not produce a verbose error page. SPAs typically do not serve directory listings because routing is handled client-side. The scanner\'s configuration checks may therefore produce zero findings on an SPA — and zero findings do not mean the application has no configuration weaknesses.',
        ],
      },
    ],
    tasks: [
      {
        title: 'Manual header inspection',
        steps: [
          'Use curl to inspect the response headers on the target',
          'Look specifically for the Server header, X-Powered-By header, and any other technology-disclosing headers',
        ],
        code: [
          { label: 'PowerShell', code: 'curl.exe -I http://localhost:3001' },
        ],
      },
      {
        title: 'Run the scanner\'s configuration module',
        steps: ['Run the scanner with only the config module and record its findings'],
        code: [
          { label: 'PowerShell', code: 'cd C:\\Users\\devas\\Documents\\Cybersecurity\\Web-Security-Scanner\npython scanner.py --url http://localhost:3001 --modules config' },
        ],
      },
      {
        title: 'Compare your manual results with the scanner',
        steps: [
          'Create a comparison table: Check | Manual observation | Scanner reported? | Notes',
        ],
      },
      {
        title: 'Investigate the SPA limitation',
        steps: [
          'Based on what you learned in Exercise 04, explain why the configuration module may produce zero findings on this target',
        ],
      },
      {
        title: 'Generate an HTML report',
        steps: ['Run the config module with --html-output to produce the exercise report'],
        code: [
          { label: 'PowerShell', code: 'python scanner.py --url http://localhost:3001 --modules config --html-output reports/exercise05-config.html' },
        ],
      },
    ],
    questions: [
      { q: 'How many configuration findings did the scanner report?', format: 'number', type: 'number', answers: ['0'] },
      { q: 'Is the Server header present in the response?', format: 'PRESENT/MISSING', type: 'keyword', answers: ['MISSING'] },
      { q: 'Is the X-Powered-By header present in the response?', format: 'PRESENT/MISSING', type: 'keyword', answers: ['MISSING'] },
      { q: 'Does a disclosed technology automatically prove a vulnerability exists?', format: 'YES/NO', type: 'yesno', answers: ['NO'] },
      { q: 'What is a configuration weakness?', format: 'short phrase', type: 'keyword', answers: ['setup'], aliases: ['configuration'] },
      { q: 'What is information disclosure?', format: 'short phrase', type: 'keyword', answers: ['reveal'], aliases: ['disclosure'] },
      { q: 'What is directory listing?', format: 'short phrase', type: 'keyword', answers: ['Index of /'] },
      { q: 'What are verbose errors?', format: 'short phrase', type: 'keyword', answers: ['debug'], aliases: ['error'] },
      { q: 'Why do SPAs produce zero config findings?', format: 'short phrase', type: 'keyword', answers: ['shell', 'client-side', 'routing'] },
      { q: 'What is the difference between an observation and a confirmed vulnerability?', format: 'short phrase', type: 'keyword', answers: ['observation', 'confirmed', 'demonstrated', 'exploited'] },
    ],
    evidence: [
      'Manual curl output — complete response headers',
      'Scanner config module output — console output from --modules config',
      'Comparison table — manual vs. scanner results',
      'HTML report — the generated exercise05-config.html report file',
      'Written answers to all 10 questions',
    ],
    checklist: [
      'Started the Juice Shop container using docker compose up -d',
      'Verified the target responds at http://localhost:3001',
      'Used curl to manually inspect response headers',
      'Checked for Server and X-Powered-By headers',
      'Ran the scanner\'s configuration module with --modules config',
      'Compared manual observations with scanner output',
      'Explained the SPA limitation',
      'Generated an HTML report',
      'Captured all required evidence',
    ],
  },
  {
    id: 6,
    number: '06',
    slug: 'burp-suite-verification',
    title: 'Burp Suite Verification',
    tagline: 'Manually verify scanner observations using Burp Suite Community Edition.',
    module: 'Manual Verification',
    duration: '50 min',
    level: 'Intermediate',
    icon: 'crosshair',
    objectives: [
      'Set up Burp Suite Proxy with your browser',
      'Capture and inspect HTTP requests and responses',
      'Locate and examine HTTP response headers',
      'Compare manual Burp observations with scanner observations',
      'Understand the difference between an observation and a confirmed vulnerability',
    ],
    background: [
      {
        heading: 'Why manual verification matters',
        paragraphs: [
          'Automated tools have limitations: they may produce false positives (reporting something that is not actually a problem), false negatives (missing issues a human would catch), and they cannot always determine the practical significance of a finding.',
          'Manual verification is the process of independently confirming — or refuting — a scanner\'s findings using your own tools and judgment. In this exercise, you will use Burp Suite to manually verify the header observations from Exercise 02.',
        ],
      },
      {
        heading: 'Burp Proxy basics',
        paragraphs: [
          'Burp Proxy sits between your browser and the web server. It intercepts all HTTP traffic, allowing you to view every request your browser sends and every response the server returns. Key concepts: Proxy (intercepts traffic), Intercept (pauses requests for inspection), HTTP History (log of captured traffic).',
        ],
      },
    ],
    tasks: [
      {
        title: 'Set up Burp Suite Proxy',
        steps: [
          'Open Burp Suite Community Edition and go to Proxy → Options',
          'Ensure a proxy listener is bound to port 8080 on loopback only (127.0.0.1)',
          'Configure your browser (Firefox recommended) to use manual proxy 127.0.0.1:8080 for all protocols',
          'HTTP only — no CA certificate install is needed for this exercise',
          'Verify the proxy works: with Intercept on, browse to http://localhost:3001 and Forward the request',
        ],
      },
      {
        title: 'Capture a request and response',
        steps: [
          'Capture a GET / request to http://localhost:3001 and examine the response',
        ],
      },
      {
        title: 'Examine the response headers',
        steps: [
          'Record all headers in the complete response header block (Proxy → HTTP History also works)',
        ],
      },
      {
        title: 'Verify the two header observations',
        steps: [
          'Verification 1: determine whether Content-Security-Policy is present or absent in the raw response',
          'Verification 2: determine whether Strict-Transport-Security is present or absent in the raw response',
        ],
      },
      {
        title: 'Run the scanner\'s header module',
        steps: ['Re-run the header module so you can compare its output with your Burp capture'],
        code: [
          { label: 'PowerShell', code: 'cd C:\\Users\\devas\\Documents\\Cybersecurity\\Web-Security-Scanner\npython scanner.py --url http://localhost:3001 --modules headers' },
        ],
      },
      {
        title: 'Compare Burp observations with scanner output',
        steps: [
          'Complete the comparison table: Header | Scanner observation | Burp observation | Match?',
          'Note any discrepancies and explain possible reasons (same URL? redirects? configuration differences?)',
        ],
      },
      {
        title: 'Capture screenshots',
        steps: [
          'Burp intercept view, response headers, scanner output, and your comparison table',
        ],
      },
    ],
    questions: [
      { q: 'What HTTP status did Burp observe?', format: 'status code', type: 'number', answers: ['200'] },
      { q: 'Did Burp observation of CSP match the scanner?', format: 'MATCH/DIFFER', type: 'keyword', answers: ['MATCH'] },
      { q: 'Did Burp observation of HSTS match the scanner?', format: 'MATCH/DIFFER', type: 'keyword', answers: ['MATCH'] },
      { q: 'Is CSP present in the Burp response?', format: 'PRESENT/MISSING', type: 'keyword', answers: ['MISSING'] },
      { q: 'Is HSTS present in the Burp response?', format: 'PRESENT/MISSING', type: 'keyword', answers: ['MISSING'] },
      { q: 'Does a missing security header automatically represent an exploitable vulnerability?', format: 'YES/NO', type: 'yesno', answers: ['NO'] },
      { q: 'What is the difference between an observation and a confirmed vulnerability?', format: 'short phrase', type: 'keyword', answers: ['observation', 'confirmed', 'demonstrated', 'exploited'] },
      { q: 'Why is manual verification important?', format: 'short phrase', type: 'keyword', answers: ['verification', 'confirm', 'confirming', 'refuting'] },
      { q: 'What are the limitations of automated scanning?', format: 'short phrase', type: 'keyword', answers: ['false positive', 'false negative', 'coverage', 'context'] },
      { q: 'What did you learn from comparing Burp with scanner output?', format: 'short phrase', type: 'keyword', answers: ['matched', 'confirmed', 'match'] },
    ],
    evidence: [
      'Burp intercept screenshot — intercepted request to http://localhost:3001',
      'Burp response headers screenshot — complete response header block for GET /',
      'Scanner output screenshot — header module output for comparison',
      'Comparison table — Burp vs. scanner',
      'Written answers to all 10 questions',
    ],
    checklist: [
      'Started the Juice Shop container using docker compose up -d',
      'Installed and launched Burp Suite Community Edition',
      'Configured Burp Proxy listener on port 8080',
      'Configured your browser to use Burp Proxy',
      'Captured a request to http://localhost:3001 in Burp Suite',
      'Examined the complete response header block',
      'Manually verified the two header-related observations',
      'Ran the scanner\'s header module',
      'Compared Burp observations with scanner output',
      'Captured all required screenshots',
    ],
  },
  {
    id: 7,
    number: '07',
    slug: 'evidence-and-screenshots',
    title: 'Evidence and Screenshots',
    tagline: 'Compile and organize all evidence into a professional lab submission.',
    module: 'Reporting',
    duration: '45 min',
    level: 'Beginner',
    icon: 'folder',
    objectives: [
      'Understand why evidence matters in security testing',
      'Organize scanner output, HTML reports, and screenshots',
      'Apply consistent naming conventions to evidence files',
      'Distinguish between observations, indicators, and confirmed vulnerabilities',
      'Maintain honesty and integrity in security reporting',
    ],
    background: [
      {
        heading: 'Why evidence matters',
        paragraphs: [
          'In security testing, evidence is the proof that supports your findings. Without evidence, a security assessment is just a collection of opinions. Evidence supports your findings, enables verification by others, provides context, demonstrates professionalism, and creates accountability for what you tested, how you tested it, and what you found.',
        ],
      },
      {
        heading: 'Three distinct concepts',
        table: {
          headers: ['Concept', 'Definition', 'Example'],
          rows: [
            ['Observation', 'Something you noticed during testing', 'The Content-Security-Policy header is absent from the response'],
            ['Indicator', 'A signal that suggests a vulnerability might exist', 'A SQL error message appeared when a single quote was sent'],
            ['Confirmed vulnerability', 'A demonstrated security flaw that can be exploited', 'An attacker extracts the user database via UNION-based SQL injection'],
          ],
        },
        after: [
          'In this lab you are not expected to confirm vulnerabilities. Use the term "confirmed vulnerability" only if you have actively demonstrated exploitation.',
        ],
      },
      {
        heading: 'Evidence honesty',
        paragraphs: [
          'All evidence must be genuine (captured from your own testing of the authorized target), accurate, complete, and reproducible. Do not fabricate scanner output or screenshots, copy evidence from other students, use evidence from unauthorized targets, or alter screenshots to change their meaning. Fabrication is academic dishonesty.',
        ],
      },
      {
        heading: 'Naming conventions',
        paragraphs: ['Use the pattern exercise<NN>-<description>-<sequence>.png — for example exercise01-console-output-01.png, exercise02-curl-headers-01.png, exercise06-burp-intercept-01.png. Lowerercase letters and hyphens, exercise number included, brief content description, sequence number for multiples.'],
      },
    ],
    tasks: [
      {
        title: 'Gather all evidence',
        steps: [
          'Collect scanner console output, HTML reports, curl output, Burp Suite screenshots, comparison tables, and page source observations from Exercises 01–06',
        ],
      },
      {
        title: 'Organize evidence',
        steps: [
          'Use one folder per exercise (exercise01/ ... exercise06/) plus a report/ folder for lab-report.md, or a single folder with the naming conventions above',
        ],
      },
      {
        title: 'Verify evidence quality',
        steps: [
          'Every screenshot must be clear and readable, show the target URL http://localhost:3001, be complete, unedited, and relevant to its filename',
        ],
      },
      {
        title: 'Write your lab report',
        steps: [
          'Reference your evidence files, clearly distinguish observations from confirmed vulnerabilities, and provide analysis and recommendations',
        ],
      },
      {
        title: 'Final review',
        steps: [
          'Verify all required evidence is present, properly named, and genuine — and that your reflection questions are answered',
        ],
      },
    ],
    questions: [
      { q: 'Why is evidence important in security testing?', format: 'short phrase', type: 'keyword', answers: ['proof', 'support', 'verification', 'context', 'professionalism', 'accountability'] },
      { q: 'What is the difference between an observation, an indicator, and a confirmed vulnerability?', format: 'short phrase', type: 'keyword', answers: ['observation', 'indicator', 'confirmed'] },
      { q: 'What challenges did you face when capturing evidence?', format: 'short phrase', type: 'keyword', answers: ['organize', 'naming', 'gather', 'organizing', 'naming conventions'] },
      { q: 'How did comparing manual and scanner output change your understanding?', format: 'short phrase', type: 'keyword', answers: ['limitation', 'capability', 'verification', 'comparison'] },
      { q: 'Why is it important to report zero findings with caveats?', format: 'short phrase', type: 'keyword', answers: ['caveat', 'limitation', 'clean bill of health', 'not prove'] },
      { q: 'What did you learn about honesty and integrity?', format: 'short phrase', type: 'keyword', answers: ['honest', 'integrity', 'genuine', 'fabricate', 'fabrication'] },
      { q: 'How would you ensure evidence quality in a professional assessment?', format: 'short phrase', type: 'keyword', answers: ['quality', 'genuine', 'accurate', 'reproducible', 'complete', 'clear', 'readable'] },
      { q: 'How has this lab changed your perspective on scanning tools?', format: 'short phrase', type: 'keyword', answers: ['limitation', 'manual', 'complement', 'assist', 'triage'] },
    ],
    evidence: [
      'All scanner console output from Exercises 01–05 (screenshots or text files)',
      'All generated HTML report files',
      'curl header output and comparison tables from Exercises 02 and 03',
      'Page source observation from Exercise 04',
      'Burp Suite screenshots from Exercise 06',
      'Completed lab report referencing all evidence files',
    ],
    checklist: [
      'All evidence is from the authorized target (http://localhost:3001)',
      'All screenshots are clear and readable',
      'All files are properly named and organized',
      'Lab report is complete and references evidence files',
      'No fabricated evidence',
      'Reflection questions answered',
    ],
  },
];

export const AUTHORIZATION = {
  target: 'http://localhost:3001',
  targetName: 'OWASP Juice Shop',
  scope: 'LOCAL LAB ONLY',
  authorized: [
    'The local Docker container running on your own machine',
    'The specific URL http://localhost:3001',
    'The duration of this lab exercise',
  ],
  prohibited: [
    'Scanning or testing any target other than http://localhost:3001',
    'Credential attacks, brute-forcing, or password guessing',
    'Privilege escalation or authentication bypass',
    'Data extraction beyond what the exercises require',
    'Destructive actions — deleting, modifying, or corrupting data',
    'Modifying the Juice Shop container, application, or configuration',
    'Automated exploitation or denial of service',
  ],
};
