<?php
declare(strict_types=1);

/**
 * SecurAI Active Scanner
 * Non-destructive security checks against a target URL.
 * Only use on sites you own or have written permission to test.
 */

class SecurAIScanner
{
    private string $url;
    private string $host;
    private string $scheme;
    private array  $findings = [];
    private array  $headers  = [];
    private int    $statusCode = 0;
    private string $body = '';
    private float  $responseTime = 0;

    public function __construct(string $url)
    {
        $url = trim($url);
        if (!preg_match('#^https?://#i', $url)) {
            $url = 'https://' . $url;
        }
        $this->url    = rtrim($url, '/');
        $parts        = parse_url($this->url);
        $this->host   = $parts['host'] ?? '';
        $this->scheme = $parts['scheme'] ?? 'https';

        if ($this->host === '') {
            throw new InvalidArgumentException('Invalid URL');
        }
    }

    public function run(): array
    {
        $this->fetchTarget();
        $this->checkHttpsRedirect();
        $this->checkSecurityHeaders();
        $this->checkServerDisclosure();
        $this->checkCookieFlags();
        $this->checkCorsMisconfig();
        $this->checkDotFiles();
        $this->checkRobotsTxt();
        $this->checkDirectoryListing();
        $this->checkHttpMethods();
        $this->checkOpenRedirect();
        $this->checkHttpToHttps();

        return [
            'target'        => $this->url,
            'status'        => $this->statusCode,
            'response_time' => round($this->responseTime, 3),
            'findings'      => $this->findings,
            'summary'       => $this->summary(),
        ];
    }

    // ─────────────────────────────────────────────
    private function fetchTarget(): void
    {
        $ch = curl_init($this->url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADER         => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_TIMEOUT        => 10,
            CURLOPT_USERAGENT      => 'SecurAI-Scanner/1.0 (+https://github.com/elham-bidarigh/securAI-active-scanner)',
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
        ]);
        $t0 = microtime(true);
        $raw = curl_exec($ch);
        $this->responseTime = microtime(true) - $t0;
        $this->statusCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $headerSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);

        if ($raw !== false) {
            $headerText = substr($raw, 0, $headerSize);
            $this->body = substr($raw, $headerSize);
            $this->headers = $this->parseHeaders($headerText);
        }
        curl_close($ch);
    }

    private function parseHeaders(string $text): array
    {
        $headers = [];
        foreach (explode("\n", $text) as $line) {
            if (str_contains($line, ':')) {
                [$k, $v] = explode(':', $line, 2);
                $headers[strtolower(trim($k))] = trim($v);
            }
        }
        return $headers;
    }

    private function add(string $id, string $sev, string $cat, string $title, string $detail, string $fix): void
    {
        $this->findings[] = compact('id','sev','cat','title','detail','fix');
    }

    // ─────────────────────────────────────────────
    // CHECK 1: HTTPS redirect
    // ─────────────────────────────────────────────
    private function checkHttpsRedirect(): void
    {
        if ($this->scheme !== 'https') return;

        $http = 'http://' . $this->host;
        $ch = curl_init($http);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADER         => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_TIMEOUT        => 8,
            CURLOPT_NOBODY         => true,
        ]);
        curl_exec($ch);
        $loc = curl_getinfo($ch, CURLINFO_REDIRECT_URL);
        curl_close($ch);

        if (!$loc || !str_starts_with(strtolower($loc), 'https://')) {
            $this->add('https-redirect','high','Transport',
                'HTTP does not redirect to HTTPS',
                'Plain HTTP is served without a redirect to HTTPS. Session tokens and user data can be intercepted.',
                'Configure your web server to return 301 to HTTPS for all HTTP requests, and add HSTS.');
        }
    }

    // ─────────────────────────────────────────────
    // CHECK 2: Security headers
    // ─────────────────────────────────────────────
    private function checkSecurityHeaders(): void
    {
        $required = [
            'strict-transport-security' => [
                'title' => 'Missing HSTS header',
                'sev'   => 'medium',
                'fix'   => 'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
            ],
            'content-security-policy' => [
                'title' => 'Missing Content-Security-Policy',
                'sev'   => 'high',
                'fix'   => "Add a CSP, e.g. Content-Security-Policy: default-src 'self'; script-src 'self'",
            ],
            'x-content-type-options' => [
                'title' => 'Missing X-Content-Type-Options',
                'sev'   => 'low',
                'fix'   => 'Add: X-Content-Type-Options: nosniff',
            ],
            'x-frame-options' => [
                'title' => 'Missing X-Frame-Options',
                'sev'   => 'medium',
                'fix'   => 'Add: X-Frame-Options: DENY (or use CSP frame-ancestors)',
            ],
            'referrer-policy' => [
                'title' => 'Missing Referrer-Policy',
                'sev'   => 'low',
                'fix'   => 'Add: Referrer-Policy: strict-origin-when-cross-origin',
            ],
            'permissions-policy' => [
                'title' => 'Missing Permissions-Policy',
                'sev'   => 'low',
                'fix'   => 'Add: Permissions-Policy: geolocation=(), camera=(), microphone=()',
            ],
        ];

        foreach ($required as $h => $meta) {
            if (!isset($this->headers[$h])) {
                $this->add('hdr-' . $h, $meta['sev'], 'Headers', $meta['title'],
                    "The response is missing the {$h} header.", $meta['fix']);
            }
        }

        // Weak HSTS
        if (isset($this->headers['strict-transport-security'])) {
            $hsts = $this->headers['strict-transport-security'];
            if (!preg_match('/max-age=(\d+)/', $hsts, $m) || (int)$m[1] < 15552000) {
                $this->add('hsts-weak','medium','Transport',
                    'Weak HSTS max-age',
                    "HSTS max-age is less than 180 days: {$hsts}",
                    'Set max-age=31536000 (1 year) or higher.');
            }
        }
    }

    // ─────────────────────────────────────────────
    // CHECK 3: Server disclosure
    // ─────────────────────────────────────────────
    private function checkServerDisclosure(): void
    {
        if (isset($this->headers['server'])) {
            $this->add('srv-header','low','Disclosure',
                'Server header discloses software',
                'Server: ' . $this->headers['server'],
                'Hide or generalize the Server header in your web server config.');
        }
        if (isset($this->headers['x-powered-by'])) {
            $this->add('xpb','low','Disclosure',
                'X-Powered-By leaks technology stack',
                'X-Powered-By: ' . $this->headers['x-powered-by'],
                'Set expose_php=Off in php.ini and remove the header.');
        }
    }

    // ─────────────────────────────────────────────
    // CHECK 4: Cookie flags
    // ─────────────────────────────────────────────
    private function checkCookieFlags(): void
    {
        $raw = '';
        foreach ($this->headers as $k => $v) {
            if ($k === 'set-cookie') $raw .= $v . "\n";
        }
        // Also parse raw headers for multiple Set-Cookie lines
        $ch = curl_init($this->url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADER         => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_TIMEOUT        => 8,
            CURLOPT_NOBODY         => true,
        ]);
        $resp = curl_exec($ch);
        curl_close($ch);
        if ($resp && preg_match_all('/^Set-Cookie:\s*(.+)$/mi', $resp, $m)) {
            foreach ($m[1] as $cookie) {
                $name = strtok($cookie, '=');
                if (!preg_match('/;\s*Secure/i', $cookie)) {
                    $this->add('cookie-secure','medium','Cookies',
                        "Cookie '{$name}' missing Secure flag",
                        "Cookie sent over HTTP can be intercepted.",
                        'Add ; Secure to the Set-Cookie header.');
                }
                if (!preg_match('/;\s*HttpOnly/i', $cookie)) {
                    $this->add('cookie-httponly','medium','Cookies',
                        "Cookie '{$name}' missing HttpOnly flag",
                        'JavaScript can read this cookie — XSS leads to session theft.',
                        'Add ; HttpOnly to the Set-Cookie header.');
                }
                if (!preg_match('/;\s*SameSite/i', $cookie)) {
                    $this->add('cookie-samesite','low','Cookies',
                        "Cookie '{$name}' missing SameSite attribute",
                        'May be sent on cross-site requests.',
                        'Add ; SameSite=Lax or ; SameSite=Strict.');
                }
            }
        }
    }

    // ─────────────────────────────────────────────
    // CHECK 5: CORS misconfiguration
    // ─────────────────────────────────────────────
    private function checkCorsMisconfig(): void
    {
        $ch = curl_init($this->url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADER         => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_TIMEOUT        => 8,
            CURLOPT_NOBODY         => true,
            CURLOPT_HTTPHEADER     => ['Origin: https://evil.example'],
        ]);
        $resp = curl_exec($ch);
        curl_close($ch);

        if ($resp && preg_match('/Access-Control-Allow-Origin:\s*(.+)/i', $resp, $m)) {
            $acao = trim($m[1]);
            $creds = preg_match('/Access-Control-Allow-Credentials:\s*true/i', $resp);
            if ($acao === '*' && $creds) {
                $this->add('cors-wild','critical','CORS',
                    'Wildcard CORS with credentials',
                    'Access-Control-Allow-Origin: * combined with Allow-Credentials: true allows any site to read authenticated responses.',
                    'Whitelist exact origins; never use * with credentials.');
            } elseif ($acao === 'https://evil.example') {
                $this->add('cors-reflect','high','CORS',
                    'CORS reflects arbitrary Origin',
                    "Server echoed back the attacker's Origin.",
                    'Validate Origin against an allowlist.');
            }
        }
    }

    // ─────────────────────────────────────────────
    // CHECK 6: Dot files
    // ─────────────────────────────────────────────
    private function checkDotFiles(): void
    {
        $targets = [
            '/.git/HEAD' => 'Git repository exposed — full source code may be downloadable.',
            '/.env'      => 'Environment file exposed — credentials may be leaked.',
            '/.htaccess' => 'Apache config exposed.',
            '/.DS_Store' => 'macOS metadata exposed.',
        ];
        foreach ($targets as $path => $desc) {
            $code = $this->head($this->url . $path);
            if ($code === 200) {
                $this->add('dot' . str_replace(['/', '.'], '-', $path),
                    $path === '/.env' || $path === '/.git/HEAD' ? 'critical' : 'high',
                    'Disclosure',
                    "Exposed file: {$path}",
                    $desc,
                    "Block access to {$path} in your web server or reverse proxy.");
            }
        }
    }

    // ─────────────────────────────────────────────
    // CHECK 7: robots.txt
    // ─────────────────────────────────────────────
    private function checkRobotsTxt(): void
    {
        $code = $this->head($this->url . '/robots.txt');
        if ($code !== 200) return;

        $body = @file_get_contents($this->url . '/robots.txt', false,
            stream_context_create(['http' => ['timeout' => 6]]));
        if ($body === false) return;

        $sensitive = ['admin','backup','private','staging','dev','test','api','internal'];
        $hits = [];
        foreach (explode("\n", $body) as $line) {
            if (preg_match('/^Disallow:\s*(.+)/i', $line, $m)) {
                foreach ($sensitive as $word) {
                    if (stripos($m[1], $word) !== false) {
                        $hits[] = trim($m[1]);
                        break;
                    }
                }
            }
        }
        if ($hits) {
            $this->add('robots','low','Disclosure',
                'robots.txt exposes sensitive paths',
                'Paths found: ' . implode(', ', array_slice($hits, 0, 5)),
                'robots.txt is public. Move sensitive paths behind auth — not to robots.txt.');
        }
    }

    // ─────────────────────────────────────────────
    // CHECK 8: Directory listing
    // ─────────────────────────────────────────────
    private function checkDirectoryListing(): void
    {
        foreach (['/uploads/', '/files/', '/backup/', '/images/'] as $dir) {
            $code = $this->head($this->url . $dir);
            if ($code !== 200) continue;

            $body = @file_get_contents($this->url . $dir, false,
                stream_context_create(['http' => ['timeout' => 6]]));
            if ($body && preg_match('/<title>Index of/i', $body)) {
                $this->add('dirlist-' . trim($dir, '/'), 'medium', 'Disclosure',
                    "Directory listing enabled: {$dir}",
                    'Anyone can browse the contents of this directory.',
                    'Disable auto-index in your web server (Options -Indexes in Apache).');
            }
        }
    }

    // ─────────────────────────────────────────────
    // CHECK 9: HTTP methods
    // ─────────────────────────────────────────────
    private function checkHttpMethods(): void
    {
        foreach (['TRACE','PUT','DELETE'] as $m) {
            $ch = curl_init($this->url);
            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_CUSTOMREQUEST  => $m,
                CURLOPT_NOBODY         => true,
                CURLOPT_TIMEOUT        => 6,
            ]);
            curl_exec($ch);
            $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);

            if ($m === 'TRACE' && $code === 200) {
                $this->add('trace','medium','Methods',
                    'TRACE method enabled',
                    'TRACE can be used in Cross-Site Tracing (XST) attacks.',
                    'Disable TRACE in your web server: TraceEnable off');
            }
            if (in_array($m, ['PUT','DELETE']) && in_array($code, [200, 201, 204])) {
                $this->add('method-' . strtolower($m),'high','Methods',
                    "{$m} method allowed on root URL",
                    "Unrestricted write methods on the base URL can allow file overwrite.",
                    "Restrict {$m} to authenticated endpoints only.");
            }
        }
    }

    // ─────────────────────────────────────────────
    // CHECK 10: Open redirect (safe — no follow)
    // ─────────────────────────────────────────────
    private function checkOpenRedirect(): void
    {
        $params = ['redirect','url','next','return','returnUrl','dest','continue'];
        $payload = 'https://evil.example/pwned';

        foreach ($params as $p) {
            $test = $this->url . '/?' . $p . '=' . urlencode($payload);
            $ch = curl_init($test);
            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_HEADER         => true,
                CURLOPT_FOLLOWLOCATION => false,
                CURLOPT_TIMEOUT        => 6,
                CURLOPT_NOBODY         => true,
            ]);
            curl_exec($ch);
            $loc = curl_getinfo($ch, CURLINFO_REDIRECT_URL);
            curl_close($ch);

            if ($loc && str_contains($loc, 'evil.example')) {
                $this->add('openredirect-' . $p,'high','Redirect',
                    "Open redirect via '{$p}' parameter",
                    "The server redirects to an arbitrary URL provided in '{$p}'. Used in phishing.",
                    'Validate redirect targets against an allowlist of internal paths.');
                return;
            }
        }
    }

    // ─────────────────────────────────────────────
    // CHECK 11: HTTP → HTTPS upgrade
    // ─────────────────────────────────────────────
    private function checkHttpToHttps(): void
    {
        // Already covered in checkHttpsRedirect
    }

    // ─────────────────────────────────────────────
    private function head(string $url): int
    {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_NOBODY         => true,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => 6,
            CURLOPT_FOLLOWLOCATION => false,
        ]);
        curl_exec($ch);
        $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        return $code;
    }

    private function summary(): array
    {
        $counts = ['critical'=>0,'high'=>0,'medium'=>0,'low'=>0];
        foreach ($this->findings as $f) {
            $counts[$f['sev']] = ($counts[$f['sev']] ?? 0) + 1;
        }
        $weights = ['critical'=>10,'high'=>6,'medium'=>3,'low'=>1];
        $max = count($this->findings) * 10 ?: 1;
        $penalty = 0;
        foreach ($counts as $sev => $n) {
            $penalty += $n * $weights[$sev];
        }
        $score = max(0, 100 - (int) round($penalty / max($max, 1) * 100));
        return ['counts' => $counts, 'score' => $score];
    }
}