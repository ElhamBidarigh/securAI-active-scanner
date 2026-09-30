<?php
declare(strict_types=1);
require 'scanner.php';

$result = null;
$error  = '';
$url    = $_GET['url'] ?? '';

// Basic rate limiting via session
session_start();
$now = time();
$_SESSION['scans'] = array_filter($_SESSION['scans'] ?? [], fn($t) => $t > $now - 3600);
$canScan = count($_SESSION['scans']) < 10;

if ($url !== '' && $canScan) {
    // Basic SSRF protection: no localhost, no private IPs
    $host = parse_url(preg_match('#^https?://#i', $url) ? $url : 'https://' . $url, PHP_URL_HOST) ?? '';
    $blocked = false;
    if ($host && (filter_var($host, FILTER_VALIDATE_IP)
        ? !filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)
        : preg_match('/^(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|169\.254\.|::1)/i', $host))) {
        $blocked = true;
    }

    if ($blocked) {
        $error = 'Scanning private/local addresses is not allowed.';
    } else {
        try {
            $scanner = new SecurAIScanner($url);
            $result  = $scanner->run();
            $_SESSION['scans'][] = $now;
        } catch (Throwable $e) {
            $error = 'Scan failed: ' . htmlspecialchars($e->getMessage());
        }
    }
} elseif (!$canScan && $url !== '') {
    $error = 'Rate limit: max 10 scans per hour.';
}

function sev_class(string $s): string { return 'sev-' . $s; }
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>SecurAI Active Scanner</title>
<link rel="stylesheet" href="style.css">
</head>
<body>
<div class="wrap">
  <header>
    <div class="logo"><div class="mark">S</div><span>SecurAI Active Scanner</span></div>
    <p class="sub">Non-destructive security checks. Only scan sites you own or have written permission to test.</p>
  </header>

  <form method="GET" class="scan-form">
    <input type="url" name="url" placeholder="https://example.com" value="<?= htmlspecialchars($url) ?>" required>
    <button type="submit" <?= !$canScan ? 'disabled' : '' ?>>Scan</button>
  </form>

  <p class="quota">Scans used this hour: <b><?= count($_SESSION['scans'] ?? []) ?></b> / 10</p>

  <?php if ($error): ?>
    <div class="error"><?= $error ?></div>
  <?php endif; ?>

  <?php if ($result): ?>
    <?php $s = $result['summary']; ?>
    <section class="report">
      <div class="head">
        <div class="gauge" style="--score:<?= $s['score'] ?>">
          <div class="num"><?= $s['score'] ?></div>
          <div class="lbl">/ 100</div>
        </div>
        <div class="meta">
          <h2><?= htmlspecialchars($result['target']) ?></h2>
          <p>HTTP <?= $result['status'] ?> · <?= $result['response_time'] ?>s · <?= count($result['findings']) ?> finding(s)</p>
          <div class="counts">
            <span class="chip c-crit"><?= $s['counts']['critical'] ?> Critical</span>
            <span class="chip c-high"><?= $s['counts']['high'] ?> High</span>
            <span class="chip c-med"><?= $s['counts']['medium'] ?> Medium</span>
            <span class="chip c-low"><?= $s['counts']['low'] ?> Low</span>
          </div>
        </div>
      </div>

      <?php if (empty($result['findings'])): ?>
        <div class="clean">✅ No issues found. Excellent.</div>
      <?php else: ?>
        <?php
        usort($result['findings'], fn($a,$b) => array_search($b['sev'],['critical','high','medium','low'])
                                          <=> array_search($a['sev'],['critical','high','medium','low']));
        foreach ($result['findings'] as $f): ?>
          <div class="finding <?= sev_class($f['sev']) ?>">
            <div class="row">
              <span class="sev <?= sev_class($f['sev']) ?>"><?= strtoupper($f['sev']) ?></span>
              <span class="cat"><?= htmlspecialchars($f['cat']) ?></span>
            </div>
            <h3><?= htmlspecialchars($f['title']) ?></h3>
            <p><?= htmlspecialchars($f['detail']) ?></p>
            <div class="fix"><b>Fix:</b> <?= htmlspecialchars($f['fix']) ?></div>
          </div>
        <?php endforeach; ?>
      <?php endif; ?>
    </section>
  <?php endif; ?>

<footer>
    SecurAI Active Scanner ·
    <a href="https://github.com/ElhamBidarigh/securAI-active-scanner">GitHub</a> ·
    Need a self-assessment instead?
    <a href="https://elhambidarigh.github.io/securai/">Try the 31-point checklist →</a>
  </footer>
</div>
</body>
</html>
