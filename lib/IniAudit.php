<?php
declare(strict_types=1);

namespace IniAudit;

const RANK = ['critical' => 0, 'high' => 1, 'medium' => 2, 'low' => 3, 'info' => 4];
const DANGEROUS = ['exec', 'system', 'passthru', 'shell_exec', 'proc_open', 'popen'];

final class Finding
{
    public function __construct(
        public string $sev,
        public string $rule,
        public string $where,
        public string $msg
    ) {
    }
}

/**
 * Parses php.ini text. Returns [settings, notes]:
 *   settings: key => ['value' => string, 'line' => int]  (last assignment wins)
 *   notes:    list of ['line' => int, 'text' => string]  (lines that were ignored)
 */
function parse(string $text): array
{
    $settings = [];
    $notes = [];
    $lines = preg_split('/\r\n|\n|\r/', $text) ?: [];
    foreach ($lines as $i => $raw) {
        $n = $i + 1;
        $line = trim($raw);
        if ($line === '' || $line[0] === ';' || $line[0] === '#') {
            continue;
        }
        if ($line[0] === '[') {
            continue; // section header
        }
        $eq = strpos($line, '=');
        if ($eq === false) {
            $notes[] = ['line' => $n, 'text' => substr($line, 0, 40)];
            continue;
        }
        $key = strtolower(trim(substr($line, 0, $eq)));
        if ($key === '' || preg_match('/^[a-z0-9_.\[\]]+$/', $key) !== 1) {
            $notes[] = ['line' => $n, 'text' => substr($line, 0, 40)];
            continue;
        }
        $settings[$key] = ['value' => value(substr($line, $eq + 1)), 'line' => $n];
    }
    return [$settings, $notes];
}

/** Strips quotes and trailing comments from a raw value. */
function value(string $raw): string
{
    $raw = trim($raw);
    if ($raw === '') {
        return '';
    }
    $q = $raw[0];
    if ($q === '"' || $q === "'") {
        $end = strpos($raw, $q, 1);
        return $end === false ? substr($raw, 1) : substr($raw, 1, $end - 1);
    }
    $semi = strpos($raw, ';');
    if ($semi !== false) {
        $raw = substr($raw, 0, $semi);
    }
    return trim($raw);
}

/** true for On/1/true/yes, false for Off/0/false/no/none/empty, null for anything else. */
function truthy(?string $v): ?bool
{
    if ($v === null) {
        return null;
    }
    $v = strtolower(trim($v));
    if (in_array($v, ['1', 'on', 'true', 'yes'], true)) {
        return true;
    }
    if (in_array($v, ['', '0', 'off', 'false', 'no', 'none'], true)) {
        return false;
    }
    return null;
}

/** @return Finding[] */
function audit(string $text, string $label): array
{
    [$s, $notes] = parse($text);
    $out = [];
    $at = static fn (string $k): string => $label . ':' . $s[$k]['line'];
    $on = static fn (string $k): bool => isset($s[$k]) && truthy($s[$k]['value']) === true;

    foreach ($notes as $n) {
        $out[] = new Finding('info', 'PHP000', $label . ':' . $n['line'], 'not a setting, ignored: ' . $n['text']);
    }
    if ($on('allow_url_include')) {
        $out[] = new Finding('high', 'PHP001', $at('allow_url_include'), 'allow_url_include is on: include and require can load remote code');
    }
    if ($on('allow_url_fopen')) {
        $out[] = new Finding('medium', 'PHP002', $at('allow_url_fopen'), 'allow_url_fopen is on: file functions can fetch URLs, which turns path bugs into SSRF');
    }
    if ($on('display_errors')) {
        $out[] = new Finding('medium', 'PHP003', $at('display_errors'), 'display_errors is on: errors with paths and queries are sent to visitors');
    } elseif (isset($s['display_errors']) && strtolower($s['display_errors']['value']) === 'stdout') {
        $out[] = new Finding('medium', 'PHP003', $at('display_errors'), 'display_errors is stdout: errors are sent to visitors');
    }
    if ($on('expose_php')) {
        $out[] = new Finding('low', 'PHP004', $at('expose_php'), 'expose_php is on: X-Powered-By reveals the PHP version');
    }
    $df = isset($s['disable_functions']) ? array_map('trim', explode(',', strtolower($s['disable_functions']['value']))) : [];
    if (count(array_intersect($df, DANGEROUS)) === 0) {
        $where = isset($s['disable_functions']) ? $at('disable_functions') : $label . ':1';
        $out[] = new Finding('medium', 'PHP005', $where, 'disable_functions does not block any of: ' . implode(', ', DANGEROUS));
    }
    if ($on('register_globals')) {
        $out[] = new Finding('high', 'PHP006', $at('register_globals'), 'register_globals is on: request data becomes variables');
    }
    if (!isset($s['open_basedir']) || trim($s['open_basedir']['value']) === '') {
        $out[] = new Finding('low', 'PHP007', isset($s['open_basedir']) ? $at('open_basedir') : $label . ':1', 'open_basedir is not set: scripts can read any file the user can');
    }
    if (!$on('session.cookie_httponly')) {
        $out[] = new Finding('medium', 'PHP008', isset($s['session.cookie_httponly']) ? $at('session.cookie_httponly') : $label . ':1', 'session.cookie_httponly is not on: JavaScript can read the session cookie');
    }
    if (!$on('session.use_strict_mode')) {
        $out[] = new Finding('medium', 'PHP009', isset($s['session.use_strict_mode']) ? $at('session.use_strict_mode') : $label . ':1', 'session.use_strict_mode is not on: unknown session ids are accepted (fixation)');
    }
    if (isset($s['cgi.fix_pathinfo']) && truthy($s['cgi.fix_pathinfo']['value']) === true) {
        $out[] = new Finding('medium', 'PHP010', $at('cgi.fix_pathinfo'), 'cgi.fix_pathinfo=1: behind nginx, /upload.jpg/x.php can run an uploaded file as PHP');
    }
    if ($on('enable_dl')) {
        $out[] = new Finding('medium', 'PHP011', $at('enable_dl'), 'enable_dl is on: scripts can load extensions at run time');
    }
    if (isset($s['log_errors']) && truthy($s['log_errors']['value']) === false) {
        $out[] = new Finding('low', 'PHP012', $at('log_errors'), 'log_errors is off: failures leave no trace');
    }
    if (!$on('session.cookie_secure')) {
        $out[] = new Finding('low', 'PHP013', isset($s['session.cookie_secure']) ? $at('session.cookie_secure') : $label . ':1', 'session.cookie_secure is not on: the session cookie can travel over plain HTTP');
    }
    return $out;
}

/** @param Finding[] $f @return Finding[] */
function sort_findings(array $f): array
{
    usort($f, static function (Finding $a, Finding $b): int {
        $ra = RANK[$a->sev];
        $rb = RANK[$b->sev];
        if ($ra !== $rb) {
            return $ra <=> $rb;
        }
        [$fa, $la] = split_where($a->where);
        [$fb, $lb] = split_where($b->where);
        return [$fa, $la, $a->rule] <=> [$fb, $lb, $b->rule];
    });
    return $f;
}

/** @return array{0:string,1:int} */
function split_where(string $w): array
{
    $p = strrpos($w, ':');
    return $p === false ? [$w, 0] : [substr($w, 0, $p), (int) substr($w, $p + 1)];
}
