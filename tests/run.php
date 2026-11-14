<?php
declare(strict_types=1);

require __DIR__ . '/../lib/IniAudit.php';

use IniAudit\Finding;
use function IniAudit\audit;
use function IniAudit\parse;
use function IniAudit\sort_findings;
use function IniAudit\truthy;
use function IniAudit\value;

$passed = 0;
$failed = 0;
function check(bool $ok, string $what): void
{
    global $passed, $failed;
    if ($ok) {
        $passed++;
    } else {
        $failed++;
        echo "FAIL: $what\n";
    }
}

/** @return string[] */
function rules(string $ini): array
{
    return array_map(static fn (Finding $f) => $f->rule, audit($ini, 't.ini'));
}
function has(string $ini, string $rule): bool
{
    return in_array($rule, rules($ini), true);
}
/** An ini that satisfies every "must be set" rule, plus extra lines. */
function base(string $extra = ''): string
{
    return "open_basedir=/var/www\ndisable_functions=exec,system\nsession.cookie_httponly=1\nsession.use_strict_mode=1\nsession.cookie_secure=1\n$extra\n";
}

// parser
[$s, $n] = parse("; comment\n[PHP]\nfoo = bar\nBaz=1\n");
check($s['foo']['value'] === 'bar' && $s['foo']['line'] === 3, 'basic key value and line');
check(isset($s['baz']) && $s['baz']['value'] === '1', 'keys are lower-cased');
check($n === [], 'no notes for a clean file');
[$s] = parse("a=1\na=2\n");
check($s['a']['value'] === '2' && $s['a']['line'] === 2, 'last assignment wins');
[$s] = parse("a = \"x ; y\" ; trailing\nb = 'q'\nc = off ; c\n");
check($s['a']['value'] === 'x ; y', 'quoted value keeps semicolon');
check($s['b']['value'] === 'q', 'single quotes');
check($s['c']['value'] === 'off', 'unquoted trailing comment removed');
[$s, $n] = parse("# hash comment\nnot a setting\n= novalue\nbad key! = 1\n");
check(count($n) === 3 && $s === [], 'invalid lines become notes');
[$s] = parse("a=1\r\nb=2\rc=3\n");
check(isset($s['a'], $s['b'], $s['c']), 'CRLF and CR line endings');
[$s] = parse("session.save_path = \"/tmp\"\nextension[]=foo\n");
check(isset($s['session.save_path']) && isset($s['extension[]']), 'dotted keys and array keys');
check(value('  "abc') === 'abc', 'unterminated quote tolerated');
check(value('') === '', 'empty value');
check(truthy('On') === true && truthy('1') === true && truthy('TRUE') === true && truthy('yes') === true, 'truthy values');
check(truthy('Off') === false && truthy('0') === false && truthy('none') === false && truthy('') === false, 'falsy values');
check(truthy('maybe') === null && truthy(null) === null, 'unknown values');

// rules
check(has(base('allow_url_include=On'), 'PHP001'), 'PHP001 on');
check(!has(base('allow_url_include=Off'), 'PHP001'), 'PHP001 off');
check(has(base('allow_url_fopen=1'), 'PHP002'), 'PHP002 on');
check(!has(base('allow_url_fopen=0'), 'PHP002'), 'PHP002 off');
check(has(base('display_errors=On'), 'PHP003') && has(base('display_errors=stdout'), 'PHP003'), 'PHP003 on and stdout');
check(!has(base('display_errors=stderr'), 'PHP003') && !has(base('display_errors=Off'), 'PHP003'), 'PHP003 stderr and off are fine');
check(has(base('display_errors=On' . "\n" . 'display_errors=Off'), 'PHP003') === false, 'PHP003 later override wins');
check(has(base('expose_php=On'), 'PHP004') && !has(base('expose_php=Off'), 'PHP004'), 'PHP004');
check(has("open_basedir=/x\nsession.cookie_httponly=1\nsession.use_strict_mode=1\nsession.cookie_secure=1\n", 'PHP005'), 'PHP005 missing');
check(has(base("disable_functions=\n"), 'PHP005'), 'PHP005 empty');
check(has(base("disable_functions=phpinfo,show_source\n"), 'PHP005'), 'PHP005 without dangerous functions');
check(!has(base("disable_functions=\"phpinfo, exec\"\n"), 'PHP005'), 'PHP005 spaces and quotes tolerated');
check(has(base('register_globals=On'), 'PHP006') && !has(base('register_globals=Off'), 'PHP006'), 'PHP006');
check(has("disable_functions=exec\nsession.cookie_httponly=1\nsession.use_strict_mode=1\nsession.cookie_secure=1\n", 'PHP007'), 'PHP007 missing');
check(has(base("open_basedir=\n"), 'PHP007'), 'PHP007 empty');
check(!has(base(), 'PHP007'), 'PHP007 set');
check(has(base("session.cookie_httponly=0\n"), 'PHP008'), 'PHP008 off');
check(!has(base(), 'PHP008') && !has(base(), 'PHP009') && !has(base(), 'PHP013'), 'session flags satisfied');
check(has(base("session.use_strict_mode=0\n"), 'PHP009'), 'PHP009 off');
check(has(base("cgi.fix_pathinfo=1\n"), 'PHP010') && !has(base("cgi.fix_pathinfo=0\n"), 'PHP010') && !has(base(), 'PHP010'), 'PHP010 only when explicitly 1');
check(has(base('enable_dl=On'), 'PHP011') && !has(base('enable_dl=Off'), 'PHP011'), 'PHP011');
check(has(base('log_errors=Off'), 'PHP012') && !has(base('log_errors=On'), 'PHP012') && !has(base(), 'PHP012'), 'PHP012 only when explicitly off');
check(has(base("session.cookie_secure=0\n"), 'PHP013'), 'PHP013 off');
check(has("this is not valid\n", 'PHP000'), 'PHP000 for invalid lines');
check(rules(base()) === [], 'a fully hardened file has no findings');
check(rules('') !== [], 'an empty file triggers the "must be set" rules');

// locations and severities
$f = audit("a=1\nallow_url_include=On\n", 'x/y.ini');
$f1 = array_values(array_filter($f, static fn ($x) => $x->rule === 'PHP001'))[0];
check($f1->where === 'x/y.ini:2' && $f1->sev === 'high', 'where is label:line, severity high');
$f5 = array_values(array_filter(audit('', 'e.ini'), static fn ($x) => $x->rule === 'PHP005'))[0];
check($f5->where === 'e.ini:1', 'missing settings point at line 1');

// sorting
$sorted = sort_findings([
    new Finding('low', 'B', 'a.ini:1', ''),
    new Finding('high', 'A', 'b.ini:9', ''),
    new Finding('high', 'A', 'b.ini:10', ''),
    new Finding('high', 'A', 'a.ini:2', ''),
]);
check(array_map(static fn ($x) => $x->where, $sorted) === ['a.ini:2', 'b.ini:9', 'b.ini:10', 'a.ini:1'], 'sort by severity, file, numeric line');

// hostile input and fuzz: never throws
$hostile = [str_repeat('a', 100000), str_repeat('=', 5000), "\0\0\0=\0", str_repeat("a=\"", 3000), "\xff\xfe=\xff", str_repeat("[", 10000), "a=" . str_repeat('"', 10001)];
$ok = true;
foreach ($hostile as $h) {
    try {
        audit($h, 'h.ini');
    } catch (Throwable $e) {
        $ok = false;
    }
}
check($ok, 'hostile inputs do not throw');
mt_srand(42);
$seed = base("display_errors=On\n; c\n[S]\nx = \"y;z\"\n");
$ok = true;
for ($i = 0; $i < 3000; $i++) {
    $t = $seed;
    for ($k = 0, $m = 1 + mt_rand(0, 5); $k < $m; $k++) {
        $pos = mt_rand(0, max(0, strlen($t) - 1));
        switch (mt_rand(0, 2)) {
            case 0: $t[$pos] = chr(mt_rand(0, 255)); break;
            case 1: $t = substr($t, 0, $pos) . substr($t, $pos + mt_rand(1, 6)); break;
            default: $t = substr($t, 0, $pos) . ['"', "'", '=', ';', '[', "\n"][mt_rand(0, 5)] . substr($t, $pos);
        }
        if ($t === '') {
            $t = 'a';
        }
    }
    try {
        audit($t, 'f.ini');
    } catch (Throwable $e) {
        $ok = false;
        echo 'fuzz exception: ' . $e->getMessage() . "\n";
        break;
    }
}
check($ok, 'fuzzing 3000 inputs never throws');

// CLI
$bin = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(__DIR__ . '/../bin/ini-audit');
$ex = escapeshellarg(__DIR__ . '/../examples/ini');
function cli(string $args): array
{
    global $bin;
    exec("$bin $args 2>/dev/null", $out, $rc);
    return [$out, $rc];
}
check(cli($ex)[1] === 0, 'cli default exit 0');
check(cli("$ex --fail-on high")[1] === 1, 'cli --fail-on high exits 1');
check(cli(escapeshellarg(__DIR__ . '/../examples/ini/hardened.ini') . ' --fail-on medium')[1] === 0, 'hardened file passes --fail-on medium');
[$out] = cli("$ex --tsv");
check(str_starts_with($out[0], '# '), 'tsv first line is the summary');
$cols = true;
foreach (array_slice($out, 1) as $l) {
    if (substr_count($l, "\t") !== 3) {
        $cols = false;
    }
}
check($cols, 'tsv rows have four columns');
check(cli('/no/such/path')[1] === 2, 'missing path exits 2');
check(cli('')[1] === 2, 'no args exits 2');
check(cli("$ex --bogus")[1] === 2, 'unknown flag exits 2');
check(cli("$ex --fail-on nope")[1] === 2, 'bad --fail-on exits 2');
check(cli("$ex $ex")[1] === 2, 'two paths exit 2');

echo "$passed passed, $failed failed\n";
exit($failed > 0 ? 1 : 0);
