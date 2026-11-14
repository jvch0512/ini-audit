# ini-audit

ini-audit reads `php.ini` style files (also `conf.d/*.ini` and pool overrides) and flags settings that weaken a production PHP install: remote file inclusion switches, errors shown to visitors, no function restrictions, session cookies without protection flags and the `cgi.fix_pathinfo` setting that matters behind nginx. The last assignment of a key wins, like PHP itself, and the finding points at that line.

**Live demo:** https://jvch0512.github.io/ini-audit/ (Synthetic php.ini files.)

PHP 8, standard library only. The demo page is rendered from the tool's `--tsv` output by `scripts/site.py` (Python 3, only needed to regenerate the page).

## Use

```bash
php bin/ini-audit examples/ini
php bin/ini-audit /etc/php/8.3/fpm/php.ini --tsv
php bin/ini-audit /etc/php --fail-on high      # exit 1 if any high finding
```

Pass a file or a directory (all `*.ini` files, recursively).

| Rule | Severity | What it catches |
|---|---|---|
| PHP001 | high | `allow_url_include` on: remote code inclusion |
| PHP002 | medium | `allow_url_fopen` on |
| PHP003 | medium | `display_errors` on (paths, queries and secrets reach the visitor) |
| PHP004 | low | `expose_php` on: version header |
| PHP005 | medium | `disable_functions` empty or without any of `exec`, `system`, `passthru`, `shell_exec`, `proc_open`, `popen` |
| PHP006 | high | `register_globals` on (legacy, removed in PHP 5.4) |
| PHP007 | low | `open_basedir` not set |
| PHP008 | medium | `session.cookie_httponly` not on |
| PHP009 | medium | `session.use_strict_mode` not on |
| PHP010 | medium | `cgi.fix_pathinfo=1` explicitly set (path info trick behind nginx) |
| PHP011 | medium | `enable_dl` on |
| PHP012 | low | `log_errors` off |
| PHP013 | low | `session.cookie_secure` not on |
| PHP000 | info | a line that is not a setting, ignored |

See [examples](examples) and [docs/sample-output.txt](docs/sample-output.txt).

## Limits

- Only the file you give it is read. It does not know which settings your SAPI overrides at run time (`php_admin_value`, `ini_set`).
- PHP 8 defaults are not applied. Rules that need a value to be set (PHP005, PHP007, PHP008, PHP009, PHP013) fire when it is missing, so a CLI-only ini will show them too.
- It does not interpret `${ENV}` expansion or `;` inside unquoted values beyond what PHP does for comments.
- It does not run PHP code: use `php --ini` and `php -i` to see what is really loaded.

## Where it fits

Hosting, platform and appsec review: a pre-deploy gate for php.ini changes and a first pass on inherited PHP estates.

## Tests

```bash
make test    # 56 checks
```

MIT.
