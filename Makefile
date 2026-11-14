test:
	php tests/run.php

sample:
	mkdir -p docs site
	php bin/ini-audit examples/ini > docs/sample-output.txt; true
	php bin/ini-audit examples/ini --tsv > docs/sample-output.tsv; true
	python3 scripts/site.py docs/sample-output.tsv site/index.html "ini-audit" "Audits php.ini files for risky settings: remote includes, error display, session cookie flags, dangerous functions. PHP." "Synthetic php.ini files."
