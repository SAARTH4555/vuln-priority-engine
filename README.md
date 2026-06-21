"
    Wait, I'll just replace all `â€”` with `-`.

    *Final check on the "Quick start" section:*
    `git clone https://github.com/SAARTH4555/vuln-priority-engine`
    `cd vuln-priority-engine`
    `pip install -r requirements.txt`
    ...
    Looks good.

    *Final check on the "How it works" section:*
    `Two real-world scanner output formats are parsed into one common NormalizedFinding shape (app/models.py):`
    `app/adapters/trivy_adapter.py - parses Aqua Trivy's JSON report schema (trivy image -f json ...), including its multi-vendor CVSS block (nvd/redhat/ghsa) and mixed Results entries (os-pkgs, secrets, etc.).`
    `app/adapters/csv_adapter.py - parses generic CVE CSV exports (the kind Nessus/Qualys/OpenVAS/homegrown inventories produce), tolerating common header synonyms (host/hostname/ip -> asset_id, cve/vulnerability_id -> cve_id, etc.) and skipping non-CVE or malformed rows instead of failing the whole file.`
    Looks good.

    *Final check on the "Enrichment" section:*
    `Every normalized finding is merged with three signals, loaded from bundled, offline fixtures in data/:`
    ...
    `Missing intel degrades gracefully