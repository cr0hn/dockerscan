CREATE TABLE IF NOT EXISTS cves (
    cve_id TEXT PRIMARY KEY,
    description TEXT NOT NULL,
    severity TEXT NOT NULL,
    cvss_v3_score REAL,
    cvss_v3_vector TEXT,
    published_date TEXT NOT NULL,
    modified_date TEXT NOT NULL,
    references_json TEXT
);

CREATE TABLE IF NOT EXISTS affected_products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT NOT NULL,
    vendor TEXT NOT NULL,
    product TEXT NOT NULL,
    version_start TEXT,
    version_end TEXT,
    version_start_type TEXT,
    version_end_type TEXT,
    FOREIGN KEY (cve_id) REFERENCES cves(cve_id)
);

CREATE TABLE IF NOT EXISTS package_aliases (
    cpe_vendor TEXT NOT NULL,
    cpe_product TEXT NOT NULL,
    package_name TEXT NOT NULL,
    package_source TEXT,
    PRIMARY KEY (cpe_vendor, cpe_product, package_name, package_source)
);

CREATE TABLE IF NOT EXISTS metadata (
    key TEXT PRIMARY KEY,
    value TEXT
);

CREATE INDEX IF NOT EXISTS idx_products_vendor_product ON affected_products(vendor, product);
CREATE INDEX IF NOT EXISTS idx_products_cve ON affected_products(cve_id);
CREATE INDEX IF NOT EXISTS idx_aliases_name ON package_aliases(package_name);
CREATE INDEX IF NOT EXISTS idx_aliases_cpe ON package_aliases(cpe_vendor, cpe_product);
CREATE INDEX IF NOT EXISTS idx_cves_severity ON cves(severity);
CREATE INDEX IF NOT EXISTS idx_cves_published ON cves(published_date);
