// Package cvedb provides CVE database management for DockerScan.
//
// This package manages an SQLite database of CVE vulnerabilities downloaded
// from the National Vulnerability Database (NVD). It provides functionality
// for downloading, querying, and managing the CVE database.
//
// # Features
//
//   - Download and update CVE database from remote source
//   - Query CVEs by package name and version
//   - CPE (Common Platform Enumeration) parsing and normalization
//   - Package name aliasing and normalization
//   - Batch queries for multiple packages
//   - Pure Go implementation (no CGO dependencies)
//
// # Database Schema
//
// The database contains the following tables:
//   - cves: CVE records with CVSS scores, descriptions, and dates
//   - affected_products: Products affected by each CVE
//   - package_aliases: Mapping between package names and CPE identifiers
//   - metadata: Database version and update information
//
// # Basic Usage
//
//	// Download database
//	downloader := cvedb.NewDownloader("", "", cvedb.DefaultDBPath)
//	if err := downloader.Download(ctx); err != nil {
//	    log.Fatal(err)
//	}
//
//	// Open database
//	db, err := cvedb.Open(cvedb.DefaultDBPath)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer db.Close()
//
//	// Query CVEs
//	cves, err := db.QueryByPackage("nginx", "dpkg")
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	for _, cve := range cves {
//	    fmt.Printf("%s: %s (%s)\n", cve.CVEID, cve.Description, cve.Severity)
//	}
//
// # Database Updates
//
// The database can be updated by checking if a new version is available:
//
//	downloader := cvedb.NewDownloader("", "", cvedb.DefaultDBPath)
//	needsUpdate, remoteChecksum, err := downloader.NeedsUpdate()
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	if needsUpdate {
//	    fmt.Println("Updating CVE database...")
//	    if err := downloader.Download(ctx); err != nil {
//	        log.Fatal(err)
//	    }
//	}
//
// # Package Name Normalization
//
// The package provides intelligent package name normalization to match
// Debian/Alpine/RPM package names against CVE product names:
//
//	normalized := cvedb.NormalizePackageName("libssl1.1")
//	// Returns: "ssl"
//
//	aliases := cvedb.GetCommonAliases("nginx")
//	// Returns: ["nginx", "nginx-core"]
//
// # CPE Parsing
//
// CPE (Common Platform Enumeration) identifiers can be parsed:
//
//	vendor, product, version, err := cvedb.ParseCPE23("cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*")
//	// vendor="nginx", product="nginx", version="1.18.0"
package cvedb
