package com.triagebot.ingest;

import java.util.List;

/**
 * Minimal shape of the JSON we accept into /api/ingest.
 * Real OWASP Dependency-Check JSON is deeply nested; we only pull
 * the fields this project actually uses. Field names are chosen to
 * match a simplified/flattened export, not the raw DC schema.
 */
public class DependencyCheckReport {

    private List<VulnerabilityEntry> vulnerabilities;

    public List<VulnerabilityEntry> getVulnerabilities() { return vulnerabilities; }
    public void setVulnerabilities(List<VulnerabilityEntry> vulnerabilities) { this.vulnerabilities = vulnerabilities; }

    public static class VulnerabilityEntry {
        private String cveId;
        private String dependencyName;
        private String vulnerableClass;
        private double cvssScore;

        public String getCveId() { return cveId; }
        public void setCveId(String cveId) { this.cveId = cveId; }

        public String getDependencyName() { return dependencyName; }
        public void setDependencyName(String dependencyName) { this.dependencyName = dependencyName; }

        public String getVulnerableClass() { return vulnerableClass; }
        public void setVulnerableClass(String vulnerableClass) { this.vulnerableClass = vulnerableClass; }

        public double getCvssScore() { return cvssScore; }
        public void setCvssScore(double cvssScore) { this.cvssScore = cvssScore; }
    }
}
