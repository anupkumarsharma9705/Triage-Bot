package com.triagebot.finding;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;

import java.time.LocalDateTime;

@Entity
public class Finding {

    @Id
    @GeneratedValue
    private Long id;

    private String cveId;              // e.g. CVE-2023-1234
    private String dependencyName;     // e.g. jackson-databind-2.9.8.jar
    private String vulnerableClass;    // e.g. com.fasterxml.jackson.databind.ObjectMapper
    private double cvssScore;          // from Dependency-Check JSON
    private boolean reachable;         // computed by ReachabilityAnalyzer (Day 1 PM)
    private boolean internetFacing;    // set via simple config later
    private double riskScore;          // computed by RiskScoringService (Day 2 AM)
    private LocalDateTime scannedAt;

    public Finding() {
        // required by JPA
    }

    public Finding(String cveId, String dependencyName, String vulnerableClass, double cvssScore) {
        this.cveId = cveId;
        this.dependencyName = dependencyName;
        this.vulnerableClass = vulnerableClass;
        this.cvssScore = cvssScore;
        this.scannedAt = LocalDateTime.now();
    }

    public Long getId() { return id; }

    public String getCveId() { return cveId; }
    public void setCveId(String cveId) { this.cveId = cveId; }

    public String getDependencyName() { return dependencyName; }
    public void setDependencyName(String dependencyName) { this.dependencyName = dependencyName; }

    public String getVulnerableClass() { return vulnerableClass; }
    public void setVulnerableClass(String vulnerableClass) { this.vulnerableClass = vulnerableClass; }

    public double getCvssScore() { return cvssScore; }
    public void setCvssScore(double cvssScore) { this.cvssScore = cvssScore; }

    public boolean isReachable() { return reachable; }
    public void setReachable(boolean reachable) { this.reachable = reachable; }

    public boolean isInternetFacing() { return internetFacing; }
    public void setInternetFacing(boolean internetFacing) { this.internetFacing = internetFacing; }

    public double getRiskScore() { return riskScore; }
    public void setRiskScore(double riskScore) { this.riskScore = riskScore; }

    public LocalDateTime getScannedAt() { return scannedAt; }
    public void setScannedAt(LocalDateTime scannedAt) { this.scannedAt = scannedAt; }
}
