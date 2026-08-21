package com.triagebot.ingest;

import com.triagebot.finding.Finding;
import com.triagebot.finding.FindingRepository;
import com.triagebot.reachability.ReachabilityAnalyzer;
import com.triagebot.scoring.RiskScoringService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;

@RestController
@RequestMapping("/api")
public class TriageController {

    private final FindingRepository findingRepository;
    private final ReachabilityAnalyzer reachabilityAnalyzer;
    private final RiskScoringService riskScoringService;

    public TriageController(FindingRepository findingRepository,
                            ReachabilityAnalyzer reachabilityAnalyzer,
                            RiskScoringService riskScoringService) {
        this.findingRepository = findingRepository;
        this.reachabilityAnalyzer = reachabilityAnalyzer;
        this.riskScoringService = riskScoringService;
    }

    /**
     * @param sourceRoot absolute path to the checked-out repo being scanned.
     *                   In the real CI workflow this is the PR's checkout directory.
     */
    @PostMapping("/ingest")
    public ResponseEntity<String> ingest(@RequestBody DependencyCheckReport report,
                                         @RequestParam String sourceRoot) {
        if (report.getVulnerabilities() == null || report.getVulnerabilities().isEmpty()) {
            return ResponseEntity.badRequest().body("No vulnerabilities found in report");
        }

        Path root = Path.of(sourceRoot);
        if (!root.toFile().isDirectory()) {
            return ResponseEntity.badRequest().body("sourceRoot is not a valid directory: " + sourceRoot);
        }

        List<Finding> findings = report.getVulnerabilities().stream()
                .map(v -> new Finding(v.getCveId(), v.getDependencyName(), v.getVulnerableClass(), v.getCvssScore()))
                .toList();

        for (Finding f : findings) {
            try {
                boolean reachable = reachabilityAnalyzer.isReachable(root, f.getVulnerableClass());
                f.setReachable(reachable);
            } catch (IOException e) {
                // Fail safe: if we can't analyze it, don't silently mark it unreachable
                // (that would wrongly deprioritize it). Mark reachable=true so it's not lost.
                f.setReachable(true);
            }
        }

        for (Finding f : findings) {
            f.setRiskScore(riskScoringService.calculateRisk(f));
        }

        findingRepository.saveAll(findings);

        return ResponseEntity.ok(findings.size() + " findings ingested");
    }
}