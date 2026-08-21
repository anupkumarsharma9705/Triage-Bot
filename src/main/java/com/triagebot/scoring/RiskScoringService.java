package com.triagebot.scoring;

import com.triagebot.finding.Finding;
import org.springframework.stereotype.Service;

/**
 * riskScore = cvssScore * reachMultiplier * exposureMultiplier
 *
 * Deliberately simple: the point is multi-factor prioritization over raw CVSS,
 * not formula sophistication. Not calibrated against real incident data.
 */
@Service
public class RiskScoringService {

    private static final double REACHABLE_MULTIPLIER = 1.0;
    private static final double UNREACHABLE_MULTIPLIER = 0.3;

    private static final double INTERNET_FACING_MULTIPLIER = 1.0;
    private static final double INTERNAL_ONLY_MULTIPLIER = 0.5;

    public double calculateRisk(Finding f) {
        double reachMultiplier = f.isReachable() ? REACHABLE_MULTIPLIER : UNREACHABLE_MULTIPLIER;
        double exposureMultiplier = f.isInternetFacing() ? INTERNET_FACING_MULTIPLIER : INTERNAL_ONLY_MULTIPLIER;
        return f.getCvssScore() * reachMultiplier * exposureMultiplier;
    }
}