package com.triagebot.scoring;

import com.triagebot.finding.Finding;
import com.triagebot.finding.FindingRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api")
public class ReportController {

    private final FindingRepository findingRepository;

    public ReportController(FindingRepository findingRepository) {
        this.findingRepository = findingRepository;
    }

    @GetMapping("/report")
    public List<Finding> getReport() {
        return findingRepository.findAllByOrderByRiskScoreDesc();
    }
}