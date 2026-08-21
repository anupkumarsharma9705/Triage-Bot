package com.triagebot.finding;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface FindingRepository extends JpaRepository<Finding, Long> {

    // Used by /api/report on Day 2 AM
    List<Finding> findAllByOrderByRiskScoreDesc();
}
