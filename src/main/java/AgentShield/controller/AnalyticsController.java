package AgentShield.controller;

import AgentShield.model.AnalyticsResponse;
import AgentShield.model.Scan;
import AgentShield.repository.ScanRepository;
import org.springframework.web.bind.annotation.*;

import java.util.LinkedHashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/analytics")
public class AnalyticsController {

    private final ScanRepository scanRepository;

    public AnalyticsController(ScanRepository scanRepository) {
        this.scanRepository = scanRepository;
    }

    @GetMapping
    public AnalyticsResponse getAnalytics() {

        long total = scanRepository.count();

        /*
         * Count based on the actual action taken.
         *
         * BLOCKED  = threat was actually blocked
         * ALLOWED  = request was allowed
         *
         * FLAGGED requests are not counted as BLOCKED.
         */
        long blocked =
                scanRepository.countByActionTaken("BLOCKED");

        long allowed =
                scanRepository.countByActionTaken("ALLOWED");

        double blockRate = 0;

        if (total > 0) {
            blockRate = ((double) blocked / total) * 100;
        }

        /*
         * Risk distribution
         */
        Map<String, Long> riskDistribution =
                new LinkedHashMap<>();

        riskDistribution.put(
                "CRITICAL",
                scanRepository.countByRiskLevel("CRITICAL")
        );

        riskDistribution.put(
                "HIGH",
                scanRepository.countByRiskLevel("HIGH")
        );

        riskDistribution.put(
                "MEDIUM",
                scanRepository.countByRiskLevel("MEDIUM")
        );

        riskDistribution.put(
                "LOW",
                scanRepository.countByRiskLevel("LOW")
        );

        /*
         * Attack distribution
         */
        Map<String, Long> attackDistribution =
                new LinkedHashMap<>();

        for (Scan scan : scanRepository.findAll()) {

            if (!scan.isMalicious()) {
                continue;
            }

            String attackType = scan.getAttackType();

            if (attackType == null ||
                    attackType.trim().isEmpty()) {
                continue;
            }

            /*
             * A scan can contain multiple attack types:
             *
             * INSTRUCTION_OVERRIDE, SECRET_EXTRACTION
             *
             * So we split them individually.
             */
            String[] attacks =
                    attackType.split(",");

            for (String attack : attacks) {

                attack = attack.trim();

                if (!attack.isEmpty()) {

                    attackDistribution.put(
                            attack,
                            attackDistribution.getOrDefault(
                                    attack,
                                    0L
                            ) + 1
                    );
                }
            }
        }

        return new AnalyticsResponse(
                total,
                blocked,
                allowed,
                Math.round(blockRate * 100.0) / 100.0,
                riskDistribution,
                attackDistribution
        );
    }
}