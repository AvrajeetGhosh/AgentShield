package AgentShield.controller;

import AgentShield.model.StatisticsResponse;
import AgentShield.repository.ScanRepository;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/statistics")
public class StatisticsController {

    private final ScanRepository scanRepository;

    public StatisticsController(ScanRepository scanRepository) {
        this.scanRepository = scanRepository;
    }

    @GetMapping
    public StatisticsResponse getStatistics() {

        long total =
                scanRepository.count();

        long blocked =
                scanRepository.countByActionTaken("BLOCKED");

        long allowed =
                scanRepository.countByActionTaken("ALLOWED");

        return new StatisticsResponse(
                total,
                blocked,
                allowed
        );
    }
}