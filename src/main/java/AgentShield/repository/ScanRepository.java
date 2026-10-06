package AgentShield.repository;

import AgentShield.model.Scan;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface ScanRepository extends JpaRepository<Scan, Long> {

    long countByMalicious(boolean malicious);

    long countByAttackType(String attackType);

    long countByRiskLevel(String riskLevel);

    long countByActionTaken(String actionTaken);

    long countByActionTakenAndMalicious(
            String actionTaken,
            boolean malicious
    );

    long countByClientIpAndMalicious(
            String clientIp,
            boolean malicious
    );
    long countByClientIpAndActionTaken(
            String clientIp,
            String actionTaken
    );

    long countByClientIpAndTimestampAfter(
            String clientIp,
            java.time.LocalDateTime timestamp
    );
    List<Scan> findAllByOrderByTimestampDesc();
    List<Scan> findTop10ByClientIpOrderByTimestampDesc(String clientIp);
}