package AgentShield.repository;

import AgentShield.model.SecuritySettings;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SecuritySettingsRepository
        extends JpaRepository<SecuritySettings, Long> {
}