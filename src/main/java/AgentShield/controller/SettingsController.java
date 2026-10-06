package AgentShield.controller;

import AgentShield.model.SecuritySettings;
import AgentShield.repository.SecuritySettingsRepository;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;

@RestController
@RequestMapping("/api/settings")
@CrossOrigin
public class SettingsController {

    private final SecuritySettingsRepository settingsRepository;

    public SettingsController(SecuritySettingsRepository settingsRepository) {
        this.settingsRepository = settingsRepository;
    }

    @GetMapping
    public SecuritySettings getSettings() {

        return settingsRepository.findById(1L)
                .orElseGet(this::createDefaultSettings);
    }

    @PutMapping
    public SecuritySettings updateSettings(
            @RequestBody SecuritySettings incomingSettings) {

        SecuritySettings settings = settingsRepository
                .findById(1L)
                .orElseGet(this::createDefaultSettings);

        settings.setFirewallEnabled(
                incomingSettings.isFirewallEnabled()
        );

        settings.setDetectionEnabled(
                incomingSettings.isDetectionEnabled()
        );

        settings.setAutoBlockEnabled(
                incomingSettings.isAutoBlockEnabled()
        );

        settings.setLoggingEnabled(
                incomingSettings.isLoggingEnabled()
        );

        settings.setMaliciousRequestThreshold(
                incomingSettings.getMaliciousRequestThreshold()
        );

        settings.setRateLimitThreshold(
                incomingSettings.getRateLimitThreshold()
        );

        settings.setRateLimitWindowSeconds(
                incomingSettings.getRateLimitWindowSeconds()
        );

        settings.setUpdatedAt(LocalDateTime.now());

        return settingsRepository.save(settings);
    }

    private SecuritySettings createDefaultSettings() {

        SecuritySettings settings = new SecuritySettings();

        settings.setId(1L);
        settings.setFirewallEnabled(true);
        settings.setDetectionEnabled(true);
        settings.setAutoBlockEnabled(true);
        settings.setLoggingEnabled(true);
        settings.setUpdatedAt(LocalDateTime.now());

        return settingsRepository.save(settings);
    }
}