package AgentShield.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "security_settings")
public class SecuritySettings {

    @Id
    private Long id;

    private boolean firewallEnabled;

    private boolean detectionEnabled;

    private boolean autoBlockEnabled;

    private boolean loggingEnabled;

    private int maliciousRequestThreshold = 3;

    private int rateLimitThreshold = 10;

    private int rateLimitWindowSeconds = 60;

    private LocalDateTime updatedAt;

    private boolean failClosedOnAiUnavailable = false;

    public SecuritySettings() {
    }


    public boolean isFailClosedOnAiUnavailable() {
        return failClosedOnAiUnavailable;
    }

    public void setFailClosedOnAiUnavailable(
            boolean failClosedOnAiUnavailable) {

        this.failClosedOnAiUnavailable =
                failClosedOnAiUnavailable;
    }

    public SecuritySettings(
            Long id,
            boolean firewallEnabled,
            boolean detectionEnabled,
            boolean autoBlockEnabled,
            boolean loggingEnabled,
            LocalDateTime updatedAt) {

        this.id = id;
        this.firewallEnabled = firewallEnabled;
        this.detectionEnabled = detectionEnabled;
        this.autoBlockEnabled = autoBlockEnabled;
        this.loggingEnabled = loggingEnabled;
        this.updatedAt = updatedAt;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public boolean isFirewallEnabled() {
        return firewallEnabled;
    }

    public void setFirewallEnabled(boolean firewallEnabled) {
        this.firewallEnabled = firewallEnabled;
    }

    public boolean isDetectionEnabled() {
        return detectionEnabled;
    }

    public void setDetectionEnabled(boolean detectionEnabled) {
        this.detectionEnabled = detectionEnabled;
    }

    public boolean isAutoBlockEnabled() {
        return autoBlockEnabled;
    }

    public void setAutoBlockEnabled(boolean autoBlockEnabled) {
        this.autoBlockEnabled = autoBlockEnabled;
    }

    public boolean isLoggingEnabled() {
        return loggingEnabled;
    }

    public void setLoggingEnabled(boolean loggingEnabled) {
        this.loggingEnabled = loggingEnabled;
    }

    public LocalDateTime getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(LocalDateTime updatedAt) {
        this.updatedAt = updatedAt;
    }

    public int getMaliciousRequestThreshold() {
        return maliciousRequestThreshold;
    }

    public void setMaliciousRequestThreshold(int maliciousRequestThreshold) {
        this.maliciousRequestThreshold = maliciousRequestThreshold;
    }

    public int getRateLimitThreshold() {
        return rateLimitThreshold;
    }

    public void setRateLimitThreshold(int rateLimitThreshold) {
        this.rateLimitThreshold = rateLimitThreshold;
    }

    public int getRateLimitWindowSeconds() {
        return rateLimitWindowSeconds;
    }

    public void setRateLimitWindowSeconds(int rateLimitWindowSeconds) {
        this.rateLimitWindowSeconds = rateLimitWindowSeconds;
    }
}