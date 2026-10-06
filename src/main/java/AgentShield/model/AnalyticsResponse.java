package AgentShield.model;

import java.util.Map;

public class AnalyticsResponse {

    private long totalScans;
    private long blockedScans;
    private long allowedScans;

    private double blockRate;

    private Map<String, Long> riskDistribution;
    private Map<String, Long> attackDistribution;

    public AnalyticsResponse() {
    }

    public AnalyticsResponse(
            long totalScans,
            long blockedScans,
            long allowedScans,
            double blockRate,
            Map<String, Long> riskDistribution,
            Map<String, Long> attackDistribution) {

        this.totalScans = totalScans;
        this.blockedScans = blockedScans;
        this.allowedScans = allowedScans;
        this.blockRate = blockRate;
        this.riskDistribution = riskDistribution;
        this.attackDistribution = attackDistribution;
    }

    public long getTotalScans() {
        return totalScans;
    }

    public long getBlockedScans() {
        return blockedScans;
    }

    public long getAllowedScans() {
        return allowedScans;
    }

    public double getBlockRate() {
        return blockRate;
    }

    public Map<String, Long> getRiskDistribution() {
        return riskDistribution;
    }

    public Map<String, Long> getAttackDistribution() {
        return attackDistribution;
    }
}