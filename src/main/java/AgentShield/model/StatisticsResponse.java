package AgentShield.model;

public class StatisticsResponse {

    private long totalScans;
    private long blockedScans;
    private long allowedScans;

    public StatisticsResponse(
            long totalScans,
            long blockedScans,
            long allowedScans) {

        this.totalScans = totalScans;
        this.blockedScans = blockedScans;
        this.allowedScans = allowedScans;
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
}