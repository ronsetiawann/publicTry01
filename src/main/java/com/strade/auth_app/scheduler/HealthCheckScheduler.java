package com.strade.auth_app.scheduler;

import com.strade.auth_app.config.properties.SchedulerProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Health check scheduler
 * Monitors system health and connectivity
 */
@Component
@Slf4j
@RequiredArgsConstructor
@ConditionalOnProperty(
        prefix = "app.scheduler.health-check",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
)
public class HealthCheckScheduler {

    private final JdbcTemplate jdbcTemplate;
    private final RedisTemplate<String, Object> redisTemplate;
    private final SchedulerProperties schedulerProperties;

    /**
     * Check database connectivity
     * Runs every 5 minutes
     */
    @Scheduled(fixedRate = 300000)
    public void checkDatabaseHealth() {
        if (!schedulerProperties.getHealthCheck().isDatabase()) {
            return;
        }

        try {
            jdbcTemplate.queryForObject("SELECT 1", Integer.class);
            log.debug("Database health check: OK");
        } catch (Exception e) {
            log.error("Database health check FAILED", e);
            // Could trigger alert via notification queue
            // notificationService.sendAlert(...);
        }
    }

    /**
     * Check Redis connectivity
     * Runs every 5 minutes
     */
    @Scheduled(fixedRate = 300000)
    public void checkRedisHealth() {
        if (!schedulerProperties.getHealthCheck().isRedis()) {
            return;
        }

        try {
            String testKey = "health:check:" + System.currentTimeMillis();
            redisTemplate.opsForValue().set(testKey, "OK");
            String value = (String) redisTemplate.opsForValue().get(testKey);
            redisTemplate.delete(testKey); // Cleanup

            if ("OK".equals(value)) {
                log.debug("Redis health check: OK");
            } else {
                log.warn("Redis health check: Unexpected value - {}", value);
            }
        } catch (Exception e) {
            log.error("Redis health check FAILED", e);
            // Could trigger alert via notification queue
        }
    }
}