package com.strade.auth_app.dto.scheduler;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class SchedulerStatusResponse {
    private String schedulerGroup;
    private String jobName;
    private Boolean enabled;
    private String lastRun;
    private String nextRun;
}
