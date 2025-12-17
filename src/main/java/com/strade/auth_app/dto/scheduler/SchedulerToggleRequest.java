package com.strade.auth_app.dto.scheduler;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class SchedulerToggleRequest {
    private String schedulerGroup;  // token-cleanup, session-cleanup, etc
    private String jobName;          // expired-denylist, mark-inactive, etc (optional)
    private Boolean enabled;
}

