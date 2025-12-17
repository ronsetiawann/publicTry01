package com.strade.auth_app.util;

import com.strade.auth_app.entity.UserView;
import com.strade.auth_app.repository.jpa.UserViewRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import java.util.Optional;

@Component
@RequiredArgsConstructor
@Slf4j
public class SecurityUtils {

    private final UserViewRepository userViewRepository;

    /**
     * Get current authenticated user ID
     */
    public String getCurrentUserId() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !authentication.isAuthenticated()) {
            return null;
        }

        Object principal = authentication.getPrincipal();

        if (principal instanceof String) {
            return (String) principal;
        }

        return null;
    }

    /**
     * Get current user view
     */
    public Optional<UserView> getCurrentUser() {
        String userId = getCurrentUserId();
        if (userId == null) {
            return Optional.empty();
        }
        return userViewRepository.findById(Long.valueOf(userId));
    }
}