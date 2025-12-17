package com.strade.auth_app.repository.jpa;

import com.strade.auth_app.entity.NotificationQueue;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

@Repository
public interface NotificationQueueRepository extends JpaRepository<NotificationQueue, UUID> {

    /**
     * Find pending notifications for processing
     */
    @Query("SELECT n FROM NotificationQueue n " +
            "WHERE n.status = :status " +
            "AND n.createdAt >= :threshold " +
            "ORDER BY n.createdAt ASC")
    List<NotificationQueue> findPendingNotifications(
            @Param("status") Byte status,
            @Param("threshold") LocalDateTime threshold
    );

    // Overloaded version with limit
    @Query(value = "SELECT TOP(:limit) * FROM Auth.NotificationQueue " +
            "WHERE Status = 0 AND CreatedAt >= :threshold " +
            "ORDER BY CreatedAt ASC",
            nativeQuery = true)
    List<NotificationQueue> findPendingNotifications(
            @Param("limit") int limit,
            @Param("threshold") LocalDateTime threshold
    );

    /**
     * Delete old notifications by status and date
     */
    @Modifying
    @Query("DELETE FROM NotificationQueue n " +
            "WHERE n.status IN :statuses " +
            "AND n.createdAt < :threshold")
    int deleteByStatusInAndCreatedAtBefore(
            @Param("statuses") List<Byte> statuses,
            @Param("threshold") LocalDateTime threshold
    );

    /**
     * Find stuck pending notifications
     */
    List<NotificationQueue> findByStatusAndCreatedAtBefore(
            Byte status,
            LocalDateTime threshold
    );

    /**
     * Count by status
     */
    long countByStatus(Byte status);

    /**
     * Find by user and type (for debugging/tracking)
     */
    List<NotificationQueue> findByUserIdAndTypeOrderByCreatedAtDesc(
            String userId,
            String type
    );

    //void deleteByStatusInAndCreatedAtBefore(List<Byte> statuses, LocalDateTime threshold);
}
