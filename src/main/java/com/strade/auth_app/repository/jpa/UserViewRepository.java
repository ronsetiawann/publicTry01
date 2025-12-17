package com.strade.auth_app.repository.jpa;

import com.strade.auth_app.entity.UserView;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserViewRepository extends JpaRepository<UserView, Long> {
    Optional<UserView> findByUserId (String userId);
}
