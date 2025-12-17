package com.strade.auth_app.repository.jpa;

import com.strade.auth_app.entity.UserContact;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserContactRepository extends JpaRepository<UserContact, Long> {
    Optional<UserContact> findByUserId(String userId);
}
