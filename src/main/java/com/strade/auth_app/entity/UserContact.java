package com.strade.auth_app.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.*;

/**
 * User Contact View Entity - Read-only
 * Maps to SL.UserContactView
 */
@Entity
@Table(name = "[UserContactView]", schema = "SL")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserContact {

    @Id
    @Column(name = "UserID", length = 30, nullable = false)
    private String userId;

    @Column(name = "UserName", length = 200)
    private String userName;

    @Column(name = "Email", length = 100)
    private String email;

    @Column(name = "PhoneNo", length = 20)
    private String phoneNo;

}
