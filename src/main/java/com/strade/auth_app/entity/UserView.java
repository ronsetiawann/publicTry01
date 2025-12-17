package com.strade.auth_app.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.*;

@Entity
@Table(name = "UserView", schema = "WebTrading")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserView {

    @Id
    @Column(name = "UserId", length = 30, nullable = false)
    private String userId;

    @Column(name = "GroupID", length = 30)
    private String groupId;

    @Column(name = "GroupPermission")
    private Boolean groupPermission;

    @Column(name = "AsClient")
    private Boolean asClient;

    @Column(name = "AsSales")
    private Boolean asSales;

    @Column(name = "AsDealer")
    private Boolean asDealer;

    @Column(name = "AsSupervisor")
    private Boolean asSupervisor;

    @Column(name = "AsController")
    private Boolean asController;
}
