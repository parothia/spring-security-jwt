package com.jwt.springsecurityjwt.Repo;

import com.jwt.springsecurityjwt.domain.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface RoleRepo extends JpaRepository<Role,Long> {
    Role findByName(String role);
}
