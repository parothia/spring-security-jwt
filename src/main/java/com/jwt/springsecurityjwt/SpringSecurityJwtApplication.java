package com.jwt.springsecurityjwt;

import com.jwt.springsecurityjwt.domain.Role;
import com.jwt.springsecurityjwt.domain.User;
import com.jwt.springsecurityjwt.service.UserService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;

@SpringBootApplication
public class SpringSecurityJwtApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringSecurityJwtApplication.class, args);
	}

	@Bean
	PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	@Bean
	CommandLineRunner run(UserService userService){
		return args -> {
			userService.saveRole(new Role(null,"ROLE_USER"));
			userService.saveRole(new Role(null,"ROLE_ADMIN"));

			userService.saveUser(new User(null,"user","user","password",new ArrayList<>()));
			userService.saveUser(new User(null,"admin","admin","password",new ArrayList<>()));
			
//			userService.saveUser(new User(null,"user","user","password"));
//			userService.saveUser(new User(null,"admin","admin","password"));

			userService.addRoleToUser("user","ROLE_USER");
			userService.addRoleToUser("admin","ROLE_ADMIN");
		};
	}
}
