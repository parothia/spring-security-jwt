package com.jwt.springsecurityjwt;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloResource {
    @RequestMapping("/hello")
    public String Hello() {
        return "Hello World";
    }
}
