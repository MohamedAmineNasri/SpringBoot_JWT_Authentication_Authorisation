package tn.esprit.springboot_jwt_authentication_authorisation.controllers;


import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/user")
public class UserController {

    @GetMapping
    public String get() {
        return "Get user controller";
    }

    @PostMapping
    public String post() {
        return "post user controller";
    }

    @PutMapping
    public String put() {
        return "put user controller";
    }

    @DeleteMapping
    public String delete() {
        return "delete user controller";
    }
}
