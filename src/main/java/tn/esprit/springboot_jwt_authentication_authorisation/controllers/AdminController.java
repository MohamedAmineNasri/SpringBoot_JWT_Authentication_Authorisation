package tn.esprit.springboot_jwt_authentication_authorisation.controllers;


import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/admin")
public class AdminController {

    @GetMapping
    public String get() {
        return "Get admin controller";
    }

    @PostMapping
    public String post() {
        return "post admin controller";
    }

    @PutMapping
    public String put() {
        return "put admin controller";
    }

    @DeleteMapping
    public String delete() {
        return "delete admin controller";
    }
}
