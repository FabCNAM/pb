package com.bzhcreationweb.blog.controller;


import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;


@Controller
@RequestMapping("/admin")
public class AdminController {

    @PostMapping
    public String loadAdmin(Model model, Principal Blogger) {
        System.out.println("COUCOU ADMIN");
        System.out.println(Blogger.getName());
        return "admin";
    }
}
