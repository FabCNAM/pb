package com.bzhcreationweb.blog.controller;

import com.bzhcreationweb.blog.blogger.dao.BloggerDAO;
import com.bzhcreationweb.blog.service.JwtUserDetailsService;
import com.bzhcreationweb.blog.utils.JwtTokenUtil;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.nio.file.AccessDeniedException;

@RestController
@RequestMapping("/auth")
public class AuthenticationController {

    protected final Log logger = LogFactory.getLog(getClass());

    final BloggerDAO userRepository;
    final AuthenticationManager authenticationManager;
    final JwtUserDetailsService userDetailsService;
    final JwtTokenUtil jwtTokenUtil;

    public AuthenticationController(BloggerDAO userRepository, AuthenticationManager authenticationManager,
                                    JwtUserDetailsService userDetailsService, JwtTokenUtil jwtTokenUtil) {
        this.userRepository = userRepository;
        this.authenticationManager = authenticationManager;
        this.userDetailsService = userDetailsService;
        this.jwtTokenUtil = jwtTokenUtil;
    }
    /*
    @PostMapping("/login")
    public ResponseEntity<?> loginUser(@RequestParam("login") String username,
                                       @RequestParam("password") String password) {
        Map<String, Object> responseMap = new HashMap<>();
        try {
            System.out.println(username+" "+password);
            Authentication auth = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
            if (auth.isAuthenticated()) {
                UserDetails userDetails = userDetailsService.loadUserByUsername(username);
                String token = jwtTokenUtil.generateToken(userDetails);

                final Cookie cookie = new Cookie("jwtToken", token);
                cookie.setMaxAge(24 * 60 * 60); // 1 day
                cookie.setSecure(false); // Set to true for HTTPS
                cookie.setHttpOnly(true);
                cookie.setPath("/");
                System.out.println("VOTRE TOKEN EST : "+token);
                HttpHeaders headers = new HttpHeaders();
                headers.add(HttpHeaders.SET_COOKIE, cookie.toString());
                return ResponseEntity.ok().headers(headers).body(new JwtResponse(token));
                /*
                System.out.println("D--");
                responseMap.put("error", false);
                responseMap.put("message", "Logged In");
                responseMap.put("token", token);
                return ResponseEntity.ok(responseMap);
            } else {
                System.out.println("ABIS");
                responseMap.put("error", true);
                responseMap.put("message", "Invalid Credentials");
                return ResponseEntity.status(401).body(responseMap);

                 *//*
            }
        } catch (DisabledException e) {
            e.printStackTrace();
            responseMap.put("error", true);
            responseMap.put("message", "User is disabled");
            return ResponseEntity.status(500).body(responseMap);
        } catch (BadCredentialsException e) {
            responseMap.put("error", true);
            responseMap.put("message", "Invalid Credentials");
            return ResponseEntity.status(401).body(responseMap);
        } catch (Exception e) {
            e.printStackTrace();
            responseMap.put("error", true);
            responseMap.put("message", "Something went wrong");
            return ResponseEntity.status(500).body(responseMap);
        }
        return null;
    }
    */



    @PostMapping(path="/login")
    public StringHolder loginUser(@RequestBody LoginRequest loginRequest) throws AccessDeniedException {

        String password = loginRequest.getPassword();
        String username = loginRequest.getLogin();

        System.err.println(username+" "+password);
        Authentication auth = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
        if (auth.isAuthenticated()) {
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);
            //création d'un TOKEN
            String token = jwtTokenUtil.generateToken(userDetails);
            StringHolder stringHolder = new StringHolder();
            stringHolder.setValue(token);
            System.out.println("VOTRE TOKEN EST : "+token+" (Stringholder : "+stringHolder.getValue()+")");
            //encapsulate json into string
            return new StringHolder(token);
        }

        throw new AccessDeniedException("Invalid Login");
    }

    /*
    @PostMapping("/register")
    public ResponseEntity<?> saveUser(@RequestParam("name") String name,
                                      @RequestParam("surname") String surname,
                                      @RequestParam("username") String userName, @RequestParam("role") String role
            , @RequestParam("password") String password) {
        System.out.println("save user 1");
        Map<String, Object> responseMap = new HashMap<>();
        Blogger user = new Blogger();
        System.out.println("save user 2");
        user.setSurname(surname);
        user.setUsername(userName);
        user.setName(name);
        user.setPassword(new BCryptPasswordEncoder().encode(password));
        if(role.equals("admin")) {
            user.setRole(Role.ADMIN);
        }else {
            user.setRole(Role.BLOGGER);
        }
        userRepository.save(user);
        UserDetails userDetails = userDetailsService.loadUserByUsername(userName);
        String token = jwtTokenUtil.generateToken(userDetails);
        responseMap.put("error", false);
        responseMap.put("username", userName);
        responseMap.put("message", "Account created successfully");
        responseMap.put("token", token);
        return ResponseEntity.ok(responseMap);
    }
     */


}