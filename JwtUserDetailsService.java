package com.bzhcreationweb.blog.service;

import com.bzhcreationweb.blog.Role;
import com.bzhcreationweb.blog.blogger.dao.BloggerDAO;
import com.bzhcreationweb.blog.blogger.model.Blogger;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;

@Service
public class JwtUserDetailsService implements UserDetailsService {

    final BloggerDAO userRepository;

    public JwtUserDetailsService(BloggerDAO userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        /*
        //try to retrieve blogger by using it's username
        Optional<Blogger> optionalBlogger = userRepository.findBloggerByUsername(username);
        //if found ...
        if(optionalBlogger.isPresent()) {
            System.out.println("1");
            //retrieve it
            Blogger blogger = optionalBlogger.get();
            System.out.println("2");
            //create an 'User' (in regard of Spring)
            User.UserBuilder builder = User.builder()
                    .username(username)
                    .password(blogger.getPassword());
            System.out.println("3");
            HashSet<String> roles = rolesBuilding(blogger);
            builder.roles(roles.toArray(new String[roles.size()]));
            UserDetails details = builder.build();
            System.out.println("4");
            System.out.println(details.getUsername());
            System.out.println(details.getPassword());
            return details;

        }
        //not found
        throw new UsernameNotFoundException(username);
             */
    Blogger user = userRepository.findBloggerByUsername(username);
    List<GrantedAuthority> authorityList = new ArrayList<>();
            authorityList.add(new SimpleGrantedAuthority(user.getRole().name()));
            System.out.println(new User(user.getUsername(), user.getPassword(), authorityList));
            return new User(user.getUsername(), user.getPassword(), authorityList);

    }

    public HashSet<String> rolesBuilding(Blogger blogger) {
        HashSet<String> roles = new HashSet<>();
        switch (blogger.getRole()) {
            case BLOGGER:
                roles.add("BLOGGER");
                break;
            case ADMIN:
                roles.add("ADMIN");
            default:
                break;
        }
        return roles;
    }
}