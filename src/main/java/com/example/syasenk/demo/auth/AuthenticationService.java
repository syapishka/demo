package com.example.syasenk.demo.auth;

import com.example.syasenk.demo.config.JwtService;
import com.example.syasenk.demo.entities.Role;
import com.example.syasenk.demo.entities.User;
import com.example.syasenk.demo.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthenticationService {
    @Autowired
    private UserRepository userRepository;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtService jwtService;

    public AuthenticationResponse register(RegisterRequest request) {
        User user = User.builder()
                .name(request.getName())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .build();

        userRepository.save(user);

        String jwt = jwtService.generateToken(user);

        return AuthenticationResponse.builder().email(user.getEmail()).token(jwt).build();

    }

    public AuthenticationResponse login(AuthenticationRequest request) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                request.getEmail(),
                request.getPassword()
        ));

        User user = userRepository.findByEmail(request.getEmail()).orElseThrow();

        String jwt = jwtService.generateToken(user);

        return AuthenticationResponse.builder().email(user.getEmail()).token(jwt).build();

    }
}
