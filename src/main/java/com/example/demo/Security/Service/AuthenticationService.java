package com.example.demo.Security.Service;

import com.example.demo.Model.Employee;
import com.example.demo.Model.role;
import com.example.demo.Repository.JPAEmployeeRepository;
import com.example.demo.Security.Auth.authenticationRequest;
import com.example.demo.Security.Auth.authenticationResponse;
import com.example.demo.Security.Auth.registerRequest;
import com.example.demo.Security.Service.JwtService;
import com.example.demo.Security.Token.Token;
import com.example.demo.Security.Token.TokenRepository;
import com.example.demo.Security.Token.tokenType;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Service;

import java.io.IOException;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final JPAEmployeeRepository repository;

    private final TokenRepository tokenRepository;

    private final PasswordEncoder passwordEncoder;

    private final JwtService jwtService;

    private final AuthenticationManager authenticationManager;


    public authenticationResponse register(registerRequest requset) {

        var employee = Employee.builder()
                .firstName(requset.getFirstName())
                .lastName(requset.getLastName())
                .email(requset.getEmail())
                .password(passwordEncoder.encode(requset.getPassword()))
                .role(role.USER)
                .build();

        var saveEmployee = repository.save(employee);

        var JwtToken = jwtService.generateToken(employee);

        var refreshToken = jwtService.generateRefreshToken(employee);

        saveEmployeeToken(saveEmployee, JwtToken);

        return authenticationResponse.builder()
                .accessToken(JwtToken)
                .refreshToken(refreshToken)
                .build();
    }

    private void saveEmployeeToken(Employee Employee, String JwtToken) {
        var token = Token
                .builder()
                .employee(Employee)
                .token(JwtToken)
                .tokenType(tokenType.BEARER)
                .expired(false)
                .revoked(false)
                .build();
        tokenRepository.save(token);
    }

    private void revokeAllTokens(Employee employee){
        var validTokens = tokenRepository.findAllValidTokenByUser(employee.getId());
        if (validTokens.isEmpty())
            return;
        validTokens.forEach(token -> {
            token.setRevoked(true);
            token.setExpired(true);
        });
        tokenRepository.saveAll(validTokens);

    }

    public authenticationResponse authenticate(authenticationRequest requset) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        requset.getEmail(),
                        requset.getPassword()
                )
        );

        var employee = repository.findByEmail(requset.getEmail())
                .orElseThrow();
        var JwtToken = jwtService.generateToken(employee);
        var refreshToken = jwtService.generateRefreshToken(employee);

        revokeAllTokens(employee);

        saveEmployeeToken(employee, JwtToken);

        return authenticationResponse.builder()
                .accessToken(JwtToken)
                .refreshToken(refreshToken)
                .build();
    }

    public void refreshToken(
            HttpServletRequest requset,
            HttpServletResponse response
    ) throws IOException {
        final String authHeader = requset.getHeader(HttpHeaders.AUTHORIZATION);
        final String userEmail;
        final String refreshToken;

        if (authHeader == null || !authHeader.startsWith("Bearer ")){
            return;
        }

        refreshToken = authHeader.substring(7);
        userEmail = jwtService.extractUsername(refreshToken);

        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null){
            var employee = this.repository.findByEmail(userEmail).orElseThrow();


            if (jwtService.isValid(refreshToken, employee)) {
                var accessToken = jwtService.generateRefreshToken(employee);
                revokeAllTokens(employee);
                saveEmployeeToken(employee, accessToken);
                var authResponse = authenticationResponse.builder()
                        .accessToken(accessToken)
                        .refreshToken(refreshToken)
                        .build();

                new ObjectMapper().writeValue(response.getOutputStream(), authResponse);
            }
        }
    }
}
