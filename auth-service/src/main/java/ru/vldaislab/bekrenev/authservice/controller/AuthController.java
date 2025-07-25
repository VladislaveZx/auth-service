package ru.vldaislab.bekrenev.authservice.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import ru.vldaislab.bekrenev.authservice.model.dto.LoginRequestWithUsernameDto;
import ru.vldaislab.bekrenev.authservice.model.dto.RegisterRequestDto;
import ru.vldaislab.bekrenev.authservice.service.AuthService;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterRequestDto request) {
        return ResponseEntity.ok(authService.register(request));
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequestWithUsernameDto request) {
        return ResponseEntity.ok(authService.login(request));
    }
}

