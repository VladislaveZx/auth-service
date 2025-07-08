package ru.vldaislab.bekrenev.authservice.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import ru.vldaislab.bekrenev.authservice.model.dto.AuthResponseDto;
import ru.vldaislab.bekrenev.authservice.model.dto.LoginRequestWithUsernameDto;
import ru.vldaislab.bekrenev.authservice.model.dto.RegisterRequestDto;
import ru.vldaislab.bekrenev.authservice.model.user.User;
import ru.vldaislab.bekrenev.authservice.repository.UserRepository;

@Service
@RequiredArgsConstructor
public class AuthService implements UserDetailsService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    public AuthResponseDto register(RegisterRequestDto request) {
        if (userRepository.existsByEmail(request.email())) {
            throw new RuntimeException("Email already exists");
        }
        var user = User.builder()
                .username(request.username())
                .firstName(request.firstName())
                .lastName(request.lastName())
                .email(request.email())
                .password(passwordEncoder.encode(request.password()))
                .build();
        userRepository.save(user);
        var jwt = jwtService.generateToken(user);
        return new AuthResponseDto(jwt);
    }

    public AuthResponseDto login(LoginRequestWithUsernameDto request) {
        var user = userRepository.findByUsername(request.username())
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
        if (!passwordEncoder.matches(request.password(), user.getPassword())) {
            throw new RuntimeException("Invalid credentials");
        }
        var jwt = jwtService.generateToken(user);
        return new AuthResponseDto(jwt);
    }

    @Override
    public User loadUserByUsername(String username) throws UsernameNotFoundException {
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
    }
}

