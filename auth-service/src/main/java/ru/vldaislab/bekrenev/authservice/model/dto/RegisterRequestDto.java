package ru.vldaislab.bekrenev.authservice.model.dto;


import lombok.Builder;

@Builder
public record RegisterRequestDto ( String username, String firstName, String lastName, String email, String password){}
