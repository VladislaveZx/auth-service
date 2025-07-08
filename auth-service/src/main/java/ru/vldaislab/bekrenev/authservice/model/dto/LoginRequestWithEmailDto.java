package ru.vldaislab.bekrenev.authservice.model.dto;

import org.springframework.stereotype.Component;

public record LoginRequestWithEmailDto (String email, String password){
}
