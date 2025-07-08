package ru.vldaislab.bekrenev.authservice.model.dto;

import org.springframework.stereotype.Component;

public record LoginRequestWithUsernameDto (String username, String password){
}
