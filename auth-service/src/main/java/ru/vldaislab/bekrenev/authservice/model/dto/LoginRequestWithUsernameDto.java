package ru.vldaislab.bekrenev.authservice.model.dto;

import lombok.Builder;
import org.springframework.stereotype.Component;

@Builder
public record LoginRequestWithUsernameDto (String username, String password){
}
