package ru.vldaislab.bekrenev.authservice.model.dto;

import lombok.Builder;

@Builder
public record AuthResponseDto(String token){
}
