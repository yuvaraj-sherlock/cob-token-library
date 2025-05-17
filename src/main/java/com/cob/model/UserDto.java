package com.cob.model;

import lombok.Data;

@Data
public class UserDto {
    private String userName;
    private String password;
    private String role;
}
