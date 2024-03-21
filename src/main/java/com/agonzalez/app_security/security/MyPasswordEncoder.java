package com.agonzalez.app_security.security;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

//@Component
//lo comente porque no lo vamos a usar, solo se puede implementar un passwordEncoder
//voy a utilizar el de spring
public class MyPasswordEncoder /*implements PasswordEncoder*/ {

   // @Override
    public String encode(CharSequence rawPassword) {
        return String.valueOf(rawPassword.toString().hashCode());
    }

   // @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        var passwordAsString = String.valueOf(rawPassword.toString().hashCode());
        return encodedPassword.equals(passwordAsString);
    }
}
