package com.example.securingweb;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.logout;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest
@Import(WebSecurityConfig.class)
public class WebSecurityConfigTest {

    @Autowired
    private MockMvc mockMvc;

    @Nested
    @DisplayName("공개된 엔드포인트 테스트")
    class PublicEndpoints {

        @Test
        @DisplayName("GET /home은 인증 없이 접근 가능해야 함")
        void testHomePageAccessibleWithoutAuth() throws Exception {
            mockMvc.perform(get("/home"))
                    .andExpect(status().isOk())
                    .andExpect(view().name("home"));
        }

        @Test
        @DisplayName("GET /은 인증 없이 접근 가능해야 함")
        void testRootAccessibleWithoutAuth() throws Exception {
            mockMvc.perform(get("/"))
                    .andExpect(status().isOk())
                    .andExpect(view().name("home"));
        }

        @Test
        @DisplayName("GET /login은 인증 없이 접근 가능해야 함")
        void testLoginPageAccessibleWithoutAuth() throws Exception {
            mockMvc.perform(get("/login"))
                    .andExpect(status().isOk())
                    .andExpect(view().name("login"));
        }
    }

    @Nested
    @DisplayName("보호된 엔드포인트 테스트")
    class ProtectedEndpoints {

        @Test
        @DisplayName("GET /hello는 인증이 필요하며, 인증되지 않은 사용자는 로그인 페이지로 리다이렉트되어야 함")
        void testHelloPageRequiresAuth() throws Exception {
            mockMvc.perform(get("/hello"))
                    .andExpect(status().is3xxRedirection())
                    .andExpect(redirectedUrlPattern("**/login"));
        }

        @Test
        @WithMockUser(username = "user", roles = {"USER"})
        @DisplayName("GET /hello는 인증된 사용자에게 접근 가능해야 함")
        void testHelloPageAccessibleWithAuth() throws Exception {
            mockMvc.perform(get("/hello"))
                    .andExpect(status().isOk())
                    .andExpect(view().name("hello"));
        }
    }

    @Nested
    @DisplayName("로그인 테스트")
    class LoginTests {

        @Test
        @DisplayName("올바른 자격 증명으로 로그인 시도 시, 성공적으로 인증되고 /으로 리다이렉트되어야 함")
        void testSuccessfulLogin() throws Exception {
            mockMvc.perform(formLogin("/login")
                            .user("user")
                            .password("password"))
                    .andExpect(status().is3xxRedirection())
                    .andExpect(redirectedUrl("/"));
        }

        @Test
        @DisplayName("잘못된 자격 증명으로 로그인 시도 시, 로그인 페이지로 리다이렉트되고 에러가 표시되어야 함")
        void testFailedLogin() throws Exception {
            mockMvc.perform(formLogin("/login")
                            .user("user")
                            .password("wrongpassword"))
                    .andExpect(status().is3xxRedirection())
                    .andExpect(redirectedUrl("/login?error"));
        }

        @Test
        @DisplayName("로그인 시 CSRF 토큰이 필요함")
        void testLoginRequiresCsrf() throws Exception {
            mockMvc.perform(formLogin("/login")
                            .user("user")
                            .password("password"))
                    .andExpect(status().is3xxRedirection())
                    .andExpect(redirectedUrl("/"));
        }
    }

    @Nested
    @DisplayName("로그아웃 테스트")
    class LogoutTests {

        @Test
        @WithMockUser(username = "user", roles = {"USER"})
        @DisplayName("로그아웃 시도 시, 세션이 무효화되고 /login?logout으로 리다이렉트되어야 함")
        void testLogout() throws Exception {
            mockMvc.perform(logout("/logout"))
                    .andExpect(status().is3xxRedirection())
                    .andExpect(redirectedUrl("/login?logout"));
        }

        @Test
        @DisplayName("로그아웃은 인증되지 않은 사용자도 시도할 수 있으며, /login?logout으로 리다이렉트되어야 함")
        void testLogoutByUnauthenticatedUser() throws Exception {
            mockMvc.perform(logout("/logout"))
                    .andExpect(status().is3xxRedirection())
                    .andExpect(redirectedUrl("/login?logout"));
        }
    }
}