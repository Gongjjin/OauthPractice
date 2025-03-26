package ServerLessArch.Be.login.dto;

import lombok.Data;

@Data
public class TokenResponseStatus {
    // Getters and Setters
    private int statusCode;
    private String message;
    private String accessToken;

    public static TokenResponseStatus addStatus(int statusCode, String accessToken) {
        TokenResponseStatus response = new TokenResponseStatus();
        response.setStatusCode(statusCode);
        if (statusCode == 200) {
            response.setMessage("Token refresh successful");
            response.setAccessToken(accessToken);
        } else {
            response.setMessage("Invalid refresh token");
            response.setAccessToken(null);
        }
        return response;
    }

}
