package it.pieroaiello.securityjwt.exception;


public class UnauthorizedException extends RuntimeException {

    /**
     * Custom exception for 401
     *
     * @param message
     */
    public UnauthorizedException(String message){
        super(message);
    }

}
