package it.pieroaiello.securityjwt.exception;


public class UnauthorizedException extends RuntimeException {

    /**
     *
     * @param message
     */
    public UnauthorizedException(String message){
        super(message);
    }

}
