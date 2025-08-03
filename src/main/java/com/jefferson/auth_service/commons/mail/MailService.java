package com.jefferson.auth_service.commons.mail;

import jakarta.mail.MessagingException;
import org.thymeleaf.context.IContext;

public interface MailService {
    public void sendMail(String address, String subject , String path, IContext context) throws MessagingException;
}
