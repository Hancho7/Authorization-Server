package com.jefferson.auth_service.commons.mail;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.IContext;

public class MailServiceImpl implements  MailService{
    private final JavaMailSenderImpl sender;
    private final MimeMessage message;
    private final TemplateEngine engine;

    public MailServiceImpl(JavaMailSenderImpl sender, MimeMessage message, TemplateEngine engine){
        this.sender = sender;
        this.message= sender.createMimeMessage();
        this.engine= engine;
    }

    @Override
    public void sendMail(String address, String subject , String path, IContext context) throws MessagingException {
        MimeMessageHelper helper = new MimeMessageHelper(message);
        String content = engine.process(path, context);
        helper.setSubject(subject);
        helper.setText(content, true);
        helper.setTo(address);

        sender.send(message);

    }
}
