package com.example.security.controller;

import com.google.code.kaptcha.Producer;
import org.apache.tomcat.util.codec.binary.Base64;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.util.FastByteArrayOutputStream;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.imageio.ImageIO;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.awt.image.BufferedImage;
import java.io.IOException;

@RestController
public class VerifyCodeController {
    private final Producer producer;

    @Autowired
    public VerifyCodeController(Producer producer) {
        this.producer = producer;
    }

    @GetMapping("/vc.jpg")
    public String verifyCOde(HttpServletResponse response, HttpSession session) throws IOException {
        // 生成验证码
        String verifyCode = producer.createText();
        // 保存到 session
        session.setAttribute("kaptcha", verifyCode);
        // 生成图片
        BufferedImage image = producer.createImage(verifyCode);
        FastByteArrayOutputStream fastByteArrayOutputStream = new FastByteArrayOutputStream();
        ImageIO.write(image, "jpg", fastByteArrayOutputStream);
        // 返回base64
        return Base64.encodeBase64String(fastByteArrayOutputStream.toByteArray());

        // 传统web开发返回图片
        /*response.setContentType("image/png");
        ServletOutputStream outputStream = response.getOutputStream();
        ImageIO.write(image, "jpg", outputStream);*/

    }
}
