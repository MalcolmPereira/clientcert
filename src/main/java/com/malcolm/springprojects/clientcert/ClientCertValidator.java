package com.malcolm.springprojects.clientcert;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

@RestController
public class ClientCertValidator {

    private static final String DEFAULT_SERVER_CERT = "/malcolm_io_sever.crt";

    private static final String DEFAULT_CERT_TYPE = "X.509";

    private static final String SSL_CLIENT_CERT_HEADER = "ssl-client-cert";

    private static final String SSL_CLIENT_CERT_ATTRIBUTE = "javax.servlet.request.X509Certificate";

    private static final String LINE_BREAK_URL_ENCODED = "%0A";

    private static final String LINE_BREAK_REPLACE = "\n";

    private static final String EQUAL_ENCODED = "%3D";

    private static final String EQUAL_REPLACE = "=";

    private static final Logger LOGGER = LoggerFactory.getLogger(ClientCertValidator.class);

    private final HttpServletRequest context;

    @Autowired
    public ClientCertValidator(HttpServletRequest context) {
        this.context = context;
    }

    @GetMapping("/server")
    public String getServerDetails()  {
        try(InputStream inputStream = ClientCertValidator.class.getResourceAsStream(DEFAULT_SERVER_CERT)){
            CertificateFactory certificateFactory = CertificateFactory.getInstance(DEFAULT_CERT_TYPE);
            X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(inputStream);
            return certificate.getSubjectX500Principal().getName();
        }catch (CertificateException | IOException err){
            LOGGER.error("Error while getting server certificate details", err);
            return "No Server Certificate found";
        }
    }



    @GetMapping("/client")
    public String getClientDetails()   {
        Object clientCert = this.context.getHeader(SSL_CLIENT_CERT_HEADER);
        LOGGER.info("Client Certificate from Request Header : {}", clientCert);

        if(clientCert != null && clientCert.toString().length() > 0) {
            try (InputStream inputStream = new ByteArrayInputStream(
                    URLDecoder.decode(
                         clientCert.toString()
                             .replaceAll(LINE_BREAK_URL_ENCODED, LINE_BREAK_REPLACE), StandardCharsets.UTF_8.name())
                             .replaceAll(EQUAL_ENCODED, EQUAL_REPLACE).getBytes()
                        )
                ) {
                CertificateFactory certificateFactory = CertificateFactory.getInstance(DEFAULT_CERT_TYPE);
                X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(inputStream);
                return certificate.getSubjectX500Principal().getName();
            } catch (CertificateException | IOException err) {
                LOGGER.error("Error while getting client certificate details", err);
            }
        }

        X509Certificate[] certs = (X509Certificate[]) this.context.getAttribute(SSL_CLIENT_CERT_ATTRIBUTE);
        LOGGER.info("Client Certificate from Request Attribute : {} {}", SSL_CLIENT_CERT_ATTRIBUTE, certs);
        if(certs == null || certs.length == 0){
           LOGGER.error("No Client Certificate found");
           return "No Client Certificate found";
        }

        return certs[0].getSubjectX500Principal().getName();
    }
}