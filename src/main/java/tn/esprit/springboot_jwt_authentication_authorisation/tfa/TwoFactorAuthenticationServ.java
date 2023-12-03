package tn.esprit.springboot_jwt_authentication_authorisation.tfa;

import dev.samstevens.totp.code.*;
import dev.samstevens.totp.exceptions.QrGenerationException;
import dev.samstevens.totp.qr.QrData;
import dev.samstevens.totp.qr.QrGenerator;
import dev.samstevens.totp.qr.ZxingPngQrGenerator;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.time.SystemTimeProvider;
import dev.samstevens.totp.time.TimeProvider;
import dev.samstevens.totp.util.Utils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import static dev.samstevens.totp.util.Utils.getDataUriForImage;

@Service
@Slf4j
public class TwoFactorAuthenticationServ {

    public String generateNewSecret() {
        return new  DefaultSecretGenerator().generate();
    }

    public String generateQrCodeImage(String secret) {
        QrData data = new QrData.Builder()
                .label("Auth-Application")//Aplication name
                .secret(secret)
                .issuer("Auth-Application")
                .algorithm(HashingAlgorithm.SHA1)
                .digits(6)
                .period(30)
                .build();
        QrGenerator generator = new ZxingPngQrGenerator();
        byte[] imageData = new byte[0];
        try {
            imageData = generator.generate(data);
        }   catch (QrGenerationException e){
            //throw new RuntimeException(e);
            e.printStackTrace();
            log.error("Error while generating Qr code");
        }
        return getDataUriForImage(imageData, generator.getImageMimeType());
    }

    //Otp : one time password
    public boolean isOtpValid(String secret, String code) {
        TimeProvider timeProvider = new SystemTimeProvider();
        CodeGenerator codeGenerator = new DefaultCodeGenerator();
        CodeVerifier verifier = new DefaultCodeVerifier(codeGenerator, timeProvider);
        return verifier.isValidCode(secret,code);
    }

    public boolean isOtpNotValid (String secret, String code) {
        return !this.isOtpValid(secret,code);
    }
}
