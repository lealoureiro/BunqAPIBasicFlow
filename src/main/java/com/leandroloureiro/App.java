package com.leandroloureiro;

import com.leandroloureiro.bunqapi.BunqAPI;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.xml.bind.DatatypeConverter;
import java.security.KeyPair;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


/**
 * @author Leandro Loureiro
 */
public class App {

    private static final Logger LOGGER = LogManager.getLogger(App.class.getName());

    private static final Pattern API_KEY_FORMAT = Pattern.compile("[0-9a-f]{64}");

    private App() {

    }

    public static void main(final String[] args) throws InterruptedException {

        LOGGER.info("Bunq API Basic Flow");

        if (args.length == 0) {
            LOGGER.fatal("Please specify your Sandbox API key with format: java -jar <jar_file> <api_key>");
            System.exit(1);
        }

        final Matcher m = API_KEY_FORMAT.matcher(args[0]);
        if (!m.matches()) {
            LOGGER.fatal("Invalid API Key format!");
            System.exit(1);
        }

        final KeyPair keyPair = BunqAPI.generateRSA2048KeyPair();

        if (keyPair == null) {
            LOGGER.fatal("Failed to generate RSA 2048 Key Pair!");
            System.exit(1);
        }

        final String publicKey = formatPublicKey(keyPair.getPublic().getEncoded());

        LOGGER.debug("Generated Public Key to sender to server: {}", publicKey);

        final BunqAPI api = new BunqAPI(args[0], keyPair.getPrivate().getEncoded());

        api.installation(publicKey);
        api.createDeviceServer();
        api.login();
        api.getMonetaryAccounts();
        api.listInstallations();

    }

    private static String formatPublicKey(final byte[] publicKey) {

        final String publicKeyBase64 = DatatypeConverter.printBase64Binary(publicKey);
        return String.format("-----BEGIN PUBLIC KEY-----\\n%s\\n-----END PUBLIC KEY-----\\n", publicKeyBase64);

    }

}
