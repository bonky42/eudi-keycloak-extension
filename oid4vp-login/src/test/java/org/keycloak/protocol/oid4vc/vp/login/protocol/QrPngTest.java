package org.keycloak.protocol.oid4vc.vp.login.protocol;

import com.google.zxing.BinaryBitmap;
import com.google.zxing.MultiFormatReader;
import com.google.zxing.Result;
import com.google.zxing.client.j2se.BufferedImageLuminanceSource;
import com.google.zxing.common.HybridBinarizer;
import org.junit.jupiter.api.Test;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class QrPngTest {

    private static final String PREFIX = "data:image/png;base64,";

    /** A realistic wallet URI: long, and carrying escaped characters. */
    private static final String WALLET_URI =
        "openid4vp://?client_id=x509_san_dns%3Aaccounts.example.org"
            + "&request_uri=https%3A%2F%2Faccounts.example.org%2Frealms%2Fwallet"
            + "%2Fbroker%2Foid4vp%2Fendpoint%2Frequest%2FR2h0LXRva2VuLWlkZW50aWZpZXI";

    @Test
    void aRenderedQrDecodesBackToItsExactText() throws Exception {
        String uri = QrPng.dataUri(WALLET_URI, 240);

        assertTrue(uri.startsWith(PREFIX), "the URI must be a base64 PNG image, got=" + uri);
        BufferedImage image = ImageIO.read(new ByteArrayInputStream(
            Base64.getDecoder().decode(uri.substring(PREFIX.length()))));

        Result decoded = new MultiFormatReader().decode(new BinaryBitmap(
            new HybridBinarizer(new BufferedImageLuminanceSource(image))));

        assertEquals(WALLET_URI, decoded.getText(),
            "the round trip must yield the EXACT text: a QR decoding to anything else would send "
                + "the holder to a transaction that is not theirs");
    }

    @Test
    void theRequestedSizeIsALowerBoundNotAnExactSize() throws Exception {
        // Large enough for the content: ZXing renders at exactly the requested size.
        String normalUri = QrPng.dataUri(WALLET_URI, 240);
        BufferedImage normalImage = ImageIO.read(new ByteArrayInputStream(
            Base64.getDecoder().decode(normalUri.substring(PREFIX.length()))));
        assertEquals(240, normalImage.getWidth());
        assertEquals(240, normalImage.getHeight());

        // Too small for the content: ZXing does not crop the QR to fit, since a truncated QR would
        // no longer decode. It renders larger than asked rather than produce an unreadable image,
        // so sizePx is a floor, not an exact size.
        String tinyUri = QrPng.dataUri(WALLET_URI, 64);
        BufferedImage tinyImage = ImageIO.read(new ByteArrayInputStream(
            Base64.getDecoder().decode(tinyUri.substring(PREFIX.length()))));
        assertTrue(tinyImage.getWidth() > 64,
            "text too long for 64px must produce a larger image, not a truncated one, got="
                + tinyImage.getWidth());
        assertEquals(tinyImage.getWidth(), tinyImage.getHeight(),
            "the image stays square even when the requested size is exceeded");
    }

    @Test
    void anEmptyTextIsRefusedRatherThanRenderedBlank() {
        // An empty QR is visually indistinguishable from a valid one, and the holder would scan
        // something leading nowhere. Better that the caller knows it failed.
        assertThrows(IllegalStateException.class, () -> QrPng.dataUri("", 240));
        assertThrows(IllegalStateException.class, () -> QrPng.dataUri(null, 240));
    }
}
