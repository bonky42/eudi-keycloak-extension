package org.keycloak.protocol.oid4vc.vp.login.protocol;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.EncodeHintType;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.EnumMap;
import java.util.Map;

/**
 * Renders text as a PNG QR code, encoded as a {@code data:} URI.
 *
 * <p><b>Server side, with ZXing</b>, which the Keycloak distribution already ships for TOTP
 * enrolment QR codes — rather than adding a JavaScript library to the theme. A login page depending
 * on a third-party script would be a supply-chain risk on the most sensitive page of the product,
 * and would not work on a closed network.</p>
 *
 * <p>A pure function, with no state and no dependency on the Keycloak runtime: it can be tested on
 * its own, and its encode-then-decode round trip is what proves it renders the EXACT text.</p>
 */
public final class QrPng {

    private QrPng() {
    }

    /**
     * @param text   the text to encode, typically the wallet URI
     * @param sizePx the image's minimum side in pixels. ZXing never renders below the QR's module
     *               count plus its quiet zone, so the image can come out larger than
     *               {@code sizePx} for long text, but never smaller
     * @return a {@code data:image/png;base64,...} URI
     * @throws IllegalStateException if encoding fails, empty or null text included: an empty QR is
     *         visually indistinguishable from a valid one, and the holder would scan something
     *         leading nowhere. The caller decides what to do — the login page renders with the deep
     *         link alone.
     */
    public static String dataUri(String text, int sizePx) {
        if (text == null || text.isEmpty()) {
            throw new IllegalStateException("refusing to render a QR code for empty text");
        }
        try {
            // No MARGIN hint: QRCodeWriter's default of 4 modules is already the minimum ISO/IEC
            // 18004 requires for readers to lock on reliably. Shrinking it would degrade reading by
            // a phone camera in poor light — which the ZXing-on-ZXing round-trip test cannot
            // detect, since it re-reads its own output with no noise.
            Map<EncodeHintType, Object> hints = new EnumMap<>(EncodeHintType.class);
            hints.put(EncodeHintType.CHARACTER_SET, StandardCharsets.UTF_8.name());
            hints.put(EncodeHintType.ERROR_CORRECTION, ErrorCorrectionLevel.M);

            BitMatrix matrix =
                new QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, sizePx, sizePx, hints);

            ByteArrayOutputStream png = new ByteArrayOutputStream();
            MatrixToImageWriter.writeToStream(matrix, "PNG", png);
            return "data:image/png;base64," + Base64.getEncoder().encodeToString(png.toByteArray());
        } catch (WriterException | IOException e) {
            throw new IllegalStateException("failed to render the QR code: " + e.getMessage(), e);
        }
    }
}
