package com.sf.bioregistra.crypto;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;
import javax.imageio.ImageIO;
import java.awt.*;
import java.awt.color.ColorSpace;
import java.awt.image.BufferedImage;
import java.awt.image.ColorModel;
import java.awt.image.ComponentColorModel;
import java.awt.image.DataBuffer;
import java.awt.image.DataBufferByte;
import java.awt.image.Raster;
import java.awt.image.WritableRaster;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Properties;
import java.util.stream.Collectors;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

@SuppressWarnings("PMD")
public class StegUtil {

    private static final Logger logger = LoggerFactory.getLogger(StegUtil.class);
    private static final String FINGERPRINT_MESSAGE = "MIV1";
    private static final String AES_TYPE = "AES";
    private int offset;
    private int width;
    private int height;
    private byte[] carrier;
    private String hiddenMessage;
    private boolean encryption;
    private boolean compression;

    /**
     * Gets the decode message from the carrier.
     * Should be called after #reveal(File carrierDir, File outDir, char[] password)
     *
     * @return the decoded message
     */
    public String getDecodedMessage() {
        return hiddenMessage;
    }

    /**
     * @return true if encryption enabled, false otherwise
     */
    public boolean isEncryption() {
        return encryption;
    }

    /**
     * @param encrypt true to enable encryption, false otherwise
     */
    public void setEncryption(boolean encrypt) {
        this.encryption = encrypt;
    }

    /**
     * @return true if compression enabled, false otherwise
     */
    public boolean isCompression() {
        return compression;
    }

    /**
     * @param compression true to enable compression, false otherwise
     */
    public void setCompression(boolean compression) {
        this.compression = compression;
    }

    /**
     * @param carrierDir directory containing the carrier images
     * @param secretFile absolute path to the secret file
     * @param outputDir  path to save the steg file
     * @param message    message to hide, with the secret file
     * @param password   password to encrypt the secret file and message, ONLY if encryption enabled
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws IllegalStateException
     * @throws ShortBufferException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public void hide(File carrierDir, File secretFile, File outputDir, String message, char[] password) throws IOException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, IllegalStateException, ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        if (!(outputDir.isDirectory() && outputDir.exists())) {
            throw new FileNotFoundException("");
        }
        if (secretFile == null) {
            throw new FileNotFoundException("");
        }
        if (message == null) {
            message = "";
        }
        if (encryption && password == null) {
            throw new IllegalArgumentException("Encryption cannot be done with no password");
        }
        byte[] payload = getBytes(secretFile);
        byte[] fingerprinMsg = FINGERPRINT_MESSAGE.getBytes();
        String[] carriers = null;
        String imageFileNameWithoutExt = null;
        String sectretFname = secretFile.getName();
        File imageFile = null;
        int payloadSize = payload.length;
        int freeSpaceInCarrier = 0;
        int _bytesWritten;
        int payloadOffset = 0;
        int fnameLen = sectretFname.length();
        FilterDirectory filter = new FilterDirectory("JPG");
        carriers = carrierDir.list(filter);

        payload = addMessageToPayload(payload, message.getBytes());
        payloadSize += message.getBytes().length;

        if (compression) {
            payload = compressPayload(payload);
            payloadSize = payload.length;
        }
        if (encryption) {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.reset();
            messageDigest.update(new String(password).getBytes());

            payload = encryptPayload(payload, messageDigest.digest());
            payloadSize = payload.length;
        }

        for (int i = 0; i < carriers.length; i++) {
            offset = 0;
            _bytesWritten = 0;
            imageFile = new File(carrierDir + File.separator + carriers[i]);
            imageFileNameWithoutExt = getFilenameWithoutExtension(imageFile.getName());
            carrier = convertImageToRGBPixels(imageFile);

            freeSpaceInCarrier = carrier.length / 8;
            freeSpaceInCarrier -= encode(fingerprinMsg, 4, 0);

            if (i == 0) {
                freeSpaceInCarrier -= encode(getBytes(payloadSize), 4, 0);

                freeSpaceInCarrier -= encode(getBytes(fnameLen), 4, 0);

                freeSpaceInCarrier -= encode(sectretFname.getBytes(), sectretFname.getBytes().length, 0);

                freeSpaceInCarrier -= encode(getBytes(message.getBytes().length), 4, 0);
            }


            if (freeSpaceInCarrier < payloadSize) {
                _bytesWritten = encode(payload, freeSpaceInCarrier, payloadOffset);
            } else {
                _bytesWritten = encode(payload, payloadSize, payloadOffset);
            }
            freeSpaceInCarrier -= _bytesWritten;
            payloadSize -= _bytesWritten;
            payloadOffset += _bytesWritten;
            ImageIO.write(convertRGBPixelsToImage(carrier), "png", new File(outputDir + File.separator + imageFileNameWithoutExt + ".png"));
            if (payloadSize > 0) {
                continue;
            } else {
                break;
            }
        }
        if (payloadSize > 0) {
            throw new IllegalArgumentException("Not enough cover images");
        }

    }

    /**
     * encodes the #bytesToWrite bytes payload into the carrier image starting from #payloadOffset
     *
     * @param payload       to hide in the carrier image
     * @param bytesToWrite  number of bytes to write
     * @param payloadOffset a pointer in the payload byte array indicating the position to start encoding from
     * @return number of bytes written
     */
    private int encode(byte[] payload, int bytesToWrite, int payloadOffset) {
        int bytesWritten = 0;
        for (int i = 0; i < bytesToWrite; i++, payloadOffset++) {
            int payloadByte = payload[payloadOffset];
            bytesWritten++;
            for (int bit = 7; bit >= 0; --bit, ++offset) {
                //assign an integer to b,shifted by bit spaces AND 1
                //a single bit of the current byte
                int byteValue = (payloadByte >>> bit) & 1;
                //assign the bit by taking[(previous byte value) AND 0xfe]
                //or bit to
                try {
                    carrier[offset] = (byte) ((carrier[offset] & 0xFE) | byteValue);
                } catch (ArrayIndexOutOfBoundsException e) {
                    logger.error("Encoding error: {}", e.getMessage());
                }
            }
        }
        return bytesWritten;
    }

    /**
     * Appends the message to the end of the payload.
     *
     * @param payload  append the message to this payload
     * @param msgBytes the message to append
     * @return payload + message
     */
    private byte[] addMessageToPayload(byte[] payload, byte[] msgBytes) {
        int totalSize = payload.length + msgBytes.length;
        byte[] _payload = new byte[totalSize];
        System.arraycopy(payload, 0, _payload, 0, payload.length);
        System.arraycopy(msgBytes, 0, _payload, payload.length, msgBytes.length);
        return _payload;
    }

    /**
     * Extracts the secret file fom the provided steg image(s)
     *
     * @param carrierDir directory containing the steg images
     * @param outputDirectory     directory to place the extracted secret file
     * @param password   password to decrypt the secret file and message, ONLY if the payload was encrypted
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws IllegalStateException
     * @throws ShortBufferException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public void reveal(File carrierDir, File outputDirectory, char[] password) throws IOException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, IllegalStateException, ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        byte payload[] = null;
        byte[] tmp = null;
        int payloadRemaining = 0;
        int fnameSize = 0;
        int payloadSize = 0;
        String fname = null;
        int msgLen = 0;
        int bytesToDecodeFromCarrier = 0;
        ArrayList<byte[]> payloadData = new ArrayList<>();
        List<String> carriers = Arrays.stream(Objects.requireNonNull(carrierDir.list((dir, name) -> !(".DS_Store".equalsIgnoreCase(name)))))
                .filter(fileName -> !("png".equalsIgnoreCase(fileName)))
        .collect(Collectors.toList());
        for (int i = 0; i < carriers.size(); i++) {
            offset = 0;
            String imageName = carrierDir + File.separator + carriers.get(i);
            carrier = convertImageToRGBPixels(new File(imageName));
            if (!isStegnographed(carrier)) {
                continue;
            }
            bytesToDecodeFromCarrier = carrier.length / 8 - 4;// - 4 bcoz we have already decoded the neurotech
            if (i == 0) {
                tmp = decode(carrier, 4); //extracting the payload size
                payloadSize = toInteger(tmp);
                payloadRemaining = payloadSize;
                bytesToDecodeFromCarrier -= 4;
                //System.out.println("Bytes to Decode: " + bytesToDecodeFromCarrier);
                //System.out.println("Payload Size: " + payloadSize);

                tmp = null;
                tmp = decode(carrier, 4); //extracting the size of the filename
                fnameSize = toInteger(tmp);
                bytesToDecodeFromCarrier -= 4;

                tmp = null;
                tmp = decode(carrier, fnameSize);
                bytesToDecodeFromCarrier -= fnameSize;
                fname = new String(tmp);

                tmp = null;
                tmp = decode(carrier, 4);
                msgLen = toInteger(tmp);
                bytesToDecodeFromCarrier -= 4;
            }
            if (payloadRemaining > bytesToDecodeFromCarrier) {
                payload = decode(carrier, bytesToDecodeFromCarrier);
                payloadRemaining = payloadRemaining - bytesToDecodeFromCarrier;
            } else {
                payload = decode(carrier, payloadRemaining);
                payloadRemaining = payloadRemaining - payloadRemaining;
            }
            payloadData.add(payload);
            if (payloadRemaining == 0) {
                break;
            }
        }
        if (payloadRemaining > 0) {
            throw new IllegalArgumentException("Some Stego Files missing!");
        }
        try (OutputStream fOutStream = Files.newOutputStream(Paths.get(outputDirectory + File.separator + fname))) {
            if (!payloadData.isEmpty()) {
                byte[] secretData = new byte[payloadSize];
                byte[] message;// = new byte[msgLen];
                byte[] secretFile;// = new byte[payloadSize - msgLen];
                int ptr = 0;
                for (byte[] tmpArray : payloadData) {
                    for (int j = 0; j < tmpArray.length; j++, ptr++) {
                        secretData[ptr] = tmpArray[j];
                    }
                }
                if (encryption) {
                    MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
                    messageDigest.reset();
                    messageDigest.update(new String(password).getBytes());
                    secretData = decryptPayload(secretData, messageDigest.digest());
                    payloadSize = secretData.length;
                }

                if (compression) {
                    secretData = decompressPayload(secretData);
                    payloadSize = secretData.length;
                }
                message = new byte[msgLen];
                secretFile = new byte[payloadSize - msgLen];

                for (int i = 0; i < payloadSize - msgLen; i++) {
                    secretFile[i] = secretData[i];
                }

                for (int j = 0; j < (msgLen); j++) {
                    message[j] = secretData[j + (payloadSize - msgLen)];
                }
                hiddenMessage = new String(message);
                fOutStream.write(secretFile);
            }
        }

    }

    /**
     * decodes #bytesToRead bytes from the carrier
     *
     * @param carrier
     * @param bytesToRead
     * @return
     */
    private byte[] decode(byte[] carrier, int bytesToRead) {
        byte[] _decode = new byte[bytesToRead];
        for (int i = 0; i < _decode.length; ++i) {
            for (int bit = 0; bit < 8; ++bit, ++offset) {
                try {
                    _decode[i] = (byte) ((_decode[i] << 1) | (carrier[offset] & 1));
                } catch (ArrayIndexOutOfBoundsException exception) {
                    logger.error("Decoding Error : {}", exception.getMessage());
                }
            }
        }
        return _decode;
    }

    /**
     * Converts a byte array with RGB pixel values to
     * a bufferedImage
     *
     * @param carrier byte array of RGB pixels
     * @return BufferedImage
     */
    private BufferedImage convertRGBPixelsToImage(byte[] carrier) {
        ColorSpace colorSpace = ColorSpace.getInstance(ColorSpace.CS_sRGB);
        int[] nBits = {8, 8, 8};
        int[] bOffs = {2, 1, 0}; // band offsets r g b
        int pixelStride = 3; //assuming r, g, b, skip, r, g, b, skip..
        ColorModel colorModel = new ComponentColorModel(
                colorSpace, nBits, false, false,
                Transparency.OPAQUE,
                DataBuffer.TYPE_BYTE);
        WritableRaster raster = Raster.createInterleavedRaster(
                new DataBufferByte(carrier, carrier.length), width, height, width * 3, pixelStride, bOffs, null);

        return new BufferedImage(colorModel, raster, false, null);
    }

    /**
     * Converts an Image to RG pixel array
     *
     * @param filename image to convert
     * @return byte array
     * @throws IOException
     */
    private byte[] convertImageToRGBPixels(File filename) throws IOException {
        BufferedImage image = ImageIO.read(filename);
        width = image.getWidth();
        height = image.getHeight();
        BufferedImage clone = new BufferedImage(width, height, BufferedImage.TYPE_3BYTE_BGR);
        Graphics2D graphics = clone.createGraphics();
        graphics.drawRenderedImage(image, null);
        graphics.dispose();
        image.flush();
        WritableRaster raster = clone.getRaster();
        DataBufferByte buff = (DataBufferByte) raster.getDataBuffer();
        return buff.getData();
    }

    /**
     * Compress the payload
     *
     * @param payload
     * @return compressed payload
     * @throws IOException
     */
    private byte[] compressPayload(byte[] payload) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        GZIPOutputStream zos = new GZIPOutputStream(bos);
        zos.write(payload);
        zos.finish();
        zos.close();
        bos.close();
        return bos.toByteArray();
    }

    /**
     * decompress the payload
     *
     * @param payload
     * @return decompressed payload
     * @throws IOException
     */
    private byte[] decompressPayload(byte[] payload) throws IOException {
        ByteArrayInputStream bis = new ByteArrayInputStream(payload);
        GZIPInputStream zis = new GZIPInputStream(bis);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] dataBuf = new byte[4096];
        int bytes_read = 0;
        while ((bytes_read = zis.read(dataBuf)) > 0) {
            out.write(dataBuf, 0, bytes_read);
        }
        payload = out.toByteArray();
        out.close();
        zis.close();
        bis.close();
        return payload;
    }

    /**
     * Encrypts the paylaod using AES-256
     *
     * @param payload  byte array to encrypt
     * @param password password to hashed to SHA-256
     * @return encrypted payload
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws IllegalStateException
     * @throws ShortBufferException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    private byte[] encryptPayload(byte[] payload, byte[] password) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, IllegalStateException, ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        SecretKeySpec key = new SecretKeySpec(password, AES_TYPE);
        Cipher cipher = Cipher.getInstance(AES_TYPE);
        cipher.init(Cipher.ENCRYPT_MODE, key);

        byte[] cipherText = new byte[cipher.getOutputSize(payload.length)];
        int ctLength = cipher.update(payload, 0, payload.length, cipherText, 0);
        ctLength += cipher.doFinal(cipherText, ctLength);
        return cipherText;
    }

    /**
     * decrypts the payoad
     *
     * @param payload  payload to decrypt
     * @param password hashed using sha-256
     * @return decrypted payload
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws IllegalStateException
     * @throws ShortBufferException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    private byte[] decryptPayload(byte[] payload, byte[] password) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, IllegalStateException, ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        SecretKeySpec key = new SecretKeySpec(password, AES_TYPE);
        Cipher cipher = Cipher.getInstance(AES_TYPE);
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] plainText = new byte[cipher.getOutputSize(payload.length)];
        int ptLength = cipher.update(payload, 0, payload.length, plainText, 0);
        ptLength += cipher.doFinal(plainText, ptLength);
        return plainText;
    }

    /**
     * @param name Filename
     * @return filename without extension
     */
    private String getFilenameWithoutExtension(String name) {
        return name.replaceFirst("[.][^.]+$", "");
    }

    /**
     * Converts a byte array to int
     *
     * @param byteArray byte array to convert
     * @return converted int
     */
    private int toInteger(byte[] byteArray) {
        return byteArray[0] << 24 | (byteArray[1] & 0xFF) << 16 | (byteArray[2] & 0xFF) << 8 | (byteArray[3] & 0xFF);
    }

    /**
     * Converts the contents of the file to byte array
     *
     * @param file Filename
     * @return file converted into byte array
     * @throws IOException
     */
    private byte[] getBytes(File file) throws IOException {
        // Get the size of the file
        long length = file.length();
        // You cannot create an array using a long type.
        // It needs to be an int type.
        // Before converting to an int type, check
        // to ensure that file is not larger than Integer.MAX_VALUE.
        if (length > Integer.MAX_VALUE) {
            // File is too large
            return null;
        }
        try (InputStream inputStream = Files.newInputStream(Paths.get(file.getPath()))) {
            // Create the byte array to hold the data
            byte[] bytes = new byte[(int) length];
            // Read in the bytes
            int offset = 0;
            int numRead = 0;
            while (offset < bytes.length && (numRead = inputStream.read(bytes, offset, bytes.length - offset)) >= 0) {
                offset += numRead;
            }
            // Ensure all the bytes have been read in
            if (offset < bytes.length) {
                inputStream.close();
                throw new IOException("Could not completely read file " + file.getName());
            }
            // Close the input stream and return bytes
            inputStream.close();
            return bytes;
        }
    }

    /**
     * Converts an integer to bytes
     *
     * @param intValue integer to convert
     * @return
     */
    private byte[] getBytes(int intValue) {
        return new byte[]{(byte) (intValue >> 24), (byte) (intValue >> 16), (byte) (intValue >> 8), (byte) intValue};
    }

    /**
     * Matches the first four bytes of the image to the FINGERPRINT_MESSAGE
     *
     * @param carrier carrier byte array
     * @return true if FINGERPRINT_MESSAGE found, false otherwise
     */
    private boolean isStegnographed(byte[] carrier) {
        byte[] tmp = new byte[4];
        String fingerPrint = null;
        tmp = decode(carrier, 4);
        fingerPrint = new String(tmp);
        return fingerPrint.equals(FINGERPRINT_MESSAGE);
    }

    public static void main(String[] args) throws NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, IOException, ShortBufferException, IllegalBlockSizeException, NoSuchProviderException, InvalidKeyException {
        //useful for loading initial properties

        StegUtil stegUtil = new StegUtil();
        File parent = new File("steg-prep");
//        File carrierDir = new File(parent, "image");

        File encodeOutputDir = new File(parent, "encode-result");
        encodeOutputDir.mkdirs();
        File revealOutputDir = new File(parent, "reveal-result");
        revealOutputDir.mkdirs();
        File secretFile = new File(revealOutputDir, "steg-prep.properties");

//        stegUtil.hide(carrierDir, secretFile, encodeOutputDir, null, null);

        stegUtil.reveal(encodeOutputDir, revealOutputDir, null);

//        File revealFile = new File(encodeOutputDir, "seamfix-logo-sec-2.png");

        Properties props = new Properties();
        props.load(Files.newInputStream(Paths.get(secretFile.getPath())));
    }
}

/**
 * @author Naveed Quadri
 */
class FilterDirectory implements FilenameFilter {


    private String[] extentions;

    public FilterDirectory(String ext) {
        this(new String[]{ext});
    }

    public FilterDirectory(String[] formats) {
        if (formats == null) {
            extentions = new String[0];
        } else {
            extentions = Arrays.copyOf(formats, formats.length);
        }
    }

    public boolean accept(File dir, String name) {
        // We always allow directories, regardless of their extension
        if (dir.isDirectory()) {
            return true;
        }

        // Ok, it is a regular file, so check the extension
        name = dir.getName().toLowerCase();
        for (int i = extentions.length - 1; i >= 0; i--) {
            if (name.endsWith(extentions[i])) {
                return true;
            }
        }
        return false;

    }
}
