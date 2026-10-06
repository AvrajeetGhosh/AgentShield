package AgentShield.security;

import net.sourceforge.tess4j.Tesseract;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

@Service
public class ImageOcrService {

    private final Tesseract tesseract;

    public ImageOcrService() {

        this.tesseract = new Tesseract();

        tesseract.setDatapath(
                "C:\\Program Files\\Tesseract-OCR\\tessdata"
        );

        tesseract.setLanguage("eng");

        tesseract.setOcrEngineMode(1);

        tesseract.setPageSegMode(6);
    }
    public String extractText(byte[] imageBytes) throws IOException {

        if (imageBytes == null || imageBytes.length == 0) {
            throw new IllegalArgumentException(
                    "Image file is empty."
            );
        }

        File tempFile = Files.createTempFile(
                "agentshield-ocr-",
                ".png"
        ).toFile();

        try {

            Files.write(
                    tempFile.toPath(),
                    imageBytes
            );

            try {
                return tesseract.doOCR(tempFile);

            } catch (Exception e) {

                throw new RuntimeException(
                        "OCR processing failed: " + e.getMessage(),
                        e
                );
            }

        } finally {

            Files.deleteIfExists(
                    tempFile.toPath()
            );
        }
    }
}