package AgentShield.security;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.text.PDFTextStripper;
import org.springframework.stereotype.Service;

import java.io.IOException;

@Service
public class PdfTextExtractorService {

    public String extractText(byte[] pdfBytes) throws IOException {

        if (pdfBytes == null || pdfBytes.length == 0) {
            throw new IllegalArgumentException(
                    "PDF file is empty."
            );
        }

        try (PDDocument document =
                     Loader.loadPDF(pdfBytes)) {

            PDFTextStripper stripper =
                    new PDFTextStripper();

            return stripper.getText(document);
        }
    }
}