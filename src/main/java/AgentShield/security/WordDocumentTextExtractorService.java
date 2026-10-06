package AgentShield.security;

import org.apache.poi.openxml4j.exceptions.OLE2NotOfficeXmlFileException;
import org.apache.poi.openxml4j.exceptions.NotOfficeXmlFileException;
import org.apache.poi.xwpf.usermodel.XWPFDocument;
import org.apache.poi.xwpf.usermodel.XWPFParagraph;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.io.IOException;

@Service
public class WordDocumentTextExtractorService {

    public String extractText(byte[] docxBytes) throws IOException {

        if (docxBytes == null || docxBytes.length == 0) {
            throw new IllegalArgumentException(
                    "Word document is empty."
            );
        }

        try (XWPFDocument document =
                     new XWPFDocument(
                             new ByteArrayInputStream(docxBytes)
                     )) {

            StringBuilder text = new StringBuilder();

            for (XWPFParagraph paragraph :
                    document.getParagraphs()) {

                if (paragraph.getText() != null &&
                        !paragraph.getText().isBlank()) {

                    text.append(paragraph.getText())
                            .append("\n");
                }
            }

            String extracted = text.toString().trim();

            if (extracted.isEmpty()) {
                throw new IllegalArgumentException(
                        "No readable text found in Word document."
                );
            }

            return extracted;

        } catch (NotOfficeXmlFileException e) {

            throw new IllegalArgumentException(
                    "Invalid DOCX file. The uploaded file is not a valid Word document."
            );
        }
    }
}