package AgentShield.controller;

import AgentShield.model.DetectionResult;
import AgentShield.model.Scan;
import AgentShield.model.ScanRequest;
import AgentShield.model.SecuritySettings;
import AgentShield.repository.ScanRepository;
import AgentShield.repository.SecuritySettingsRepository;
import AgentShield.security.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.List;

@RestController
@RequestMapping("/api/firewall")
public class FirewallController {

    private final PromptInjectionDetector detector;
    private final LocalAiSecurityAnalyzer aiAnalyzer;
    private final ScanRepository scanRepository;
    private final SecuritySettingsRepository settingsRepository;
    private final PdfTextExtractorService pdfTextExtractorService;
    private final ImageOcrService imageOcrService;
    private final WordDocumentTextExtractorService wordDocumentTextExtractorService;

    private static final long MAX_PDF_SIZE = 10 * 1024 * 1024;      // 10 MB
    private static final long MAX_WORD_SIZE = 10 * 1024 * 1024;     // 10 MB
    private static final long MAX_IMAGE_SIZE = 10 * 1024 * 1024;     // 10 MB




    public FirewallController(
            PromptInjectionDetector detector,
            LocalAiSecurityAnalyzer aiAnalyzer,
            ScanRepository scanRepository,
            SecuritySettingsRepository settingsRepository,
            PdfTextExtractorService pdfTextExtractorService, ImageOcrService imageOcrService,
            WordDocumentTextExtractorService wordDocumentTextExtractorService)  {

        this.detector = detector;
        this.aiAnalyzer = aiAnalyzer;
        this.scanRepository = scanRepository;
        this.settingsRepository = settingsRepository;
        this.pdfTextExtractorService =
                pdfTextExtractorService;
        this.imageOcrService = imageOcrService;
        this.wordDocumentTextExtractorService =
                wordDocumentTextExtractorService;
    }




    @PostMapping(
            value = "/scan-pdf",
            consumes = MediaType.MULTIPART_FORM_DATA_VALUE
    )
    public DetectionResult scanPdf(
            @RequestParam("file") MultipartFile file,
            jakarta.servlet.http.HttpServletRequest httpRequest
    ) throws Exception {


        if (file == null || file.isEmpty()) {
            throw new IllegalArgumentException(
                    "PDF file is empty."
            );
        }

        String filename = file.getOriginalFilename();

        if (filename == null ||
                !filename.toLowerCase().endsWith(".pdf")) {

            throw new IllegalArgumentException(
                    "Only PDF files are supported."
            );
        }

        if (file.getSize() > MAX_PDF_SIZE) {
            throw new IllegalArgumentException(
                    "PDF file is too large. Maximum allowed size is 10 MB."
            );
        }

        try (InputStream inputStream = file.getInputStream()) {

            byte[] header = inputStream.readNBytes(5);

            if (header.length < 5 ||
                    !"%PDF-".equals(
                            new String(
                                    header,
                                    StandardCharsets.ISO_8859_1
                            )
                    )) {

                throw new IllegalArgumentException(
                        "Invalid PDF file. The uploaded file is not a valid PDF."
                );
            }
        }

        String extractedText =
                pdfTextExtractorService.extractText(
                        file.getBytes()
                );

        ScanRequest request = new ScanRequest();

        request.setContent(extractedText);
        request.setInputSource("PDF");

        return scan(request, httpRequest);
    }


    @PostMapping(
            value = "/scan-image",
            consumes = MediaType.MULTIPART_FORM_DATA_VALUE
    )
    public DetectionResult scanImage(
            @RequestParam("file") MultipartFile file,
            jakarta.servlet.http.HttpServletRequest httpRequest
    ) throws Exception {

        if (file == null || file.isEmpty()) {
            throw new IllegalArgumentException(
                    "Image file is empty."
            );
        }

        String filename = file.getOriginalFilename();

        if (filename == null) {
            throw new IllegalArgumentException(
                    "Image filename is missing."
            );
        }

        if (file.getSize() > MAX_IMAGE_SIZE) {
            throw new IllegalArgumentException(
                    "Image file is too large. Maximum allowed size is 10 MB."
            );
        }

        String lowerFilename =
                filename.toLowerCase();

        if (!lowerFilename.endsWith(".png")
                && !lowerFilename.endsWith(".jpg")
                && !lowerFilename.endsWith(".jpeg")
                && !lowerFilename.endsWith(".bmp")
                && !lowerFilename.endsWith(".tiff")
                && !lowerFilename.endsWith(".webp")) {

            throw new IllegalArgumentException(
                    "Unsupported image format."
            );
        }

        String extractedText =
                imageOcrService.extractText(
                        file.getBytes()
                );

        if (extractedText == null ||
                extractedText.trim().isEmpty()) {

            throw new IllegalArgumentException(
                    "No readable text found in image."
            );
        }

        ScanRequest request =
                new ScanRequest();

        request.setContent(extractedText);
        request.setInputSource("IMAGE_OCR");

        return scan(
                request,
                httpRequest
        );
    }

    @PostMapping(
            value = "/scan-word",
            consumes = MediaType.MULTIPART_FORM_DATA_VALUE
    )
    public DetectionResult scanWord(
            @RequestParam("file") MultipartFile file,
            jakarta.servlet.http.HttpServletRequest httpRequest
    ) throws Exception {

        if (file == null || file.isEmpty()) {
            throw new IllegalArgumentException(
                    "Word document is empty."
            );
        }

        String filename = file.getOriginalFilename();

        if (filename == null) {
            throw new IllegalArgumentException(
                    "Word document filename is missing."
            );
        }

        String lowerFilename = filename.toLowerCase();

        if (!lowerFilename.endsWith(".docx")) {
            throw new IllegalArgumentException(
                    "Only .docx Word documents are supported."
            );
        }

        if (file.getSize() > MAX_WORD_SIZE) {
            throw new IllegalArgumentException(
                    "Word document is too large. Maximum allowed size is 10 MB."
            );
        }
        

        String extractedText =
                wordDocumentTextExtractorService.extractText(
                        file.getBytes()
                );

        ScanRequest request = new ScanRequest();

        request.setContent(extractedText);
        request.setInputSource("WORD_DOCUMENT");

        return scan(request, httpRequest);
    }



    @PostMapping("/scan")
    public DetectionResult scan(
            @RequestBody ScanRequest request,
            jakarta.servlet.http.HttpServletRequest httpRequest) {
        long startTime = System.currentTimeMillis();

        if (request == null) {
            throw new IllegalArgumentException(
                    "Scan request cannot be null."
            );
        }

        if (request.getContent() == null ||
                request.getContent().isBlank()) {

            throw new IllegalArgumentException(
                    "Content cannot be empty."
            );
        }

        String clientIp =
                httpRequest != null
                        ? httpRequest.getRemoteAddr()
                        : "UNKNOWN";

        String inputSource = request.getInputSource();

        if (inputSource == null || inputSource.isBlank()) {
            inputSource = "USER_MESSAGE";
        }

        String requestId =
                "AS-" +
                        java.util.UUID.randomUUID()
                                .toString()
                                .substring(0, 8)
                                .toUpperCase();

        SecuritySettings settings = getSettings();

        DetectionResult result;

        // =========================================================
        // 1. FIREWALL PROTECTION
        // =========================================================

        if (!settings.isFirewallEnabled()) {

            result = new DetectionResult(
                    false,
                    "NONE",
                    "LOW",
                    0,
                    "Firewall protection is disabled by configuration."
            );

            result.setActionTaken("ALLOWED");
            result.setDetectionSource("FIREWALL_DISABLED");
        }

        // =========================================================
        // 2. PROMPT INJECTION DETECTION
        // =========================================================

        else if (!settings.isDetectionEnabled()) {

            result = new DetectionResult(
                    false,
                    "NONE",
                    "LOW",
                    0,
                    "Prompt injection detection is disabled by configuration."
            );

            result.setActionTaken("ALLOWED");
            result.setDetectionSource("DETECTION_DISABLED");
        }

        // =========================================================
        // 3. HYBRID DETECTION
        // =========================================================

        else {

            /*
             * Layer 1:
             * Existing deterministic Java rule engine.
             */
            result = detector.detect(request.getContent());

            // -----------------------------------------------------
            // Java rules detected a threat
            // -----------------------------------------------------

            if (result.isMalicious()) {

                result.setDetectionSource("RULE_ENGINE");

                if (settings.isAutoBlockEnabled()) {
                    result.setActionTaken("BLOCKED");
                } else {
                    result.setActionTaken("FLAGGED");
                }

            }

            // -----------------------------------------------------
            // Java rules found nothing suspicious
            // Run local AI semantic analysis
            // -----------------------------------------------------

            else {

                String aiClassification =
                        aiAnalyzer.analyze(request.getContent());

                // -------------------------------------------------
                // Local AI detected a semantic threat
                // -------------------------------------------------

                if ("MALICIOUS".equals(aiClassification)) {

                    /*
                     * AI detected a semantic prompt injection
                     * that the deterministic rules did not detect.
                     */

                    result.setMalicious(true);

                    result.setAttackType(
                            "AI_SEMANTIC_DETECTION"
                    );

                    result.setRiskLevel("HIGH");

                    result.setRiskScore(70);

                    result.setReason(
                            "Local AI semantic analysis identified a likely prompt injection attempt."
                    );

                    result.setDetectionSource("LOCAL_AI");

                    if (settings.isAutoBlockEnabled()) {
                        result.setActionTaken("BLOCKED");
                    } else {
                        result.setActionTaken("FLAGGED");
                    }

                }

                // -------------------------------------------------
                // AI says SAFE
                // -------------------------------------------------

                else if ("SAFE".equals(aiClassification)) {

                    /*
                     * Both the deterministic rule engine
                     * and local AI found no threat.
                     */

                    result.setActionTaken("ALLOWED");

                    result.setDetectionSource(
                            "RULE_ENGINE + LOCAL_AI"
                    );
                }

                // -------------------------------------------------
                // AI unavailable / unknown
                // -------------------------------------------------

                else {

                    /*
                     * Local AI could not provide a classification.
                     *
                     * The deterministic rule engine found nothing
                     * suspicious, but the secondary AI layer is unavailable.
                     *
                     * The security policy determines whether this should
                     * be allowed or blocked.
                     */

                    result.setDetectionSource(
                            "LOCAL_AI_UNAVAILABLE"
                    );

                    if (settings.isFailClosedOnAiUnavailable()) {

                        result.setMalicious(true);

                        result.setAttackType(
                                "AI_UNAVAILABLE"
                        );

                        result.setRiskLevel("HIGH");

                        result.setRiskScore(70);

                        result.setReason(
                                "Local AI security analysis was unavailable and fail-closed security policy is enabled."
                        );

                        if (settings.isAutoBlockEnabled()) {
                            result.setActionTaken("BLOCKED");
                        } else {
                            result.setActionTaken("FLAGGED");
                        }

                    } else {

                        result.setActionTaken("ALLOWED");

                        result.setReason(
                                "Local AI security analysis was unavailable. "
                                        + "Request allowed because fail-closed policy is disabled."
                        );
                    }
                }
            }
        }

        // =========================================================
// 3.5 REPEATED ATTACK DETECTION
// =========================================================

        if (result.isMalicious()) {

            long previousMaliciousRequests =
                    scanRepository.countByClientIpAndMalicious(
                            clientIp,
                            true
                    );

            /*
             * If this client has already generated
             * 3 or more malicious requests, treat
             * the current request as repeated abuse.
             */
            if (previousMaliciousRequests >=
                    settings.getMaliciousRequestThreshold()) {

                String existingAttackType =
                        result.getAttackType();

                if (existingAttackType == null ||
                        existingAttackType.isBlank()) {

                    result.setAttackType("CLIENT_ABUSE");

                } else if (!existingAttackType.contains("CLIENT_ABUSE")) {

                    result.setAttackType(
                            existingAttackType + ", CLIENT_ABUSE"
                    );
                }

                result.setReason(
                        result.getReason()
                                + " Repeated malicious activity detected from the same client."
                );

                result.setDetectionSource(
                        result.getDetectionSource()
                                + " + BEHAVIOR_ANALYSIS"
                );

                /*
                 * Escalate risk to CRITICAL.
                 */
                result.setRiskLevel("CRITICAL");

                if (result.getRiskScore() < 90) {
                    result.setRiskScore(90);
                }

                /*
                 * Repeated malicious activity should be
                 * blocked when automatic blocking is enabled.
                 */
                if (settings.isAutoBlockEnabled()) {
                    result.setActionTaken("BLOCKED");
                } else {
                    result.setActionTaken("FLAGGED");
                }
            }
        }

        // =========================================================
// MULTI-STEP JAILBREAK / BEHAVIOR ANALYSIS
// =========================================================

        boolean multiStepJailbreak =
                detectMultiStepJailbreak(
                        clientIp,
                        request.getContent()
                );

        if (multiStepJailbreak) {

            String existingAttackType =
                    result.getAttackType();

            if (existingAttackType == null
                    || existingAttackType.isBlank()
                    || "NONE".equals(existingAttackType)) {

                result.setAttackType(
                        "MULTI_STEP_JAILBREAK"
                );

            } else if (!existingAttackType.contains(
                    "MULTI_STEP_JAILBREAK")) {

                result.setAttackType(
                        existingAttackType
                                + ", MULTI_STEP_JAILBREAK"
                );
            }

            result.setMalicious(true);

            result.setRiskLevel("CRITICAL");

            if (result.getRiskScore() < 90) {
                result.setRiskScore(90);
            }

            result.setReason(
                    result.getReason()
                            + " A sequence of related manipulation attempts was detected from the same client."
            );

            String existingSource =
                    result.getDetectionSource();

            if (existingSource == null
                    || existingSource.isBlank()) {

                result.setDetectionSource(
                        "BEHAVIOR_ANALYSIS"
                );

            } else if (!existingSource.contains(
                    "BEHAVIOR_ANALYSIS")) {

                result.setDetectionSource(
                        existingSource
                                + " + BEHAVIOR_ANALYSIS"
                );
            }

            if (settings.isAutoBlockEnabled()) {
                result.setActionTaken("BLOCKED");
            } else {
                result.setActionTaken("FLAGGED");
            }
        }

        // =========================================================
// 3.6 REQUEST RATE / BURST DETECTION
// =========================================================

        LocalDateTime rateLimitWindowStart =
                LocalDateTime.now().minusSeconds(
                        settings.getRateLimitWindowSeconds()
                );

        long recentRequestCount =
                scanRepository.countByClientIpAndTimestampAfter(
                        clientIp,
                        rateLimitWindowStart
                );

        /*
         * If this client has already made more than
         * 10 requests during the previous 60 seconds,
         * flag the client for excessive request activity.
         */
        if (recentRequestCount >=
                settings.getRateLimitThreshold()) {

            String existingAttackType =
                    result.getAttackType();

            if (existingAttackType == null ||
                    existingAttackType.isBlank() ||
                    "NONE".equals(existingAttackType)) {

                result.setAttackType("RATE_LIMIT_EXCEEDED");

            } else if (!existingAttackType.contains("RATE_LIMIT_EXCEEDED")) {

                result.setAttackType(
                        existingAttackType + ", RATE_LIMIT_EXCEEDED"
                );
            }

            result.setReason(
                    result.getReason()
                            + " Excessive request frequency detected from the same client."
            );

            String existingSource =
                    result.getDetectionSource();

            if (existingSource == null ||
                    existingSource.isBlank()) {

                result.setDetectionSource(
                        "BEHAVIOR_ANALYSIS"
                );

            } else if (!existingSource.contains("BEHAVIOR_ANALYSIS")) {

                result.setDetectionSource(
                        existingSource + " + BEHAVIOR_ANALYSIS"
                );
            }

            /*
             * Rate abuse is treated as HIGH risk.
             * Do not reduce an already higher risk.
             */
            if (result.getRiskScore() < 70) {
                result.setRiskScore(70);
            }

            if (!"CRITICAL".equals(result.getRiskLevel())) {
                result.setRiskLevel("HIGH");
            }

            /*
             * If automatic blocking is enabled,
             * block the excessive request.
             */
            if (settings.isAutoBlockEnabled()) {
                result.setActionTaken("BLOCKED");
            } else {
                result.setActionTaken("FLAGGED");
            }
        }

        // =========================================================
        // 4. PROCESSING TIME
        // =========================================================

        long processingTime =
                System.currentTimeMillis() - startTime;

        result.setProcessingTimeMs(processingTime);

        // =========================================================
        // 5. DATABASE LOGGING
        // =========================================================

        if (settings.isLoggingEnabled()) {

            Scan scan = new Scan();

            scan.setRequestId(requestId);

            scan.setClientIp(clientIp);
            scan.setInputSource(inputSource);
            scan.setContent(request.getContent());

            scan.setMalicious(result.isMalicious());

            scan.setAttackType(result.getAttackType());

            scan.setRiskLevel(result.getRiskLevel());

            scan.setRiskScore(result.getRiskScore());

            scan.setReason(result.getReason());

            scan.setActionTaken(result.getActionTaken());

            scan.setProcessingTimeMs(processingTime);

            scan.setDetectionSource(result.getDetectionSource());

            scan.setTimestamp(LocalDateTime.now());

            scanRepository.save(scan);
        }

        // =========================================================
        // 6. RETURN REQUEST ID
        // =========================================================

        result.setRequestId(requestId);
        result.setInputSource(inputSource);
        return result;
    }

    // =============================================================
    // SETTINGS
    // =============================================================

    private SecuritySettings getSettings() {

        return settingsRepository.findById(1L)
                .orElseGet(this::createDefaultSettings);
    }

    private SecuritySettings createDefaultSettings() {

        SecuritySettings settings = new SecuritySettings();

        settings.setId(1L);
        settings.setFirewallEnabled(true);
        settings.setDetectionEnabled(true);
        settings.setAutoBlockEnabled(true);
        settings.setLoggingEnabled(true);
        settings.setUpdatedAt(LocalDateTime.now());

        return settingsRepository.save(settings);
    }

    private boolean detectMultiStepJailbreak(
            String clientIp,
            String currentContent) {

        List<Scan> recentScans =
                scanRepository.findTop10ByClientIpOrderByTimestampDesc(
                        clientIp
                );

        int manipulationSignals = 0;

        for (Scan scan : recentScans) {

            String attackType = scan.getAttackType();

            if (attackType == null) {
                continue;
            }

            if (attackType.contains("INSTRUCTION_OVERRIDE")
                    || attackType.contains("ROLE_CHANGE")
                    || attackType.contains("JAILBREAK")
                    || attackType.contains("CONTEXT_POISONING")
                    || attackType.contains("INDIRECT_PROMPT_INJECTION")
                    || attackType.contains("SECRET_EXTRACTION")) {

                manipulationSignals++;
            }
        }

        String currentText =
                currentContent == null
                        ? ""
                        : currentContent.toLowerCase();

        boolean currentManipulation =
                currentText.contains("ignore previous")
                        || currentText.contains("ignore all previous")
                        || currentText.contains("from now on")
                        || currentText.contains("you are now")
                        || currentText.contains("act as")
                        || currentText.contains("developer mode")
                        || currentText.contains("jailbreak")
                        || currentText.contains("bypass")
                        || currentText.contains("disable safety")
                        || currentText.contains("override");

        return manipulationSignals >= 2
                && currentManipulation;
    }
}