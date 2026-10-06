package AgentShield.controller;

import AgentShield.security.LocalAiSecurityAnalyzer;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/ai-test")
public class AiTestController {

    private final LocalAiSecurityAnalyzer analyzer;

    public AiTestController(LocalAiSecurityAnalyzer analyzer) {
        this.analyzer = analyzer;
    }

    @PostMapping
    public Map<String, String> test(@RequestBody Map<String, String> request) {

        String content = request.get("content");

        String result = analyzer.analyze(content);

        return Map.of(
                "content", content == null ? "" : content,
                "classification", result
        );
    }
}