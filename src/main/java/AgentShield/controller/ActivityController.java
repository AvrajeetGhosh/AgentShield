package AgentShield.controller;

import AgentShield.model.Scan;
import AgentShield.repository.ScanRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/activity")
public class ActivityController {

    private final ScanRepository scanRepository;

    public ActivityController(ScanRepository scanRepository) {
        this.scanRepository = scanRepository;
    }

    @GetMapping
    public List<Scan> getActivity() {

        return scanRepository.findAllByOrderByTimestampDesc();
    }
}