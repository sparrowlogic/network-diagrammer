package com.sparrowlogic.networkdiagram.controller;

import com.sparrowlogic.networkdiagram.service.AwsInfrastructureService;
import com.sparrowlogic.networkdiagram.service.MermaidDiagramService;
import org.commonmark.parser.Parser;
import org.commonmark.renderer.html.HtmlRenderer;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class DiagramController {
    
    private final AwsInfrastructureService awsService;
    private final MermaidDiagramService mermaidService;
    
    public DiagramController(AwsInfrastructureService awsService, MermaidDiagramService mermaidService) {
        this.awsService = awsService;
        this.mermaidService = mermaidService;
    }

    @GetMapping("/")
    public String showForm() {
        return "form";
    }

    @PostMapping("/generate")
    public String generateDiagram(@RequestParam String profile, @RequestParam String region, @RequestParam String vpcId, Model model) {
        try {
            var infrastructure = awsService.getInfrastructure(profile, region, vpcId);
            var diagramOutput = mermaidService.generateDiagram(infrastructure);
            
            // Parse the output to separate load balancer sections
            var sections = new java.util.ArrayList<java.util.Map<String, String>>();
            var lines = diagramOutput.split("\n");
            var currentSection = new java.util.HashMap<String, String>();
            var currentText = new StringBuilder();
            
            for (var line : lines) {
                if (line.startsWith("=== ") && line.endsWith(" ===")) {
                    // Save previous section if exists
                    if (!currentSection.isEmpty()) {
                        currentSection.put("text", currentText.toString().trim());
                        sections.add(currentSection);
                    }
                    // Start new section
                    currentSection = new java.util.HashMap<>();
                    currentSection.put("title", line.replace("===", "").trim());
                    currentText = new StringBuilder();
                } else if (!line.trim().isEmpty()) {
                    currentText.append(line).append("\n");
                }
            }
            
            // Add last section
            if (!currentSection.isEmpty()) {
                currentSection.put("text", currentText.toString().trim());
                sections.add(currentSection);
            }
            
            model.addAttribute("sections", sections);
            model.addAttribute("diagram", "");
            model.addAttribute("markdown", "");
            
            return "index";
        } catch (Exception e) {
            model.addAttribute("error", "Error loading AWS infrastructure: " + e.getMessage());
            return "error";
        }
    }
}
