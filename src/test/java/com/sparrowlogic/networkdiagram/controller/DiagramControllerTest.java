package com.sparrowlogic.networkdiagram.controller;

import com.sparrowlogic.networkdiagram.model.InfrastructureComponents;
import com.sparrowlogic.networkdiagram.service.AwsInfrastructureService;
import com.sparrowlogic.networkdiagram.service.MermaidDiagramService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;

import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(DiagramController.class)
class DiagramControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private AwsInfrastructureService awsService;

    @MockBean
    private MermaidDiagramService mermaidService;

    @Test
    void shouldShowForm() throws Exception {
        mockMvc.perform(get("/"))
                .andExpect(status().isOk())
                .andExpect(view().name("form"));
    }

    @Test
    void shouldGenerateDiagramWithParameters() throws Exception {
        var components = new InfrastructureComponents(List.of(), List.of(), List.of(), List.of(), "vpc-123", List.of());
        when(awsService.getInfrastructure("prod", "us-east-1", "vpc-123")).thenReturn(components);
        when(mermaidService.generateDiagram(components)).thenReturn("graph TD\n");

        mockMvc.perform(post("/generate")
                .param("profile", "prod")
                .param("region", "us-east-1")
                .param("vpcId", "vpc-123"))
                .andExpect(status().isOk())
                .andExpect(view().name("index"))
                .andExpect(model().attributeExists("diagram", "markdown"));
    }

    @Test
    void shouldHandleError() throws Exception {
        when(awsService.getInfrastructure("default", "us-east-1", "vpc-123"))
                .thenThrow(new RuntimeException("AWS error"));

        mockMvc.perform(post("/generate")
                .param("profile", "default")
                .param("region", "us-east-1")
                .param("vpcId", "vpc-123"))
                .andExpect(status().isOk())
                .andExpect(view().name("error"))
                .andExpect(model().attribute("error", "Error loading AWS infrastructure: AWS error"));
    }
}
